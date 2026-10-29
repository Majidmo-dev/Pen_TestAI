import json, subprocess
from dataclasses import dataclass, field

from scope import split_target

MAX_OUTPUT_CHARS = 1_000_000
MAX_SUMMARY_CHARS = 4000


class ScopeError(ValueError):
    """A tool argument would take the action outside scope (e.g. a port)."""


@dataclass
class Target:
    raw: str
    scheme: str  # '' when the planner gave a bare host
    host: str
    port: int | None
    path: str


@dataclass
class Result:
    ok: bool
    summary: dict
    parsed: dict = field(default_factory=dict)
    artifacts: list = field(default_factory=list)


class Tool:
    """Subclasses set name/description/args and implement build() and parse().

    args maps arg name -> {"type": "str"|"int", "description": ..., "choices": [...]}.
    """
    name = ""
    description = ""
    active = False   # active tools require human approval
    timeout = 60
    args: dict = {}

    def describe(self) -> dict:
        return {"description": self.description, "active": self.active,
                "args": self.args}

    def build(self, target: Target, args: dict, scope) -> list:
        raise NotImplementedError

    def parse(self, stdout: str, target: Target, cmd: list) -> dict:
        raise NotImplementedError


def _validate_args(tool: Tool, args: dict) -> dict:
    types = {"str": str, "int": int}
    clean = {}
    for k, v in args.items():
        spec = tool.args.get(k)
        if spec is None:
            raise ValueError(f"unknown argument for {tool.name}: {k!r}")
        want = types[spec["type"]]
        if not isinstance(v, want) or isinstance(v, bool):
            raise ValueError(f"{k} must be {spec['type']}, got {type(v).__name__}")
        if "choices" in spec and v not in spec["choices"]:
            raise ValueError(f"{k} must be one of {spec['choices']}")
        clean[k] = v
    return clean


def _shorten(obj, limit=MAX_SUMMARY_CHARS):
    s = json.dumps(obj)
    if len(s) <= limit:
        return obj
    return {"truncated": True, "preview": s[:limit]}


class SafeRunner:
    """The only path from a plan to a subprocess. Enforces scope independently of
    the agent loop, rejects duplicate calls, applies timeouts, and audits everything."""

    def __init__(self, scope, audit):
        self.scope = scope
        self.audit = audit
        self._seen = set()

    def _deny(self, step, reason, event=None, **fields):
        if event:
            self.audit.log(event, step=step, source="runner", reason=reason, **fields)
        return Result(ok=False, summary={"denied": reason})

    def run(self, tool: Tool, raw_target: str, step: int, **args) -> Result:
        t = split_target(raw_target)
        if t is None:
            return self._deny(step, f"invalid target: {raw_target!r}",
                              "INVALID_TARGET", proposed=raw_target)
        target = Target(raw_target, *t)
        if not self.scope.is_allowed(target.host):
            return self._deny(step, f"{target.host} out of scope",
                              "SCOPE_VIOLATION_ATTEMPT", proposed=raw_target)

        try:
            args = _validate_args(tool, args)
            cmd = tool.build(target, args, self.scope)
        except ScopeError as e:
            return self._deny(step, str(e), "SCOPE_VIOLATION_ATTEMPT",
                              proposed=raw_target, args=args)
        except ValueError as e:
            return self._deny(step, f"invalid arguments: {e}", "INVALID_ARGS", args=args)

        key = tuple(cmd)
        if key in self._seen:
            return self._deny(step, "duplicate call rejected; try something new",
                              "DUPLICATE_CALL", cmd=cmd)
        self._seen.add(key)

        try:
            proc = subprocess.run(cmd, capture_output=True, text=True,
                                  timeout=tool.timeout, errors="replace")
            stdout, stderr, rc = proc.stdout, proc.stderr, proc.returncode
        except subprocess.TimeoutExpired as e:
            def _txt(b):
                return b.decode(errors="replace") if isinstance(b, bytes) else (b or "")
            stdout, stderr, rc = _txt(e.stdout), _txt(e.stderr) + "\n[timeout]", -1
        except FileNotFoundError:
            self.audit.log_tool_call(step, cmd, target.host, rc=127)
            return Result(ok=False, summary={"error": f"{cmd[0]} not installed"})

        stdout = stdout[:MAX_OUTPUT_CHARS]
        self.audit.log_tool_call(step, cmd, target.host, rc)
        artifacts = [self.audit.log_tool_output(
            step, f"$ {' '.join(cmd)}\n[rc={rc}]\n--- stdout ---\n{stdout}"
                  f"\n--- stderr ---\n{stderr[:20000]}")]

        parsed = tool.parse(stdout, target, cmd)
        if rc != 0:
            parsed["returncode"] = rc
            if stderr.strip():
                parsed["stderr"] = stderr.strip()[-500:]
        artifacts.append(self.audit.log_tool_output(step, json.dumps(parsed, indent=1)))

        return Result(ok=rc == 0, summary=_shorten(parsed), parsed=parsed,
                      artifacts=artifacts)
