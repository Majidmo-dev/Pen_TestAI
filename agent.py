import time
from urllib.parse import urlsplit


def target_host(raw: str):
    """Hostname a tool will actually contact, or None if it can't be determined.

    Bare targets containing '/' (e.g. CIDR ranges like 'dvwa/0') are rejected:
    checking only the part before the slash would let a range escape scope.
    """
    if not isinstance(raw, str) or not raw.strip():
        return None
    raw = raw.strip()
    if "://" not in raw:
        if "/" in raw:
            return None
        raw = "//" + raw
    try:
        return urlsplit(raw).hostname
    except ValueError:
        return None


class PentestAgent:
    def __init__(self, runner, gate, llm_client, tools, audit, max_steps=25,
                 max_seconds=None):
        self.runner = runner
        self.gate = gate
        self.llm = llm_client
        self.tools = {t.name: t for t in tools}
        self.audit = audit
        self.max_steps = max_steps
        self.max_seconds = max_seconds
        self.history = []
        self.stop_reason = None

    def run(self, target: str, objective: str) -> str:
        t0 = time.monotonic()
        for step in range(self.max_steps):
            if self.max_seconds is not None and time.monotonic() - t0 > self.max_seconds:
                self.stop_reason = "time_limit"
                self.audit.log("TIME_LIMIT", step=step)
                return "Time limit reached — partial results in history."
            plan = self.llm.plan(target=target, history=self.history,
                                 tools=self.tools, objective=objective)
            self.audit.log_plan(step, plan)
            action = plan.get("action")

            if action == "done":
                self.stop_reason = "done"
                self.audit.log("DONE", step=step, findings=plan.get("findings", []))
                return plan.get("report", "No report.")

            if action == "clarify":
                self.history.append({"step": step,
                                     "clarification": plan.get("reasoning", "")})
                continue

            if action != "tool":
                self.history.append({"step": step, "bad_action": plan})
                continue

            tool_name = plan.get("tool")
            if tool_name not in self.tools:
                self.history.append({"step": step, "denied": f"unknown tool: {tool_name}"})
                continue

            args = plan.get("args")
            args = dict(args) if isinstance(args, dict) else {}
            raw_t = plan.get("target") or args.pop("target", None) or target
            args.pop("target", None)  # passed positionally below

            plan_target = target_host(raw_t)
            if plan_target is None:
                self.audit.log("INVALID_TARGET", step=step, proposed=raw_t)
                self.history.append({"step": step, "denied": f"invalid target: {raw_t!r}"})
                continue
            if not self.runner.scope.is_allowed(plan_target):
                self.audit.log("SCOPE_VIOLATION_ATTEMPT", step=step, proposed=raw_t)
                self.history.append({"step": step, "denied": f"{raw_t} out of scope"})
                continue

            tool = self.tools[tool_name]
            if tool.active:
                if self.gate is None or not self.gate.require(plan):
                    self.audit.log_approval(step, granted=False, operator="none")
                    self.history.append({"step": step, "denied": "active tool needs approval"})
                    continue
                self.audit.log_approval(step, granted=True, operator="console")

            result = self.runner.run(tool, raw_t, step=step, **args)
            self.history.append({"step": step, "expectation": plan.get("expectation"),
                                 "result": result.summary})

        self.stop_reason = "step_limit"
        return "Step limit reached — partial results in history."
