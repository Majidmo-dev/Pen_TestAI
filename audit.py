import json, hashlib, time, os, re
from pathlib import Path


def _entry_hash(entry: dict) -> str:
    return hashlib.sha256(json.dumps(entry, sort_keys=True).encode()).hexdigest()


def verify_chain(path) -> bool:
    """Check the hash chain in <path>/events.jsonl without creating or modifying anything."""
    f = Path(path) / "events.jsonl"
    if not f.is_file():
        return False
    prev = "GENESIS"
    try:
        with open(f) as fh:
            for line in fh:
                entry = json.loads(line)
                h = entry.pop("hash")
                if _entry_hash(entry) != h or entry["prev_hash"] != prev:
                    return False
                prev = h
    except (json.JSONDecodeError, KeyError, TypeError, AttributeError):
        return False
    return True


class AuditLog:
    def __init__(self, path: str):
        self.path = Path(path)
        self.path.mkdir(parents=True, exist_ok=True)
        self.file = open(self.path / "events.jsonl", "a", buffering=1)
        self._prev_hash = self._load_last_hash()
        # Continue numbering across runs so earlier artifacts are never overwritten.
        self._art_n = max((int(m.group(1)) for f in self.path.glob("step_*_*.txt")
                           if (m := re.fullmatch(r"step_\d+_(\d+)\.txt", f.name))),
                          default=0)

    def _load_last_hash(self) -> str:
        f = self.path / "events.jsonl"
        if not f.exists() or f.stat().st_size == 0:
            return "GENESIS"
        last = f.read_text().strip().splitlines()[-1]
        try:
            return json.loads(last)["hash"]
        except (json.JSONDecodeError, KeyError, TypeError) as e:
            # Fail closed: appending to a damaged chain would hide the damage.
            raise RuntimeError(
                f"{f}: last audit entry is corrupt or truncated ({e}); "
                "refusing to append. Use a new AUDIT_DIR.") from None

    def log(self, event_type: str, **fields):
        entry = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "type": event_type,
            "prev_hash": self._prev_hash,
            **fields,
        }
        entry["hash"] = _entry_hash(entry)
        self._prev_hash = entry["hash"]
        self.file.write(json.dumps(entry) + "\n")
        self.file.flush()
        os.fsync(self.file.fileno())

    def log_plan(self, step: int, plan: dict):
        self.log("PLAN", step=step,
                 **{k: plan.get(k) for k in
                    ("reasoning", "action", "tool", "args", "expectation")})

    def log_tool_call(self, step: int, cmd: list, target: str, rc: int):
        self.log("TOOL_CALL", step=step, cmd=cmd, target=target, returncode=rc)

    def log_tool_output(self, step: int, output: str) -> str:
        self._art_n += 1
        fname = f"step_{step:03d}_{self._art_n:02d}.txt"
        with open(self.path / fname, "x") as f:  # "x": never overwrite evidence
            f.write(output)
        self.log("TOOL_OUTPUT", step=step, artifact=fname,
                 sha256=hashlib.sha256(output.encode()).hexdigest())
        return fname

    def log_approval(self, step: int, granted: bool, operator: str):
        self.log("APPROVAL", step=step, granted=granted, operator=operator)

    def events_of_type(self, event_type: str) -> list:
        out = []
        for line in open(self.path / "events.jsonl"):
            e = json.loads(line)
            if e["type"] == event_type:
                out.append(e)
        return out

    def all_observed_urls(self) -> list:
        urls = []
        for f in sorted(self.path.glob("step_*.txt")):
            urls.extend(re.findall(r"https?://[^\s\"'\])>]+", f.read_text()))
        return urls

    def verify(self) -> bool:
        return verify_chain(self.path)
