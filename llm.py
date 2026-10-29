import json, re, os
import prompts

class Planner:
    def __init__(self, client=None, model="gpt-4o-mini"):
        self.client = client  # openai.OpenAI or None (mock mode)
        self.model = model

    @classmethod
    def from_env(cls):
        key = os.environ.get("OPENAI_API_KEY", "")
        if not key:
            return MockPlanner()
        import openai
        return cls(client=openai.OpenAI(api_key=key),
                   model=os.environ.get("OPENAI_MODEL", "gpt-4o-mini"))

    def plan(self, target, history, tools, objective):
        schemas = {name: t.describe() for name, t in tools.items()}
        raw = self._call(
            system=prompts.SYSTEM_PROMPT + "\n\n" + prompts.FINAL_REPORT_FORMAT,
            user=prompts.TASK_TEMPLATE.format(
                target=target,
                scope_summary="see runtime allowlist (not shown to you)",
                objective=objective,
                tool_schemas=json.dumps(schemas, indent=1),
                history=json.dumps(history[-6:], indent=1),
            ),
        )
        return self._parse(raw)

    def _call(self, system, user):
        resp = self.client.chat.completions.create(
            model=self.model,
            messages=[{"role": "system", "content": system},
                      {"role": "user", "content": user}],
            temperature=0.2,
        )
        return resp.choices[0].message.content

    def _parse(self, raw: str) -> dict:
        # Take the first complete JSON object; a greedy regex would swallow
        # everything between the first '{' and the last '}'.
        decoder = json.JSONDecoder()
        for m in re.finditer(r"\{", raw or ""):
            try:
                step, _ = decoder.raw_decode(raw, m.start())
            except json.JSONDecodeError:
                continue
            if isinstance(step, dict):
                return step
        return {"action": "clarify",
                "reasoning": f"Unparseable model output: {(raw or '')[:300]}"}

class MockPlanner(Planner):
    """Deterministic stand-in so the pipeline runs without an API key."""
    def plan(self, target, history, tools, objective):
        n = len([h for h in history if "result" in h])
        if n == 0:
            return {"reasoning": "Start with reconnaissance.", "action": "tool",
                    "tool": "nmap", "target": target, "args": {},
                    "expectation": "open ports and services"}
        if n == 1:
            return {"reasoning": "Probe the web service.", "action": "tool",
                    "tool": "webprobe", "target": f"http://{target}", "args": {},
                    "expectation": "HTTP status and server headers"}
        return {"action": "done", "findings": [],
                "report": "(mock planner — no LLM connected)"}
