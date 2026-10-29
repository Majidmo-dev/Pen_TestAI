class PentestAgent:
    def __init__(self, runner, gate, llm_client, tools, audit, max_steps=25):
        self.runner = runner
        self.gate = gate
        self.llm = llm_client
        self.tools = {t.name: t for t in tools}
        self.audit = audit
        self.max_steps = max_steps
        self.history = []

    def run(self, target: str, objective: str) -> str:
        for step in range(self.max_steps):
            plan = self.llm.plan(target=target, history=self.history,
                                 tools=self.tools, objective=objective)
            self.audit.log_plan(step, plan)
            action = plan.get("action")

            if action == "done":
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

            raw_t = plan.get("target") or plan.get("args", {}).get("target") or target
            plan_target = raw_t.replace("http://", "").replace("https://", "").split("/")[0]
            if not self.runner.scope.is_allowed(plan_target):
                self.audit.log("SCOPE_VIOLATION_ATTEMPT", step=step, proposed=raw_t)
                self.history.append({"denied": f"{raw_t} out of scope"})
                continue

            tool = self.tools[tool_name]
            if tool.active:
                if self.gate is None or not self.gate.require(plan):
                    self.audit.log_approval(step, granted=False, operator="none")
                    self.history.append({"step": step, "denied": "active tool needs approval"})
                    continue
                self.audit.log_approval(step, granted=True, operator="console")

            result = self.runner.run(tool, raw_t, step=step, **plan.get("args", {}))
            self.history.append({"step": step, "expectation": plan.get("expectation"),
                                 "result": result.summary})

        return "Step limit reached — partial results in history."
