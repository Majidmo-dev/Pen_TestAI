import argparse, os, yaml
from scope import Scope
from audit import AuditLog
from approval import ApprovalGate
from llm import Planner
from tools.base import SafeRunner
from tools.recon import NmapScan, WebProbe
from agent import PentestAgent

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--target", required=True)
    p.add_argument("--scope", default="scope.yaml")
    p.add_argument("--objective",
                   default="Map attack surface, identify likely vulnerabilities.")
    p.add_argument("--no-approval", action="store_true",
                   help="Fail closed if any active tool would be needed (CI/safe mode)")
    args = p.parse_args()

    scope = Scope(args.scope)  # validates config eagerly
    audit = AuditLog(os.environ.get("AUDIT_DIR", "./audit_logs/current_engagement"))
    gate = None if args.no_approval else ApprovalGate()
    agent = PentestAgent(
        runner=SafeRunner(scope, audit),
        gate=gate,
        llm_client=Planner.from_env(),
        tools=[NmapScan(), WebProbe()],
        audit=audit,
    )
    report = agent.run(args.target, objective=args.objective)
    print(report)

if __name__ == "__main__":
    main()
