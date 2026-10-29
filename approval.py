class ApprovalGate:
    def require(self, action: dict) -> bool:
        print("\n=== AGENT REQUESTS ACTIVE ACTION ===")
        print(f"Tool:   {action.get('tool')}")
        print(f"Target: {action.get('target')}")
        print(f"Args:   {action.get('args', {})}")
        print(f"Reason: {action.get('reasoning', 'none given')}")
        return input("Approve? [y/N] ").strip().lower() == "y"
