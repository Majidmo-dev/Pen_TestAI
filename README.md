# pentest-agent

An LLM-guided penetration testing assistant with **hard-coded guardrails**:
sandboxed execution, machine-enforced scope, human approval for active actions,
hash-chained audit logging, and a measurable evaluation harness.

> **LEGAL WARNING** — Run this ONLY against systems you own or have written
> authorization to test. The scope enforcement here is a safety net, not a
> license. Unauthorized testing is illegal (CFAA, Computer Misuse Act, etc.).

## Architecture

```
planner (LLM) ──▶ plan JSON ──▶ [scope check] ──▶ [approval gate] ──▶ SafeRunner
                                     │                    │              │
                                     ▼                    ▼              ▼
                            SCOPE_VIOLATION_ATTEMPT    audit log    tools (nmap, webprobe)
                                                                              │
                                                                              ▼
                                                                       parser ──▶ typed JSON
                                                                              │
                                                                              ▼
                                                                    history ──▶ planner
```

The LLM never sees the allowlist and cannot bypass runtime checks.

## Quickstart

```bash
cp .env.example .env            # add your API key (optional — demo mode works without)
make lab-up                   # start DVWA lab container
make run                      # run the agent against the lab
make eval                     # run the evaluation harness
make verify-audit AUDIT_DIR=./audit_logs/current_engagement
make lab-down                 # tear down the lab
```

Without an API key, a built-in MockPlanner demonstrates the full pipeline
(its "findings" are canned and will score poorly — that's expected).

## Repo map

| File | Role |
|---|---|
| `scope.yaml` | Per-engagement allowlist — edit before every run |
| `scope.py` | CIDR/domain/port enforcement, `is_allowed()` |
| `tools/base.py` | `SafeRunner`: scope gate, dedupe, parsers, timeouts |
| `tools/recon.py` | Passive tools: `nmap`, `webprobe` |
| `tools/parsers.py` | nmap XML / curl output → typed JSON |
| `agent.py` | Plan-validate-execute loop, scope-drift blocks |
| `llm.py` | Planner: prompt, JSON extraction, fail-closed parsing |
| `prompts.py` | System prompt, task template, report contract |
| `audit.py` | Hash-chained event log + artifact storage |
| `approval.py` | Human-in-the-loop for active tools |
| `eval.py` | Scenarios with manual ground truth, scoring |
| `main.py` | CLI entrypoint |

## Safety properties

1. Scope enforced in `SafeRunner`, not in prompts — prompt injection cannot bypass it.
2. `active` tools require approval; passive tools are the default.
3. Duplicate tool calls are mechanically rejected (anti-loop).
4. Every out-of-scope proposal is blocked AND logged (`SCOPE_VIOLATION_ATTEMPT`).
5. Findings in eval are credited from tool output in the audit log, not the model's claims.

## Next steps

- Add a link-follower (crawl same-domain links) so the agent maps pages behind the root URL.
- Add 2+ lab scenarios (Metasploitable, a WordPress container) — three scenarios triangulate, one confirms bias.
- Keep `forbidden_hit == 0` as an absolute gate on every change.

DVWA lab default credentials: `admin` / `password` (see `docker logs` for the container IP if DNS fails).
