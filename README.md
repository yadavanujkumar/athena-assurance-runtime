# ATHENA

**Autonomous Trust, Health, Evaluation & Network Assurance Runtime**

ATHENA is an open-source, local-first assurance runtime for software and AI-enabled systems. It builds a living project graph, maintains durable memory, plans investigations proactively, evaluates risks and policies, and keeps humans in control of consequential actions.

> **The user defines intent. ATHENA determines what needs to be investigated.**

## Vision

ATHENA is designed to operate as a persistent assurance layer rather than a one-shot scanner. It can observe a project, construct a graph of its components and relationships, retain durable context, generate investigation objectives when the user has not specified them, investigate findings, propose remediation, validate changes, and escalate decisions according to explicit authority.

## Current foundation

- Stable project knowledge graph with Python AST discovery
- Durable SQLite memory for facts, events, objectives, findings and decisions
- Autonomous planning kernel with user-objective and no-objective modes
- Explicit bounded-authority model
- CLI and Python runtime foundation
- Deterministic tests for graph, planning and memory behavior

## Architecture direction

```text
User intent (optional)
        ↓
Project discovery → Living knowledge graph ↔ Durable memory
        ↓                         ↑
Autonomous planner → investigation tasks
        ↓
Investigators / detectors / governance agents
        ↓
Evidence → risk → remediation plan
        ↓
Authority decision ──→ human approval when required
        ↓
Action → validation → graph + memory update
        ↓
Continuous re-evaluation
```

The core is intentionally independent of the UI and model provider. CLI, SDK, API and UI are adapters around the runtime. Local/open-source model providers will be supported through a provider abstraction; no paid service is required for the deterministic core.

## Quick start

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e '.[dev]'
athena init .
athena status .
athena inspect .
```

## Roadmap

1. **Foundation** — graph, durable memory, authority, planner (current)
2. **Investigation runtime** — task lifecycle, evidence ledger, agent contracts
3. **AI/agent discovery** — models, prompts, tools, data flows, permissions
4. **Proactive assurance** — change/event triggers and self-generated objectives
5. **Remediation** — sandboxed patches, test execution, verification and rollback
6. **Governance packs** — NIST AI RMF, ISO/IEC 42001, EU AI Act, OWASP and custom policies
7. **Interfaces** — CLI, SDK, API and web graph/operations console
8. **Continuous runtime** — live agent/tool observation and multi-agent governance

## License

Apache-2.0
