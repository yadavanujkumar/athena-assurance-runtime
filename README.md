# ATHENA

**Autonomous Trust, Health, Evaluation & Network Assurance Runtime**

ATHENA is an open-source, local-first assurance runtime for software and AI-enabled systems. It builds a living project graph, maintains durable memory, plans investigations proactively, evaluates risks and policies, and keeps humans in control of consequential actions.

> Define what you want checked. ATHENA investigates, reasons, proposes actions, validates outcomes, remembers decisions, and keeps watching.

## Design principles

- **Autonomy with bounded authority** — observation and investigation can be autonomous; consequential changes require policy/approval.
- **Graph before guesswork** — project entities and relationships are explicit, inspectable state.
- **Memory is durable** — project facts, investigations, decisions, approvals and observations survive context windows.
- **Evidence before claims** — findings point to concrete files, lines, commands or graph facts.
- **Provider-neutral** — the core does not require a paid AI API. Optional model providers can be added later.
- **CLI/API/UI independent** — the runtime is the product; interfaces are adapters.

## Current MVP

The first implementation provides:

- project discovery and graph construction
- persistent SQLite memory
- objectives and investigation plans
- deterministic autonomous inspection loop
- Python code heuristics for high-value defects
- dependency/configuration inspection
- governance findings with severity/confidence/evidence
- bounded remediation planning
- human approval records
- CLI commands for init, inspect, status, findings and objectives
- tests for graph, memory, policy and runtime behavior

## Quick start

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e '.[dev]'

athena init .
athena inspect .
athena status .
athena findings .
```

Or without installation:

```bash
python -m athena.cli inspect .
```

## Architecture

```text
Project → Discover → Knowledge Graph → Memory
                         ↓
                    Planner/Loop
                         ↓
        Inspectors → Evidence → Findings
                         ↓
                  Policy/Authority
                    ↓         ↓
                 Act        Escalate
                    ↓         ↓
                 Verify ← Human
                    ↓
                 Memory
                    ↓
               Continue watch
```

## Roadmap

1. Core runtime + durable state (current)
2. Multi-language AST/code intelligence
3. AI/agent discovery and behavior assurance
4. Pluggable detectors and policy packs
5. Local LLM provider (Ollama) with model-independent reasoning contracts
6. Remediation sandbox + validation loop
7. Git/CI integration
8. Web UI and graph visualization
9. NIST AI RMF / ISO 42001 / EU AI Act / OWASP control mappings
10. Continuous runtime observation and multi-agent governance

## License

Apache-2.0
