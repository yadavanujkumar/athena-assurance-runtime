# ATHENA

**Autonomous Trust, Health, Evaluation & Network Assurance Runtime**

[![CI](https://github.com/yadavanujkumar/athena-assurance-runtime/actions/workflows/test.yml/badge.svg)](https://github.com/yadavanujkumar/athena-assurance-runtime/actions/workflows/test.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

ATHENA is an open-source, local-first autonomous assurance runtime for software and AI-enabled systems. It continuously observes, investigates, reasons, and acts — while keeping humans in control of every consequential decision.

> **The user defines intent. ATHENA determines what needs to be investigated.**

---

## What ATHENA Does

```text
Observe → Understand → Reason → Investigate → Assess → Act → Validate → Remember → Continue Watching
```

ATHENA is NOT just a linter or a vulnerability scanner. It is a **persistent assurance layer** that:

- Builds a **living knowledge graph** of your project (files, symbols, AI components, dependencies, advisories)
- Maintains **durable SQLite memory** — every finding, decision, reasoning chain, and evidence item survives restarts
- Plans investigations **proactively**, adapting to detected changes and active findings
- Investigates using **deterministic detectors** for security, secrets, AI boundaries, and supply-chain risk
- Reasons about **blast radius, governance mappings, and prior decisions** for every finding
- Proposes **bounded remediation** with content-hash preconditions — ATHENA never writes without approval
- Validates remediation and **rolls back** if tests fail or concurrent edits are detected
- Supports **watch mode** for continuous re-evaluation

---

## Architecture

```text
User intent (optional)
        ↓
Project discovery → Living knowledge graph ↔ Durable memory (SQLite)
        ↓                         ↑
Autonomous planner → investigation tasks (durable work queue + leases)
        ↓
Investigators / detectors (Python safety, secrets, configuration, AI, supply-chain)
        ↓
Evidence ledger → risk scoring → reasoning (governance, blast radius, lifecycle)
        ↓
Authority engine ──→ human approval required for MODIFY / BLOCK
        ↓
SafeRemediationEngine → atomic write → validation → rollback on failure
        ↓
Graph + memory update → continuous re-evaluation (watch mode)
```

### Key Modules

| Module | Role |
|--------|------|
| `runtime.py` | Core `AthenaRuntime` — orchestrates all subsystems |
| `graph.py` | Living `KnowledgeGraph` with entity/relationship traversal |
| `memory.py` | Durable SQLite facts, events, findings, decisions, objectives |
| `investigation.py` | `InvestigationEngine` — deterministic investigation runner |
| `planner.py` | `Planner` — autonomous task planning with priority deduplication |
| `reasoning.py` | `ReasoningEngine` — blast radius, governance, prior decisions |
| `policy.py` | `PolicyEngine` + `Authority` — explicit write-authority boundary |
| `assurance.py` | `AssuranceEngine` — lifecycle-aware decision generation |
| `remediation.py` | `SafeRemediationEngine` — hash-verified atomic patches |
| `remediation_loop.py` | Apply → validate → rollback lifecycle |
| `work.py` | Durable `WorkQueue` with dependency-aware claiming |
| `leases.py` | `WorkLeaseStore` — prevents concurrent workers stealing work |
| `evidence.py` | Immutable `EvidenceLedger` with provenance tracking |
| `lifecycle.py` | `FindingLifecycle` — new/recurring/worsening/reopened/resolved |
| `cli.py` | `athena` command-line interface |

---

## Installation

### Requirements

- Python 3.11, 3.12, or 3.13
- No runtime dependencies (pure stdlib)

### Install

```bash
# Clone the repository
git clone https://github.com/yadavanujkumar/athena-assurance-runtime.git
cd athena-assurance-runtime

# Create a virtual environment and install
python -m venv .venv
# On Linux/macOS:
source .venv/bin/activate
# On Windows:
.venv\Scripts\activate

pip install -e ".[dev]"
```

---

## Quick Start

### Initialize a project

```bash
# Run from your project root
athena init /path/to/your/project
```

ATHENA creates a `.athena/` directory with:
- `athena.db` — SQLite database for durable state
- `graph.json` — project knowledge graph snapshot
- `config.json` — runtime configuration

### Inspect for findings

```bash
athena inspect /path/to/your/project
```

ATHENA runs all detectors (Python safety, secrets, configuration, AI components, dependencies) and returns structured findings.

### Run a full autonomous cycle

```bash
athena run /path/to/your/project
```

ATHENA plans investigation tasks, investigates, reasons, proposes remediation, and creates decisions. Consequential actions require explicit human approval.

### Check status

```bash
athena status /path/to/your/project
```

### View findings

```bash
athena findings /path/to/your/project
```

### View pending decisions

```bash
athena decisions /path/to/your/project
```

### Approve a decision

```bash
athena approve /path/to/your/project REQUEST_ID --actor "your-name" --rationale "Reviewed and agreed"
```

### Watch mode (continuous re-evaluation)

```bash
athena watch /path/to/your/project --interval 10
```

### Health check

```bash
athena health /path/to/your/project
```

### Export assurance bundle

```bash
athena export /path/to/your/project --output assurance-report.json
```

---

## Authority Model

ATHENA enforces an **explicit autonomy boundary**. No write authority is implicit.

| Action | Default | Requires |
|--------|---------|----------|
| `OBSERVE` | ✅ enabled | nothing |
| `INVESTIGATE` | ✅ enabled | nothing |
| `RECOMMEND` | ✅ enabled | nothing |
| `MODIFY` | ❌ disabled | `authority.modify: true` + human approval |
| `BLOCK` | ❌ disabled | `authority.block: true` + human approval |

Configure authority in `.athena/config.json`:

```json
{
  "authority": {
    "observe": true,
    "investigate": true,
    "recommend": true,
    "modify": false,
    "block": false
  }
}
```

---

## Safety Guarantees

ATHENA is designed with safety as a first-class concern:

- **No secrets exposed** — detectors record location (file:line) but never the secret value
- **No unrestricted command execution** — validation commands are allowlisted (pytest, npm test, go test, etc.)
- **No path traversal** — all remediation writes are verified to remain within the project root
- **Content-hash preconditions** — every patch proposal records the exact SHA-256 of the file before modification
- **Atomic writes** — patches use a write-to-temp-then-replace strategy to avoid partial writes
- **Rollback on failure** — validation failures automatically restore the original content
- **Concurrent edit detection** — if the file changes during validation, rollback is blocked to preserve the later edit
- **Human approval required** — MODIFY and BLOCK actions always require durable `decision_request` approval

---

## Configuration Reference

`.athena/config.json`:

```json
{
  "max_work_per_cycle": 5,
  "max_attempts": 3,
  "lease_ttl_seconds": 300,
  "watch_interval_seconds": 5.0,
  "validation_enabled": true,
  "authority": {
    "observe": true,
    "investigate": true,
    "recommend": true,
    "modify": false,
    "block": false
  }
}
```

| Field | Default | Description |
|-------|---------|-------------|
| `max_work_per_cycle` | 5 | Maximum investigation tasks per autonomous cycle |
| `max_attempts` | 3 | Maximum retry attempts before a work item is failed |
| `lease_ttl_seconds` | 300 | Worker lease duration in seconds |
| `watch_interval_seconds` | 5.0 | Polling interval for watch mode (minimum 0.5s) |
| `validation_enabled` | true | Whether to run tests after remediation |

---

## LLM Integration (Optional)

ATHENA's reasoning is deterministic and requires no LLM. An optional advisory LLM can be enabled for richer context:

```python
from athena.llm import OptionalReasoning

# Optional local Ollama adapter (no hosted API required)
llm = OptionalReasoning.local_ollama(model="llama3.2")
```

LLM output is **advisory only** — it can never select an ATHENA action or authorize a write.

---

## Python SDK

```python
from athena.runtime import AthenaRuntime
from athena.policy import Authority

# Create runtime with default conservative authority
runtime = AthenaRuntime("/path/to/project")

# Initialize — discover project, build graph
runtime.initialize()

# Inspect — run all detectors
findings = runtime.inspect()

# Set an objective
objective = runtime.set_objective("Ensure no hard-coded secrets and no dangerous eval() usage")

# Run autonomous cycle
result = runtime.run_autonomous_cycle("security assurance")
print(result["findings"])
print(result["decisions"])

# Check health
health = runtime.health()
print(health)

# Export assurance bundle
from athena.export import AssuranceExporter
bundle = AssuranceExporter(runtime).bundle()

runtime.close()
```

---

## Development

```bash
# Run tests
python -m pytest tests/ -v

# Run linter
python -m ruff check .

# Run with coverage
python -m pytest tests/ --cov=athena --cov-report=term-missing
```

---

## Governance Frameworks Supported

ATHENA maps findings to applicable governance controls:

- **NIST AI RMF** — GOVERN, MAP, MEASURE, MANAGE
- **ISO/IEC 42001** — AIMS (AI management system)
- **EU AI Act** — RISK (AI risk classification)
- **OWASP** — AI-SECURITY

---

## Example Project

See [`example_project/`](example_project/) for a demonstration project with an intentional `eval()` vulnerability that ATHENA detects, reasons about, and proposes remediation for.

---

## License

Apache-2.0 — see [LICENSE](LICENSE) for details.
