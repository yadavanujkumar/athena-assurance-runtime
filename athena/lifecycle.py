from __future__ import annotations

import hashlib
from dataclasses import dataclass, asdict
from datetime import UTC, datetime

from .models import Finding


@dataclass(frozen=True, slots=True)
class FindingState:
    id: str
    fingerprint: str
    status: str
    first_seen: str
    last_seen: str
    occurrences: int
    confidence: float

    def to_dict(self) -> dict:
        return asdict(self)


class FindingLifecycle:
    """Correlates findings across assurance cycles using evidence-derived fingerprints."""

    def __init__(self, memory) -> None:
        self.memory = memory

    def fingerprint(self, finding: Finding) -> str:
        evidence = "|".join(sorted(str(x) for x in finding.evidence))
        raw = "|".join((finding.title, finding.description, evidence))
        return hashlib.sha256(raw.encode()).hexdigest()[:20]

    def reconcile(self, findings: list[Finding]) -> list[dict]:
        previous = self.memory.fact("finding.lifecycle") or {}
        now = datetime.now(UTC).isoformat()
        current: dict[str, dict] = {}
        output: list[dict] = []

        for finding in findings:
            fp = self.fingerprint(finding)
            old = previous.get(finding.id) or previous.get(fp)
            state = FindingState(
                finding.id,
                fp,
                "reopened" if old and old.get("status") == "resolved" else "open",
                old.get("first_seen", now) if old else now,
                now,
                int(old.get("occurrences", 0)) + 1 if old else 1,
                finding.confidence,
            )
            current[finding.id] = state.to_dict()
            output.append(state.to_dict())

        active_fps = {self.fingerprint(f) for f in findings}
        for key, old in previous.items():
            if key not in current and old.get("fingerprint") not in active_fps:
                resolved = dict(old)
                resolved["status"] = "resolved"
                resolved["last_seen"] = now
                current[key] = resolved
                output.append(resolved)

        self.memory.fact("finding.lifecycle", current)
        self.memory.remember("finding_reconciliation", {"active": len(findings), "states": output})
        return output
