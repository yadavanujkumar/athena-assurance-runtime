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
    state: str
    first_seen: str
    last_seen: str
    occurrences: int
    confidence: float
    severity: str

    def to_dict(self) -> dict:
        return asdict(self)


class FindingLifecycle:
    """Correlates findings across assurance cycles and records meaningful transitions."""

    _SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

    def __init__(self, memory) -> None:
        self.memory = memory

    def fingerprint(self, finding: Finding) -> str:
        evidence = "|".join(sorted(str(x) for x in finding.evidence))
        raw = "|".join((finding.title, finding.description, evidence))
        return hashlib.sha256(raw.encode()).hexdigest()[:20]

    @classmethod
    def _state_for(cls, finding: Finding, old: dict | None) -> str:
        if old is None:
            return "new"
        if old.get("status") == "resolved":
            return "reopened"
        old_severity = cls._SEVERITY_RANK.get(str(old.get("severity", "")).lower(), 0)
        new_severity = cls._SEVERITY_RANK.get(finding.severity.value.lower(), 0)
        if new_severity > old_severity or finding.confidence > float(old.get("confidence", 0.0)) + 0.05:
            return "worsening"
        return "recurring"

    def reconcile(self, findings: list[Finding]) -> list[dict]:
        previous = self.memory.fact("finding.lifecycle") or {}
        now = datetime.now(UTC).isoformat()
        current: dict[str, dict] = {}
        output: list[dict] = []

        for finding in findings:
            fp = self.fingerprint(finding)
            old = previous.get(finding.id) or previous.get(fp)
            state = self._state_for(finding, old)
            state_record = FindingState(
                finding.id,
                fp,
                "open",
                state,
                old.get("first_seen", now) if old else now,
                now,
                int(old.get("occurrences", 0)) + 1 if old else 1,
                finding.confidence,
                finding.severity.value,
            ).to_dict()
            current[finding.id] = state_record
            output.append(state_record)
            if old and state != old.get("state", "recurring"):
                self.memory.remember("finding_lifecycle_transition", {"finding_id": finding.id, "from": old.get("state", old.get("status", "unknown")), "to": state, "occurrences": state_record["occurrences"]})

        active_fps = {self.fingerprint(f) for f in findings}
        for key, old in previous.items():
            if key not in current and old.get("fingerprint") not in active_fps:
                resolved = dict(old)
                resolved["status"] = "resolved"
                resolved["state"] = "resolved"
                resolved["last_seen"] = now
                current[key] = resolved
                output.append(resolved)
                if old.get("state") != "resolved":
                    self.memory.remember("finding_lifecycle_transition", {"finding_id": old.get("id", key), "from": old.get("state", "open"), "to": "resolved", "occurrences": old.get("occurrences", 0)})

        self.memory.fact("finding.lifecycle", current)
        self.memory.remember("finding_reconciliation", {"active": len(findings), "states": output})
        return output
