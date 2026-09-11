from __future__ import annotations

from dataclasses import dataclass, asdict
from .models import utc_now


@dataclass(frozen=True, slots=True)
class Evidence:
    id: str
    kind: str
    source: str
    content: str
    confidence: float = 1.0
    collected_at: str = ""

    def __post_init__(self) -> None:
        if not self.collected_at:
            object.__setattr__(self, "collected_at", utc_now())

    def to_dict(self) -> dict:
        return asdict(self)


class EvidenceLedger:
    """Evidence boundary with optional durable persistence through MemoryStore."""

    def __init__(self, memory=None) -> None:
        self.items: list[Evidence] = []
        self.memory = memory

    def add(self, evidence: Evidence) -> Evidence:
        self.items.append(evidence)
        if self.memory is not None:
            self.memory.remember("evidence_record", evidence.to_dict())
        return evidence

    def by_kind(self, kind: str) -> list[Evidence]:
        return [item for item in self.items if item.kind == kind]

    def to_dict(self) -> list[dict]:
        return [item.to_dict() for item in self.items]
