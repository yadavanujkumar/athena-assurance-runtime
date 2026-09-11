from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Action(str, Enum):
    OBSERVE = "observe"
    INVESTIGATE = "investigate"
    RECOMMEND = "recommend"
    MODIFY = "modify"
    BLOCK = "block"


@dataclass(slots=True)
class Entity:
    id: str
    kind: str
    name: str
    path: str | None = None
    attributes: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class Relationship:
    source: str
    relation: str
    target: str
    attributes: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class Finding:
    id: str
    title: str
    description: str
    severity: Severity
    confidence: float
    evidence: list[str] = field(default_factory=list)
    remediation: str | None = None
    status: str = "open"
    created_at: str = field(default_factory=utc_now)


@dataclass(slots=True)
class Objective:
    id: str
    text: str
    status: str = "active"
    created_at: str = field(default_factory=utc_now)


@dataclass(slots=True)
class Decision:
    id: str
    finding_id: str
    action: Action
    approved: bool
    rationale: str
    created_at: str = field(default_factory=utc_now)
