from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path


@dataclass(slots=True)
class RuntimeConfig:
    max_work_per_cycle: int = 5
    max_attempts: int = 3
    lease_ttl_seconds: int = 300
    watch_interval_seconds: float = 5.0
    authority: dict[str, bool] = field(default_factory=lambda: {"observe": True, "investigate": True, "recommend": True, "modify": False, "block": False})
    validation_enabled: bool = True

    @classmethod
    def load(cls, root: Path) -> "RuntimeConfig":
        path = root / ".athena" / "config.json"
        if not path.exists():
            return cls()
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
            config = cls()
            for key in ("max_work_per_cycle", "max_attempts", "lease_ttl_seconds", "watch_interval_seconds", "validation_enabled"):
                if key in raw:
                    setattr(config, key, raw[key])
            if isinstance(raw.get("authority"), dict):
                config.authority.update({k: bool(v) for k, v in raw["authority"].items() if k in config.authority})
            config.max_work_per_cycle = max(1, int(config.max_work_per_cycle))
            config.max_attempts = max(1, int(config.max_attempts))
            config.lease_ttl_seconds = max(1, int(config.lease_ttl_seconds))
            config.watch_interval_seconds = max(0.5, float(config.watch_interval_seconds))
            return config
        except (OSError, ValueError, TypeError, json.JSONDecodeError):
            return cls()

    def save(self, root: Path) -> Path:
        directory = root / ".athena"
        directory.mkdir(exist_ok=True)
        path = directory / "config.json"
        path.write_text(json.dumps(asdict(self), indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return path
