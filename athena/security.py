from __future__ import annotations

import os
import stat
from pathlib import Path


class SecurityBoundaryError(ValueError):
    """Raised when an operation crosses ATHENA's project boundary."""


def safe_project_path(root: Path, candidate: str | Path) -> Path:
    """Resolve a path and require it to remain inside the project root."""
    root = root.resolve()
    path = (root / candidate).resolve() if not Path(candidate).is_absolute() else Path(candidate).resolve()
    try:
        path.relative_to(root)
    except ValueError as exc:
        raise SecurityBoundaryError(f"Path escapes project root: {candidate}") from exc
    return path


def validate_file_target(root: Path, candidate: str | Path) -> Path:
    path = safe_project_path(root, candidate)
    if path.exists() and path.is_symlink():
        raise SecurityBoundaryError("Symlink targets are not permitted for remediation")
    if path.exists() and not path.is_file():
        raise SecurityBoundaryError("Remediation target is not a regular file")
    return path


def secure_file_mode(path: Path) -> int | None:
    try:
        mode = stat.S_IMODE(path.stat().st_mode)
    except OSError:
        return None
    return mode if mode & stat.S_IWUSR else None


def has_safe_permissions(path: Path) -> bool:
    """Reject world/group-writable project files from privileged modification."""
    try:
        mode = path.stat().st_mode
    except OSError:
        return False
    return not bool(mode & (stat.S_IWGRP | stat.S_IWOTH))
