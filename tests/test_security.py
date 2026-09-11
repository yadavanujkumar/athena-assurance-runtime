from pathlib import Path

import pytest

from athena.security import SecurityBoundaryError, has_safe_permissions, safe_project_path


def test_safe_project_path_rejects_escape(tmp_path: Path):
    with pytest.raises(SecurityBoundaryError):
        safe_project_path(tmp_path, "../outside.txt")


def test_safe_project_path_accepts_child(tmp_path: Path):
    assert safe_project_path(tmp_path, "src/app.py") == (tmp_path / "src/app.py").resolve()


def test_safe_permissions_for_normal_file(tmp_path: Path):
    target = tmp_path / "app.py"
    target.write_text("pass\n", encoding="utf-8")
    assert has_safe_permissions(target)
