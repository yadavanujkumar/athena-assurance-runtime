from pathlib import Path

from athena.validation import ValidationEngine


def test_detects_python_tests(tmp_path: Path):
    (tmp_path / "tests").mkdir()
    assert "python -m pytest" in ValidationEngine().detect_commands(tmp_path)


def test_rejects_non_read_only_command(tmp_path: Path):
    result = ValidationEngine().run(tmp_path, "rm -rf .")
    assert result.available is False
    assert result.passed is False


def test_runs_simple_python_validation(tmp_path: Path):
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests/test_ok.py").write_text("def test_ok():\n    assert 1 + 1 == 2\n", encoding="utf-8")
    result = ValidationEngine().run(tmp_path, "python -m pytest -q")
    assert result.available is True
    assert result.passed is True
