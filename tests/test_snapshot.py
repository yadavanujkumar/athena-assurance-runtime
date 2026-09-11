from pathlib import Path

from athena.snapshot import Snapshotter


def test_snapshot_changes_when_content_changes(tmp_path: Path) -> None:
    path = tmp_path / "app.py"
    path.write_text("value = 1\n", encoding="utf-8")
    snapshotter = Snapshotter(tmp_path)
    first = snapshotter.capture()

    path.write_text("value = 2\n", encoding="utf-8")
    second = snapshotter.capture()
    assert first.fingerprint != second.fingerprint
    assert second.file_count == 1


def test_snapshot_ignores_ignored_directories(tmp_path: Path) -> None:
    path = tmp_path / "app.py"
    path.write_text("value = 1\n", encoding="utf-8")
    ignored = tmp_path / ".athena" / "state.json"
    ignored.parent.mkdir()
    ignored.write_text("secret state", encoding="utf-8")

    snapshot = Snapshotter(tmp_path).capture()
    assert snapshot.file_count == 1
