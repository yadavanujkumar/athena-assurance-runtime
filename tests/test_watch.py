from athena.watch import ProjectWatcher

def test_fingerprint_changes_on_file_update(tmp_path):
    watcher = ProjectWatcher(tmp_path)
    (tmp_path / 'app.py').write_text('x = 1', encoding='utf-8')
    first = watcher.fingerprint()
    (tmp_path / 'app.py').write_text('x = 2', encoding='utf-8')
    second = watcher.fingerprint()
    assert first != second

def test_once_emits_current_fingerprint(tmp_path):
    watcher = ProjectWatcher(tmp_path)
    values = []
    watcher.run(values.append, once=True)
    assert len(values) == 1
    assert values[0] == watcher.fingerprint()
