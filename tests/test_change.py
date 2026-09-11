from athena.change import ChangeAnalyzer


def test_compare_classifies_added_removed_modified():
    analyzer = ChangeAnalyzer()
    previous = {"app.py": ("old-sha", 10, 1), "old.txt": ("gone", 4, 1)}
    current = {"app.py": ("new-sha", 12, 2), "new.txt": ("new", 4, 3)}
    changes = analyzer.compare(previous, current)
    assert [(c.path, c.kind) for c in changes] == [
        ("app.py", "modified"),
        ("new.txt", "added"),
        ("old.txt", "removed"),
    ]


def test_same_content_is_not_a_change_even_when_metadata_differs():
    analyzer = ChangeAnalyzer()
    previous = {"app.py": ("same-sha", 10, 1)}
    current = {"app.py": ("same-sha", 10, 999)}
    assert analyzer.compare(previous, current) == []


def test_classify_detects_security_ai_and_dependencies():
    analyzer = ChangeAnalyzer()
    changes = [
        type("Change", (), {"path": "src/agent.py"})(),
        type("Change", (), {"path": "pyproject.toml"})(),
        type("Change", (), {"path": "config/auth.yaml"})(),
    ]
    assert analyzer.classify(changes) == {"source", "ai", "dependency", "security"}
