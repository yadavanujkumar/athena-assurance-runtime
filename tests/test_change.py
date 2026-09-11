from athena.change import ChangeAnalyzer


def test_compare_classifies_added_removed_modified():
    analyzer = ChangeAnalyzer()
    previous = {"app.py": (10, 1), "old.txt": (4, 1)}
    current = {"app.py": (12, 2), "new.txt": (4, 3)}
    changes = analyzer.compare(previous, current)
    assert [(c.path, c.kind) for c in changes] == [
        ("app.py", "modified"),
        ("new.txt", "added"),
        ("old.txt", "removed"),
    ]


def test_classify_detects_security_ai_and_dependencies():
    analyzer = ChangeAnalyzer()
    changes = [
        type("Change", (), {"path": "src/agent.py"})(),
        type("Change", (), {"path": "pyproject.toml"})(),
        type("Change", (), {"path": "config/auth.yaml"})(),
    ]
    assert analyzer.classify(changes) == {"source", "ai", "dependency", "security"}
