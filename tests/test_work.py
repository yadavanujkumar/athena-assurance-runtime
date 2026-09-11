from pathlib import Path

from athena.memory import Memory
from athena.work import WorkQueue


def make_queue(tmp_path: Path) -> WorkQueue:
    return WorkQueue(Memory(tmp_path / "memory.sqlite3").db)


def test_work_is_durable_and_duplicate_safe(tmp_path: Path) -> None:
    queue = make_queue(tmp_path)
    first = queue.enqueue(kind="security_review", reason="Review auth", priority=95, objective="security", context_key="drift-1")
    duplicate = queue.enqueue(kind="security_review", reason="Review auth", priority=100, objective="security", context_key="drift-1")
    assert first.id == duplicate.id
    assert duplicate.priority == 100
    claimed = queue.claim_next()
    assert claimed is not None
    assert claimed.id == first.id
    queue.complete(first.id)

    second_queue = make_queue(tmp_path)
    persisted = second_queue.get(first.id)
    assert persisted is not None
    assert persisted.status == "completed"
    assert persisted.attempts == 1


def test_work_respects_dependencies_and_priority(tmp_path: Path) -> None:
    queue = make_queue(tmp_path)
    scope = queue.enqueue(kind="scope", reason="Scope objective", priority=100, context_key="x")
    review = queue.enqueue(kind="review", reason="Review evidence", priority=120, depends_on=(scope.id,), context_key="x")
    assert queue.claim_next().id == scope.id
    queue.complete(scope.id)
    assert queue.claim_next().id == review.id


def test_failed_work_retries_then_becomes_failed(tmp_path: Path) -> None:
    queue = make_queue(tmp_path)
    item = queue.enqueue(kind="test", reason="Run tests", priority=80)
    for _ in range(3):
        claimed = queue.claim_next()
        assert claimed is not None
        queue.fail(item.id, "temporary failure")
    assert queue.get(item.id).status == "failed"
    queue.resume(item.id)
    assert queue.get(item.id).status == "queued"
