"""Tests for WorkLeaseStore: concurrency safety, expiry, renewal, release."""

from __future__ import annotations

import sqlite3
import time
from pathlib import Path

from athena.leases import WorkLeaseStore
from athena.memory import Memory


def _make_store(tmp_path: Path, owner: str = "worker-1") -> tuple[WorkLeaseStore, sqlite3.Connection]:
    db = Memory(tmp_path / "test.sqlite3").db
    return WorkLeaseStore(db, owner=owner), db


def test_acquire_basic(tmp_path: Path) -> None:
    store, _ = _make_store(tmp_path)
    lease = store.acquire("work-1", ttl_seconds=60)
    assert lease is not None
    assert lease.work_id == "work-1"
    assert lease.owner == "worker-1"


def test_same_worker_reacquires(tmp_path: Path) -> None:
    """The same worker can reacquire its own lease."""
    store, _ = _make_store(tmp_path)
    first = store.acquire("work-1", ttl_seconds=60)
    second = store.acquire("work-1", ttl_seconds=120)
    assert first is not None
    assert second is not None
    assert second.work_id == first.work_id


def test_second_worker_blocked(tmp_path: Path) -> None:
    """A second worker cannot acquire a lease held by another active worker."""
    db = Memory(tmp_path / "test.sqlite3").db
    worker1 = WorkLeaseStore(db, owner="worker-1")
    worker2 = WorkLeaseStore(db, owner="worker-2")

    lease1 = worker1.acquire("work-1", ttl_seconds=300)
    lease2 = worker2.acquire("work-1", ttl_seconds=300)

    assert lease1 is not None
    assert lease2 is None


def test_expired_lease_can_be_reclaimed(tmp_path: Path) -> None:
    """An expired lease can be reclaimed by any worker after reclaim_expired()."""
    db = Memory(tmp_path / "test.sqlite3").db
    worker1 = WorkLeaseStore(db, owner="worker-1")
    worker2 = WorkLeaseStore(db, owner="worker-2")

    # Acquire with a 1-second TTL
    lease1 = worker1.acquire("work-1", ttl_seconds=1)
    assert lease1 is not None

    # Worker 2 should be blocked initially
    assert worker2.acquire("work-1", ttl_seconds=60) is None

    # Wait for expiry
    time.sleep(1.5)

    # Reclaim expired leases
    reclaimed = worker2.reclaim_expired()
    assert reclaimed >= 1

    # Now worker 2 can acquire
    lease2 = worker2.acquire("work-1", ttl_seconds=60)
    assert lease2 is not None
    assert lease2.owner == "worker-2"


def test_release_allows_reacquisition(tmp_path: Path) -> None:
    """After release, another worker can acquire the lease."""
    db = Memory(tmp_path / "test.sqlite3").db
    worker1 = WorkLeaseStore(db, owner="worker-1")
    worker2 = WorkLeaseStore(db, owner="worker-2")

    worker1.acquire("work-1", ttl_seconds=300)
    assert worker2.acquire("work-1", ttl_seconds=300) is None

    released = worker1.release("work-1")
    assert released is True

    lease2 = worker2.acquire("work-1", ttl_seconds=300)
    assert lease2 is not None
    assert lease2.owner == "worker-2"


def test_renewal_extends_expiry(tmp_path: Path) -> None:
    """Renewing a lease extends its expiry time."""
    store, _ = _make_store(tmp_path)
    lease = store.acquire("work-1", ttl_seconds=5)
    assert lease is not None

    renewed = store.renew("work-1", ttl_seconds=300)
    assert renewed is not None
    assert renewed.expires_at > lease.expires_at


def test_release_other_worker_noop(tmp_path: Path) -> None:
    """A worker cannot release a lease held by another worker."""
    db = Memory(tmp_path / "test.sqlite3").db
    worker1 = WorkLeaseStore(db, owner="worker-1")
    worker2 = WorkLeaseStore(db, owner="worker-2")

    worker1.acquire("work-1", ttl_seconds=300)
    released = worker2.release("work-1")  # Worker 2 doesn't hold this
    assert released is False

    # Worker 1 still holds it
    assert worker2.acquire("work-1", ttl_seconds=300) is None


def test_renew_without_holding_returns_none(tmp_path: Path) -> None:
    """A worker that does not hold the lease cannot renew it."""
    db = Memory(tmp_path / "test.sqlite3").db
    worker1 = WorkLeaseStore(db, owner="worker-1")
    worker2 = WorkLeaseStore(db, owner="worker-2")

    worker1.acquire("work-1", ttl_seconds=300)
    renewed = worker2.renew("work-1", ttl_seconds=300)
    assert renewed is None
