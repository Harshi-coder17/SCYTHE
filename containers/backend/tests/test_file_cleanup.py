"""
Unit tests for file_cleanup task across retention threshold pruning, UUID matching,
orphan root files, and quarantine sample cleanup.
"""

import os
import time
import json
import pytest
from unittest.mock import patch, MagicMock

from tasks.file_cleanup import file_cleanup_task
import tasks.file_cleanup as cleanup_module


@pytest.fixture(autouse=True)
def isolated_retention_database(monkeypatch):
    from sqlalchemy import create_engine, event
    from sqlalchemy.orm import sessionmaker
    from database.models import Base
    engine = create_engine("sqlite:///:memory:")
    @event.listens_for(engine, "connect")
    def foreign_keys(connection, _record):
        connection.execute("PRAGMA foreign_keys=ON")
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine)
    monkeypatch.setattr(cleanup_module, "SessionLocal", factory)
    yield factory
    engine.dispose()


def test_file_cleanup_oserror_on_scandir():
    with patch.object(cleanup_module.settings, "SHARED_DIR", "/fake/shared"):
        with patch("os.scandir", side_effect=OSError("Volume unmounted")):
            result = file_cleanup_task(retention_days=14)
            assert result["status"] == "error"
            assert "Cannot scan" in result["detail"]


def test_file_cleanup_prunes_expired_and_preserves_recent(tmp_path):
    shared_dir = tmp_path / "shared_scans"
    shared_dir.mkdir()
    
    # 1. Expired UUID directory
    expired_uuid = "123e4567-e89b-12d3-a456-426614174000"
    expired_dir = shared_dir / expired_uuid
    expired_dir.mkdir()
    (expired_dir / "shadow_model_report.json").write_text("{}", encoding="utf-8")
    
    # 2. Recent UUID directory
    recent_uuid = "987fcdeb-51a2-43d7-9012-345678901234"
    recent_dir = shared_dir / recent_uuid
    recent_dir.mkdir()
    
    # 3. Non-UUID directory (e.g. system or internal folder)
    non_uuid_dir = shared_dir / "internal_cache"
    non_uuid_dir.mkdir()
    
    # 4. Orphan files at root (expired vs recent)
    expired_orphan = shared_dir / "scan_1111.json"
    expired_orphan.write_text("{}")
    recent_orphan = shared_dir / "scan_2222.png"
    recent_orphan.write_text("png")
    
    # 5. Quarantine directory and sample
    quarantine_dir = shared_dir / "quarantine"
    quarantine_dir.mkdir()
    expired_quarantine = quarantine_dir / "sample_old.exe"
    expired_quarantine.write_text("malware")
    recent_quarantine = quarantine_dir / "sample_new.exe"
    recent_quarantine.write_text("malware")

    now = time.time()
    cutoff_seconds = 14 * 86400
    expired_mtime = now - cutoff_seconds - 3600  # 1 hour older than retention
    recent_mtime = now - 3600                    # 1 hour old

    os.utime(expired_dir, (expired_mtime, expired_mtime))
    os.utime(recent_dir, (recent_mtime, recent_mtime))
    os.utime(non_uuid_dir, (expired_mtime, expired_mtime))
    os.utime(expired_orphan, (expired_mtime, expired_mtime))
    os.utime(recent_orphan, (recent_mtime, recent_mtime))
    # Unassociated legacy samples use the longer incident-evidence window.
    os.utime(expired_quarantine, (now - 400 * 86400, now - 400 * 86400))
    os.utime(recent_quarantine, (recent_mtime, recent_mtime))

    with patch.object(cleanup_module.settings, "SHARED_DIR", str(shared_dir)):
        summary = file_cleanup_task(retention_days=14)
        
        assert summary["status"] == "ok"
        assert summary["dirs_removed"] == 1
        assert summary["dirs_skipped"] == 1
        assert summary["orphans_removed"] == 2  # expired_orphan + expired_quarantine
        
        assert not expired_dir.exists()
        assert recent_dir.exists()
        assert non_uuid_dir.exists()  # non-UUID skipped
        assert not expired_orphan.exists()
        assert recent_orphan.exists()
        assert not expired_quarantine.exists()
        assert recent_quarantine.exists()


def test_file_cleanup_dual_tier_db_retention_and_statistics_sync():
    from datetime import datetime, timedelta, timezone
    from sqlalchemy import create_engine, event
    from sqlalchemy.orm import sessionmaker
    from database.models import Scan, Incident, Statistics, Base

    test_engine = create_engine("sqlite:///:memory:", echo=False)

    @event.listens_for(test_engine, "connect")
    def set_sqlite_pragma(dbapi_connection, connection_record):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    TestSessionLocal = sessionmaker(bind=test_engine, autocommit=False, autoflush=False)
    Base.metadata.create_all(bind=test_engine)

    with TestSessionLocal() as db:
        from database.models import User
        u = User(id="test-user", email="test@scythe.invalid", hashed_password="pw")
        db.add(u)
        db.commit()

        now = datetime.now(timezone.utc)
        # Scan 1: old, NO incidents -> should be purged after retention_days (14 days)
        s1 = Scan(id="old-no-inc", user_id="test-user", url="http://safe.local", status="completed", created_at=now - timedelta(days=20))
        # Scan 2: old, WITH incidents -> should be PRESERVED until incident_retention_days (365 days)
        s2 = Scan(id="old-with-inc", user_id="test-user", url="http://phish.local", status="completed", created_at=now - timedelta(days=20))
        # Scan 3: ancient, WITH incidents -> should be purged because age > incident_retention_days (365 days)
        s3 = Scan(id="ancient-with-inc", user_id="test-user", url="http://oldphish.local", status="completed", created_at=now - timedelta(days=400))
        # Scan 4: recent -> preserved
        s4 = Scan(id="recent-scan", user_id="test-user", url="http://recent.local", status="completed", created_at=now - timedelta(days=5))
        for scan in (s1, s2, s3, s4):
            scan.updated_at = scan.created_at

        db.add_all([s1, s2, s3, s4])
        db.commit()

        inc2 = Incident(scan_id="old-with-inc", severity="HIGH", created_at=s2.created_at)
        inc3 = Incident(scan_id="ancient-with-inc", severity="CRITICAL", created_at=s3.created_at)
        db.add_all([inc2, inc3])

        # Drifted initial statistics (e.g. 10 total, 5 critical, 5 high)
        stats = Statistics(id=1, total_incidents=10, critical_count=5, high_count=5)
        db.add(stats)
        db.commit()

        mock_scandir = MagicMock()
        mock_scandir.__enter__.return_value = []
        with patch.object(cleanup_module, "SessionLocal", TestSessionLocal):
            with patch.object(cleanup_module.settings, "SHARED_DIR", "/fake/shared"):
                with patch("os.scandir", return_value=mock_scandir):
                    file_cleanup_task(retention_days=14, incident_retention_days=365)

    with TestSessionLocal() as db:
        remaining_scans = {s.id for s in db.query(Scan).all()}
        assert "old-no-inc" not in remaining_scans, "Old non-incident scan should be purged"
        assert "ancient-with-inc" not in remaining_scans, "Ancient incident scan should be purged"
        assert "old-with-inc" in remaining_scans, "Old incident scan within incident retention should be preserved"
        assert "recent-scan" in remaining_scans, "Recent scan should be preserved"

        stats = db.query(Statistics).filter(Statistics.id == 1).first()
        assert stats is not None
        assert stats.total_incidents == 1, f"Expected 1 total incident, got {stats.total_incidents}"
        assert stats.high_count == 1
        assert stats.critical_count == 0, "Ancient critical incident was purged, critical_count should sync to 0"


def test_incident_active_and_nested_artifact_retention(tmp_path, isolated_retention_database, monkeypatch):
    from datetime import datetime, timedelta, timezone
    from database.models import User, Scan, Incident
    old = datetime.now(timezone.utc) - timedelta(days=40)
    ids = ["123e4567-e89b-12d3-a456-426614174001", "123e4567-e89b-12d3-a456-426614174002", "123e4567-e89b-12d3-a456-426614174003"]
    with isolated_retention_database() as db:
        db.add(User(id="owner", email="retention@example.test", hashed_password="fixture"))
        db.commit()
        for key, state in zip(ids, ("completed", "risk_fusion_done", "file_analysis_queued")):
            db.add(Scan(id=key, user_id="owner", status=state, created_at=old, updated_at=old))
        db.commit()
        db.add(Incident(scan_id=ids[1], severity="HIGH", created_at=old))
        db.commit()
    for key in ids:
        folder = tmp_path / key
        folder.mkdir()
        os.utime(folder, (old.timestamp(), old.timestamp()))
    nested = tmp_path / "files" / ids[0]
    nested.mkdir(parents=True)
    (nested / "metadata.json").write_text(json.dumps({"scan_id": ids[0]}))
    os.utime(nested, (old.timestamp(), old.timestamp()))
    legacy = tmp_path / "emails" / "legacy_email"
    legacy.mkdir(parents=True)
    os.utime(legacy, (old.timestamp(), old.timestamp()))
    monkeypatch.setattr(cleanup_module.settings, "SHARED_DIR", str(tmp_path))
    result = file_cleanup_task(retention_days=14)
    assert result["status"] == "ok" and result["dirs_removed"] == 2
    assert not nested.exists() and not (tmp_path / ids[0]).exists()
    assert (tmp_path / ids[1]).exists() and (tmp_path / ids[2]).exists()
    assert legacy.exists() and result["unknown_associations_retained"] == 1
    with isolated_retention_database() as db:
        assert {s.id for s in db.query(Scan)} == set(ids[1:])


def test_database_outage_preserves_expired_evidence(tmp_path, monkeypatch):
    folder = tmp_path / "123e4567-e89b-12d3-a456-426614174001"
    folder.mkdir()
    old = time.time() - 400 * 86400
    os.utime(folder, (old, old))
    monkeypatch.setattr(cleanup_module.settings, "SHARED_DIR", str(tmp_path))
    monkeypatch.setattr(cleanup_module, "SessionLocal", MagicMock(side_effect=RuntimeError("offline")))
    assert file_cleanup_task()["status"] == "error"
    assert folder.exists()


def test_remove_refuses_path_outside_shared_root(tmp_path):
    root = tmp_path / "shared"
    root.mkdir()
    outside = tmp_path / "other"
    outside.mkdir()
    with pytest.raises(OSError):
        cleanup_module._remove(outside, root.resolve())
    assert outside.exists()

