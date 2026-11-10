"""Durable history must survive a new session without crossing tenant boundaries."""
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from api.routes import scan_history
from database.models import Base, Scan, User


def test_history_is_owned_paginated_and_preserves_unknown():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        for identity in ("alice", "bob"):
            db.add(User(id=identity, email=identity + "@example.test", hashed_password="test-fixture"))
        db.commit()
        now = datetime.now(timezone.utc)
        for identity, owner, age in (("old", "alice", 2), ("new", "alice", 1), ("private", "bob", 0)):
            db.add(Scan(id=identity, user_id=owner, status="risk_fusion_done", risk_score=None,
                        severity="UNKNOWN", created_at=now - timedelta(days=age)))
        db.commit()
        first = scan_history(limit=1, offset=0, db=db, current_user=SimpleNamespace(id="alice"))
        second = scan_history(limit=1, offset=1, db=db, current_user=SimpleNamespace(id="alice"))
        other = scan_history(limit=50, offset=0, db=db, current_user=SimpleNamespace(id="bob"))
        empty = scan_history(limit=50, offset=0, db=db, current_user=SimpleNamespace(id="absent"))
        assert [x["scan_id"] for x in first["items"]] == ["new"]
        assert first["items"][0]["risk_score"] is None and first["next_offset"] == 1
        assert [x["scan_id"] for x in second["items"]] == ["old"] and second["next_offset"] is None
        assert [x["scan_id"] for x in other["items"]] == ["private"]
        assert empty == {"items": [], "next_offset": None}
    engine.dispose()
