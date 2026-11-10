"""Staged artifacts are invisible until the owning scan commits its final state."""
import asyncio
from datetime import datetime, timezone
import json
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

from fastapi import HTTPException
import pytest

from api import routes
from websocket import websocket_manager as manager_module

SCAN_ID = "87654321-4321-4321-9210-210987654321"
REPORT = {"risk_score": 91, "severity": "CRITICAL", "is_placeholder": False}


def scan_fixture(status):
    return SimpleNamespace(id=SCAN_ID, user_id="owner", status=status, url="https://example.org",
                           risk_score=None, severity=None, created_at=datetime.now(timezone.utc),
                           updated_at=datetime.now(timezone.utc))


def db_for(scan):
    db = MagicMock()
    db.query.return_value.filter.return_value.first.return_value = scan
    return db


@pytest.mark.parametrize("state", ["risk_fusion_running", "cancelled", "failed_timeout", "risk_fusion_retrying"])
def test_api_hides_staged_final_report_and_download(tmp_path, monkeypatch, state):
    (tmp_path / "risk_report.json").write_text(json.dumps(REPORT))
    monkeypatch.setattr(routes, "_scan_dir", lambda _: str(tmp_path))
    db = db_for(scan_fixture(state))
    user = SimpleNamespace(id="owner")
    assert routes.get_scan(SCAN_ID, db=db, current_user=user)["risk_report"] is None
    with pytest.raises(HTTPException) as caught:
        routes.get_scan_artifact(SCAN_ID, "risk_report.json", db=db, current_user=user)
    assert caught.value.status_code == 404


def test_committed_report_available_but_owner_enforced(tmp_path, monkeypatch):
    (tmp_path / "risk_report.json").write_text(json.dumps(REPORT))
    monkeypatch.setattr(routes, "_scan_dir", lambda _: str(tmp_path))
    db = db_for(scan_fixture("risk_fusion_done"))
    assert routes.get_scan(SCAN_ID, db=db, current_user=SimpleNamespace(id="owner"))["risk_report"] == REPORT
    with pytest.raises(HTTPException) as caught:
        routes.get_scan(SCAN_ID, db=db, current_user=SimpleNamespace(id="other"))
    assert caught.value.status_code == 404


def test_pending_nonverdict_artifact_stays_accessible(tmp_path, monkeypatch):
    (tmp_path / "browser.png").write_bytes(b"fixture")
    monkeypatch.setattr(routes, "_scan_dir", lambda _: str(tmp_path))
    response = routes.get_scan_artifact(SCAN_ID, "browser.png", db=db_for(scan_fixture("risk_fusion_running")),
                                        current_user=SimpleNamespace(id="owner"))
    assert str(response.path) == str(tmp_path / "browser.png")


def test_only_matching_timeout_diagnostic_visible():
    diagnostic = {"status": "unavailable", "error": "analysis_timeout", "severity": "UNKNOWN", "risk_score": None}
    assert manager_module.report_is_visible("failed_timeout", diagnostic)
    assert not manager_module.report_is_visible("cancelled", diagnostic)
    assert not manager_module.report_is_visible("risk_fusion_running", diagnostic)
    assert not manager_module.report_is_visible("failed_timeout", REPORT)


@pytest.mark.asyncio
@pytest.mark.parametrize("cached", [True, False])
async def test_late_reconnect_cannot_see_report_before_commit(tmp_path, monkeypatch, cached):
    directory = tmp_path / SCAN_ID
    directory.mkdir()
    (directory / "risk_report.json").write_text(json.dumps(REPORT))
    monkeypatch.setattr(manager_module.settings, "SHARED_DIR", str(tmp_path))
    monkeypatch.setattr(manager_module, "_persisted_scan_status", lambda _: "risk_fusion_running")
    manager = manager_module.WebSocketManager()
    manager._redis = SimpleNamespace(get=AsyncMock(return_value=json.dumps(REPORT) if cached else None))
    manager._forward_channel = AsyncMock()
    websocket = SimpleNamespace(send_text=AsyncMock())
    await manager.connect_browser(SCAN_ID, websocket)
    await asyncio.sleep(0)
    websocket.send_text.assert_not_called()
    manager.disconnect_browser(SCAN_ID)


@pytest.mark.asyncio
async def test_late_reconnect_reads_committed_report(tmp_path, monkeypatch):
    monkeypatch.setattr(manager_module, "_persisted_scan_status", lambda _: "risk_fusion_done")
    manager = manager_module.WebSocketManager()
    manager._redis = SimpleNamespace(get=AsyncMock(return_value=json.dumps(REPORT)))
    websocket = SimpleNamespace(send_text=AsyncMock())
    await manager.connect_browser(SCAN_ID, websocket)
    websocket.send_text.assert_awaited_once_with(json.dumps(REPORT))
    manager.disconnect_browser(SCAN_ID)


@pytest.mark.asyncio
async def test_postsubscribe_and_pubsub_do_not_publish_after_cancellation(monkeypatch):
    async def messages():
        yield {"type": "message", "data": json.dumps(REPORT)}

    monkeypatch.setattr(manager_module, "_persisted_scan_status", lambda _: "cancelled")
    pubsub = SimpleNamespace(subscribe=AsyncMock(), unsubscribe=AsyncMock(), close=AsyncMock(), listen=messages)
    manager = manager_module.WebSocketManager()
    manager._redis = SimpleNamespace(get=AsyncMock(return_value=json.dumps(REPORT)), pubsub=lambda: pubsub)
    websocket = SimpleNamespace(send_text=AsyncMock())
    await manager._forward_channel("ws:scan:" + SCAN_ID, websocket, one_shot=True, scan_id=SCAN_ID)
    websocket.send_text.assert_not_called()
