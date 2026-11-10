"""Real stage execution against isolated files/SQLite; no network or mail is sent."""
import json
from contextlib import contextmanager
from types import SimpleNamespace
from unittest.mock import MagicMock
import uuid
import zipfile
import io

import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from api import email_routes as emails
from config import settings
from database.database import Base
from database.models import User, Scan
from services import diagnostic_reports as reports
from services import manual_file_scan_service as files
from tasks import file_analysis as stages


@pytest.fixture
def state(tmp_path, monkeypatch):
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine)
    db = factory()
    owner = User(id=str(uuid.uuid4()), email="operator@example.test", hashed_password="test")
    db.add(owner)
    db.commit()
    @contextmanager
    def session():
        with factory() as item:
            yield item
    monkeypatch.setattr(reports, "get_db_session", session)
    monkeypatch.setattr(settings, "SHARED_DIR", str(tmp_path))
    monkeypatch.setattr(files, "_SHARED_DIR", str(tmp_path))
    monkeypatch.setattr(emails, "SHARED_DIR", str(tmp_path))
    monkeypatch.setattr(reports.redis, "from_url", lambda *_: MagicMock())
    monkeypatch.setattr(reports.websocket_manager, "broadcast_risk_update_sync", MagicMock())
    cache = MagicMock()
    cache.get.return_value = None
    monkeypatch.setattr(files, "_REDIS", cache)
    monkeypatch.setattr(stages, "_REDIS", cache)
    yield SimpleNamespace(path=tmp_path, db=db, owner=owner, factory=factory, cache=cache)
    db.close()
    engine.dispose()


def upload(state, monkeypatch, content=b"harmless fixture", name="audit.txt"):
    monkeypatch.setattr(stages, "dispatch_file_analysis", lambda _: SimpleNamespace(id="job-1"))
    return files.queue_manual_file_scan(name, content, state.owner, state.db)


def execute(scan_id):
    result = [stages.hash_analysis_task.run(scan_id), stages.static_analysis_task.run(scan_id), stages.malware_analysis_task.run(scan_id)]
    return stages.file_consistency_task.run(stages.content_analysis_task.run(result, scan_id), scan_id)


def test_async_file_stages_persist_owned_report_and_preserve_gate(state, monkeypatch):
    monkeypatch.setattr("services.malware_scanner.scan_file_clamav", lambda _: (True, "Clean (clamd)"))
    result = upload(state, monkeypatch)
    scan_id = result["scan_id"]
    assert result["status"] == "file_analysis_queued"
    execute(scan_id)
    report = json.loads((state.path / scan_id / "risk_report.json").read_text())
    assert report["risk_score"] == 0 and report["is_placeholder"] and report["heuristic_only"]
    assert not report["automatic_decision"]
    state.db.expire_all()
    assert state.db.get(Scan, scan_id).status == "file_scan_done"
    assert state.db.get(Scan, scan_id).user_id == state.owner.id
    assert (state.path / "files" / scan_id / "hash_features.json").exists()


@pytest.mark.parametrize("outcome", [(False, "CRITICAL: scanner unavailable"), RuntimeError("offline")])
def test_async_av_failure_never_produces_zero_risk(state, monkeypatch, outcome):
    def scan(_):
        if isinstance(outcome, Exception):
            raise outcome
        return outcome
    monkeypatch.setattr("services.malware_scanner.scan_file_clamav", scan)
    result = upload(state, monkeypatch)
    execute(result["scan_id"])
    report = json.loads((state.path / result["scan_id"] / "risk_report.json").read_text())
    assert report["risk_score"] is None and report["severity"] == "UNKNOWN"
    assert report["status"] == "unavailable"
    state.cache.setex.assert_not_called()


def test_macro_archive_is_inspected_without_extraction(state, monkeypatch):
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w") as item:
        item.writestr("word/vbaProject.bin", b"fixture")
    result = upload(state, monkeypatch, archive.getvalue(), "audit.docm")
    feature = stages.content_analysis_task.run([], result["scan_id"])[0]
    assert feature["macro_project_present"]
    assert feature["execution"] == "never_executed"
    assert not (state.path / "word").exists()


def test_tampered_payload_is_unavailable(state, monkeypatch):
    monkeypatch.setattr("services.malware_scanner.scan_file_clamav", lambda _: (True, "Clean"))
    result = upload(state, monkeypatch)
    (state.path / "files" / result["scan_id"] / "payload.bin").write_bytes(b"changed")
    execute(result["scan_id"])
    report = json.loads((state.path / result["scan_id"] / "risk_report.json").read_text())
    assert report["risk_score"] is None


def binding(state, owner_id=None, mailbox="operator@example.test"):
    directory = state.path / "emails" / "fixture-1"
    directory.mkdir(parents=True)
    (directory / "parsed.json").write_text(json.dumps({"metadata": {"subject": "fixture"}}))
    (directory / "owner.json").write_text(json.dumps({"owner_user_id": owner_id or state.owner.id, "owner_email": mailbox}))
    return directory


def test_claiming_owner_email_does_not_authorize(state):
    directory = binding(state)
    (directory / "owner.json").write_text(json.dumps({"owner_email": state.owner.email}))
    with pytest.raises(HTTPException) as exc:
        emails._authorize_email_artifact("fixture-1", state.owner)
    assert exc.value.status_code == 403


def test_scoped_ingest_binds_only_configured_user_and_mailbox(state, monkeypatch):
    binding(state)
    monkeypatch.setattr(settings, "EMAIL_POLLER_TOKEN", "a" * 48)
    monkeypatch.setattr(settings, "EMAIL_OWNER_USER_ID", state.owner.id)
    monkeypatch.setattr(settings, "EMAIL_ADDRESS", "operator@example.test")
    monkeypatch.setattr("services.email_investigation.run_email_investigation", lambda _: {"status": "email_analysis_queued", "job_id": "fixture"})
    result = emails.poller_ingest(emails.EmailInvestigateRequest(email_id="fixture-1"), "Bearer " + "a" * 48, state.db)
    assert state.db.get(Scan, result["scan_id"]).user_id == state.owner.id
    duplicate = emails.poller_ingest(emails.EmailInvestigateRequest(email_id="fixture-1"), "Bearer " + "a" * 48, state.db)
    assert duplicate["duplicate"] and duplicate["scan_id"] == result["scan_id"]
    with pytest.raises(HTTPException) as exc:
        emails.poller_ingest(emails.EmailInvestigateRequest(email_id="fixture-1"), "Bearer wrong", state.db)
    assert exc.value.status_code == 401
    monkeypatch.setattr(settings, "EMAIL_ADDRESS", "another@example.test")
    with pytest.raises(HTTPException) as exc:
        emails.poller_ingest(emails.EmailInvestigateRequest(email_id="fixture-1"), "Bearer " + "a" * 48, state.db)
    assert exc.value.status_code == 403


def test_email_list_and_detail_do_not_expose_other_user(state):
    binding(state)
    alice = emails.list_emails(100, 0, state.db, state.owner)
    assert alice["total"] == 1 and alice["emails"][0]["subject"] == "fixture"
    other = SimpleNamespace(id="different", is_superuser=False)
    assert emails.list_emails(100, 0, state.db, other)["total"] == 0
    with pytest.raises(HTTPException):
        emails.get_email("fixture-1", state.db, other)

@pytest.mark.parametrize("av_available", [True, False])
def test_email_finalization_persists_unknown_gate_and_heuristic_evidence(state, monkeypatch, av_available):
    from tasks import email_consistency as consistency
    import database.database as database
    directory = binding(state)
    scan = Scan(id=str(uuid.uuid4()), user_id=state.owner.id, status="email_analysis_queued")
    state.db.add(scan)
    state.db.commit()
    owner = json.loads((directory / "owner.json").read_text())
    owner["scan_id"] = scan.id
    (directory / "owner.json").write_text(json.dumps(owner))
    for filename, value in [("header_features.json", {"header_score": 80}), ("url_features.json", {"url_score": 90}),
                            ("attachment_features.json", {"attachment_score": 0, "av_available": av_available}),
                            ("content_features.json", {"content_score": 50})]:
        (directory / filename).write_text(json.dumps(value))
    @contextmanager
    def session():
        with state.factory() as db:
            yield db
    monkeypatch.setattr(database, "get_db_session", session)
    monkeypatch.setattr(consistency, "SHARED_DIR", str(state.path))
    consistency.email_consistency_task.run(["fixture-1"] * 4, "fixture-1")
    report = json.loads((state.path / scan.id / "risk_report.json").read_text())
    assert report["risk_score"] is None and report["severity"] == "UNKNOWN"
    assert report["heuristic_score"] > 0 and report["is_placeholder"]
    assert not report["automatic_decision"]
    assert (directory / "risk_report.json").exists()
    state.db.expire_all()
    assert state.db.get(Scan, scan.id).status == ("email_scan_done" if av_available else "email_scan_unavailable")


def test_mailbox_ids_are_scoped_to_owner_and_content(monkeypatch):
    import email
    from email_engine import poller
    message = email.message_from_bytes(b"Message-ID: <shared-id>\nSubject: fixture\n\nbody")
    monkeypatch.setattr(poller, "settings", SimpleNamespace(EMAIL_OWNER_USER_ID="owner-one"))
    first = poller._make_email_id(message, b"original")
    monkeypatch.setattr(poller, "settings", SimpleNamespace(EMAIL_OWNER_USER_ID="owner-two"))
    second = poller._make_email_id(message, b"original")
    third = poller._make_email_id(message, b"changed")
    assert len({first, second, third}) == 3


def test_file_dispatch_failure_is_recorded_unavailable(state, monkeypatch):
    def failed(_):
        raise RuntimeError("broker unavailable")
    monkeypatch.setattr(stages, "dispatch_file_analysis", failed)
    with pytest.raises(HTTPException) as exc:
        files.queue_manual_file_scan("fixture.txt", b"harmless", state.owner, state.db)
    assert exc.value.status_code == 503
    assert state.db.query(Scan).one().status == "file_dispatch_failed"

def test_mime_attachment_hash_uses_decoded_bytes_and_removes_temporary_file(monkeypatch):
    import hashlib
    from email.message import EmailMessage
    from pathlib import Path
    from services.email.parser.attachement_parser import AttachmentParser
    message = EmailMessage()
    message["From"] = "sender@example.test"
    message["To"] = "owner@example.test"
    message.set_content("Offline binary fixture")
    original = b"\x00\x01\xfe\xfffixture"
    message.add_attachment(original, maintype="application", subtype="octet-stream", filename="fixture.bin")
    observed = []
    def macro(path):
        observed.append(path)
        assert Path(path).read_bytes() == original
        return False
    monkeypatch.setattr(AttachmentParser, "has_macro", macro)
    result = AttachmentParser.parse(message.as_bytes())
    assert result["attachment_count"] == 1
    assert result["attachments"][0]["sha256_hash"] == hashlib.sha256(original).hexdigest()
    assert observed and not Path(observed[0]).exists()


def test_email_failure_callback_persists_unavailable_report(state, monkeypatch):
    from tasks.email_failure import EmailAnalysisTask
    directory = binding(state)
    scan = Scan(id=str(uuid.uuid4()), user_id=state.owner.id, status="email_analysis_queued")
    state.db.add(scan)
    state.db.commit()
    owner = json.loads((directory / "owner.json").read_text())
    owner["scan_id"] = scan.id
    (directory / "owner.json").write_text(json.dumps(owner))
    monkeypatch.setattr(settings, "EMAIL_SHARED_DIR", str(state.path))
    EmailAnalysisTask().on_failure(RuntimeError("fixture failure"), "job", ["fixture-1"], {}, None)
    report = json.loads((state.path / scan.id / "risk_report.json").read_text())
    assert report["risk_score"] is None and report["is_placeholder"]
    state.db.expire_all()
    assert state.db.get(Scan, scan.id).status == "email_scan_unavailable"


def test_file_failure_callback_never_produces_clean_verdict(state, monkeypatch):
    result = upload(state, monkeypatch)
    stages.FileAnalysisTask().on_failure(RuntimeError("fixture"), "job", [result["scan_id"]], {}, None)
    report = json.loads((state.path / result["scan_id"] / "risk_report.json").read_text())
    assert report["risk_score"] is None and report["severity"] == "UNKNOWN"
    state.db.expire_all()
    assert state.db.get(Scan, result["scan_id"]).status == "file_scan_unavailable"

def test_all_four_email_stages_feed_the_real_finalizer(state, monkeypatch):
    from tasks import email_header_analysis, email_url_analysis, email_attachment_analysis, email_content_analysis, email_consistency
    import database.database as database
    directory = binding(state)
    parsed = {"metadata": {"subject": "Local fixture", "from_address": "sender@example.test"},
              "authentication": {"spf_result": "pass", "dkim_result": "pass", "dmarc_result": "pass"},
              "received_chain": {}, "domain": {}, "attachments": {"attachment_count": 0, "attachments": []},
              "content": {"body_text": "This is an offline fixture", "extracted_urls": []}}
    (directory / "parsed.json").write_text(json.dumps(parsed))
    (directory / "attachments_manifest.json").write_text(json.dumps({"attachments": []}))
    scan = Scan(id=str(uuid.uuid4()), user_id=state.owner.id, status="email_analysis_queued")
    state.db.add(scan)
    state.db.commit()
    owner = json.loads((directory / "owner.json").read_text())
    owner["scan_id"] = scan.id
    (directory / "owner.json").write_text(json.dumps(owner))
    @contextmanager
    def session():
        with state.factory() as db:
            yield db
    monkeypatch.setattr(database, "get_db_session", session)
    modules = [email_header_analysis, email_url_analysis, email_attachment_analysis, email_content_analysis, email_consistency]
    for module in modules:
        monkeypatch.setattr(module, "SHARED_DIR", str(state.path))
    values = [email_header_analysis.email_header_analysis_task.run("fixture-1"),
              email_url_analysis.email_url_analysis_task.run("fixture-1"),
              email_attachment_analysis.email_attachment_analysis_task.run("fixture-1"),
              email_content_analysis.email_content_analysis_task.run("fixture-1")]
    email_consistency.email_consistency_task.run(values, "fixture-1")
    report = json.loads((state.path / scan.id / "risk_report.json").read_text())
    assert all(report["feature_availability"].values())
    assert report["risk_score"] is None and report["is_placeholder"]

def test_async_pipeline_does_not_reuse_pre_content_analysis_cache(state, monkeypatch):
    state.cache.get.return_value = json.dumps({"risk_score": 0, "severity": "Safe", "status": "complete"})
    called = []
    monkeypatch.setattr(stages, "dispatch_file_analysis", lambda scan_id: (called.append(scan_id) or SimpleNamespace(id="new-analysis")))
    result = files.queue_manual_file_scan("fixture.docm", b"fixture", state.owner, state.db)
    assert called == [result["scan_id"]]
    assert result["status"] == "file_analysis_queued"


def test_async_cache_hit_creates_new_owned_report(state, monkeypatch):
    state.cache.get.return_value = json.dumps({"pipeline_version": "file_static_v10_v1", "status": "complete",
                                               "scan_id": str(uuid.uuid4()), "file_id": str(uuid.uuid4()),
                                               "filename": "previous.txt", "risk_score": 0, "severity": "Safe"})
    def unexpected(_):
        raise AssertionError("Matching technical cache should avoid task dispatch")
    monkeypatch.setattr(stages, "dispatch_file_analysis", unexpected)
    result = files.queue_manual_file_scan("new-name.txt", b"fixture", state.owner, state.db)
    assert result["cached"] and result["filename"] == "new-name.txt"
    assert (state.path / result["scan_id"] / "risk_report.json").exists()
    assert state.db.get(Scan, result["scan_id"]).user_id == state.owner.id

@pytest.mark.parametrize("kind", ["file", "email"])
def test_recovery_timeout_writes_durable_unavailable_report_and_blocks_late_results(state, monkeypatch, kind):
    from datetime import datetime, timedelta, timezone
    from tasks import job_reconciliation as recovery
    @contextmanager
    def session():
        with state.factory() as db:
            yield db
    monkeypatch.setattr(recovery, "get_db_session", session)
    scan = Scan(id=str(uuid.uuid4()), user_id=state.owner.id, status=f"{kind}_analysis_queued",
                risk_score=0, severity="Safe", updated_at=datetime.now(timezone.utc) - timedelta(hours=2))
    state.db.add(scan)
    state.db.commit()
    result = recovery.job_reconciliation_task.run(timeout_minutes=30)
    assert result["reconciled"] == 1
    path = state.path / scan.id / "risk_report.json"
    original = path.read_bytes()
    report = json.loads(original)
    assert report["risk_score"] is None and report["error"] == "analysis_timeout"
    assert report["is_placeholder"] and report["status"] == "unavailable"
    assert not reports.save_report(scan.id, {"risk_score": 0, "severity": "Safe"}, f"{kind}_scan_done")
    assert path.read_bytes() == original
    state.db.expire_all()
    assert state.db.get(Scan, scan.id).status == "failed_timeout"
    assert state.db.get(Scan, scan.id).risk_score is None


def test_recovery_keeps_fresh_and_completed_scans_unchanged(state, monkeypatch):
    from datetime import datetime, timedelta, timezone
    from tasks import job_reconciliation as recovery
    @contextmanager
    def session():
        with state.factory() as db:
            yield db
    monkeypatch.setattr(recovery, "get_db_session", session)
    fresh = Scan(id=str(uuid.uuid4()), user_id=state.owner.id, status="file_analysis_queued")
    done = Scan(id=str(uuid.uuid4()), user_id=state.owner.id, status="email_scan_done", updated_at=datetime.now(timezone.utc) - timedelta(hours=2))
    state.db.add_all([fresh, done])
    state.db.commit()
    result = recovery.job_reconciliation_task.run()
    assert result["reconciled"] == 0
    assert not (state.path / fresh.id / "risk_report.json").exists()
    assert not reports.save_report(done.id, {"risk_score": None, "severity": "UNKNOWN"}, "email_scan_unavailable")
    state.db.expire_all()
    assert state.db.get(Scan, done.id).status == "email_scan_done"


def test_duplicate_email_delivery_cannot_resurrect_timeout(state, monkeypatch):
    directory = binding(state)
    scan = Scan(id=str(uuid.uuid4()), user_id=state.owner.id, status="failed_timeout")
    state.db.add(scan)
    state.db.commit()
    owner = json.loads((directory / "owner.json").read_text())
    owner["scan_id"] = scan.id
    (directory / "owner.json").write_text(json.dumps(owner))
    def unexpected(*_):
        raise AssertionError("A terminal immutable attempt must not be redispatched")
    monkeypatch.setattr("services.email_investigation.run_email_investigation", unexpected)
    result = emails._queue("fixture-1", state.owner, state.db)
    assert result["duplicate"] and result["status"] == "failed_timeout"


def test_report_owner_mismatch_cannot_write_artifact(state):
    scan = Scan(id=str(uuid.uuid4()), user_id=state.owner.id, status="file_analysis_queued")
    state.db.add(scan)
    state.db.commit()
    with pytest.raises(ValueError):
        reports.save_report(scan.id, {"risk_score": 0}, "file_scan_done", owner_user_id="different-owner")
    assert not (state.path / scan.id / "risk_report.json").exists()
