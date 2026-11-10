"""Local-only authenticated email/Celery smoke test. Never contacts IMAP/SMTP.

Passwords and login/ingestion tokens remain in memory. Fixture identifiers are
recorded before creation so an interrupted run can be cleaned up precisely.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
import json
from pathlib import Path
import secrets
import subprocess
import time
from urllib.parse import urlsplit
import uuid

import requests
import urllib3

MARKER = "SCYTHE_SMOKE_JSON="


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", default="https://localhost:8443")
    parser.add_argument("--worker", default="scythe_celery_worker")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--allow-local-self-signed", action="store_true")
    args = parser.parse_args()
    target = urlsplit(args.base)
    if target.hostname not in {"localhost", "127.0.0.1", "::1"} or target.scheme not in {"http", "https"}:
        parser.error("Only a loopback API endpoint is permitted")
    if args.allow_local_self_signed:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    run = uuid.uuid4().hex[:12]
    emails = [f"scythe-email-smoke-{run}-{number}@example.test" for number in (1, 2)]
    email_id = f"email-smoke-{run}"
    result = {"run_id": run, "started_at": datetime.now(timezone.utc).isoformat(),
              "base": args.base, "fixture_accounts": [{"email": item, "user_id": None} for item in emails],
              "email_id": email_id, "scan_id": None, "checks": [], "passed": False,
              "fixture_mode": "local RFC822 parser and Celery only; no IMAP or SMTP; DNS enrichment explicitly unavailable"}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    sessions = []

    def save():
        args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")

    def check(name, passed, **details):
        result["checks"].append({"check": name, "passed": bool(passed), **details})
        save()
        if not passed:
            raise AssertionError(name)

    def docker(code, data=None):
        source = "import json\nDATA = " + repr(data or {}) + "\n" + code
        process = subprocess.run(["docker", "exec", "-i", args.worker, "python", "-"], input=source,
                                 text=True, capture_output=True, timeout=90)
        if process.returncode:
            raise RuntimeError(f"Container helper failed with exit {process.returncode}")
        lines = [line[len(MARKER):] for line in process.stdout.splitlines() if line.startswith(MARKER)]
        if not lines:
            raise RuntimeError("Container helper did not return a bounded result")
        return json.loads(lines[-1])

    def request(session, method, path, **kwargs):
        deadline = time.monotonic() + 90
        for attempt in range(10):
            response = session.request(method, args.base.rstrip("/") + path, timeout=(10, 60), **kwargs)
            if response.status_code != 429:
                return response
            raw = response.headers.get("Retry-After", "")
            try:
                wait = max(0.0, float(raw))
            except ValueError:
                try:
                    when = parsedate_to_datetime(raw)
                    wait = max(0.0, (when - datetime.now(timezone.utc)).total_seconds())
                except (TypeError, ValueError):
                    wait = min(2 ** attempt, 15)
            if time.monotonic() + wait >= deadline or attempt == 9:
                return response  # Never retry before an advertised Retry-After.
            time.sleep(wait)
        raise RuntimeError("Unreachable retry state")

    save()  # Identifiers are durable before the first account creation or artifact write.
    try:
        for index, email in enumerate(emails):
            session = requests.Session()
            session.trust_env = False
            session.verify = not args.allow_local_self_signed
            sessions.append(session)
            password = secrets.token_urlsafe(30) + "aA7!"
            response = request(session, "POST", "/api/auth/register", json={"email": email, "password": password})
            check(f"register_{index + 1}", response.status_code == 202, http_status=response.status_code)
            response = request(session, "POST", "/api/auth/login", data={"username": email, "password": password})
            check(f"login_{index + 1}", response.status_code == 200, http_status=response.status_code)
            session.headers["Authorization"] = "Bearer " + response.json()["access_token"]
            password = None
        identities = docker('''from database.database import get_db_session
from database.models import User
with get_db_session() as db:
    rows = db.query(User).filter(User.email.in_(DATA["emails"])).all()
    mapping = {row.email: row.id for row in rows}
print("SCYTHE_SMOKE_JSON=" + json.dumps(mapping))''', {"emails": emails})
        for item in result["fixture_accounts"]:
            item["user_id"] = identities.get(item["email"])
        save()
        check("fixture_identity_lookup", all(item["user_id"] for item in result["fixture_accounts"]))
        owner_id = identities[emails[0]]
        seeded = docker('''from datetime import datetime, timezone
from email.message import EmailMessage
from email.utils import format_datetime
from pathlib import Path
from unittest.mock import patch
import hashlib
from config import settings
from email_engine import parser, url_extraction, attachment_handler
from services.email.parser.domain_parser import DomainParser
message = EmailMessage()
message["From"] = "Offline Fixture <sender@example.test>"
message["To"] = DATA["email"]
message["Subject"] = "SCYTHE local workflow fixture " + DATA["run"]
message["Message-ID"] = "<" + DATA["email_id"] + "@example.test>"
message["Date"] = format_datetime(datetime.now(timezone.utc))
message["Authentication-Results"] = "offline-fixture; spf=pass smtp.mailfrom=example.test; dkim=pass header.d=example.test; dmarc=pass"
message.set_content("This local fixture contains a harmless text attachment and a reference to https://example.test/local-fixture for URL syntax only. No email is sent and no URL is visited.")
attachment = ("Harmless SCYTHE local attachment " + DATA["run"]).encode()
message.add_attachment(attachment, maintype="text", subtype="plain", filename="fixture.txt")
raw = message.as_bytes()
root = settings.EMAIL_SHARED_DIR
with patch.object(DomainParser, "get_mx_records", return_value=None), patch.object(DomainParser, "check_dnssec", return_value=None):
    parser.parse_and_save(DATA["email_id"], raw, shared_dir=root, owner_email=DATA["email"], owner_user_id=DATA["owner_id"])
url_extraction.extract_and_save(DATA["email_id"], raw, shared_dir=root)
attachment_handler.extract_and_save(DATA["email_id"], raw, shared_dir=root)
folder = Path(root) / "emails" / DATA["email_id"]
(folder / "fixture_provenance.json").write_text(json.dumps({"kind":"offline_local_smoke", "raw_sha256":hashlib.sha256(raw).hexdigest(), "dns":"explicitly_unavailable", "no_imap_or_smtp":True}))
parsed = json.loads((folder / "parsed.json").read_text())
manifest = json.loads((folder / "attachments_manifest.json").read_text())
print("SCYTHE_SMOKE_JSON=" + json.dumps({"raw_sha256": hashlib.sha256(raw).hexdigest(), "attachment_sha256": hashlib.sha256(attachment).hexdigest(), "parser_attachment_sha256":parsed["attachments"]["attachments"][0]["sha256_hash"], "manifest_count":manifest["attachment_count"]}))''', {"email_id": email_id, "run": run, "email": emails[0], "owner_id": owner_id})
        result["fixture_checksums"] = seeded
        save()
        check("decoded_attachment_integrity", seeded["attachment_sha256"] == seeded["parser_attachment_sha256"] and seeded["manifest_count"] == 1)
        owner, other = sessions
        response = request(other, "GET", f"/api/email/{email_id}")
        check("cross_user_email_read_denied", response.status_code == 403, http_status=response.status_code)
        response = request(other, "POST", "/api/email/investigate", json={"email_id": email_id})
        check("cross_user_investigate_denied", response.status_code == 403, http_status=response.status_code)
        response = request(owner, "POST", "/api/email/investigate", json={"email_id": email_id})
        check("owner_investigate_queued", response.status_code == 200, http_status=response.status_code)
        queued = response.json()
        scan_id = queued.get("scan_id")
        result["scan_id"] = scan_id
        result["job_id"] = queued.get("job_id")
        save()
        check("owned_scan_association", bool(scan_id) and queued.get("status") == "email_analysis_queued")
        response = request(owner, "POST", "/api/email/investigate", json={"email_id": email_id})
        duplicate = response.json()
        check("inflight_duplicate_idempotent", response.status_code == 200 and duplicate.get("duplicate") is True and duplicate.get("scan_id") == scan_id)
        deadline = time.monotonic() + 150
        detail = {}
        while time.monotonic() < deadline:
            response = request(owner, "GET", f"/api/email/{email_id}")
            if response.status_code != 200:
                check("owner_email_detail", False, http_status=response.status_code)
            detail = response.json()
            if detail.get("status") in {"email_scan_done", "email_scan_unavailable", "failed_timeout", "email_dispatch_failed"}:
                break
            time.sleep(2)
        report = detail.get("risk_report") or {}
        result["final_status"] = detail.get("status")
        save()
        check("all_celery_branches_finalized", detail.get("status") == "email_scan_done", status=detail.get("status"))
        check("final_model_gate_preserved", report.get("risk_score") is None and report.get("severity") == "UNKNOWN" and report.get("is_placeholder") is True and report.get("automatic_decision") is False)
        response = request(owner, "GET", f"/api/scans/{scan_id}")
        canonical = response.json()
        check("canonical_scan_report_parity", response.status_code == 200 and canonical.get("risk_report") == report)
        for path in (f"/api/scans/{scan_id}", f"/api/scans/{scan_id}/artifacts/risk_report.json"):
            response = request(other, "GET", path)
            check("cross_user_scan_artifact_denied_" + path.rsplit("/", 1)[-1], response.status_code == 404, http_status=response.status_code)
        technical = docker('''from pathlib import Path
import hashlib
from config import settings
from database.database import get_db_session
from database.models import Incident
folder = Path(settings.EMAIL_SHARED_DIR) / "emails" / DATA["email_id"]
names = ["header_features.json","url_features.json","attachment_features.json","content_features.json","email_consistency.json","risk_report.json"]
features = json.loads((folder / "attachment_features.json").read_text())
url_features = json.loads((folder / "url_features.json").read_text())
manifest = json.loads((folder / "attachments_manifest.json").read_text())
entry = manifest["attachments"][0]
payload = folder / "attachments" / entry["safe_name"]
with get_db_session() as db:
    incidents = db.query(Incident).filter(Incident.scan_id == DATA["scan_id"]).count()
print("SCYTHE_SMOKE_JSON=" + json.dumps({"stage_files":{name:(folder/name).exists() for name in names}, "av_available":features.get("av_available"), "av_results":features.get("antivirus"), "url_contract":url_features.get("url_evidence", {}).get("contract_version"), "url_count":url_features.get("url_evidence", {}).get("urls", {}).get("url_count"), "url_enrichment":url_features.get("url_evidence", {}).get("feature_availability"), "payload_checksum_matches":hashlib.sha256(payload.read_bytes()).hexdigest() == entry["sha256"], "incident_count":incidents}))''', {"email_id": email_id, "scan_id": scan_id})
        result["technical_verification"] = technical
        save()
        check("stage_artifacts_present", all(technical["stage_files"].values()))
        check("parsed_url_reaches_offline_detector_contract", technical["url_contract"] == "email_url_diagnostics_v1" and technical["url_count"] == 1 and technical["url_enrichment"].get("domain_age_days") == "unavailable")
        check("attachment_clamav_verified", technical["av_available"] is True and all(item.get("available") and not item.get("malware_detected") for item in technical["av_results"]) and technical["payload_checksum_matches"])
        check("no_automatic_incident", technical["incident_count"] == 0)
        response = request(owner, "POST", "/api/email/investigate", json={"email_id": email_id})
        repeated = response.json()
        check("terminal_duplicate_does_not_resurrect", repeated.get("duplicate") is True and repeated.get("scan_id") == scan_id and repeated.get("status") == "email_scan_done")
        scoped = docker('''import urllib.request
import urllib.error
from config import settings
req = urllib.request.Request("http://backend:8000/api/email/ingest", data=json.dumps({"email_id":DATA["email_id"]}).encode(), headers={"Content-Type":"application/json", "Authorization":"Bearer " + settings.EMAIL_POLLER_TOKEN}, method="POST")
try:
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(req, timeout=15) as response:
        code = response.status
except urllib.error.HTTPError as exc:
    code = exc.code
print("SCYTHE_SMOKE_JSON=" + json.dumps({"http_status":code, "owner_configured":bool(settings.EMAIL_OWNER_USER_ID), "mailbox_configured":bool(settings.EMAIL_ADDRESS), "token_configured":len(settings.EMAIL_POLLER_TOKEN)>=32}))''', {"email_id": email_id})
        result["scoped_ingestion"] = scoped
        check("unconfigured_mailbox_fails_closed", scoped["http_status"] in {401, 403, 503}, http_status=scoped["http_status"])
        result["passed"] = True
    except Exception as exc:
        result["error"] = {"type": type(exc).__name__, "check_or_reason": str(exc)[:150]}
    finally:
        for session in sessions:
            try:
                request(session, "POST", "/api/auth/logout")
            except Exception:
                pass
            session.close()
        try:
            cleanup = docker('''from database.database import get_db_session
from database.models import User
if not all(item.startswith("scythe-email-smoke-" + DATA["run"] + "-") and item.endswith("@example.test") for item in DATA["emails"]):
    raise ValueError("Invalid fixture cleanup scope")
with get_db_session() as db:
    users = db.query(User).filter(User.email.in_(DATA["emails"])).all()
    for user in users:
        user.is_active = False
    db.commit()
print("SCYTHE_SMOKE_JSON=" + json.dumps({"fixture_accounts_disabled":len(users)}))''', {"emails": emails, "run": run})
            result["cleanup"] = cleanup
        except Exception as exc:
            result["cleanup"] = {"requires_action": "Disable the exact fixture accounts recorded above", "error_type": type(exc).__name__}
        result["finished_at"] = datetime.now(timezone.utc).isoformat()
        save()
    print(json.dumps({"passed": result["passed"], "report": str(args.output.resolve()), "checks": len(result["checks"]), "final_status": result.get("final_status")}, indent=2))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
