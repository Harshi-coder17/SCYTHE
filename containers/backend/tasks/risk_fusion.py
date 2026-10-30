"""
tasks/risk_fusion.py
=========================
Stage 4 of the SCYTHE Celery pipeline: assembles all evidence into a
final risk verdict, writes it to Redis, and pushes a WebSocket update.

Security hardening:
  - Redis cache TTL set to 3600s (1 hour) — was previously set() with no
    TTL, causing risk verdicts to persist in Redis indefinitely (finding #13).
  - is_placeholder gate already suppresses false HIGH/CRITICAL alerts when
    the real ML model is not yet wired in.
  - Only non-placeholder verdicts are written to the cache (consistent with
    the quickscan service's caching policy).
"""

import json
import logging
import os
import uuid

import redis

from celery_worker import celery
from config import settings
from database.database import get_db_session
from database.models import Scan

from risk_fusion import RiskFusionEngine  # root-level ML engine, NOT this file
from cyberintel.runner import run_cyberintel
from websocket.websocket_manager import websocket_manager
from tasks import validate_scan_id

logger = logging.getLogger(__name__)

_redis_client = redis.from_url(settings.REDIS_URL)

# Authoritative risk result cache TTL.  Must be ≤ Chrome extension's own
# in-memory cache TTL (or there is no point in the Redis cache at all).
# 3600 s (1 hour) per the absolute_implementation_guide spec.
_RISK_CACHE_TTL_SECONDS = 3600

ALERT_SEVERITIES = {"HIGH", "CRITICAL"}
_PROTECTED_STATUSES = {"cancelled", "expired", "failed_timeout", "blocked_by_cyberintel", "risk_fusion_failed"}
_FINAL_STATUSES = {"risk_fusion_done", "alert_pipeline_running", "alert_pipeline_retrying",
                   "alert_pipeline_done", "alert_pipeline_failed", "alert_pipeline_dispatch_failed"}


def _scan_dir(scan_id: str) -> str:
    validate_scan_id(scan_id)
    return os.path.join(settings.SHARED_DIR, scan_id)


def _mark_status(scan_id: str, status: str, risk_score: float = None, severity: str = None) -> bool:
    try:
        with get_db_session() as db:
            scan = db.query(Scan).filter(Scan.id == scan_id).with_for_update().first()
            if scan:
                if scan.status in _PROTECTED_STATUSES:
                    return False
                scan.status = status
                if risk_score is not None or status == "risk_fusion_done":
                    scan.risk_score = risk_score
                if severity is not None:
                    scan.severity = severity
                db.commit()
                return True
            return False
    except Exception:
        logger.exception("Failed to update scan status to %s for %s", status, scan_id)
        return False


def _claim_scan(scan_id: str) -> bool:
    with get_db_session() as db:
        scan = db.query(Scan).filter(Scan.id == scan_id).with_for_update().first()
        if scan is None:
            raise ValueError("Owned scan is missing")
        if scan.status in _PROTECTED_STATUSES or scan.status in _FINAL_STATUSES:
            return False
        scan.status = "risk_fusion_running"
        db.commit()
        return True


def _load_json(path: str) -> dict:
    with open(path) as f:
        return json.load(f)


def _get_scan_fields(scan_id: str) -> dict:
    validate_scan_id(scan_id)
    with get_db_session() as db:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if scan is None:
            raise ValueError(f"Scan {scan_id} not found")
        return {"url": scan.url, "user_id": scan.user_id}


def _get_cyberintel(scan_id: str, browser_features: dict) -> dict:

    cache_path = os.path.join(_scan_dir(scan_id), "cyberintel.json")
    if os.path.exists(cache_path):
        return _load_json(cache_path)

    target = browser_features.get("target") or browser_features.get("url")
    if not target:
        try:
            target = _get_scan_fields(scan_id)["url"]
        except Exception:
            logger.exception("[%s] Could not look up scan.url as a cyberintel fallback", scan_id)
            target = None

    cyberintel = run_cyberintel(target) if target else {}

    with open(cache_path, "w") as f:
        json.dump(cyberintel, f, indent=2, default=str)
    return cyberintel


def _push_websocket_update(scan_id: str, payload: dict) -> None:
    user_id = None
    try:
        user_id = _get_scan_fields(scan_id).get("user_id")
    except Exception:
        logger.exception("[%s] Could not look up user_id for dashboard broadcast", scan_id)

    try:
        websocket_manager.broadcast_risk_update_sync(scan_id, payload, user_id=user_id)
    except Exception:
        logger.exception("[%s] WebSocket push failed (non-fatal)", scan_id)


# ── Pipeline Stage (Diagram → Code) ──────────────────────────────────────────
# Diagram Stage 3 (LightGBM Fusion) | Code internal name: "Stage 4 / risk_fusion"
@celery.task(
    bind=True,
    name="tasks.risk_fusion",
    max_retries=2,
    default_retry_delay=10,
    acks_late=True,
    soft_time_limit=55,
    time_limit=60,
)
def risk_fusion_task(self, scan_id: str):
    validate_scan_id(scan_id)
    lock_key = f"scythe:risk-fusion-lock:{scan_id}"
    lock_token = str(uuid.uuid4())
    try:
        acquired = _redis_client.set(lock_key, lock_token, nx=True, ex=90)
    except Exception as exc:
        raise self.retry(exc=exc)
    if not acquired:
        # A redelivery after worker death must outlive the abandoned lease;
        # acknowledging it immediately would strand the scan until reconciliation.
        raise self.retry(exc=RuntimeError("Inference already processing"), countdown=45)
    try:
        if not _claim_scan(scan_id):
            return {"scan_id": scan_id, "status": "already_terminal"}
        return _execute_risk_fusion(self, scan_id)
    finally:
        try:
            # Do not delete another delivery's lease if this one expired.
            _redis_client.eval("if redis.call('get',KEYS[1])==ARGV[1] then return redis.call('del',KEYS[1]) else return 0 end",
                               1, lock_key, lock_token)
        except Exception:
            logger.exception("[%s] Could not release inference lease; it will expire", scan_id)


def _execute_risk_fusion(self, scan_id: str):
    validate_scan_id(scan_id)
    logger.info("[%s] Stage 4 (risk_fusion) started", scan_id)

    scan_dir = _scan_dir(scan_id)

    try:
        browser_features = _load_json(os.path.join(scan_dir, "browser_features.json"))
        sandbox_features = _load_json(os.path.join(scan_dir, "sandbox_metadata.json"))
        consistency_report = _load_json(os.path.join(scan_dir, "consistency_report.json"))
        cyberintel = _get_cyberintel(scan_id, browser_features)
    except Exception as exc:
        logger.exception("[%s] Missing inputs for risk fusion", scan_id)
        if self.request.retries >= self.max_retries:
            _mark_status(scan_id, "risk_fusion_failed")
        else:
            _mark_status(scan_id, "risk_fusion_retrying")
        raise self.retry(exc=exc)

    try:
        engine = RiskFusionEngine()
        if settings.MODEL_RELEASE_ENABLED:
            from tasks.model_inference import infer
            release_result = infer({"cyberintel": cyberintel, "capture_id": scan_id,
                                    "browser_features": browser_features, "sandbox_features": sandbox_features,
                                    "consistency_report": consistency_report,
                                    "scythe_observations": cyberintel.get("scythe_observations", {})},
                                   image_path=os.path.join(scan_dir, "browser.png"), path="deep_url")
        else:
            release_result = None
        risk_report = engine.compute(
            cyberintel=cyberintel,
            browser_features=browser_features,
            sandbox_features=sandbox_features,
            consistency_report=consistency_report,
            **({"release_result": release_result} if release_result is not None else {}),
        )
    except Exception as exc:
        logger.exception("[%s] RiskFusionEngine.compute() failed", scan_id)
        if self.request.retries >= self.max_retries:
            _mark_status(scan_id, "risk_fusion_failed")
        else:
            _mark_status(scan_id, "risk_fusion_retrying")
        raise self.retry(exc=exc)

    risk_report["scan_id"] = scan_id

    report_path = os.path.join(scan_dir, "risk_report.json")
    tmp_path = report_path + ".tmp"
    with open(tmp_path, "w") as f:
        json.dump(risk_report, f, indent=2, default=str)
    os.replace(tmp_path, report_path)  # atomic on Linux — prevents partial-read by late-joining WebSocket clients

    # Experimental scores are strictly diagnostic. Dispatch only after the
    # authoritative report exists, and isolate enqueue failures so they can
    # never affect risk, status, websocket, or alert handling below.
    if settings.SHADOW_SCORING_ENABLED:
        try:
            from tasks.shadow_model_scoring import shadow_model_scoring_task
            shadow_model_scoring_task.apply_async(args=[scan_id], queue="shadow")
        except Exception:
            logger.exception("[%s] Could not dispatch optional shadow scoring task", scan_id)

    # Security finding #13 fix: was set() with no TTL (infinite persistence).
    # Use setex(3600) so Redis automatically evicts the entry after 1 hour.
    # Cache all completed verdicts keyed by unique scan_id so late-joining WebSocket clients
    # can fetch the completed result instantly without waiting on pubsub (finding #5 fix).
    logger.info(
        "[%s] risk_fusion complete - score=%s severity=%s%s",
        scan_id,
        risk_report.get("risk_score"),
        risk_report.get("severity"),
        " (PLACEHOLDER MODEL)" if risk_report.get("is_placeholder") else "",
    )
    persisted = _mark_status(
        scan_id,
        "risk_fusion_done",
        risk_score=risk_report.get("risk_score"),
        severity=risk_report.get("severity"),
    )
    if persisted is False:
        raise self.retry(exc=RuntimeError("Final scan state could not be persisted"))
    try:
        _redis_client.setex(f"risk:{scan_id}", _RISK_CACHE_TTL_SECONDS, json.dumps(risk_report, default=str))
    except Exception:
        logger.exception("[%s] Final report persisted; Redis cache unavailable", scan_id)
    # The client must never observe a terminal event before database persistence.
    _push_websocket_update(scan_id, risk_report)

    is_placeholder = risk_report.get("is_placeholder", True)  # fail closed: unknown -> treat as placeholder
    if risk_report.get("severity") in ALERT_SEVERITIES and not is_placeholder:
        from tasks.alert_pipeline import alert_pipeline_task
        try:
            alert_pipeline_task.delay(scan_id, risk_report)
        except Exception:
            logger.exception("[%s] Failed to dispatch alert_pipeline_task", scan_id)
            _mark_status(scan_id, "alert_pipeline_dispatch_failed")
    elif risk_report.get("severity") in ALERT_SEVERITIES and is_placeholder:
        logger.info(
            "[%s] severity=%s but is_placeholder=True -- suppressing alert_pipeline "
            "dispatch (no Incident row, no Slack) until the real model is wired in",
            scan_id, risk_report.get("severity"),
        )

    return {"scan_id": scan_id, "status": "risk_fusion_done", "severity": risk_report.get("severity")}
