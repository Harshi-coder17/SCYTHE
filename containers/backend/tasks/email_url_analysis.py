"""
tasks/email_url_analysis.py
============================
V10 Email Architecture — Child Process P2

Reads:   /shared/emails/{email_id}/parsed.json
Runs:    URLDetector            → Blacklist, shorteners, IP URLs, HTTPS,
                                  typosquatting, homoglyph, domain age,
                                  redirect chain, URL length
         InfrastructureDetector → IP/ASN reputation, reverse DNS,
                                  country mismatch, hop count, DNSSEC
Writes:  /shared/emails/{email_id}/url_features.json
"""

import json
import logging
import os

from celery_worker import celery
from config import settings

from services.email.detectors.url_detector import URLDetector
from services.email.detectors.infrastructure_detector import InfrastructureDetector

logger = logging.getLogger(__name__)

SHARED_DIR = getattr(settings, "EMAIL_SHARED_DIR", "/shared/scans")


def _email_dir(email_id: str) -> str:
    return os.path.join(SHARED_DIR, "emails", email_id)


@celery.task(
    bind=True,
    name="tasks.email_url_analysis.email_url_analysis_task",
    queue="default",
    max_retries=3,
    default_retry_delay=5,
    acks_late=True,
    soft_time_limit=120,
    time_limit=150,
)
def email_url_analysis_task(self, email_id: str):
    logger.info("email_url_analysis started email_id=%s", email_id)

    email_dir = _email_dir(email_id)
    parsed_path = os.path.join(email_dir, "parsed.json")

    if not os.path.exists(parsed_path):
        raise FileNotFoundError(
            f"parsed.json not found for email_id={email_id} at {parsed_path}"
        )

    with open(parsed_path, "r", encoding="utf-8") as f:
        email_json = json.load(f)

    # ── Run detectors ──────────────────────────────────────────────────────
    url_result = URLDetector().detect(email_json)
    infra_result = InfrastructureDetector().detect(email_json)

    # ── Combine into url_features ──────────────────────────────────────────
    url_score = min(url_result["score"] + infra_result["score"], 100)
    url_features = {
        "email_id": email_id,
        "url_score": url_score,
        "severity": url_result["severity"] if url_result["score"] >= infra_result["score"] else infra_result["severity"],
        "urls": url_result,
        "infrastructure": infra_result,
        "extracted_urls": email_json.get("content", {}).get("extracted_urls", []),
    }

    output_path = os.path.join(email_dir, "url_features.json")
    tmp_path = output_path + ".tmp"
    os.makedirs(email_dir, exist_ok=True)
    with open(tmp_path, "w", encoding="utf-8") as f:
        json.dump(url_features, f, indent=2)
    os.replace(tmp_path, output_path)  # atomic — prevents partial-read by email_consistency_task

    logger.info(
        "email_url_analysis done email_id=%s score=%s severity=%s",
        email_id, url_score, url_features["severity"],
    )
    return email_id
