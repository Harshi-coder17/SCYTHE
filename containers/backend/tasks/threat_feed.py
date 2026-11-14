"""
tasks/threat_feed.py
====================
Celery task for periodic threat intelligence feed ingestion into Redis Tier 0 cache.
"""

import logging
import redis
from celery_worker import celery
from config import settings
from services.threat_feeds.feed_syncer import sync_threat_feeds

logger = logging.getLogger(__name__)


@celery.task(
    bind=True,
    name="tasks.sync_threat_feeds",
    queue="default",
    max_retries=2,
    default_retry_delay=60,
    acks_late=True,
)
def sync_threat_feeds_task(self, limit_per_feed: int = 1500):
    logger.info("[threat_feed_task] Ingesting latest URLhaus & OpenPhish feeds into Redis Tier 0")
    try:
        r = redis.from_url(settings.REDIS_URL)
        stats = sync_threat_feeds(r, limit_per_feed=limit_per_feed)
        logger.info("[threat_feed_task] Sync completed: %s", stats)
        return stats
    except Exception as exc:
        logger.exception("[threat_feed_task] Failed to sync threat feeds: %s", exc)
        raise self.retry(exc=exc)
