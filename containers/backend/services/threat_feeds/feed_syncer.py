"""
Threat Feed Ingestion Service (Tier-0 Redis Cache)
===================================================
Fetches and caches known malicious URLs and domains from global threat feeds
(URLhaus / abuse.ch, OpenPhish) into Redis for sub-millisecond line-rate blocking.
"""

from datetime import datetime, timezone
import hashlib
import json
import logging
from urllib.parse import urlparse
import urllib.request
import urllib.error

logger = logging.getLogger(__name__)

URLHAUS_RECENT_CSV = "https://urlhaus.abuse.ch/downloads/csv_recent/"
OPENPHISH_COMMUNITY_FEED = "https://openphish.com/feed.txt"

# Default TTL: 24 hours (86,400 seconds)
DEFAULT_FEED_TTL = 86400


def _extract_domain(url: str) -> str:
    try:
        parsed = urlparse(url)
        return (parsed.hostname or "").lower().rstrip(".")
    except Exception:
        return ""


def hash_url(url: str) -> str:
    return hashlib.sha256(url.strip().encode("utf-8")).hexdigest()


def ingest_url(redis_client, url: str, source: str, ttl: int = DEFAULT_FEED_TTL) -> bool:
    """Store a single threat indicator in Redis with URL hash and domain keys."""
    if not url or not isinstance(url, str):
        return False
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        return False

    url_h = hash_url(url)
    domain = _extract_domain(url)
    now = datetime.now(timezone.utc).isoformat()

    payload = json.dumps({
        "url": url,
        "source": source,
        "domain": domain,
        "ingested_at": now,
    })

    pipe = redis_client.pipeline()
    pipe.setex(f"threat_feed:url:{url_h}", ttl, payload)
    if domain and "." in domain:
        pipe.setex(f"threat_feed:domain:{domain}", ttl, payload)
    pipe.execute()
    return True


def fetch_urlhaus_recent(limit: int = 2000) -> list[str]:
    """Fetch recent malware/phishing URLs from URLhaus (abuse.ch)."""
    urls: list[str] = []
    req = urllib.request.Request(
        URLHAUS_RECENT_CSV,
        headers={"User-Agent": "SCYTHE-ThreatIntel-Ingest/1.0"}
    )
    try:
        if not URLHAUS_RECENT_CSV.startswith("https://"):
            raise ValueError("URLhaus feed must use HTTPS")
        with urllib.request.urlopen(req, timeout=15) as resp:  # nosec B310
            content = resp.read().decode("utf-8", errors="ignore")
            for line in content.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                # CSV columns: id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter
                parts = line.split('","')
                if len(parts) >= 3:
                    u = parts[2].strip('"')
                    if u.startswith(("http://", "https://")):
                        urls.append(u)
                        if len(urls) >= limit:
                            break
    except Exception as exc:
        logger.warning("[threat_feeds] URLhaus fetch failed or offline: %s", exc)
    return urls


def fetch_openphish_recent(limit: int = 2000) -> list[str]:
    """Fetch recent phishing URLs from OpenPhish community feed."""
    urls: list[str] = []
    req = urllib.request.Request(
        OPENPHISH_COMMUNITY_FEED,
        headers={"User-Agent": "SCYTHE-ThreatIntel-Ingest/1.0"}
    )
    try:
        if not OPENPHISH_COMMUNITY_FEED.startswith("https://"):
            raise ValueError("OpenPhish feed must use HTTPS")
        with urllib.request.urlopen(req, timeout=15) as resp:  # nosec B310
            content = resp.read().decode("utf-8", errors="ignore")
            for line in content.splitlines():
                line = line.strip()
                if line.startswith(("http://", "https://")):
                    urls.append(line)
                    if len(urls) >= limit:
                        break
    except Exception as exc:
        logger.warning("[threat_feeds] OpenPhish fetch failed or offline: %s", exc)
    return urls


def sync_threat_feeds(redis_client, limit_per_feed: int = 1000, ttl: int = DEFAULT_FEED_TTL) -> dict:
    """Synchronize all configured public threat intel feeds into Redis."""
    stats = {"urlhaus": 0, "openphish": 0, "total_synced": 0}

    # 1. URLhaus
    urlhaus_urls = fetch_urlhaus_recent(limit=limit_per_feed)
    for u in urlhaus_urls:
        if ingest_url(redis_client, u, "URLhaus (abuse.ch)", ttl=ttl):
            stats["urlhaus"] += 1

    # 2. OpenPhish
    openphish_urls = fetch_openphish_recent(limit=limit_per_feed)
    for u in openphish_urls:
        if ingest_url(redis_client, u, "OpenPhish", ttl=ttl):
            stats["openphish"] += 1

    stats["total_synced"] = stats["urlhaus"] + stats["openphish"]
    logger.info("[threat_feeds] Synced %d total threat indicators to Redis Tier 0", stats["total_synced"])
    return stats


def query_threat_feed(redis_client, url: str) -> tuple[bool, str, dict]:
    """
    Query Redis Tier 0 cache for an exact URL or domain match.
    Returns (is_threat, reason, metadata).
    """
    if not url or not redis_client:
        return False, "", {}

    clean_url = url.strip()
    url_h = hash_url(clean_url)
    raw = redis_client.get(f"threat_feed:url:{url_h}")

    if raw:
        try:
            meta = json.loads(raw)
            return True, f"Known threat indicator published by {meta.get('source', 'Threat Intel Feed')}", meta
        except Exception:
            return True, "Known threat indicator in active threat intelligence cache", {}

    domain = _extract_domain(clean_url)
    if domain:
        raw_dom = redis_client.get(f"threat_feed:domain:{domain}")
        if raw_dom:
            try:
                meta = json.loads(raw_dom)
                return True, f"Known malicious domain published by {meta.get('source', 'Threat Intel Feed')}", meta
            except Exception:
                return True, "Known malicious domain in active threat intelligence cache", {}

    return False, "", {}
