"""
auth/security.py
==================
"""

import hashlib
import logging
import urllib.request
import urllib.error
import bcrypt
import redis

from typing import Tuple
from config import settings

logger = logging.getLogger(__name__)

_MAX_PASSWORD_BYTES = 72

_redis_auth_client = None

def get_redis_auth_client():
    global _redis_auth_client
    if _redis_auth_client is not None:
        try:
            _redis_auth_client.ping()
            return _redis_auth_client
        except Exception:
            _redis_auth_client = None
    try:
        _redis_auth_client = redis.from_url(settings.REDIS_SECURITY_URL, socket_connect_timeout=2)
        _redis_auth_client.ping()
        return _redis_auth_client
    except Exception as e:
        logger.warning("Could not connect to Redis for account lockout: %s", e)
        return None


def _lockout_keys(email: str, client_ip: str = "") -> Tuple[str, str]:
    normalized_email = email.lower().strip()
    ip_part = f":{client_ip.strip()}" if client_ip and client_ip.strip() else ""
    return f"login_attempts:{normalized_email}{ip_part}", f"login_global:{normalized_email}"


def check_account_lockout(email: str, client_ip: str = "") -> bool:
    """
    Returns True if account is currently locked out due to excessive failed login attempts.
    Uses IP-scoped throttling to prevent unauthenticated attackers from locking out
    legitimate users on other IPs.
    """
    client = get_redis_auth_client()
    if not client:
        if getattr(settings, "AUTH_LOCKOUT_FAIL_CLOSED", True) or settings.is_production:
            logger.error("Redis unavailable during account lockout check (fail-closed)")
            raise ValueError("Authentication store unavailable")
        return False
    
    ip_key, global_key = _lockout_keys(email, client_ip)
    try:
        # Check attempts on this ip_key (whether IP-scoped or default email key)
        ip_attempts = client.get(ip_key)
        if ip_attempts and int(ip_attempts) >= settings.MAX_LOGIN_ATTEMPTS:
            logger.warning("Account %s locked out on scope %s due to failed attempts", email, ip_key)
            return True

        # Check global distributed attempts across rotating IPs
        global_attempts = client.get(global_key)
        global_threshold = getattr(settings, "MAX_GLOBAL_LOGIN_ATTEMPTS", settings.MAX_LOGIN_ATTEMPTS * 5)
        if global_attempts and int(global_attempts) >= global_threshold:
            logger.critical("ALERT [CREDENTIAL_STUFFING]: Account %s targeted by distributed login storm (%s attempts)", email, global_attempts)
            # If client_ip is provided, only lock out IPs that participated in the failures
            if client_ip:
                if ip_attempts and int(ip_attempts) > 0:
                    return True
            else:
                return True

        return False
    except redis.exceptions.RedisError as e:
        logger.error("Redis error checking account lockout for %s: %s", email, e)
        if getattr(settings, "AUTH_LOCKOUT_FAIL_CLOSED", True) or settings.is_production:
            raise ValueError("Authentication store unavailable")
        return False


def record_failed_login(email: str, client_ip: str = "") -> int:
    """
    Increments failed login counter for both IP-scoped and global counters.
    Returns new attempt count for the active scope.
    """
    client = get_redis_auth_client()
    if not client:
        return 0
    ip_key, global_key = _lockout_keys(email, client_ip)
    try:
        count = client.incr(ip_key)
        if count == 1:
            client.expire(ip_key, settings.LOCKOUT_DURATION_SECONDS)
        g_count = client.incr(global_key)
        if g_count == 1:
            client.expire(global_key, settings.LOCKOUT_DURATION_SECONDS * 2)
        return count
    except redis.exceptions.RedisError as e:
        logger.error("Redis error recording failed login for %s: %s", email, e)
        return 0


def reset_failed_login(email: str, client_ip: str = "") -> None:
    """
    Resets failed login counter on successful login.
    """
    client = get_redis_auth_client()
    if not client:
        return
    ip_key, global_key = _lockout_keys(email, client_ip)
    try:
        client.delete(ip_key, global_key)
    except redis.exceptions.RedisError as e:
        logger.warning("Redis error resetting failed login for %s: %s", email, e)



def _pre_hash(password: str) -> bytes:
    # SHA-256 pre-hash converts any length password into a fixed 64-byte hex string,
    # completely bypassing bcrypt's 72-byte truncation limit while preserving full entropy.
    return hashlib.sha256(password.encode("utf-8")).hexdigest().encode("utf-8")


def hash_password(password: str) -> str:
    pw_bytes = _pre_hash(password)
    return bcrypt.hashpw(pw_bytes, bcrypt.gensalt()).decode("utf-8")


def verify_password_with_migration(plain_password: str, hashed_password: str) -> Tuple[bool, bool]:
    """
    Returns (is_valid, needs_rehash).
    needs_rehash is True when a legacy truncated-72-byte hash succeeded and
    ALLOW_LEGACY_BCRYPT is enabled, indicating the password hash should be
    upgraded to the new SHA-256 pre-hashed format immediately upon login.
    """
    hashed_bytes = hashed_password.encode("utf-8")
    try:
        # First check SHA-256 pre-hashed password (new format)
        if bcrypt.checkpw(_pre_hash(plain_password), hashed_bytes):
            return True, False
        # Backward compatibility check only if explicitly enabled
        if getattr(settings, "ALLOW_LEGACY_BCRYPT", False):
            legacy_bytes = plain_password.encode("utf-8")[:_MAX_PASSWORD_BYTES]
            if bcrypt.checkpw(legacy_bytes, hashed_bytes):
                return True, True
        return False, False
    except ValueError:
        return False, False


def verify_password(plain_password: str, hashed_password: str) -> bool:
    is_valid, _ = verify_password_with_migration(plain_password, hashed_password)
    return is_valid


def check_pwned_password(plain_password: str) -> bool:
    """
    Check if the password has appeared in known public data breaches using the
    Have I Been Pwned (HIBP) k-Anonymity API.
    Only the first 5 characters of the SHA-1 hash (`prefix`) are sent over the wire.
    """
    if not plain_password:
        return False
    sha1_hash = hashlib.sha1(plain_password.encode("utf-8")).hexdigest().upper()  # nosec B324
    prefix, suffix = sha1_hash[:5], sha1_hash[5:]
    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "SCYTHE-Security-HIBP-Checker"}
    )
    try:
        with urllib.request.urlopen(req, timeout=2.0) as resp:  # nosec B310
            if resp.status != 200:
                return False
            for line in resp.read().decode("utf-8", errors="ignore").splitlines():
                parts = line.strip().split(":")
                if len(parts) == 2 and parts[0] == suffix:
                    count = int(parts[1]) if parts[1].isdigit() else 1
                    if count > 0:
                        logger.warning("Registration blocked: password matched HIBP k-anonymity breach list (count=%d)", count)
                        return True
        return False
    except Exception as e:
        record_hibp_failure_metric()
        if getattr(settings, "HIBP_FAIL_CLOSED", False):
            logger.error("HIBP k-anonymity check failed or timed out (%s) — failing closed (HIBP_FAIL_CLOSED=True)", e)
            raise ValueError("Password breach check service is temporarily unavailable. Please try again later.")
        logger.warning("HIBP k-anonymity check failed or timed out (%s) — failing open to prevent registration outage", e)
        return False


def record_hibp_failure_metric() -> None:
    """
    Increment telemetry counter when HIBP API reachability fails.
    Allows operations to alert on prolonged external API outages while failing open.
    Emits structured critical warning for SIEM/Slack alerts when failure threshold is breached.
    """
    client = get_redis_auth_client()
    if client:
        try:
            failures = client.incr("metric:hibp_api_failures")
            if failures == 1:
                client.expire("metric:hibp_api_failures", 3600)  # 1h window
            threshold = getattr(settings, "HIBP_FAILURE_ALERT_THRESHOLD", 10)
            if failures >= threshold and failures % threshold == 0:
                logger.critical("ALERT [HIBP_OUTAGE]: %d HIBP API failures recorded in past hour. Password breach checks are currently failing open!", failures)
        except Exception as e:
            logger.debug("Failed to record HIBP failure telemetry: %s", e)


def record_legacy_bcrypt_metric() -> None:
    """
    Increment telemetry counter for legacy bcrypt authentication events.
    Used by operations/CI checks to safely time out ALLOW_LEGACY_BCRYPT.
    """
    client = get_redis_auth_client()
    if client:
        try:
            client.incr("metric:legacy_bcrypt_authentications")
        except Exception as e:
            logger.debug("Failed to record legacy bcrypt telemetry: %s", e)
