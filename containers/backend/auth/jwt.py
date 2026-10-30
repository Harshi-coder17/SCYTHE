from datetime import datetime, timedelta, timezone
from typing import Optional
import logging
import uuid

import jwt
from jwt.exceptions import PyJWTError as JWTError
import redis

from config import settings

logger = logging.getLogger(__name__)

SECRET_KEY = settings.SECRET_KEY
ALGORITHM = getattr(settings, "ALGORITHM", "HS256") or "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = settings.ACCESS_TOKEN_EXPIRE_MINUTES

_redis_client = None

def get_redis_client():
    global _redis_client
    if _redis_client is not None:
        try:
            _redis_client.ping()
            return _redis_client
        except Exception:
            _redis_client = None
    try:
        _redis_client = redis.from_url(
            settings.REDIS_SECURITY_URL,
            socket_connect_timeout=2,
            socket_timeout=2,
            health_check_interval=30,
        )
        _redis_client.ping()
        return _redis_client
    except Exception as e:
        logger.warning("Could not connect to Redis for JWT revocation: %s", e)
        return None


PASSWORD_RESET_TOKEN_EXPIRE_MINUTES = getattr(settings, "PASSWORD_RESET_EXPIRE_MINUTES", 15)
EMAIL_VERIFICATION_TOKEN_EXPIRE_HOURS = getattr(settings, "EMAIL_VERIFICATION_EXPIRE_HOURS", 24)

_local_revoked_jtis: set[str] = set()


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:

    to_encode = data.copy()

    expire = datetime.now(timezone.utc) + (
        expires_delta if expires_delta else timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    to_encode.update({
        "jti": str(uuid.uuid4()),
        "exp": expire,
        "iat": datetime.now(timezone.utc),
        "iss": getattr(settings, "JWT_ISSUER", settings.APP_NAME),
        "aud": "scythe-clients",
    })

    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def create_password_reset_token(user_id: str, email: str, expires_delta: Optional[timedelta] = None) -> str:
    """
    Generate a cryptographically signed, single-use, time-limited JWT for password reset.
    Scoped specifically to 'password_reset' with distinct audience 'scythe-password-reset'.
    Defaults to 15-minute expiration.
    """
    to_encode = {
        "sub": user_id,
        "email": email,
        "scope": "password_reset",
    }
    expire = datetime.now(timezone.utc) + (
        expires_delta if expires_delta else timedelta(minutes=PASSWORD_RESET_TOKEN_EXPIRE_MINUTES)
    )
    to_encode.update({
        "jti": str(uuid.uuid4()),
        "exp": expire,
        "iat": datetime.now(timezone.utc),
        "iss": getattr(settings, "JWT_ISSUER", settings.APP_NAME),
        "aud": "scythe-password-reset",
    })

    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def create_email_verification_token(user_id: str, email: str, expires_delta: Optional[timedelta] = None) -> str:
    """
    Generate a cryptographically signed, single-use, time-limited JWT for email verification.
    Scoped specifically to 'email_verification' with distinct audience 'scythe-email-verification'.
    Defaults to 24-hour expiration.
    """
    to_encode = {
        "sub": user_id,
        "email": email,
        "scope": "email_verification",
    }
    expire = datetime.now(timezone.utc) + (
        expires_delta if expires_delta else timedelta(hours=EMAIL_VERIFICATION_TOKEN_EXPIRE_HOURS)
    )
    to_encode.update({
        "jti": str(uuid.uuid4()),
        "exp": expire,
        "iat": datetime.now(timezone.utc),
        "iss": getattr(settings, "JWT_ISSUER", settings.APP_NAME),
        "aud": "scythe-email-verification",
    })

    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def is_token_revoked(jti: str, db=None) -> bool:
    """
    Check if a token jti is revoked.
    Order of checks:
      1. Local in-memory revoked set (_local_revoked_jtis).
      2. Redis blacklist key (jwt_blacklist:{jti}).
      3. Postgres RevokedToken table (if Redis misses or is unavailable, and db is provided).
      4. If Redis is unavailable and db is None, enforces fail-closed policy (raises JWTError).
    """
    if not jti:
        return False

    if jti in _local_revoked_jtis:
        return True

    redis_available = False
    redis_error = None
    client = None
    try:
        client = _redis_client if _redis_client is not None else get_redis_client()
        if client is None:
            redis_error = redis.exceptions.RedisError("Redis client not initialized")
        else:
            if client.get(f"jwt_blacklist:{jti}"):
                return True
            redis_available = True
    except redis.exceptions.RedisError as e:
        redis_error = e
        redis_available = False
        logger.warning("Redis error during JWT blacklist check: %s", e)

    # If Redis is unavailable or misses, fall back to RevokedToken table in Postgres
    if db is not None:
        try:
            from database.models import RevokedToken
            revoked_entry = db.query(RevokedToken).filter(RevokedToken.jti == jti).first()
            if revoked_entry is not None and (
                isinstance(revoked_entry, RevokedToken)
                or (hasattr(revoked_entry, "jti") and getattr(revoked_entry, "jti") == jti)
            ):
                # If Redis is available, backfill Redis cache
                if redis_available and client:
                    try:
                        ttl = 900
                        if hasattr(revoked_entry, "expires_at") and revoked_entry.expires_at:
                            now_ts = datetime.utcnow()
                            diff = int((revoked_entry.expires_at - now_ts).total_seconds())
                            ttl = max(60, diff)
                        client.setex(f"jwt_blacklist:{jti}", ttl, "revoked")
                    except Exception:
                        pass
                return True
            # Checked in Postgres and not found
            return False
        except Exception as e:
            logger.error("Database error during RevokedToken check: %s", e)
            if not redis_available and (getattr(settings, "JWT_REVOCATION_FAIL_CLOSED", True) or settings.is_production):
                raise JWTError("Authentication store unavailable")
            return False

    if redis_available:
        return False

    if getattr(settings, "JWT_REVOCATION_FAIL_CLOSED", True) or settings.is_production:
        logger.error("Redis error during JWT blacklist check (fail-closed): %s", redis_error)
        raise JWTError("Authentication store unavailable")

    return False


def decode_access_token(token: str, db=None) -> dict:

    payload = jwt.decode(
        token,
        SECRET_KEY,
        algorithms=[ALGORITHM],
        issuer=getattr(settings, "JWT_ISSUER", settings.APP_NAME),
        audience="scythe-clients",
    )
    jti = payload.get("jti")
    if jti:
        if is_token_revoked(jti, db=db):
            raise JWTError("Token has been revoked")
    return payload


def decode_password_reset_token(token: str, db=None) -> dict:
    """
    Decode and validate a password reset token.
    Enforces scope='password_reset', valid signature, expiration, and checks Redis/DB revocation blacklist.
    """
    payload = jwt.decode(
        token,
        SECRET_KEY,
        algorithms=[ALGORITHM],
        issuer=getattr(settings, "JWT_ISSUER", settings.APP_NAME),
        audience="scythe-password-reset",
    )
    if payload.get("scope") != "password_reset":
        raise JWTError("Invalid token scope for password reset")

    jti = payload.get("jti")
    if jti:
        if is_token_revoked(jti, db=db):
            raise JWTError("Token has been revoked")

    return payload


def decode_email_verification_token(token: str, db=None) -> dict:
    """
    Decode and validate an email verification token.
    Enforces scope='email_verification', audience='scythe-email-verification',
    valid signature, expiration, and checks Redis/DB revocation blacklist.
    """
    payload = jwt.decode(
        token,
        SECRET_KEY,
        algorithms=[ALGORITHM],
        issuer=getattr(settings, "JWT_ISSUER", settings.APP_NAME),
        audience="scythe-email-verification",
    )
    if payload.get("scope") != "email_verification":
        raise JWTError("Invalid token scope for email verification")

    jti = payload.get("jti")
    if jti:
        if is_token_revoked(jti, db=db):
            raise JWTError("Token has been revoked")

    return payload


def revoke_token(token: str, db=None, *, commit: bool = True) -> bool:
    """
    Revoke a JWT token by jti.
    Writes to Redis blacklist (with TTL) AND persists to RevokedToken table in Postgres if db is provided.
    Set commit=False when composing revocation with another database update in one transaction.
    """
    try:
        payload = jwt.decode(
            token,
            SECRET_KEY,
            algorithms=[ALGORITHM],
            issuer=getattr(settings, "JWT_ISSUER", settings.APP_NAME),
            options={"verify_exp": False, "verify_aud": False},
        )
        jti = payload.get("jti")
        if not jti:
            return False
        _local_revoked_jtis.add(jti)

        token_type = payload.get("scope") or payload.get("token_type") or "access"
        exp = payload.get("exp")
        ttl = int(exp - datetime.now(timezone.utc).timestamp()) if exp else 900
        expires_at = datetime.fromtimestamp(exp, tz=timezone.utc).replace(tzinfo=None) if exp else None

        redis_success = False
        try:
            client = _redis_client if _redis_client is not None else get_redis_client()
            if client:
                set_ttl = ttl if ttl > 0 else 60
                client.setex(f"jwt_blacklist:{jti}", set_ttl, "revoked")
                redis_success = True
        except Exception as re_err:
            logger.warning("Failed to write revoked token to Redis: %s", re_err)

        db_success = False
        if db is not None:
            try:
                from database.models import RevokedToken
                existing = db.query(RevokedToken).filter(RevokedToken.jti == jti).first()
                is_already_present = existing is not None and (
                    isinstance(existing, RevokedToken)
                    or (hasattr(existing, "jti") and getattr(existing, "jti") == jti)
                )
                if not is_already_present:
                    entry = RevokedToken(
                        jti=jti,
                        token_type=token_type,
                        expires_at=expires_at,
                        revoked_at=datetime.utcnow(),
                    )
                    db.add(entry)
                    db.flush()
                if commit:
                    db.commit()
                db_success = True
            except Exception as db_err:
                logger.error("Failed to persist RevokedToken to database: %s", db_err)
                try:
                    db.rollback()
                except Exception:
                    pass

        if db is not None and not commit:
            # A compound password-reset transaction must not commit unless the
            # durable revocation row was successfully added to that transaction.
            return db_success

        if redis_success or db_success:
            return True

        if not settings.is_production and db is None and (_redis_client is None or not redis_success):
            return True

        if (getattr(settings, "JWT_REVOCATION_FAIL_CLOSED", True) or settings.is_production) and not redis_success and not db_success:
            raise redis.exceptions.RedisError("Revocation stores unavailable")

        return False
    except Exception as e:
        logger.error("Failed to revoke token: %s", e)
        if (getattr(settings, "JWT_REVOCATION_FAIL_CLOSED", True) or settings.is_production) and isinstance(e, redis.exceptions.RedisError):
            raise
        return False


def get_subject_from_token(token: str) -> Optional[str]:

    try:
        payload = decode_access_token(token)
    except JWTError:
        return None

    return payload.get("sub")
