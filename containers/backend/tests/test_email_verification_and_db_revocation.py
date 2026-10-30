"""
Tests for Email Verification Flow and Database-Backed JWT Revocation Table (H21).
"""

import logging
from datetime import datetime, timedelta
from unittest.mock import MagicMock, patch

import pytest
from fastapi import HTTPException
from jwt.exceptions import PyJWTError as JWTError
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

import auth.jwt as jwt_module
from auth.jwt import (
    create_access_token,
    decode_access_token,
    create_password_reset_token,
    decode_password_reset_token,
    create_email_verification_token,
    decode_email_verification_token,
    revoke_token,
    is_token_revoked,
)
from auth.routes import (
    register,
    request_email_verification,
    confirm_email_verification,
)
from database.database import Base
from database.models import User, RevokedToken
from schemas.auth import (
    UserRegisterRequest,
    EmailVerificationRequest,
    EmailVerificationConfirmRequest,
)


# ============================================================================
# 1. Email Verification Token Generation and Isolation Tests
# ============================================================================

def test_email_verification_token_creation_and_payload():
    mock_redis = MagicMock()
    mock_redis.get.return_value = None

    with patch.object(jwt_module, "_redis_client", mock_redis):
        token = create_email_verification_token(
            user_id="user_verify_1",
            email="analyst@example.com",
        )
        payload = decode_email_verification_token(token)

        assert payload["sub"] == "user_verify_1"
        assert payload["email"] == "analyst@example.com"
        assert payload["scope"] == "email_verification"
        assert payload["aud"] == "scythe-email-verification"
        assert "jti" in payload

        # Verify 24-hour expiration window (within 10s variance)
        exp_diff = payload["exp"] - payload["iat"]
        assert abs(exp_diff - (24 * 3600)) < 10


def test_scope_and_audience_isolation_across_all_token_types():
    mock_redis = MagicMock()
    mock_redis.get.return_value = None

    with patch.object(jwt_module, "_redis_client", mock_redis):
        user_id = "user_iso_1"
        email = "iso@example.com"

        email_token = create_email_verification_token(user_id=user_id, email=email)
        access_token = create_access_token({"sub": user_id})
        reset_token = create_password_reset_token(user_id=user_id, email=email)

        # Email verification token must NEVER be accepted as access or password reset
        with pytest.raises(JWTError):
            decode_access_token(email_token)
        with pytest.raises(JWTError):
            decode_password_reset_token(email_token)

        # Access token must NEVER be accepted as email verification
        with pytest.raises(JWTError):
            decode_email_verification_token(access_token)

        # Password reset token must NEVER be accepted as email verification
        with pytest.raises(JWTError):
            decode_email_verification_token(reset_token)


# ============================================================================
# 2. Database-Backed Revocation Table Tests (RevokedToken)
# ============================================================================

def test_revoke_token_writes_to_redis_and_db():
    mock_redis = MagicMock()
    mock_db = MagicMock()
    mock_db.query.return_value.filter.return_value.first.return_value = None

    token = create_email_verification_token(user_id="user_rev_1", email="rev@example.com")

    with patch.object(jwt_module, "_redis_client", mock_redis):
        success = revoke_token(token, db=mock_db)
        assert success is True

        # Assert Redis was written
        mock_redis.setex.assert_called_once()
        args = mock_redis.setex.call_args[0]
        assert args[0].startswith("jwt_blacklist:")
        assert args[2] == "revoked"

        # Assert RevokedToken was persisted to DB
        mock_db.add.assert_called_once()
        added_obj = mock_db.add.call_args[0][0]
        assert isinstance(added_obj, RevokedToken)
        assert added_obj.jti is not None
        assert added_obj.token_type == "email_verification"
        assert added_obj.expires_at is not None
        mock_db.commit.assert_called_once()


def test_db_backed_fallback_revocation_when_redis_down():
    """
    H21 Security Requirement:
    When Redis is unavailable, token revocation check MUST fall back to Postgres
    RevokedToken table and correctly identify revoked tokens.
    """
    token = create_access_token({"sub": "user_fallback_1"})
    payload_raw = jwt_module.jwt.decode(
        token,
        jwt_module.SECRET_KEY,
        algorithms=[jwt_module.ALGORITHM],
        options={"verify_signature": False, "verify_aud": False},
    )
    jti = payload_raw["jti"]

    mock_db = MagicMock()
    revoked_entry = RevokedToken(
        jti=jti,
        token_type="access",
        expires_at=datetime.utcnow() + timedelta(hours=1),
    )
    mock_db.query.return_value.filter.return_value.first.return_value = revoked_entry

    # Simulate Redis completely down
    with patch.object(jwt_module, "_redis_client", None), \
         patch.object(jwt_module, "get_redis_client", return_value=None):

        # Revocation check with DB session resolves the token as revoked
        is_rev = is_token_revoked(jti, db=mock_db)
        assert is_rev is True

        # Decoding with DB session catches the revocation despite Redis outage
        with pytest.raises(JWTError, match="Token has been revoked"):
            decode_access_token(token, db=mock_db)


def test_db_backed_fallback_allows_valid_tokens_when_redis_down():
    """
    When Redis is down but Postgres is available, clean (non-revoked) tokens
    continue to authenticate normally without failing closed unnecessarily.
    """
    token = create_access_token({"sub": "user_clean_1"})

    mock_db = MagicMock()
    mock_db.query.return_value.filter.return_value.first.return_value = None

    with patch.object(jwt_module, "_redis_client", None), \
         patch.object(jwt_module, "get_redis_client", return_value=None):

        payload = decode_access_token(token, db=mock_db)
        assert payload["sub"] == "user_clean_1"


def test_redis_cache_miss_falls_back_to_db_and_backfills_cache():
    """
    When Redis is UP but misses (returns None), RevokedToken in Postgres
    is queried, and if found, Redis cache is backfilled.
    """
    token = create_access_token({"sub": "user_miss_1"})
    payload_raw = jwt_module.jwt.decode(
        token,
        jwt_module.SECRET_KEY,
        algorithms=[jwt_module.ALGORITHM],
        options={"verify_signature": False, "verify_aud": False},
    )
    jti = payload_raw["jti"]

    mock_redis = MagicMock()
    mock_redis.get.return_value = None  # Cache miss

    mock_db = MagicMock()
    revoked_entry = RevokedToken(
        jti=jti,
        token_type="access",
        expires_at=datetime.utcnow() + timedelta(minutes=30),
    )
    mock_db.query.return_value.filter.return_value.first.return_value = revoked_entry

    with patch.object(jwt_module, "_redis_client", mock_redis):
        is_rev = is_token_revoked(jti, db=mock_db)
        assert is_rev is True
        # Verify Redis backfill was triggered
        mock_redis.setex.assert_called_once()
        args = mock_redis.setex.call_args[0]
        assert args[0] == f"jwt_blacklist:{jti}"
        assert args[2] == "revoked"


# ============================================================================
# 3. Registration Automatic Token Dispatch Tests
# ============================================================================

def test_register_dispatches_verification_token_and_sets_unverified(caplog):
    mock_db = MagicMock()
    mock_db.query.return_value.filter.return_value.first.return_value = None

    payload = UserRegisterRequest(
        email="newuser@example.com",
        password="C0rr3ct-H0rse!Batt3ry#2026",
    )

    with caplog.at_level(logging.INFO), \
         patch("auth.routes.check_pwned_password", return_value=False):
        response = register(payload=payload, db=mock_db)

    assert "eligible for registration" in response.message
    # Assert User added with is_verified=False
    mock_db.add.assert_called_once()
    created_user = mock_db.add.call_args[0][0]
    assert isinstance(created_user, User)
    assert created_user.email == "newuser@example.com"
    assert created_user.is_verified is False

    # Assert verification token logged in console dispatch
    assert any("[EMAIL_VERIFICATION_TOKEN]" in record.message for record in caplog.records)


# ============================================================================
# 4. Email Verification Request Endpoint Tests (Enumeration Oracle Guard)
# ============================================================================

def test_verify_email_request_existing_unverified_user(caplog):
    mock_db = MagicMock()
    mock_user = MagicMock()
    mock_user.id = "u-verify-req-1"
    mock_user.email = "unverified@example.com"
    mock_user.is_active = True
    mock_user.is_verified = False
    mock_db.query.return_value.filter.return_value.first.return_value = mock_user

    with caplog.at_level(logging.INFO):
        response = request_email_verification(
            EmailVerificationRequest(email="unverified@example.com"),
            db=mock_db,
        )

    assert "verification link has been dispatched" in response.message
    assert any("[EMAIL_VERIFICATION_TOKEN]" in record.message for record in caplog.records)


def test_verify_email_request_nonexistent_user_opaque(caplog):
    mock_db = MagicMock()
    mock_db.query.return_value.filter.return_value.first.return_value = None

    with caplog.at_level(logging.INFO):
        response = request_email_verification(
            EmailVerificationRequest(email="nonexistent@example.com"),
            db=mock_db,
        )

    # Identical opaque response to prevent enumeration
    assert "verification link has been dispatched" in response.message
    # Must NOT log verification token for non-existent account
    assert not any("[EMAIL_VERIFICATION_TOKEN]" in record.message for record in caplog.records)


def test_verify_email_request_already_verified_user_opaque(caplog):
    mock_db = MagicMock()
    mock_user = MagicMock()
    mock_user.id = "u-verify-req-2"
    mock_user.email = "already_verified@example.com"
    mock_user.is_active = True
    mock_user.is_verified = True
    mock_db.query.return_value.filter.return_value.first.return_value = mock_user

    with caplog.at_level(logging.INFO):
        response = request_email_verification(
            EmailVerificationRequest(email="already_verified@example.com"),
            db=mock_db,
        )

    assert "verification link has been dispatched" in response.message
    # Must NOT log verification token if user is already verified
    assert not any("[EMAIL_VERIFICATION_TOKEN]" in record.message for record in caplog.records)


# ============================================================================
# 5. Email Verification Confirm Endpoint Tests & Single-Use Blacklisting
# ============================================================================

def test_confirm_email_verification_success_and_single_use():
    mock_redis = MagicMock()
    mock_redis.get.return_value = None

    with patch.object(jwt_module, "_redis_client", mock_redis):
        token = create_email_verification_token(
            user_id="u-confirm-target",
            email="target@example.com",
        )

        mock_db = MagicMock()
        mock_user = MagicMock()
        mock_user.id = "u-confirm-target"
        mock_user.email = "target@example.com"
        mock_user.is_active = True
        mock_user.is_verified = False

        # When querying User return mock_user; for RevokedToken return None
        def mock_first():
            return None
        mock_db.query.return_value.filter.return_value.first.return_value = mock_user

        response = confirm_email_verification(
            EmailVerificationConfirmRequest(token=token),
            db=mock_db,
        )

        assert "successfully verified" in response.message
        assert mock_user.is_verified is True
        mock_db.commit.assert_called()

        # Token was blacklisted in Redis and DB
        mock_redis.setex.assert_called_once()
        args = mock_redis.setex.call_args[0]
        assert args[0].startswith("jwt_blacklist:")


def test_confirm_email_verification_rejects_revoked_token():
    mock_redis = MagicMock()
    mock_redis.get.return_value = b"revoked"

    token = create_email_verification_token(user_id="u-revoked", email="revoked@example.com")

    with patch.object(jwt_module, "_redis_client", mock_redis):
        with pytest.raises(HTTPException) as exc_info:
            confirm_email_verification(
                EmailVerificationConfirmRequest(token=token),
                db=MagicMock(),
            )
        assert exc_info.value.status_code == 400
        assert "Invalid or expired email verification token" in exc_info.value.detail


def test_confirm_email_verification_rejects_invalid_token():
    with pytest.raises(HTTPException) as exc_info:
        confirm_email_verification(
            EmailVerificationConfirmRequest(token="invalid.garbage.jwt.token"),
            db=MagicMock(),
        )
    assert exc_info.value.status_code == 400
    assert "Invalid or expired email verification token" in exc_info.value.detail


# ============================================================================
# 6. SQLite In-Memory Database End-to-End Integration Test
# ============================================================================

def test_sqlite_in_memory_db_revocation_and_user_verification():
    """
    End-to-end integration test with real SQLite database:
    - Tables created from Base.metadata
    - User created and updated
    - RevokedToken persisted and queried directly through SQLAlchemy
    """
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    TestingSession = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    db = TestingSession()

    try:
        # 1. Create unverified user in real DB
        user = User(
            id="sqlite-user-1",
            email="sqlite@example.com",
            hashed_password="dummy_hash_for_testing",
            is_active=True,
            is_verified=False,
        )
        db.add(user)
        db.commit()

        # 2. Generate verification token
        token = create_email_verification_token(user_id=user.id, email=user.email)
        payload = decode_email_verification_token(token, db=db)
        jti = payload["jti"]

        # 3. Simulate Redis outage: revoke token directly into SQLite database
        with patch.object(jwt_module, "_redis_client", None), \
             patch.object(jwt_module, "get_redis_client", return_value=None):

            # Clear in-memory revoked set to strictly test DB persistence
            jwt_module._local_revoked_jtis.clear()

            # Revoke token with DB session
            rev_res = revoke_token(token, db=db)
            assert rev_res is True

            # Verify RevokedToken exists in SQLite table
            db_revoked = db.query(RevokedToken).filter(RevokedToken.jti == jti).first()
            assert db_revoked is not None
            assert db_revoked.jti == jti
            assert db_revoked.token_type == "email_verification"

            # Clear in-memory set again
            jwt_module._local_revoked_jtis.clear()

            # Revocation check must succeed via DB fallback
            assert is_token_revoked(jti, db=db) is True

            # Confirm endpoint must reject already-revoked token
            with pytest.raises(HTTPException) as exc_info:
                confirm_email_verification(
                    EmailVerificationConfirmRequest(token=token),
                    db=db,
                )
            assert exc_info.value.status_code == 400

        # 4. Now test valid verification flow on a second token
        token2 = create_email_verification_token(user_id=user.id, email=user.email)
        mock_redis = MagicMock()
        mock_redis.get.return_value = None

        with patch.object(jwt_module, "_redis_client", mock_redis):
            confirm_resp = confirm_email_verification(
                EmailVerificationConfirmRequest(token=token2),
                db=db,
            )
            assert "successfully verified" in confirm_resp.message

            # Re-query user from SQLite and verify is_verified is True
            updated_user = db.query(User).filter(User.id == user.id).first()
            assert updated_user.is_verified is True

            # Token2 is now revoked in SQLite
            payload2 = jwt_module.jwt.decode(
                token2,
                jwt_module.SECRET_KEY,
                algorithms=[jwt_module.ALGORITHM],
                options={"verify_signature": False, "verify_aud": False},
            )
            db_revoked2 = db.query(RevokedToken).filter(RevokedToken.jti == payload2["jti"]).first()
            assert db_revoked2 is not None

    finally:
        db.close()
