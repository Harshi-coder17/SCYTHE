"""
Tests for JWT Token Revocation (Security Finding #6) and jti uniqueness.
"""

import pytest
from unittest.mock import MagicMock, patch
from datetime import timedelta
from jwt.exceptions import PyJWTError as JWTError

from auth.jwt import (
    create_access_token,
    decode_access_token,
    revoke_token,
    create_password_reset_token,
    decode_password_reset_token,
)
import auth.jwt as jwt_module


def test_access_token_has_unique_jti():
    mock_redis = MagicMock()
    mock_redis.get.return_value = None
    with patch.object(jwt_module, "_redis_client", mock_redis):
        token1 = create_access_token({"sub": "user_1"})
        token2 = create_access_token({"sub": "user_1"})
        
        payload1 = decode_access_token(token1)
        payload2 = decode_access_token(token2)
        
        assert "jti" in payload1
        assert "jti" in payload2
        assert payload1["jti"] != payload2["jti"]


def test_decode_revoked_token_raises_jwt_error():
    mock_redis = MagicMock()
    mock_redis.get.return_value = b"revoked"
    
    token = create_access_token({"sub": "user_2"})
    
    with patch.object(jwt_module, "_redis_client", mock_redis):
        with pytest.raises(JWTError, match="Token has been revoked"):
            decode_access_token(token)
            
        mock_redis.get.assert_called_once()


def test_revoke_token_sets_redis_blacklist():
    mock_redis = MagicMock()
    
    token = create_access_token({"sub": "user_3"}, expires_delta=timedelta(minutes=30))
    
    with patch.object(jwt_module, "_redis_client", mock_redis):
        success = revoke_token(token)
        assert success is True
        mock_redis.setex.assert_called_once()
        args = mock_redis.setex.call_args[0]
        assert args[0].startswith("jwt_blacklist:")
        assert args[2] == "revoked"


def test_decode_token_fails_closed_when_redis_unavailable():
    token = create_access_token({"sub": "user_4"})

    with patch.object(jwt_module, "_redis_client", None):
        with pytest.raises(JWTError, match="Authentication store unavailable"):
            decode_access_token(token)


def test_password_reset_token_scope_and_audience_isolation():
    mock_redis = MagicMock()
    mock_redis.get.return_value = None
    with patch.object(jwt_module, "_redis_client", mock_redis):
        reset_token = create_password_reset_token(user_id="user_reset_1", email="analyst@example.com")
        payload = decode_password_reset_token(reset_token)

        assert payload["sub"] == "user_reset_1"
        assert payload["email"] == "analyst@example.com"
        assert payload["scope"] == "password_reset"
        assert payload["aud"] == "scythe-password-reset"

        # Password reset token must NEVER be accepted as an access token
        with pytest.raises(JWTError):
            decode_access_token(reset_token)

        # Access token must NEVER be accepted as a password reset token
        access_token = create_access_token({"sub": "user_reset_1"})
        with pytest.raises(JWTError):
            decode_password_reset_token(access_token)


def test_password_reset_token_single_use_revocation():
    mock_redis = MagicMock()
    mock_redis.get.return_value = None

    with patch.object(jwt_module, "_redis_client", mock_redis):
        token = create_password_reset_token(user_id="user_reset_2", email="user2@example.com")
        assert decode_password_reset_token(token)["sub"] == "user_reset_2"

        # Revoke the token
        revoked = revoke_token(token)
        assert revoked is True
        mock_redis.setex.assert_called_once()

        # Simulate redis returning revoked
        mock_redis.get.return_value = b"revoked"
        with pytest.raises(JWTError, match="Token has been revoked"):
            decode_password_reset_token(token)


def test_password_reset_request_endpoint_existing_user(caplog):
    import logging
    from auth.routes import request_password_reset
    from schemas.auth import PasswordResetRequest

    mock_db = MagicMock()
    mock_user = MagicMock()
    mock_user.id = "u-1234"
    mock_user.email = "existing@example.com"
    mock_user.is_active = True
    mock_db.query.return_value.filter.return_value.first.return_value = mock_user

    with caplog.at_level(logging.INFO):
        response = request_password_reset(
            PasswordResetRequest(email="existing@example.com"),
            db=mock_db,
        )

    assert "password reset link has been dispatched" in response.message
    assert any("[PASSWORD_RESET_TOKEN]" in record.message for record in caplog.records)


def test_password_reset_request_endpoint_nonexistent_user_opaque(caplog):
    import logging
    from auth.routes import request_password_reset
    from schemas.auth import PasswordResetRequest

    mock_db = MagicMock()
    mock_db.query.return_value.filter.return_value.first.return_value = None

    with caplog.at_level(logging.INFO):
        response = request_password_reset(
            PasswordResetRequest(email="nonexistent@example.com"),
            db=mock_db,
        )

    # Must return identical opaque message (enumeration oracle prevention)
    assert "password reset link has been dispatched" in response.message
    # Must NOT log any generated reset token for non-existent account
    assert not any("[PASSWORD_RESET_TOKEN]" in record.message for record in caplog.records)


def test_password_reset_confirm_endpoint_success():
    from auth.routes import confirm_password_reset
    from schemas.auth import PasswordResetConfirmRequest
    from auth.security import hash_password, verify_password

    mock_redis = MagicMock()
    mock_redis.get.return_value = None

    with patch.object(jwt_module, "_redis_client", mock_redis), \
         patch("auth.routes.check_pwned_password", return_value=False):
        token = create_password_reset_token(user_id="u-confirm-1", email="confirm@example.com")

        mock_db = MagicMock()
        mock_user = MagicMock()
        mock_user.id = "u-confirm-1"
        mock_user.email = "confirm@example.com"
        mock_user.is_active = True
        mock_user.hashed_password = hash_password("Existing!Password2026")
        mock_db.query.return_value.filter.return_value.first.return_value = mock_user
        mock_db.query.return_value.filter.return_value.with_for_update.return_value.first.return_value = mock_user

        mock_request = MagicMock()
        mock_request.client.host = "127.0.0.1"

        new_pw = "N3w!Str0ng#P@ssword2026"
        response = confirm_password_reset(
            request=mock_request,
            payload=PasswordResetConfirmRequest(token=token, new_password=new_pw),
            db=mock_db,
        )

        assert "Password has been reset successfully" in response.message
        assert mock_user.hashed_password != ""
        assert verify_password(new_pw, mock_user.hashed_password)
        mock_db.commit.assert_called_once()


def test_password_reset_confirm_rejects_breached_password():
    from auth.routes import confirm_password_reset
    from schemas.auth import PasswordResetConfirmRequest
    from fastapi import HTTPException

    mock_redis = MagicMock()
    mock_redis.get.return_value = None

    with patch.object(jwt_module, "_redis_client", mock_redis), \
         patch("auth.routes.check_pwned_password", return_value=True):
        token = create_password_reset_token(user_id="u-pwned", email="pwned@example.com")
        mock_request = MagicMock()

        with pytest.raises(HTTPException) as exc_info:
            confirm_password_reset(
                request=mock_request,
                payload=PasswordResetConfirmRequest(token=token, new_password="P@ssword12345!Secure"),
                db=MagicMock(),
            )

        assert exc_info.value.status_code == 400
        assert "data breaches" in exc_info.value.detail


def test_password_reset_confirm_rejects_invalid_or_revoked_token():
    from auth.routes import confirm_password_reset
    from schemas.auth import PasswordResetConfirmRequest
    from fastapi import HTTPException

    mock_request = MagicMock()

    # Invalid token
    with pytest.raises(HTTPException) as exc_info:
        confirm_password_reset(
            request=mock_request,
            payload=PasswordResetConfirmRequest(token="invalid.garbage.jwt.token", new_password="Valid!NewPassword2026"),
            db=MagicMock(),
        )
    assert exc_info.value.status_code == 400
    assert "Invalid or expired password reset token" in exc_info.value.detail
