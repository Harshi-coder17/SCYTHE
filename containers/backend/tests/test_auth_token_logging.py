import logging
from unittest.mock import MagicMock, patch

from auth import routes
from schemas.auth import PasswordResetRequest


def test_production_never_logs_verification_token(monkeypatch, caplog):
    monkeypatch.setattr(routes.settings, "ENVIRONMENT", "production")
    monkeypatch.setattr(routes.settings, "SMTP_HOST", "")
    secret = "verification-token-fixture-secret"

    with caplog.at_level(logging.INFO):
        routes._dispatch_verification_token("user@example.test", secret)

    assert secret not in caplog.text
    assert "token was not logged" in caplog.text


def test_production_never_logs_password_reset_token(monkeypatch, caplog):
    monkeypatch.setattr(routes.settings, "ENVIRONMENT", "production")
    monkeypatch.setattr(routes.settings, "SMTP_HOST", "")
    secret = "password-reset-fixture-secret"
    db = MagicMock()
    user = MagicMock(id="user-id", email="user@example.test", is_active=True)
    db.query.return_value.filter.return_value.first.return_value = user

    with patch("auth.routes.create_password_reset_token", return_value=secret), caplog.at_level(logging.INFO):
        routes.request_password_reset(PasswordResetRequest(email="user@example.test"), db=db)

    # The endpoint follows the same production branch; this assertion locks
    # down that the token itself is never part of its fallback log message.
    assert secret not in caplog.text
    assert "token was not logged" in caplog.text
