from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

import auth.jwt as jwt_module
from auth.jwt import create_password_reset_token
from auth.routes import confirm_password_reset
from database.database import Base
from database.models import RevokedToken, User
from schemas.auth import PasswordResetConfirmRequest


def test_password_reset_commits_password_and_durable_revocation_together():
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine)
    db = session_factory()
    user = User(
        id="reset-atomic-user",
        email="reset-atomic@example.test",
        hashed_password="old-hash",
        is_active=True,
        is_superuser=False,
        is_verified=True,
        created_at=datetime.now(timezone.utc),
    )
    db.add(user)
    db.commit()

    redis_client = MagicMock()
    redis_client.get.return_value = None
    token = create_password_reset_token(user.id, user.email)
    request = SimpleNamespace(client=SimpleNamespace(host="127.0.0.1"))
    payload = PasswordResetConfirmRequest(
        token=token,
        new_password="N3w!Str0ng#P@ssword2026",
    )

    try:
        with patch.object(jwt_module, "_redis_client", redis_client), \
             patch("auth.routes.check_pwned_password", return_value=False), \
             patch("auth.routes.reset_failed_login"):
            result = confirm_password_reset(request=request, payload=payload, db=db)
            assert "successfully" in result.message
            db.refresh(user)
            revoked = db.query(RevokedToken).one()
            assert user.hashed_password != "old-hash"
            assert revoked.token_type == "password_reset"

            # The same token is rejected from the database record even after
            # Redis cache state is cleared, proving durable single-use behavior.
            redis_client.get.return_value = None
            token_jti = jwt_module.jwt.decode(
                token,
                jwt_module.SECRET_KEY,
                algorithms=[jwt_module.ALGORITHM],
                options={"verify_signature": False, "verify_aud": False},
            )["jti"]
            jwt_module._local_revoked_jtis.discard(token_jti)
            with pytest.raises(HTTPException) as exc_info:
                confirm_password_reset(request=request, payload=payload, db=db)
            assert exc_info.value.status_code == 400
            assert db.query(RevokedToken).count() == 1
    finally:
        db.close()
        Base.metadata.drop_all(engine)
        engine.dispose()
