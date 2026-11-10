import json
from unittest.mock import MagicMock, patch

import pytest
from fastapi import HTTPException

from api.email_routes import _authorize_email_artifact, _validate_email_id
from services.email.detectors.authentication_detector import AuthenticationDetector


def test_missing_authentication_results_are_safe_defaults():
    result = AuthenticationDetector().detect({"authentication": {"spf_result": None, "dkim_result": None, "dmarc_result": None}})
    assert result["score"] >= 0
    assert any("SPF: none" in reason for reason in result["reasons"])


def test_dot_email_ids_are_rejected():
    for value in (".", "..", "../other"):
        with pytest.raises(HTTPException):
            _validate_email_id(value)


def test_email_artifact_requires_owner_manifest(tmp_path):
    user = MagicMock(is_superuser=False, email="alice@example.test")
    with patch("api.email_routes.SHARED_DIR", str(tmp_path)):
        with pytest.raises(HTTPException) as exc:
            _authorize_email_artifact("email-1", user)
        assert exc.value.status_code == 403


def test_email_artifact_owner_must_match(tmp_path):
    owner_dir = tmp_path / "emails" / "email-1"
    owner_dir.mkdir(parents=True)
    (owner_dir / "owner.json").write_text(json.dumps({"owner_email": "alice@example.test", "owner_user_id": "alice-id"}))
    alice = MagicMock(id="alice-id", is_superuser=False, email="alice@example.test")
    bob = MagicMock(id="bob-id", is_superuser=False, email="bob@example.test")
    with patch("api.email_routes.SHARED_DIR", str(tmp_path)):
        _authorize_email_artifact("email-1", alice)
        with pytest.raises(HTTPException) as exc:
            _authorize_email_artifact("email-1", bob)
        assert exc.value.status_code == 403
