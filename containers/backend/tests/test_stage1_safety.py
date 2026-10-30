import json
from unittest.mock import MagicMock, patch

import pytest

from services.url_policy import FetchTarget, UnsafeURL, hostname_matches
from services.capture import fetch_url_html as capture_url
from services import manual_file_scan_service as file_service


def test_hostname_matching_requires_label_boundary():
    assert hostname_matches("www.google.com", "google.com")
    assert not hostname_matches("notgoogle.com", "google.com")
    assert not hostname_matches("evil.example", "google.com")


def test_capture_rejects_private_destination():
    with pytest.raises(UnsafeURL):
        capture_url("http://127.0.0.1:8000/internal")


def test_capture_validates_redirect_destination():
    connection = MagicMock()
    connection.getresponse.return_value.status = 302
    connection.getresponse.return_value.getheader.return_value = "http://127.0.0.1/private"
    target = FetchTarget("https", "example.com", 443, ("93.184.216.34",))
    with patch("services.capture.resolve_fetch_target", side_effect=[target, UnsafeURL("private")]), \
         patch("services.capture._connection_for", return_value=connection):
        with pytest.raises(UnsafeURL):
            capture_url("https://example.com")
    connection.close.assert_called_once()


def test_metadata_filename_cannot_replace_payload(tmp_path):
    file_service._SHARED_DIR = str(tmp_path)
    observed = {}

    def fake_av(path):
        observed["payload"] = open(path, "rb").read()
        return True, "clean"

    with patch.object(file_service, "_REDIS") as redis_client, \
         patch("services.malware_scanner.scan_file_clamav", side_effect=fake_av):
        redis_client.get.return_value = None
        result = file_service.run_manual_file_scan("metadata.json", b"uploaded bytes")

    assert observed["payload"] == b"uploaded bytes"
    assert result["filename"] == "metadata.json"


def test_file_cache_does_not_return_previous_identity(tmp_path):
    file_service._SHARED_DIR = str(tmp_path)
    cached = {"scan_id": "other-user", "file_id": "other-file", "filename": "private.txt", "risk_score": 4, "severity": "Safe"}
    db = MagicMock()
    user = MagicMock(id="new-user")
    with patch.object(file_service, "_REDIS") as redis_client:
        redis_client.get.return_value = json.dumps(cached)
        result = file_service.run_manual_file_scan("new-name.txt", b"same bytes", user=user, db=db)

    assert result["filename"] == "new-name.txt"
    assert result["file_id"] != "other-file"
    assert result["scan_id"] != "other-user"
    db.add.assert_called_once()
