import json
from unittest.mock import MagicMock, patch

from fastapi import HTTPException
import pytest

from services import malware_scanner as scanner
from services import manual_file_scan_service as files


@pytest.mark.parametrize("response", [b"stream: ERROR\0", b"", b"stream: OK", b"stream: NOT OK\0"])
@pytest.mark.parametrize("fail_closed", [True, False])
def test_clamd_invalid_responses_never_report_clean(tmp_path, response, fail_closed):
    sample = tmp_path / "safe.txt"
    sample.write_bytes(b"harmless")
    connection = MagicMock()
    connection.recv.side_effect = [response, b""]
    context = MagicMock()
    context.__enter__.return_value = connection
    with patch.object(scanner.socket, "create_connection", return_value=context), \
            patch.object(scanner.subprocess, "run", side_effect=FileNotFoundError), \
            patch.object(scanner.settings, "CLAMAV_FAIL_CLOSED", fail_closed):
        clean, details = scanner.scan_file_clamav(str(sample))
    assert not clean
    assert details.startswith("CRITICAL:")


class Cache:
    def __init__(self):
        self.values = {}

    def get(self, key):
        return self.values.get(key)

    def setex(self, key, _ttl, value):
        self.values[key] = value


def test_same_content_with_new_extension_is_analyzed_again(tmp_path):
    cache = Cache()
    with patch.object(files, "_REDIS", cache), patch.object(files, "_SHARED_DIR", str(tmp_path)), \
            patch.object(scanner, "scan_file_clamav", return_value=(True, "Clean (clamd)")) as av:
        safe = files.run_manual_file_scan("audit.txt", b"harmless fixture")
        executable = files.run_manual_file_scan("audit.exe", b"harmless fixture")
        renamed = files.run_manual_file_scan("renamed.exe", b"harmless fixture")
    assert safe["risk_score"] == 0
    assert executable["risk_score"] == 60
    assert not executable["cached"]
    assert renamed["cached"] and renamed["risk_score"] == 60
    assert renamed["filename"] == "renamed.exe"
    assert av.call_count == 2


def test_legacy_hash_only_cache_cannot_supply_new_verdict(tmp_path):
    content = b"harmless fixture"
    cache = Cache()
    cache.values[f"filescan:hash:{files._sha256_file(content)}"] = json.dumps({"risk_score": 0, "severity": "Safe"})
    with patch.object(files, "_REDIS", cache), patch.object(files, "_SHARED_DIR", str(tmp_path)), \
            patch.object(scanner, "scan_file_clamav", return_value=(True, "Clean (clamd)")):
        result = files.run_manual_file_scan("audit.exe", content)
    assert not result["cached"] and result["risk_score"] == 60


@pytest.mark.parametrize("outcome", [(False, "CRITICAL: Anti-malware scanner unavailable"), RuntimeError("scanner failed")])
def test_scanner_failure_returns_unavailable_without_caching(tmp_path, outcome):
    cache = Cache()
    mock = {"side_effect": outcome} if isinstance(outcome, Exception) else {"return_value": outcome}
    with patch.object(files, "_REDIS", cache), patch.object(files, "_SHARED_DIR", str(tmp_path)), \
            patch.object(scanner, "scan_file_clamav", **mock):
        with pytest.raises(HTTPException) as exc:
            files.run_manual_file_scan("audit.txt", b"harmless fixture")
    assert exc.value.status_code == 503
    assert not cache.values
