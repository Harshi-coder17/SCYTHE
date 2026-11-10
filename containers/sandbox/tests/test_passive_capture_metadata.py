import hashlib
from pathlib import Path
import sys
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))
from passive_capture import capture_metadata  # noqa: E402


def test_exact_browser_redirects_and_artifact_checksums_are_recorded():
    first = SimpleNamespace(url="https://example.com/", redirected_from=None)
    last = SimpleNamespace(url="https://example.net/login", redirected_from=first)
    response = SimpleNamespace(request=last, url=last.url, status=200)
    metadata = capture_metadata(first.url, "https://example.net/after-script", response,
                                "id", "start", "shot", "end", b"png", b"html")
    assert metadata["http_redirect_chain"] == [first.url, last.url]
    assert metadata["final_url"] == "https://example.net/after-script"
    assert metadata["navigation_response_url"] == last.url
    assert metadata["final_document_status"] is None
    assert metadata["final_document_status_scope"] == "unavailable"
    assert metadata["screenshot_sha256"] == hashlib.sha256(b"png").hexdigest()
    assert metadata["html_sha256"] == hashlib.sha256(b"html").hexdigest()
    assert "client-side" in metadata["redirect_history_scope"]


def test_final_document_status_is_not_inferred_from_original_goto():
    request = SimpleNamespace(url="https://example.com/", redirected_from=None)
    original = SimpleNamespace(request=request, url=request.url, status=200)
    final = SimpleNamespace(url="https://example.net/error", status=404)
    metadata = capture_metadata(request.url, final.url, original, "id", "a", "b", "c", b"png", b"html", final)
    assert metadata["navigation_status"] == 200
    assert metadata["final_document_status"] == 404
    assert metadata["final_document_response_url"] == final.url


def test_redirect_cycles_are_bounded():
    request = SimpleNamespace(url="https://example.com/")
    request.redirected_from = request
    response = SimpleNamespace(request=request, url=request.url, status=200)
    with pytest.raises(ValueError, match="limit"):
        capture_metadata(request.url, request.url, response, "id", "a", "b", "c", b"png", b"html")
