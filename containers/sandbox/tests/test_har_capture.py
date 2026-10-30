import json
import os
import sys
from types import SimpleNamespace

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))
from har_capture import HarRecorder, redacted_url


def test_har_omits_sensitive_data_and_bounds_requests(tmp_path):
    recorder = HarRecorder(limit=1)
    request = SimpleNamespace(method="GET", url="https://user:secret@example.com/login?token=secret#password")
    recorder.request(request)
    recorder.response(SimpleNamespace(request=request, status=302), {
        "set-cookie": "session=secret", "authorization": "Bearer secret",
        "content-type": "text/html; charset=UTF-8", "location": "https://other.example/?secret=abc",
    })
    recorder.request(SimpleNamespace(method="POST", url="https://extra.example/"))
    path = str(tmp_path / "network.har")
    recorder.write(path)
    text = open(path).read()
    assert "secret" not in text and "password" not in text and "session" not in text
    document = json.loads(text)["log"]
    assert document["version"] == "1.2"
    assert document["_truncated"] and document["_totalRequests"] == 2
    assert len(document["entries"]) == 1
    entry = document["entries"][0]
    assert entry["request"]["url"] == "https://example.com/login"
    assert entry["response"]["status"] == 302
    assert entry["response"]["redirectURL"] == "https://other.example/"
    assert entry["response"]["content"] == {"size": -1, "mimeType": "text/html"}
    assert entry["time"] >= 0


def test_har_invalid_authority_and_ipv6_are_safe():
    assert redacted_url("https://example.com:bad/") == ""
    assert redacted_url("https://[2606:4700::1111]:443/a?q=private") == "https://[2606:4700::1111]:443/a"
