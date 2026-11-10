import ipaddress
import ssl
from unittest.mock import MagicMock, patch

import pytest

from services import capture
from services.url_policy import FetchTarget, UnsafeURL, resolve_fetch_target


def test_http_connection_uses_validated_ip_after_dns_changes():
    public = {ipaddress.ip_address("93.184.216.34")}
    private = {ipaddress.ip_address("127.0.0.1")}
    with patch("services.url_policy._resolved_addresses", side_effect=[public, private]) as dns, \
            patch("services.capture.socket.create_connection") as connect:
        target = resolve_fetch_target("http://rebind.example:8080/")
        connection = capture._PinnedHTTPConnection(target)
        connection.connect()
    dns.assert_called_once_with("rebind.example")
    connect.assert_called_once_with(("93.184.216.34", 8080), 10)


def test_https_keeps_hostname_verification_and_sni_with_pinned_ip():
    target = FetchTarget("https", "bank.example", 443, ("93.184.216.34",))
    connection = capture._PinnedHTTPSConnection(target)
    assert connection._context.check_hostname
    assert connection._context.verify_mode == ssl.CERT_REQUIRED
    context = MagicMock()
    connection._context = context
    with patch("services.capture.socket.create_connection") as connect:
        connection.connect()
    connect.assert_called_once_with(("93.184.216.34", 443), 10)
    context.wrap_socket.assert_called_once_with(connect.return_value, server_hostname="bank.example")


@pytest.mark.parametrize("addresses", [
    {"100.64.0.1"}, {"127.0.0.1"}, {"::1"}, {"169.254.169.254"},
    {"64:ff9b::7f00:1"}, {"64:ff9b:1::7f00:1"}, {"2002:7f00:1::"},
    {"93.184.216.34", "192.168.1.1"},
])
def test_nonpublic_and_mixed_dns_answers_fail_closed(addresses):
    values = {ipaddress.ip_address(value) for value in addresses}
    with patch("services.url_policy._resolved_addresses", return_value=values):
        with pytest.raises(UnsafeURL):
            resolve_fetch_target("https://example.com/")


def test_validated_address_fallback_never_re_resolves_hostname():
    target = FetchTarget("http", "example.com", 80, ("2606:4700::1111", "1.1.1.1"))
    connection = capture._PinnedHTTPConnection(target)
    with patch("services.capture.socket.create_connection", side_effect=[OSError("no IPv6"), MagicMock()]) as connect:
        connection.connect()
    assert [call.args[0] for call in connect.call_args_list] == [("2606:4700::1111", 80), ("1.1.1.1", 80)]


def test_capture_closes_connection_and_rejects_oversized_body():
    target = FetchTarget("https", "example.com", 443, ("93.184.216.34",))
    connection = MagicMock()
    connection.getresponse.return_value.status = 200
    connection.getresponse.return_value.read.return_value = b"x" * 33
    with patch.object(capture, "_MAX_HTML_BYTES", 32), \
            patch.object(capture, "resolve_fetch_target", return_value=target), \
            patch.object(capture, "_connection_for", return_value=connection):
        with pytest.raises(UnsafeURL, match="size limit"):
            capture.fetch_url_html("https://example.com/")
    connection.close.assert_called_once()


def test_full_scan_returns_client_error_for_blocked_capture():
    from fastapi import HTTPException
    from api.routes import full_scan
    from schemas.full_scan import FullScanRequest

    with patch("api.routes.run_quickscan", return_value={}), \
            patch("api.routes.run_stage2_analysis") as stage2:
        with pytest.raises(HTTPException) as exc:
            full_scan(FullScanRequest(url="http://127.0.0.1/private"), db=MagicMock(), current_user=MagicMock())
    assert exc.value.status_code == 400
    stage2.assert_not_called()
