"""URL policy shared by server-side capture and analysis entry points."""

import ipaddress
import socket
from dataclasses import dataclass
from urllib.parse import urlparse


_IPV6_TRANSLATION_NETWORKS = (
    ipaddress.ip_network("64:ff9b::/96"),
    ipaddress.ip_network("64:ff9b:1::/48"),
    ipaddress.ip_network("2002::/16"),
)


class UnsafeURL(ValueError):
    """Raised when a URL is not safe to fetch from the application network."""


@dataclass(frozen=True)
class FetchTarget:
    scheme: str
    hostname: str
    port: int
    addresses: tuple[str, ...]


def _resolved_addresses(hostname: str) -> set[ipaddress._BaseAddress]:
    try:
        infos = socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise UnsafeURL("URL host could not be resolved") from exc
    addresses = {ipaddress.ip_address(info[4][0]) for info in infos}
    if not addresses:
        raise UnsafeURL("URL host has no addresses")
    return addresses


def resolve_fetch_target(url: str) -> FetchTarget:
    """Resolve once and return only public addresses for the actual connection."""
    try:
        parsed = urlparse(url)
        port = parsed.port
    except ValueError as exc:
        raise UnsafeURL("URL contains an invalid authority or port") from exc
    if parsed.scheme.lower() not in {"http", "https"}:
        raise UnsafeURL("only HTTP and HTTPS URLs are allowed")
    if parsed.username or parsed.password:
        raise UnsafeURL("URLs with embedded credentials are not allowed")
    hostname = (parsed.hostname or "").rstrip(".").lower()
    if not hostname:
        raise UnsafeURL("URL must include a hostname")
    if port == 0 or any(c.isspace() or ord(c) < 32 for c in hostname):
        raise UnsafeURL("URL contains an invalid hostname or port")
    try:
        hostname = hostname.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise UnsafeURL("URL contains an invalid hostname") from exc
    addresses = _resolved_addresses(hostname)
    if any(not address.is_global or address.is_multicast
           or (address.version == 6 and any(address in network for network in _IPV6_TRANSLATION_NETWORKS))
           for address in addresses):
        raise UnsafeURL("URL resolves to a non-public address")
    return FetchTarget(
        scheme=parsed.scheme.lower(), hostname=hostname,
        port=port or (443 if parsed.scheme.lower() == "https" else 80),
        addresses=tuple(sorted(str(address) for address in addresses)),
    )


def validate_fetch_url(url: str) -> str:
    """Validate without fetching. Fetchers must connect to resolve_fetch_target's IP."""
    resolve_fetch_target(url)
    return url


def hostname_matches(hostname: str, domain: str) -> bool:
    """Match an exact domain or its subdomains, never a string suffix."""
    host = (hostname or "").rstrip(".").lower()
    trusted = domain.strip().rstrip(".").lower()
    return bool(host and trusted and (host == trusted or host.endswith("." + trusted)))
