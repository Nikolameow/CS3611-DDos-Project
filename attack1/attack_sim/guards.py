from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlparse


class TargetNotAllowed(ValueError):
    pass


def _is_loopback_ip(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_loopback
    except ValueError:
        return False


def ensure_loopback_host(host: str) -> None:
    """Raise if host does not resolve exclusively to loopback addresses."""
    host = host.strip()
    if host in {"localhost"}:
        return

    if _is_loopback_ip(host):
        return

    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror as exc:
        raise TargetNotAllowed(f"Cannot resolve host: {host}") from exc

    resolved = {info[4][0] for info in infos}
    if not resolved:
        raise TargetNotAllowed(f"Host resolves to no addresses: {host}")

    non_loopback = [ip for ip in resolved if not _is_loopback_ip(ip)]
    if non_loopback:
        raise TargetNotAllowed(
            f"Target host must be loopback only (localhost/127.0.0.1/::1). Got: {host} -> {sorted(resolved)}"
        )


def ensure_loopback_url(url: str) -> urlparse:
    parsed = urlparse(url)
    if parsed.scheme not in {"http"}:
        raise TargetNotAllowed("Only 'http://' URLs are allowed for this local simulator")
    if not parsed.hostname:
        raise TargetNotAllowed("URL must include hostname")
    ensure_loopback_host(parsed.hostname)
    return parsed
