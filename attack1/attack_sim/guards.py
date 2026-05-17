from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlparse


class TargetNotAllowed(ValueError):
    pass


def _is_allowed_lab_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return addr.is_loopback or addr.is_private


def ensure_loopback_host(host: str) -> None:
    """Raise if host does not resolve exclusively to loopback/private lab addresses."""
    host = host.strip()
    if host in {"localhost"}:
        return

    if _is_allowed_lab_ip(host):
        return

    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror as exc:
        raise TargetNotAllowed(f"Cannot resolve host: {host}") from exc

    resolved = {info[4][0] for info in infos}
    if not resolved:
        raise TargetNotAllowed(f"Host resolves to no addresses: {host}")

    disallowed = [ip for ip in resolved if not _is_allowed_lab_ip(ip)]
    if disallowed:
        raise TargetNotAllowed(
            "Target host must stay inside the lab network "
            f"(loopback or RFC1918/private addresses only). Got: {host} -> {sorted(resolved)}"
        )


def ensure_loopback_url(url: str) -> urlparse:
    parsed = urlparse(url)
    if parsed.scheme not in {"http"}:
        raise TargetNotAllowed("Only 'http://' URLs are allowed for this local simulator")
    if not parsed.hostname:
        raise TargetNotAllowed("URL must include hostname")
    ensure_loopback_host(parsed.hostname)
    return parsed
