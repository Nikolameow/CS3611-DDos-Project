from __future__ import annotations

import os
import random
import socket
import struct
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


PCAP_GLOBAL_HEADER = struct.pack(
    "<IHHIIII",
    0xa1b2c3d4,
    2,
    4,
    0,
    0,
    65535,
    101,
)


def _checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) + data[i + 1]
    total = (total >> 16) + (total & 0xFFFF)
    total += total >> 16
    return (~total) & 0xFFFF


def _ip_header(src: str, dst: str, payload: bytes, proto: int, identification: int) -> bytes:
    version_ihl = (4 << 4) | 5
    tos = 0
    total_length = 20 + len(payload)
    flags_frag = 0
    ttl = 64
    header = struct.pack(
        "!BBHHHBBHII",
        version_ihl,
        tos,
        total_length,
        identification,
        flags_frag,
        ttl,
        proto,
        0,
        struct.unpack("!I", socket.inet_aton(src))[0],
        struct.unpack("!I", socket.inet_aton(dst))[0],
    )
    chksum = _checksum(header)
    return struct.pack("!BBHHHBBHII", version_ihl, tos, total_length, identification, flags_frag, ttl, proto, chksum, struct.unpack("!I", socket.inet_aton(src))[0], struct.unpack("!I", socket.inet_aton(dst))[0])


def _tcp_header(src_ip: str, dst_ip: str, src_port: int, dst_port: int, seq: int, flags: int, payload: bytes) -> bytes:
    offset_reserved_flags = (5 << 12) | flags
    window = 65535
    urg_ptr = 0
    tcp_header = struct.pack(
        "!HHIIHHHH",
        src_port,
        dst_port,
        seq,
        0,
        offset_reserved_flags,
        window,
        0,
        urg_ptr,
    )
    pseudo_header = struct.pack(
        "!IIBBH",
        struct.unpack("!I", socket.inet_aton(src_ip))[0],
        struct.unpack("!I", socket.inet_aton(dst_ip))[0],
        0,
        socket.IPPROTO_TCP,
        len(tcp_header) + len(payload),
    )
    checksum_value = _checksum(pseudo_header + tcp_header + payload)
    return struct.pack(
        "!HHIIHHHH",
        src_port,
        dst_port,
        seq,
        0,
        offset_reserved_flags,
        window,
        checksum_value,
        urg_ptr,
    )


def _udp_header(src_ip: str, dst_ip: str, src_port: int, dst_port: int, payload: bytes) -> bytes:
    length = 8 + len(payload)
    udp_header = struct.pack("!HHHH", src_port, dst_port, length, 0)
    pseudo_header = struct.pack(
        "!IIBBH",
        struct.unpack("!I", socket.inet_aton(src_ip))[0],
        struct.unpack("!I", socket.inet_aton(dst_ip))[0],
        0,
        socket.IPPROTO_UDP,
        length,
    )
    checksum_value = _checksum(pseudo_header + udp_header + payload)
    return struct.pack("!HHHH", src_port, dst_port, length, checksum_value)


def _write_pcap_packet(fh, packet: bytes, ts: float) -> None:
    ts_sec = int(ts)
    ts_usec = int((ts - ts_sec) * 1_000_000)
    packet_header = struct.pack("<IIII", ts_sec, ts_usec, len(packet), len(packet))
    fh.write(packet_header)
    fh.write(packet)


def _random_private_ip() -> str:
    block = random.choice([10, 172, 192])
    if block == 10:
        return f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
    if block == 172:
        return f"172.{random.randint(16,31)}.{random.randint(0,255)}.{random.randint(1,254)}"
    return f"192.168.{random.randint(0,255)}.{random.randint(1,254)}"


def _private_ip_pool(size: int) -> list[str]:
    return [_random_private_ip() for _ in range(max(1, size))]


class _TrafficClock:
    """Generate non-uniform timestamps so synthetic PCAP windows are less idealized."""

    def __init__(
        self,
        *,
        base_interval_s: float,
        jitter_ratio: float,
        burst_probability: float,
        burst_multiplier: float,
        lull_probability: float,
        lull_multiplier: float,
    ):
        self._base_interval_s = max(base_interval_s, 1e-7)
        self._jitter_ratio = max(jitter_ratio, 0.0)
        self._burst_probability = max(min(burst_probability, 1.0), 0.0)
        self._burst_multiplier = max(burst_multiplier, 1.0)
        self._lull_probability = max(min(lull_probability, 1.0), 0.0)
        self._lull_multiplier = max(lull_multiplier, 1.0)
        self._mode_events_remaining = 0
        self._mode_multiplier = 1.0

    def advance(self, current_ts: float) -> float:
        if self._mode_events_remaining <= 0:
            roll = random.random()
            if roll < self._burst_probability:
                self._mode_multiplier = random.uniform(1.5, self._burst_multiplier)
                self._mode_events_remaining = random.randint(12, 80)
            elif roll < self._burst_probability + self._lull_probability:
                self._mode_multiplier = 1.0 / random.uniform(1.5, self._lull_multiplier)
                self._mode_events_remaining = random.randint(8, 50)
            else:
                self._mode_multiplier = 1.0
                self._mode_events_remaining = random.randint(4, 25)

        jitter = random.uniform(1.0 - self._jitter_ratio, 1.0 + self._jitter_ratio)
        gap = self._base_interval_s * max(jitter, 0.05) / self._mode_multiplier
        self._mode_events_remaining -= 1
        return current_ts + max(gap, 1e-7)


@dataclass(frozen=True)
class SynPcapConfig:
    target_ip: str = "127.0.0.1"
    target_port: int = 8080
    packet_count: int = 1000
    pcap_path: str = "/tmp/syn_spoof.pcap"
    min_src_port: int = 1024
    max_src_port: int = 65535
    base_rate_pps: float = 10000.0
    jitter_ratio: float = 0.75
    burst_probability: float = 0.18
    burst_multiplier: float = 5.0
    lull_probability: float = 0.10
    lull_multiplier: float = 3.0
    src_ip_pool_size: int = 1200


@dataclass(frozen=True)
class ReflectPcapConfig:
    target_ip: str = "127.0.0.1"
    target_port: int = 53
    packet_count: int = 500
    request_size: int = 32
    response_size: int = 256
    pcap_path: str = "/tmp/udp_reflect_spoof.pcap"
    min_src_port: int = 1024
    max_src_port: int = 65535
    base_request_rate: float = 8000.0
    jitter_ratio: float = 0.70
    burst_probability: float = 0.16
    burst_multiplier: float = 4.0
    lull_probability: float = 0.12
    lull_multiplier: float = 3.0
    reflector_pool_size: int = 96
    victim_pool_size: int = 800


@dataclass(frozen=True)
class NormalPcapConfig:
    server_ip: str = "127.0.0.1"
    server_port: int = 8080
    session_count: int = 700
    pcap_path: str = "/tmp/generated_normal_http.pcap"
    min_src_port: int = 1024
    max_src_port: int = 65535
    base_session_rate: float = 32.0
    jitter_ratio: float = 0.55
    burst_probability: float = 0.04
    burst_multiplier: float = 2.0
    lull_probability: float = 0.16
    lull_multiplier: float = 4.0
    client_pool_size: int = 120


def generate_syn_spoof_pcap(cfg: SynPcapConfig) -> Path:
    pcap = Path(cfg.pcap_path)
    if pcap.exists():
        pcap.unlink()
    pcap.parent.mkdir(parents=True, exist_ok=True)
    with open(pcap, "wb") as fh:
        fh.write(PCAP_GLOBAL_HEADER)
        ts = time.time()
        event_ts = ts
        clock = _TrafficClock(
            base_interval_s=1.0 / cfg.base_rate_pps,
            jitter_ratio=cfg.jitter_ratio,
            burst_probability=cfg.burst_probability,
            burst_multiplier=cfg.burst_multiplier,
            lull_probability=cfg.lull_probability,
            lull_multiplier=cfg.lull_multiplier,
        )
        src_pool = _private_ip_pool(cfg.src_ip_pool_size)
        for _ in range(cfg.packet_count):
            src_ip = random.choice(src_pool)
            src_port = random.randint(cfg.min_src_port, cfg.max_src_port)
            seq = random.randrange(0, 0xFFFFFFFF)
            tcp_payload = b""
            tcp_hdr = _tcp_header(src_ip, cfg.target_ip, src_port, cfg.target_port, seq, 0x02, tcp_payload)
            ip_hdr = _ip_header(src_ip, cfg.target_ip, tcp_hdr, socket.IPPROTO_TCP, random.randint(0, 0xFFFF))
            _write_pcap_packet(fh, ip_hdr + tcp_hdr + tcp_payload, event_ts)
            event_ts = clock.advance(event_ts)
    return pcap


def generate_normal_http_pcap(cfg: NormalPcapConfig) -> Path:
    """Generate benign TCP/HTTP-like sessions as an offline PCAP."""

    pcap = Path(cfg.pcap_path)
    if pcap.exists():
        pcap.unlink()
    pcap.parent.mkdir(parents=True, exist_ok=True)

    with open(pcap, "wb") as fh:
        fh.write(PCAP_GLOBAL_HEADER)
        ts = time.time()
        session_ts = ts
        clock = _TrafficClock(
            base_interval_s=1.0 / cfg.base_session_rate,
            jitter_ratio=cfg.jitter_ratio,
            burst_probability=cfg.burst_probability,
            burst_multiplier=cfg.burst_multiplier,
            lull_probability=cfg.lull_probability,
            lull_multiplier=cfg.lull_multiplier,
        )
        clients = [f"192.168.{random.randint(1, 40)}.{random.randint(1, 254)}" for _ in range(max(1, cfg.client_pool_size))]
        for i in range(cfg.session_count):
            src_ip = random.choice(clients)
            src_port = random.randint(cfg.min_src_port, cfg.max_src_port)
            client_seq = random.randrange(0, 0xFFFFFFFF)
            server_seq = random.randrange(0, 0xFFFFFFFF)

            request = (
                f"GET /index.html?item={i % 17} HTTP/1.1\r\n"
                f"Host: localhost:{cfg.server_port}\r\n"
                "User-Agent: benign-client\r\n"
                "Accept: */*\r\n\r\n"
            ).encode()
            response = (
                "HTTP/1.1 200 OK\r\n"
                "Content-Type: text/plain\r\n"
                f"Content-Length: {64 + (i % 96)}\r\n\r\n"
            ).encode() + (b"N" * (64 + (i % 96)))

            packets = [
                (src_ip, cfg.server_ip, src_port, cfg.server_port, client_seq, 0x02, b"", 0.0000),
                (cfg.server_ip, src_ip, cfg.server_port, src_port, server_seq, 0x12, b"", 0.0060),
                (src_ip, cfg.server_ip, src_port, cfg.server_port, client_seq + 1, 0x10, b"", 0.0110),
                (src_ip, cfg.server_ip, src_port, cfg.server_port, client_seq + 1, 0x18, request, 0.0180),
                (cfg.server_ip, src_ip, cfg.server_port, src_port, server_seq + 1, 0x10, b"", 0.0250),
                (cfg.server_ip, src_ip, cfg.server_port, src_port, server_seq + 1, 0x18, response, 0.0330),
                (src_ip, cfg.server_ip, src_port, cfg.server_port, client_seq + 1 + len(request), 0x11, b"", 0.0410),
                (cfg.server_ip, src_ip, cfg.server_port, src_port, server_seq + 1 + len(response), 0x11, b"", 0.0480),
            ]

            for src, dst, sport, dport, seq, flags, payload, offset in packets:
                tcp_hdr = _tcp_header(src, dst, sport, dport, seq, flags, payload)
                ip_hdr = _ip_header(src, dst, tcp_hdr + payload, socket.IPPROTO_TCP, random.randint(0, 0xFFFF))
                _write_pcap_packet(fh, ip_hdr + tcp_hdr + payload, session_ts + offset)
            session_ts = clock.advance(session_ts)
    return pcap


def generate_udp_reflect_spoof_pcap(cfg: ReflectPcapConfig) -> Path:
    pcap = Path(cfg.pcap_path)
    if pcap.exists():
        pcap.unlink()
    pcap.parent.mkdir(parents=True, exist_ok=True)
    with open(pcap, "wb") as fh:
        fh.write(PCAP_GLOBAL_HEADER)
        ts = time.time()
        event_ts = ts
        clock = _TrafficClock(
            base_interval_s=1.0 / cfg.base_request_rate,
            jitter_ratio=cfg.jitter_ratio,
            burst_probability=cfg.burst_probability,
            burst_multiplier=cfg.burst_multiplier,
            lull_probability=cfg.lull_probability,
            lull_multiplier=cfg.lull_multiplier,
        )
        victims = _private_ip_pool(cfg.victim_pool_size)
        reflectors = _private_ip_pool(cfg.reflector_pool_size)
        for _ in range(cfg.packet_count):
            src_ip = random.choice(victims)
            reflector_ip = random.choice(reflectors)
            src_port = random.randint(cfg.min_src_port, cfg.max_src_port)
            req_payload = b"Q" * cfg.request_size
            req_udp = _udp_header(src_ip, reflector_ip, src_port, cfg.target_port, req_payload)
            req_ip = _ip_header(src_ip, reflector_ip, req_udp + req_payload, socket.IPPROTO_UDP, random.randint(0, 0xFFFF))
            _write_pcap_packet(fh, req_ip + req_udp + req_payload, event_ts)

            resp_src_port = cfg.target_port
            resp_dst_port = src_port
            resp_payload = b"R" * cfg.response_size
            resp_udp = _udp_header(reflector_ip, src_ip, resp_src_port, resp_dst_port, resp_payload)
            resp_ip = _ip_header(reflector_ip, src_ip, resp_udp + resp_payload, socket.IPPROTO_UDP, random.randint(0, 0xFFFF))
            _write_pcap_packet(fh, resp_ip + resp_udp + resp_payload, event_ts + random.uniform(0.00002, 0.00025))
            event_ts = clock.advance(event_ts)
    return pcap


@dataclass(frozen=True)
class HttpPcapConfig:
    target_ip: str = "127.0.0.1"
    target_port: int = 8080
    request_count: int = 100
    pcap_path: str = "/tmp/http_traffic.pcap"
    paths: list[str] | None = None
    post_ratio: float = 0.0
    body_size_range: tuple[int, int] | None = None
    user_agents: list[str] | None = None
    request_interval_s: float = 0.01
    min_src_port: int = 1024
    max_src_port: int = 65535
    jitter_ratio: float = 0.80
    burst_probability: float = 0.14
    burst_multiplier: float = 4.5
    lull_probability: float = 0.10
    lull_multiplier: float = 3.5
    src_ip_pool_size: int = 500


def _http_request_payload(path: str, method: str, host: str, user_agent: str, body: bytes | None) -> bytes:
    lines = [
        f"{method} {path} HTTP/1.1",
        f"Host: {host}",
        f"User-Agent: {user_agent}",
        "Accept: */*",
        "Connection: close",
    ]
    if body is not None:
        lines.append("Content-Type: text/plain")
        lines.append(f"Content-Length: {len(body)}")
    lines.append("")
    request = "\r\n".join(lines).encode()
    if body is not None:
        request += body
    return request


def _http_response_payload(body: bytes | None) -> bytes:
    lines = [
        "HTTP/1.1 200 OK",
        "Content-Type: text/plain; charset=utf-8",
        "Connection: close",
        f"Content-Length: {len(body) if body is not None else 0}",
        "",
    ]
    response = "\r\n".join(lines).encode()
    if body is not None:
        response += body
    return response


def generate_http_pcap(cfg: HttpPcapConfig) -> Path:
    pcap = Path(cfg.pcap_path)
    if pcap.exists():
        pcap.unlink()
    pcap.parent.mkdir(parents=True, exist_ok=True)

    paths = cfg.paths or ["/", "/status", "/api/v1/data", "/search?q=test", "/login", "/submit"]
    user_agents = cfg.user_agents or [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
        "curl/7.85.0",
        "Python/3.11 aiohttp",
    ]
    body_min, body_max = cfg.body_size_range or (0, 0)
    if body_min > body_max:
        body_min, body_max = body_max, body_min

    with open(pcap, "wb") as fh:
        fh.write(PCAP_GLOBAL_HEADER)
        ts = time.time()
        request_ts = ts
        clock = _TrafficClock(
            base_interval_s=cfg.request_interval_s,
            jitter_ratio=cfg.jitter_ratio,
            burst_probability=cfg.burst_probability,
            burst_multiplier=cfg.burst_multiplier,
            lull_probability=cfg.lull_probability,
            lull_multiplier=cfg.lull_multiplier,
        )
        src_pool = _private_ip_pool(cfg.src_ip_pool_size)
        for _ in range(cfg.request_count):
            src_ip = random.choice(src_pool)
            src_port = random.randint(cfg.min_src_port, cfg.max_src_port)
            method = "POST" if random.random() < cfg.post_ratio else "GET"
            path = random.choice(paths)
            user_agent = random.choice(user_agents)
            body_size = random.randint(body_min, body_max) if body_max > 0 else 0
            body = (b"X" * body_size) if method == "POST" else None
            req_payload = _http_request_payload(path, method, cfg.target_ip, user_agent, body)
            req_tcp = _tcp_header(src_ip, cfg.target_ip, src_port, cfg.target_port, random.randrange(0, 0xFFFFFFFF), 0x18, req_payload)
            req_ip = _ip_header(src_ip, cfg.target_ip, req_tcp + req_payload, socket.IPPROTO_TCP, random.randint(0, 0xFFFF))
            _write_pcap_packet(fh, req_ip + req_tcp + req_payload, request_ts)

            resp_body = b"OK\n"
            resp_payload = _http_response_payload(resp_body)
            resp_tcp = _tcp_header(cfg.target_ip, src_ip, cfg.target_port, src_port, random.randrange(0, 0xFFFFFFFF), 0x18, resp_payload)
            resp_ip = _ip_header(cfg.target_ip, src_ip, resp_tcp + resp_payload, socket.IPPROTO_TCP, random.randint(0, 0xFFFF))
            _write_pcap_packet(fh, resp_ip + resp_tcp + resp_payload, request_ts + random.uniform(0.001, 0.008))
            request_ts = clock.advance(request_ts)
    return pcap


def list_private_ip_blocks() -> Iterable[str]:
    return ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
