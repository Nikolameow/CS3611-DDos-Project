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


@dataclass(frozen=True)
class SynPcapConfig:
    target_ip: str = "127.0.0.1"
    target_port: int = 8080
    packet_count: int = 1000
    pcap_path: str = "/tmp/syn_spoof.pcap"
    min_src_port: int = 1024
    max_src_port: int = 65535


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


def generate_syn_spoof_pcap(cfg: SynPcapConfig) -> Path:
    pcap = Path(cfg.pcap_path)
    if pcap.exists():
        pcap.unlink()
    pcap.parent.mkdir(parents=True, exist_ok=True)
    with open(pcap, "wb") as fh:
        fh.write(PCAP_GLOBAL_HEADER)
        ts = time.time()
        for i in range(cfg.packet_count):
            src_ip = _random_private_ip()
            src_port = random.randint(cfg.min_src_port, cfg.max_src_port)
            seq = random.randrange(0, 0xFFFFFFFF)
            tcp_payload = b""
            tcp_hdr = _tcp_header(src_ip, cfg.target_ip, src_port, cfg.target_port, seq, 0x02, tcp_payload)
            ip_hdr = _ip_header(src_ip, cfg.target_ip, tcp_hdr, socket.IPPROTO_TCP, random.randint(0, 0xFFFF))
            _write_pcap_packet(fh, ip_hdr + tcp_hdr + tcp_payload, ts + i * 0.0001)
    return pcap


def generate_udp_reflect_spoof_pcap(cfg: ReflectPcapConfig) -> Path:
    pcap = Path(cfg.pcap_path)
    if pcap.exists():
        pcap.unlink()
    pcap.parent.mkdir(parents=True, exist_ok=True)
    with open(pcap, "wb") as fh:
        fh.write(PCAP_GLOBAL_HEADER)
        ts = time.time()
        for i in range(cfg.packet_count):
            src_ip = _random_private_ip()
            src_port = random.randint(cfg.min_src_port, cfg.max_src_port)
            req_payload = b"Q" * cfg.request_size
            req_udp = _udp_header(src_ip, cfg.target_ip, src_port, cfg.target_port, req_payload)
            req_ip = _ip_header(src_ip, cfg.target_ip, req_udp + req_payload, socket.IPPROTO_UDP, random.randint(0, 0xFFFF))
            _write_pcap_packet(fh, req_ip + req_udp + req_payload, ts + i * 0.0001)

            resp_src_port = cfg.target_port
            resp_dst_port = src_port
            resp_payload = b"R" * cfg.response_size
            resp_udp = _udp_header(cfg.target_ip, src_ip, resp_src_port, resp_dst_port, resp_payload)
            resp_ip = _ip_header(cfg.target_ip, src_ip, resp_udp + resp_payload, socket.IPPROTO_UDP, random.randint(0, 0xFFFF))
            _write_pcap_packet(fh, resp_ip + resp_udp + resp_payload, ts + i * 0.0001 + 0.00005)
    return pcap


def list_private_ip_blocks() -> Iterable[str]:
    return ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
