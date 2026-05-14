#!/usr/bin/env python3
"""Extract windowed model features from attack PCAP files."""

from __future__ import annotations

import argparse
import csv
import hashlib
import math
import struct
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from statistics import mean, pstdev


DEFAULT_INPUT_DIR = Path("attack1/data")
DEFAULT_OUTPUT = Path("detection/data/features.csv")
DEFAULT_HTTP_PORTS = {80, 443, 8080}

FEATURE_COLUMNS = [
    "window_id",
    "source_pcap",
    "packet_count",
    "pps",
    "byte_count",
    "avg_packet_size",
    "std_packet_size",
    "tcp_ratio",
    "udp_ratio",
    "http_ratio",
    "syn_ratio",
    "ack_ratio",
    "syn_ack_ratio",
    "unique_src_ips",
    "unique_dst_ports",
    "src_ip_entropy",
    "dst_port_entropy",
    "mean_interarrival_ms",
    "label",
]


@dataclass(frozen=True)
class PacketFeature:
    timestamp: float
    size: int
    protocol: str
    src_ip: str
    src_port: int
    dst_port: int
    syn: bool
    ack: bool


def entropy(values: list[str]) -> float:
    if not values:
        return 0.0
    total = len(values)
    counts = Counter(values)
    return -sum((count / total) * math.log2(count / total) for count in counts.values())


def ratio(count: int, total: int) -> float:
    return count / total if total else 0.0


def label_from_pcap(path: Path) -> str:
    name = path.stem.lower()
    if "normal" in name or "benign" in name:
        return "normal"
    if "syn" in name:
        return "syn_flood"
    if "udp" in name:
        return "udp_reflection"
    if "http" in name:
        return "http_flood"
    return "attack"


def _pcap_endian(magic: bytes) -> str:
    if magic in {b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"}:
        return "<"
    if magic in {b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"}:
        return ">"
    raise ValueError("unsupported pcap magic")


def _ipv4_payload(frame: bytes, linktype: int) -> bytes | None:
    if linktype == 101:
        return frame
    if linktype != 1 or len(frame) < 14:
        return None
    ether_type = int.from_bytes(frame[12:14], "big")
    offset = 14
    if ether_type == 0x8100 and len(frame) >= 18:
        ether_type = int.from_bytes(frame[16:18], "big")
        offset = 18
    if ether_type != 0x0800:
        return None
    return frame[offset:]


def _parse_ipv4_packet(timestamp: float, frame: bytes, linktype: int) -> PacketFeature | None:
    packet = _ipv4_payload(frame, linktype)
    if packet is None or len(packet) < 20:
        return None
    version = packet[0] >> 4
    ihl = (packet[0] & 0x0F) * 4
    if version != 4 or ihl < 20 or len(packet) < ihl:
        return None

    total_length = int.from_bytes(packet[2:4], "big")
    protocol_id = packet[9]
    src_ip = ".".join(str(part) for part in packet[12:16])
    l4 = packet[ihl:total_length or len(packet)]

    protocol = "OTHER"
    src_port = 0
    dst_port = 0
    syn = False
    ack = False
    if protocol_id == 6 and len(l4) >= 14:
        protocol = "TCP"
        src_port = int.from_bytes(l4[0:2], "big")
        dst_port = int.from_bytes(l4[2:4], "big")
        flags = l4[13]
        syn = bool(flags & 0x02)
        ack = bool(flags & 0x10)
    elif protocol_id == 17 and len(l4) >= 4:
        protocol = "UDP"
        src_port = int.from_bytes(l4[0:2], "big")
        dst_port = int.from_bytes(l4[2:4], "big")
    elif protocol_id == 1:
        protocol = "ICMP"

    return PacketFeature(
        timestamp=timestamp,
        size=len(frame),
        protocol=protocol,
        src_ip=src_ip,
        src_port=src_port,
        dst_port=dst_port,
        syn=syn,
        ack=ack,
    )


def read_pcap_packets(path: Path) -> list[PacketFeature]:
    with path.open("rb") as file:
        header = file.read(24)
        if len(header) != 24:
            raise ValueError(f"{path} is not a complete pcap file")
        endian = _pcap_endian(header[:4])
        _, _, _, _, _, _, linktype = struct.unpack(f"{endian}IHHIIII", header)

        packets: list[PacketFeature] = []
        while True:
            packet_header = file.read(16)
            if not packet_header:
                break
            if len(packet_header) != 16:
                raise ValueError(f"{path} has a truncated packet header")
            ts_sec, ts_frac, incl_len, _orig_len = struct.unpack(f"{endian}IIII", packet_header)
            frame = file.read(incl_len)
            if len(frame) != incl_len:
                raise ValueError(f"{path} has a truncated packet body")
            timestamp = ts_sec + ts_frac / 1_000_000
            parsed = _parse_ipv4_packet(timestamp, frame, linktype)
            if parsed is not None:
                packets.append(parsed)
    return packets


def iter_windows(
    packets: list[PacketFeature],
    *,
    window_seconds: float,
    packets_per_window: int | None,
) -> list[list[PacketFeature]]:
    if packets_per_window is not None:
        return [
            packets[index : index + packets_per_window]
            for index in range(0, len(packets), packets_per_window)
            if packets[index : index + packets_per_window]
        ]

    if not packets:
        return []
    if window_seconds <= 0:
        raise ValueError("window_seconds must be positive")

    windows: list[list[PacketFeature]] = []
    current: list[PacketFeature] = []
    window_start = packets[0].timestamp
    for packet in packets:
        if packet.timestamp - window_start >= window_seconds and current:
            windows.append(current)
            current = []
            window_start = packet.timestamp
        current.append(packet)
    if current:
        windows.append(current)
    return windows


def extract_window_features(
    window_id: int,
    source_pcap: str,
    label: str,
    packets: list[PacketFeature],
    http_ports: set[int],
) -> dict[str, float | int | str]:
    timestamps = [packet.timestamp for packet in packets]
    sizes = [packet.size for packet in packets]
    protocols = [packet.protocol for packet in packets]
    src_ips = [packet.src_ip for packet in packets]
    dst_ports = [str(packet.dst_port) for packet in packets]
    interarrival = [
        (timestamps[index] - timestamps[index - 1]) * 1000
        for index in range(1, len(timestamps))
    ]

    packet_count = len(packets)
    duration = max(timestamps[-1] - timestamps[0], 1e-9)
    syn_count = sum(packet.syn for packet in packets)
    ack_count = sum(packet.ack for packet in packets)
    tcp_count = protocols.count("TCP")
    udp_count = protocols.count("UDP")
    http_count = sum(
        packet.protocol == "TCP" and (packet.src_port in http_ports or packet.dst_port in http_ports)
        for packet in packets
    )

    return {
        "window_id": window_id,
        "source_pcap": source_pcap,
        "packet_count": packet_count,
        "pps": round(packet_count / duration, 6),
        "byte_count": sum(sizes),
        "avg_packet_size": round(mean(sizes), 4),
        "std_packet_size": round(pstdev(sizes), 4) if len(sizes) > 1 else 0.0,
        "tcp_ratio": round(ratio(tcp_count, packet_count), 6),
        "udp_ratio": round(ratio(udp_count, packet_count), 6),
        "http_ratio": round(ratio(http_count, packet_count), 6),
        "syn_ratio": round(ratio(syn_count, packet_count), 6),
        "ack_ratio": round(ratio(ack_count, packet_count), 6),
        "syn_ack_ratio": round(syn_count / max(ack_count, 1), 6),
        "unique_src_ips": len(set(src_ips)),
        "unique_dst_ports": len(set(dst_ports)),
        "src_ip_entropy": round(entropy(src_ips), 6),
        "dst_port_entropy": round(entropy(dst_ports), 6),
        "mean_interarrival_ms": round(mean(interarrival), 6) if interarrival else 0.0,
        "label": label,
    }


def file_digest(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as file:
        for chunk in iter(lambda: file.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def extract_features(
    input_dir: Path,
    *,
    window_seconds: float,
    packets_per_window: int | None,
    http_ports: set[int],
    skip_duplicates: bool,
) -> list[dict[str, float | int | str]]:
    pcaps = sorted(input_dir.glob("*.pcap"))
    if not pcaps:
        raise FileNotFoundError(f"no .pcap files found under {input_dir}")

    rows: list[dict[str, float | int | str]] = []
    next_window_id = 0
    seen_digests: set[str] = set()
    for pcap in pcaps:
        if skip_duplicates:
            digest = file_digest(pcap)
            if digest in seen_digests:
                print(f"skipping duplicate pcap: {pcap}")
                continue
            seen_digests.add(digest)

        packets = read_pcap_packets(pcap)
        label = label_from_pcap(pcap)
        for window in iter_windows(
            packets,
            window_seconds=window_seconds,
            packets_per_window=packets_per_window,
        ):
            rows.append(extract_window_features(next_window_id, pcap.name, label, window, http_ports))
            next_window_id += 1
    return rows


def write_features(rows: list[dict[str, float | int | str]], output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=FEATURE_COLUMNS)
        writer.writeheader()
        writer.writerows(rows)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Extract windowed features from attack1 PCAP files.")
    parser.add_argument("--input-dir", type=Path, default=DEFAULT_INPUT_DIR)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--window-seconds", type=float, default=0.05)
    parser.add_argument("--packets-per-window", type=int, default=None)
    parser.add_argument("--http-ports", default="80,443,8080")
    parser.add_argument("--include-duplicates", action="store_true")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    http_ports = {int(port.strip()) for port in args.http_ports.split(",") if port.strip()}
    rows = extract_features(
        args.input_dir,
        window_seconds=args.window_seconds,
        packets_per_window=args.packets_per_window,
        http_ports=http_ports,
        skip_duplicates=not args.include_duplicates,
    )
    write_features(rows, args.output)
    print(f"wrote {len(rows)} feature rows to {args.output}")


if __name__ == "__main__":
    main()
