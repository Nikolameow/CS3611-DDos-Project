#!/usr/bin/env python3
"""Extract windowed model features from attack PCAP files."""

from __future__ import annotations

import argparse
import csv
import hashlib
import math
import struct
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from statistics import mean, pstdev


DEFAULT_INPUT_DIR = Path("attack1/data/scenarios")
DEFAULT_OUTPUT = Path("detection/data/features.csv")
DEFAULT_HTTP_PORTS = {80, 443, 8080}
ABNORMAL_THRESHOLD = 0.10
DOMINANT_ATTACK_THRESHOLD = 0.60

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
    "unique_dst_ips",
    "unique_src_ports",
    "unique_dst_ports",
    "src_ip_entropy",
    "dst_ip_entropy",
    "src_port_entropy",
    "dst_port_entropy",
    "mean_interarrival_ms",
    "std_interarrival_ms",
    "interarrival_cv",
    "flow_count",
    "flow_entropy",
    "small_packet_ratio",
    "large_packet_ratio",
    "label",
    "binary_label",
    "normal_ratio",
    "http_flood_ratio",
    "syn_flood_ratio",
    "udp_reflection_ratio",
    "attack_ratio",
    "dominant_attack",
    "severity",
]


@dataclass(frozen=True)
class PacketFeature:
    timestamp: float
    size: int
    protocol: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    syn: bool
    ack: bool
    origin_label: str = ""


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


def _packet_labels(default_label: str, packets: list[PacketFeature] | None) -> list[str]:
    if packets and any(packet.origin_label for packet in packets):
        return [packet.origin_label or default_label for packet in packets]
    count = len(packets) if packets else 1
    return [default_label] * count


def label_metadata(label: str, packets: list[PacketFeature] | None = None) -> dict[str, float | str]:
    packet_labels = _packet_labels(label, packets)
    total = len(packet_labels)
    counts = Counter(packet_labels)
    ratios = {
        "normal_ratio": round(ratio(counts["normal"], total), 6),
        "http_flood_ratio": round(ratio(counts["http_flood"], total), 6),
        "syn_flood_ratio": round(ratio(counts["syn_flood"], total), 6),
        "udp_reflection_ratio": round(ratio(counts["udp_reflection"], total), 6),
    }

    attack_count = total - counts["normal"]
    attack_ratio = round(ratio(attack_count, total), 6)
    if attack_ratio < ABNORMAL_THRESHOLD:
        return {
            "binary_label": "normal",
            **ratios,
            "attack_ratio": attack_ratio,
            "dominant_attack": "none",
            "severity": "none",
        }

    attack_counts = {name: count for name, count in counts.items() if name != "normal" and count > 0}
    dominant_attack, dominant_count = max(attack_counts.items(), key=lambda item: item[1])
    if ratio(dominant_count, attack_count) < DOMINANT_ATTACK_THRESHOLD:
        dominant_attack = "mixed_attack"

    if attack_ratio < 0.30:
        severity = "low"
    elif attack_ratio < 0.60:
        severity = "medium"
    else:
        severity = "high"

    return {
        "binary_label": "abnormal",
        **ratios,
        "attack_ratio": attack_ratio,
        "dominant_attack": dominant_attack,
        "severity": severity,
    }


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


def _parse_ipv4_packet(
    timestamp: float,
    frame: bytes,
    linktype: int,
    origin_label: str = "",
) -> PacketFeature | None:
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
    dst_ip = ".".join(str(part) for part in packet[16:20])
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
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        syn=syn,
        ack=ack,
        origin_label=origin_label,
    )


def read_packet_labels(path: Path) -> dict[int, str]:
    label_path = path.with_suffix(".labels.csv")
    if not label_path.exists():
        return {}

    with label_path.open("r", newline="", encoding="utf-8") as file:
        return {
            int(row["packet_index"]): row["label"]
            for row in csv.DictReader(file)
            if row.get("packet_index") and row.get("label")
        }


def read_pcap_packets(path: Path) -> list[PacketFeature]:
    packet_labels = read_packet_labels(path)
    with path.open("rb") as file:
        header = file.read(24)
        if len(header) != 24:
            raise ValueError(f"{path} is not a complete pcap file")
        endian = _pcap_endian(header[:4])
        _, _, _, _, _, _, linktype = struct.unpack(f"{endian}IHHIIII", header)

        packets: list[PacketFeature] = []
        packet_index = 0
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
            parsed = _parse_ipv4_packet(
                timestamp,
                frame,
                linktype,
                origin_label=packet_labels.get(packet_index, ""),
            )
            if parsed is not None:
                packets.append(parsed)
            packet_index += 1
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
    duration_floor_s: float = 1e-9,
) -> dict[str, float | int | str]:
    timestamps = [packet.timestamp for packet in packets]
    sizes = [packet.size for packet in packets]
    protocols = [packet.protocol for packet in packets]
    src_ips = [packet.src_ip for packet in packets]
    dst_ips = [packet.dst_ip for packet in packets]
    src_ports = [str(packet.src_port) for packet in packets]
    dst_ports = [str(packet.dst_port) for packet in packets]
    flows = [
        f"{packet.src_ip}:{packet.src_port}-{packet.dst_ip}:{packet.dst_port}-{packet.protocol}"
        for packet in packets
    ]
    interarrival = [
        (timestamps[index] - timestamps[index - 1]) * 1000
        for index in range(1, len(timestamps))
    ]

    packet_count = len(packets)
    duration = max(timestamps[-1] - timestamps[0], duration_floor_s, 1e-9)
    syn_count = sum(packet.syn for packet in packets)
    ack_count = sum(packet.ack for packet in packets)
    tcp_count = protocols.count("TCP")
    udp_count = protocols.count("UDP")
    http_count = sum(
        packet.protocol == "TCP" and (packet.src_port in http_ports or packet.dst_port in http_ports)
        for packet in packets
    )
    mean_interarrival = mean(interarrival) if interarrival else 0.0
    std_interarrival = pstdev(interarrival) if len(interarrival) > 1 else 0.0

    metadata = label_metadata(label, packets)
    window_label = "normal" if metadata["binary_label"] == "normal" else str(metadata["dominant_attack"])

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
        "unique_dst_ips": len(set(dst_ips)),
        "unique_src_ports": len(set(src_ports)),
        "unique_dst_ports": len(set(dst_ports)),
        "src_ip_entropy": round(entropy(src_ips), 6),
        "dst_ip_entropy": round(entropy(dst_ips), 6),
        "src_port_entropy": round(entropy(src_ports), 6),
        "dst_port_entropy": round(entropy(dst_ports), 6),
        "mean_interarrival_ms": round(mean_interarrival, 6),
        "std_interarrival_ms": round(std_interarrival, 6),
        "interarrival_cv": round(std_interarrival / max(mean_interarrival, 1e-9), 6),
        "flow_count": len(set(flows)),
        "flow_entropy": round(entropy(flows), 6),
        "small_packet_ratio": round(ratio(sum(size <= 80 for size in sizes), packet_count), 6),
        "large_packet_ratio": round(ratio(sum(size >= 512 for size in sizes), packet_count), 6),
        "label": window_label,
        **metadata,
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
    group_by_origin_label: bool,
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
        default_label = label_from_pcap(pcap)
        packet_groups: list[tuple[str, str, list[PacketFeature]]]
        if group_by_origin_label and any(packet.origin_label for packet in packets):
            grouped_packets: dict[str, list[PacketFeature]] = defaultdict(list)
            for packet in packets:
                grouped_packets[packet.origin_label or default_label].append(packet)
            packet_groups = [
                (f"{pcap.name}#{label}", label, grouped_packets[label])
                for label in sorted(grouped_packets)
            ]
        else:
            packet_groups = [(pcap.name, default_label, packets)]

        for source_name, label, group_packets in packet_groups:
            for window in iter_windows(
                group_packets,
                window_seconds=window_seconds,
                packets_per_window=packets_per_window,
            ):
                duration_floor = window_seconds if packets_per_window is None else 1e-9
                rows.append(
                    extract_window_features(
                        next_window_id,
                        source_name,
                        label,
                        window,
                        http_ports,
                        duration_floor_s=duration_floor,
                    )
                )
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
    parser.add_argument(
        "--group-by-origin-label",
        action="store_true",
        help="Split a labelled mixed PCAP into separate windows per packet label.",
    )
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
        group_by_origin_label=args.group_by_origin_label,
    )
    write_features(rows, args.output)
    print(f"wrote {len(rows)} feature rows to {args.output}")


if __name__ == "__main__":
    main()
