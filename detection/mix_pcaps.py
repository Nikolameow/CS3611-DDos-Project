#!/usr/bin/env python3
"""Create a mixed-flow PCAP plus packet-label sidecar for detection training."""

from __future__ import annotations

import argparse
import csv
import random
import struct
import time
from dataclasses import dataclass
from pathlib import Path


DEFAULT_SOURCES = {
    "normal": Path("attack1/data/generated_normal_http.pcap"),
    "http_flood": Path("attack1/data/generated_http_attack.pcap"),
    "syn_flood": Path("attack1/data/generated_syn_flood.pcap"),
    "udp_reflection": Path("attack1/data/generated_udp_reflect.pcap"),
}
DEFAULT_RATIOS = "normal=0.45,http_flood=0.25,syn_flood=0.20,udp_reflection=0.10"
DEFAULT_OUTPUT = Path("attack1/data/scenarios/scenario_mixed_attack_custom_seed3611.pcap")
DEFAULT_OUTPUT_DIR = Path("attack1/data/scenarios")
DEFAULT_PACKET_COUNT = 12000
DEFAULT_DURATION_S = 12.0

DEFAULT_SUITE = [
    ("scenario_normal_background_noise", "normal=0.95,http_flood=0.02,syn_flood=0.02,udp_reflection=0.01"),
    ("scenario_http_flood_noisy", "normal=0.10,http_flood=0.90"),
    ("scenario_syn_flood_noisy", "normal=0.10,syn_flood=0.90"),
    ("scenario_udp_reflection_noisy", "normal=0.10,udp_reflection=0.90"),
    ("scenario_mixed_attack_01", "normal=0.45,http_flood=0.25,syn_flood=0.20,udp_reflection=0.10"),
    ("scenario_mixed_attack_02", "normal=0.70,http_flood=0.10,syn_flood=0.10,udp_reflection=0.10"),
    ("scenario_mixed_attack_03", "normal=0.25,http_flood=0.35,syn_flood=0.25,udp_reflection=0.15"),
    ("scenario_mixed_attack_04", "normal=0.35,http_flood=0.10,syn_flood=0.45,udp_reflection=0.10"),
    ("scenario_mixed_attack_05", "normal=0.40,http_flood=0.30,syn_flood=0.05,udp_reflection=0.25"),
]


@dataclass(frozen=True)
class RawPacket:
    data: bytes
    label: str


def parse_mapping(value: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for item in value.split(","):
        if not item.strip():
            continue
        key, raw_value = item.split("=", 1)
        result[key.strip()] = raw_value.strip()
    return result


def parse_ratios(value: str) -> dict[str, float]:
    ratios = {label: float(raw) for label, raw in parse_mapping(value).items()}
    total = sum(ratios.values())
    if total <= 0:
        raise ValueError("ratio total must be positive")
    return {label: weight / total for label, weight in ratios.items()}


def pcap_endian(magic: bytes) -> str:
    if magic in {b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"}:
        return "<"
    if magic in {b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"}:
        return ">"
    raise ValueError("unsupported pcap magic")


def read_raw_packets(path: Path, label: str) -> tuple[int, list[RawPacket]]:
    with path.open("rb") as file:
        header = file.read(24)
        if len(header) != 24:
            raise ValueError(f"{path} is not a complete pcap file")
        endian = pcap_endian(header[:4])
        _, _, _, _, _, _, linktype = struct.unpack(f"{endian}IHHIIII", header)

        packets: list[RawPacket] = []
        while True:
            packet_header = file.read(16)
            if not packet_header:
                break
            if len(packet_header) != 16:
                raise ValueError(f"{path} has a truncated packet header")
            _ts_sec, _ts_frac, incl_len, _orig_len = struct.unpack(f"{endian}IIII", packet_header)
            frame = file.read(incl_len)
            if len(frame) != incl_len:
                raise ValueError(f"{path} has a truncated packet body")
            packets.append(RawPacket(frame, label))
    if not packets:
        raise ValueError(f"{path} contains no packets")
    return linktype, packets


def labels_for_count(ratios: dict[str, float], packet_count: int) -> list[str]:
    counts = {label: int(packet_count * weight) for label, weight in ratios.items()}
    assigned = sum(counts.values())
    remainders = sorted(
        ((packet_count * weight - counts[label], label) for label, weight in ratios.items()),
        reverse=True,
    )
    for _remainder, label in remainders[: packet_count - assigned]:
        counts[label] += 1

    labels: list[str] = []
    for label, count in counts.items():
        labels.extend([label] * count)
    return labels


def build_schedule(ratios: dict[str, float], packet_count: int, seed: int) -> list[str]:
    labels = labels_for_count(ratios, packet_count)
    rng = random.Random(seed)
    rng.shuffle(labels)
    return labels


def write_pcap_packet(file, packet: bytes, timestamp: float) -> None:
    ts_sec = int(timestamp)
    ts_usec = int((timestamp - ts_sec) * 1_000_000)
    file.write(struct.pack("<IIII", ts_sec, ts_usec, len(packet), len(packet)))
    file.write(packet)


def write_mixed_pcap(
    sources: dict[str, Path],
    ratios: dict[str, float],
    output: Path,
    *,
    packet_count: int,
    duration_s: float,
    seed: int,
) -> Path:
    loaded: dict[str, list[RawPacket]] = {}
    linktypes: set[int] = set()
    for label in ratios:
        if label not in sources:
            raise ValueError(f"no source pcap configured for ratio label '{label}'")
        linktype, packets = read_raw_packets(sources[label], label)
        linktypes.add(linktype)
        loaded[label] = packets
    if len(linktypes) != 1:
        raise ValueError(f"all source pcaps must use the same linktype, found {sorted(linktypes)}")

    schedule = build_schedule(ratios, packet_count, seed)
    rng = random.Random(seed + 1)
    cursors = {label: 0 for label in ratios}
    output.parent.mkdir(parents=True, exist_ok=True)
    labels_path = output.with_suffix(".labels.csv")

    global_header = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, linktypes.pop())
    start_ts = time.time()
    interval = duration_s / max(packet_count, 1)

    with output.open("wb") as pcap_file, labels_path.open("w", newline="", encoding="utf-8") as labels_file:
        pcap_file.write(global_header)
        writer = csv.DictWriter(labels_file, fieldnames=["packet_index", "timestamp", "label"])
        writer.writeheader()

        for index, label in enumerate(schedule):
            source_packets = loaded[label]
            packet = source_packets[cursors[label] % len(source_packets)]
            cursors[label] += 1
            timestamp = start_ts + index * interval + rng.uniform(0.0, interval * 0.20)
            write_pcap_packet(pcap_file, packet.data, timestamp)
            writer.writerow({"packet_index": index, "timestamp": f"{timestamp:.6f}", "label": packet.label})

    return output


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Mix normal and attack PCAP packets into one labeled PCAP.")
    parser.add_argument("--single", action="store_true", help="Write one custom-ratio PCAP instead of the default suite.")
    parser.add_argument("--sources", default=None, help="Comma-separated label=pcap entries.")
    parser.add_argument("--ratios", default=DEFAULT_RATIOS)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    parser.add_argument("--packets", type=int, default=DEFAULT_PACKET_COUNT)
    parser.add_argument("--duration", type=float, default=DEFAULT_DURATION_S)
    parser.add_argument("--seed", type=int, default=3611)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    sources = dict(DEFAULT_SOURCES)
    if args.sources:
        sources.update({label: Path(path) for label, path in parse_mapping(args.sources).items()})
    if args.single:
        output = write_mixed_pcap(
            sources=sources,
            ratios=parse_ratios(args.ratios),
            output=args.output,
            packet_count=args.packets,
            duration_s=args.duration,
            seed=args.seed,
        )
        print(f"wrote {output}")
        print(f"wrote {output.with_suffix('.labels.csv')}")
        return

    for index, (name, ratio_spec) in enumerate(DEFAULT_SUITE):
        output = args.output_dir / f"{name}_seed{args.seed}.pcap"
        write_mixed_pcap(
            sources=sources,
            ratios=parse_ratios(ratio_spec),
            output=output,
            packet_count=args.packets,
            duration_s=args.duration,
            seed=args.seed + index,
        )
        print(f"wrote {output}")
        print(f"wrote {output.with_suffix('.labels.csv')}")


if __name__ == "__main__":
    main()
