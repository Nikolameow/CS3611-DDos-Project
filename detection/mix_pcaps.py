#!/usr/bin/env python3
"""Create a mixed-flow PCAP plus packet-label sidecar for detection training."""

from __future__ import annotations

import argparse
import csv
import math
import random
import re
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
DEFAULT_SEED_COUNT = 5


@dataclass(frozen=True)
class RawPacket:
    data: bytes
    label: str


@dataclass(frozen=True)
class ScenarioSpec:
    name: str
    ratios: str
    profile: str
    packet_scale: tuple[float, float] = (0.80, 1.25)
    duration_scale: tuple[float, float] = (0.75, 1.35)


DEFAULT_SUITE = [
    ScenarioSpec("scenario_normal_web_steady", "normal=1.00", "normal", (0.55, 0.85), (1.15, 1.60)),
    ScenarioSpec("scenario_normal_web_bursty", "normal=1.00", "bursty_normal", (0.85, 1.20), (0.90, 1.25)),
    ScenarioSpec("scenario_normal_background_light", "normal=0.98,http_flood=0.01,syn_flood=0.005,udp_reflection=0.005", "normal", (0.65, 1.00), (1.00, 1.45)),
    ScenarioSpec("scenario_normal_background_noisy", "normal=0.95,http_flood=0.02,syn_flood=0.02,udp_reflection=0.01", "normal", (0.75, 1.15), (0.95, 1.35)),
    ScenarioSpec("scenario_normal_low_rate", "normal=1.00", "normal", (0.35, 0.60), (1.25, 1.80)),
    ScenarioSpec("scenario_normal_high_rate", "normal=1.00", "bursty_normal", (1.05, 1.45), (0.80, 1.10)),
    ScenarioSpec("scenario_normal_evening_peak", "normal=0.97,http_flood=0.015,syn_flood=0.01,udp_reflection=0.005", "daily_peak", (0.90, 1.35), (1.00, 1.50)),
    ScenarioSpec("scenario_normal_edge_noise", "normal=0.92,http_flood=0.03,syn_flood=0.03,udp_reflection=0.02", "normal", (0.80, 1.20), (0.95, 1.35)),
    ScenarioSpec("scenario_http_flood_noisy", "normal=0.10,http_flood=0.90", "attack_ramp"),
    ScenarioSpec("scenario_syn_flood_noisy", "normal=0.10,syn_flood=0.90", "attack_ramp"),
    ScenarioSpec("scenario_udp_reflection_noisy", "normal=0.10,udp_reflection=0.90", "attack_ramp"),
    ScenarioSpec("scenario_mixed_attack_01", "normal=0.45,http_flood=0.25,syn_flood=0.20,udp_reflection=0.10", "mixed_ramp"),
    ScenarioSpec("scenario_mixed_attack_02", "normal=0.70,http_flood=0.10,syn_flood=0.10,udp_reflection=0.10", "intermittent"),
    ScenarioSpec("scenario_mixed_attack_03", "normal=0.25,http_flood=0.35,syn_flood=0.25,udp_reflection=0.15", "mixed_ramp"),
    ScenarioSpec("scenario_mixed_attack_04", "normal=0.35,http_flood=0.10,syn_flood=0.45,udp_reflection=0.10", "intermittent"),
    ScenarioSpec("scenario_mixed_attack_05", "normal=0.40,http_flood=0.30,syn_flood=0.05,udp_reflection=0.25", "mixed_ramp"),
]


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


def normalize_ratios(ratios: dict[str, float]) -> dict[str, float]:
    total = sum(value for value in ratios.values() if value > 0)
    if total <= 0:
        return {"normal": 1.0}
    return {label: max(value, 0.0) / total for label, value in ratios.items() if value > 0}


def attack_labels(ratios: dict[str, float]) -> list[str]:
    return [label for label in ratios if label != "normal"]


def scaled_attack_ratios(base: dict[str, float], attack_scale: float) -> dict[str, float]:
    attacks = attack_labels(base)
    if not attacks:
        return {"normal": 1.0}
    attack_total = min(max(sum(base[label] for label in attacks) * attack_scale, 0.0), 0.98)
    base_attack_total = sum(base[label] for label in attacks)
    result = {"normal": 1.0 - attack_total}
    for label in attacks:
        result[label] = attack_total * (base[label] / base_attack_total)
    return normalize_ratios(result)


def profile_ratios(base: dict[str, float], progress: float, profile: str) -> dict[str, float]:
    progress = min(max(progress, 0.0), 1.0)
    attacks = attack_labels(base)
    if not attacks:
        return {"normal": 1.0}

    if profile in {"normal", "bursty_normal", "daily_peak"}:
        scale = 1.0
        if profile == "bursty_normal" and 0.35 <= progress <= 0.48:
            scale = 1.8
        elif profile == "daily_peak":
            scale = 0.75 + 0.65 * math.sin(math.pi * progress)
        return scaled_attack_ratios(base, scale)

    if profile in {"attack_ramp", "mixed_ramp"}:
        if progress < 0.15:
            scale = 0.15 + 2.33 * progress
        elif progress < 0.35:
            scale = 0.50 + 2.50 * (progress - 0.15)
        elif progress < 0.80:
            scale = 1.0 + 0.20 * math.sin(8 * math.pi * progress)
        else:
            scale = max(0.35, 1.0 - 2.5 * (progress - 0.80))
        return scaled_attack_ratios(base, scale)

    if profile == "intermittent":
        phase = int(progress * 10)
        scale = 1.25 if phase in {2, 3, 6, 7} else 0.35
        return scaled_attack_ratios(base, scale)

    return normalize_ratios(base)


def choose_label(ratios: dict[str, float], rng: random.Random) -> str:
    roll = rng.random()
    cumulative = 0.0
    last_label = "normal"
    for label, weight in ratios.items():
        cumulative += weight
        last_label = label
        if roll <= cumulative:
            return label
    return last_label


def infer_profile_from_name(path: Path) -> str:
    stem = re.sub(r"_seed\d+$", "", path.stem)
    for spec in DEFAULT_SUITE:
        if spec.name == stem:
            return spec.profile
    return "mixed_ramp"


def profile_rate_multiplier(progress: float, profile: str) -> float:
    if profile in {"normal", "bursty_normal"}:
        base = 0.85 + 0.30 * math.sin(2 * math.pi * progress)
        burst = 1.55 if profile == "bursty_normal" and 0.36 <= progress <= 0.48 else 1.0
        return max(0.25, base * burst)
    if profile == "daily_peak":
        return max(0.30, 0.45 + 1.20 * math.sin(math.pi * progress))
    if profile == "intermittent":
        return 1.80 if int(progress * 10) in {2, 3, 6, 7} else 0.55
    if profile in {"attack_ramp", "mixed_ramp"}:
        if progress < 0.20:
            return 0.45 + 3.00 * progress
        if progress < 0.80:
            return 1.05 + 0.35 * math.sin(6 * math.pi * progress)
        return max(0.35, 1.10 - 2.50 * (progress - 0.80))
    return 1.0


def next_timestamp(current_ts: float, base_interval: float, progress: float, profile: str, rng: random.Random) -> float:
    multiplier = profile_rate_multiplier(progress, profile)
    jitter = rng.lognormvariate(0.0, 0.22)
    gap = base_interval * jitter / max(multiplier, 0.05)
    return current_ts + max(gap, 1e-7)


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
    profile: str | None = None,
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

    rng = random.Random(seed + 1)
    cursors = {label: 0 for label in ratios}
    output.parent.mkdir(parents=True, exist_ok=True)
    labels_path = output.with_suffix(".labels.csv")
    profile_name = profile or infer_profile_from_name(output)

    global_header = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, linktypes.pop())
    start_ts = time.time()
    base_interval = duration_s / max(packet_count, 1)
    event_ts = start_ts

    with output.open("wb") as pcap_file, labels_path.open("w", newline="", encoding="utf-8") as labels_file:
        pcap_file.write(global_header)
        writer = csv.DictWriter(labels_file, fieldnames=["packet_index", "timestamp", "label"])
        writer.writeheader()

        for index in range(packet_count):
            progress = index / max(packet_count - 1, 1)
            current_ratios = profile_ratios(ratios, progress, profile_name)
            label = choose_label(current_ratios, rng)
            source_packets = loaded[label]
            packet = source_packets[cursors[label] % len(source_packets)]
            cursors[label] += 1
            write_pcap_packet(pcap_file, packet.data, event_ts)
            writer.writerow({"packet_index": index, "timestamp": f"{event_ts:.6f}", "label": packet.label})
            event_ts = next_timestamp(event_ts, base_interval, progress, profile_name, rng)

    return output


def scaled_count(base_count: int, scale_range: tuple[float, float], rng: random.Random) -> int:
    return max(100, round(base_count * rng.uniform(*scale_range)))


def scaled_duration(base_duration: float, scale_range: tuple[float, float], rng: random.Random) -> float:
    return max(1.0, base_duration * rng.uniform(*scale_range))


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Mix normal and attack PCAP packets into one labeled PCAP.")
    parser.add_argument("--single", action="store_true", help="Write one custom-ratio PCAP instead of the default suite.")
    parser.add_argument("--sources", default=None, help="Comma-separated label=pcap entries.")
    parser.add_argument("--ratios", default=DEFAULT_RATIOS)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    parser.add_argument("--packets", type=int, default=DEFAULT_PACKET_COUNT)
    parser.add_argument("--duration", type=float, default=DEFAULT_DURATION_S)
    parser.add_argument("--profile", default=None, help="Traffic profile for --single; defaults from output name.")
    parser.add_argument("--seed", type=int, default=3611)
    parser.add_argument("--seed-count", type=int, default=DEFAULT_SEED_COUNT)
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
            profile=args.profile,
        )
        print(f"wrote {output}")
        print(f"wrote {output.with_suffix('.labels.csv')}")
        return

    if args.seed_count < 1:
        raise ValueError("--seed-count must be at least 1")

    for seed_offset in range(args.seed_count):
        suite_seed = args.seed + seed_offset
        for index, spec in enumerate(DEFAULT_SUITE):
            scenario_seed = suite_seed * 100 + index
            rng = random.Random(scenario_seed)
            output = args.output_dir / f"{spec.name}_seed{suite_seed}.pcap"
            write_mixed_pcap(
                sources=sources,
                ratios=parse_ratios(spec.ratios),
                output=output,
                packet_count=scaled_count(args.packets, spec.packet_scale, rng),
                duration_s=scaled_duration(args.duration, spec.duration_scale, rng),
                seed=scenario_seed,
                profile=spec.profile,
            )
            print(f"wrote {output}")
            print(f"wrote {output.with_suffix('.labels.csv')}")


if __name__ == "__main__":
    main()
