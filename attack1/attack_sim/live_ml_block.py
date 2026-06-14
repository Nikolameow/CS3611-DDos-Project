from __future__ import annotations

import math
import os
import re
import subprocess
import time
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from statistics import mean, pstdev

os.environ.setdefault("OMP_NUM_THREADS", "1")

import joblib

from .defense import apply_commands, build_iptables_blacklist
from .ml_block import parse_whitelist, validate_ip


TCPDUMP_PACKET_PATTERN = re.compile(
    r"^(?:(?P<ts>[0-9]+(?:\.[0-9]+)?)\s+)?IP\s+"
    r"(?P<src>[0-9]+(?:\.[0-9]+){3})\.(?P<src_port>[0-9]+)\s+>\s+"
    r"(?P<dst>[0-9]+(?:\.[0-9]+){3})\.(?P<dst_port>[0-9]+):\s+(?P<body>.*)$"
)
FLAGS_PATTERN = re.compile(r"Flags\s+\[([^\]]+)\]")
LENGTH_PATTERN = re.compile(r"\blength\s+([0-9]+)")


@dataclass(frozen=True)
class LiveMlBlockConfig:
    detector: str
    model_path: Path
    interface: str
    port: int = 8080
    window_s: float = 1.0
    min_bad_windows: int = 1
    min_packets: int = 1
    whitelist: frozenset[str] = frozenset()
    dry_run: bool = True
    tcpdump: str = "tcpdump"


@dataclass(frozen=True)
class LivePacket:
    timestamp: float
    size: int
    protocol: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    syn: bool
    ack: bool


def _entropy(values: list[str]) -> float:
    if not values:
        return 0.0
    total = len(values)
    counts = Counter(values)
    return -sum((count / total) * math.log2(count / total) for count in counts.values())


def _ratio(count: int, total: int) -> float:
    return count / total if total else 0.0


def _parse_packet(line: str) -> LivePacket | None:
    match = TCPDUMP_PACKET_PATTERN.search(line.strip())
    if not match:
        return None

    body = match.group("body")
    protocol = "UDP" if body.startswith("UDP") or " UDP," in body else "TCP"
    flags_match = FLAGS_PATTERN.search(body)
    flags = flags_match.group(1) if flags_match else ""
    payload_match = LENGTH_PATTERN.search(body)
    payload_len = int(payload_match.group(1)) if payload_match else 0
    header_len = 42 if protocol == "UDP" else 54

    return LivePacket(
        timestamp=float(match.group("ts")) if match.group("ts") else time.time(),
        size=payload_len + header_len,
        protocol=protocol,
        src_ip=match.group("src"),
        dst_ip=match.group("dst"),
        src_port=int(match.group("src_port")),
        dst_port=int(match.group("dst_port")),
        syn="S" in flags,
        ack="." in flags,
    )


def _window_features(
    window_id: int,
    source_ip: str,
    packets: list[LivePacket],
    http_ports: set[int],
    duration_floor_s: float,
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
    tcp_count = protocols.count("TCP")
    udp_count = protocols.count("UDP")
    syn_count = sum(packet.syn for packet in packets)
    ack_count = sum(packet.ack for packet in packets)
    http_count = sum(
        packet.protocol == "TCP" and (packet.src_port in http_ports or packet.dst_port in http_ports)
        for packet in packets
    )
    mean_interarrival = mean(interarrival) if interarrival else 0.0
    std_interarrival = pstdev(interarrival) if len(interarrival) > 1 else 0.0

    return {
        "window_id": str(window_id),
        "source_pcap": f"live:{source_ip}",
        "packet_count": packet_count,
        "pps": round(packet_count / duration, 6),
        "byte_count": sum(sizes),
        "avg_packet_size": round(mean(sizes), 4),
        "std_packet_size": round(pstdev(sizes), 4) if len(sizes) > 1 else 0.0,
        "tcp_ratio": round(_ratio(tcp_count, packet_count), 6),
        "udp_ratio": round(_ratio(udp_count, packet_count), 6),
        "http_ratio": round(_ratio(http_count, packet_count), 6),
        "syn_ratio": round(_ratio(syn_count, packet_count), 6),
        "ack_ratio": round(_ratio(ack_count, packet_count), 6),
        "syn_ack_ratio": round(syn_count / max(ack_count, 1), 6),
        "unique_src_ips": len(set(src_ips)),
        "unique_dst_ips": len(set(dst_ips)),
        "unique_src_ports": len(set(src_ports)),
        "unique_dst_ports": len(set(dst_ports)),
        "src_ip_entropy": round(_entropy(src_ips), 6),
        "dst_ip_entropy": round(_entropy(dst_ips), 6),
        "src_port_entropy": round(_entropy(src_ports), 6),
        "dst_port_entropy": round(_entropy(dst_ports), 6),
        "mean_interarrival_ms": round(mean_interarrival, 6),
        "std_interarrival_ms": round(std_interarrival, 6),
        "interarrival_cv": round(std_interarrival / max(mean_interarrival, 1e-9), 6),
        "flow_count": len(set(flows)),
        "flow_entropy": round(_entropy(flows), 6),
        "small_packet_ratio": round(_ratio(sum(size <= 80 for size in sizes), packet_count), 6),
        "large_packet_ratio": round(_ratio(sum(size >= 512 for size in sizes), packet_count), 6),
    }


class LiveMlBlocker:
    def __init__(self, cfg: LiveMlBlockConfig) -> None:
        if cfg.min_bad_windows < 1:
            raise ValueError("--min-bad-windows must be at least 1")
        if cfg.min_packets < 1:
            raise ValueError("--min-packets must be at least 1")
        if cfg.window_s <= 0:
            raise ValueError("--window must be positive")

        self.cfg = cfg
        self.bundle = joblib.load(cfg.model_path)
        self.feature_names = list(self.bundle["feature_names"])
        self.samples: dict[str, list[LivePacket]] = {}
        self.bad_counts: dict[str, int] = {}
        self.blocked: set[str] = set()
        self.next_window_id = 0
        self.http_ports = {80, 443, cfg.port}

    def _predict(self, row: dict[str, float | int | str]) -> tuple[bool, str, float | None, float | None]:
        x_row = [[float(row[name]) for name in self.feature_names]]
        if self.cfg.detector == "mlp":
            prediction = str(self.bundle["model"].predict(x_row)[0])
            return prediction == "abnormal", prediction, None, None
        if self.cfg.detector == "kmeans":
            model = self.bundle["model"]
            threshold = float(self.bundle["threshold"])
            transformed = model.named_steps["scaler"].transform(x_row)
            distance_row = model.named_steps["kmeans"].transform(transformed)[0]
            score = float(min(distance_row))
            return score > threshold, "anomaly" if score > threshold else "normal", score, threshold
        raise ValueError(f"unsupported detector: {self.cfg.detector}")

    def _block_ip(self, ip: str) -> None:
        ip = validate_ip(ip)
        if ip in self.blocked:
            return
        if ip in self.cfg.whitelist:
            print(f"[live-ml-block] {ip} is whitelisted; blacklist action skipped")
            return
        self.blocked.add(ip)
        print(f"[live-ml-block] blocking {ip}")
        apply_commands(build_iptables_blacklist(ip), dry_run=self.cfg.dry_run)

    def _evaluate_window(self, ip: str, packets: list[LivePacket]) -> None:
        if len(packets) < self.cfg.min_packets:
            return
        row = _window_features(
            self.next_window_id,
            ip,
            packets,
            self.http_ports,
            duration_floor_s=self.cfg.window_s,
        )
        self.next_window_id += 1
        is_bad, decision, score, threshold = self._predict(row)
        if is_bad:
            self.bad_counts[ip] = self.bad_counts.get(ip, 0) + 1
        else:
            self.bad_counts[ip] = 0

        details = [
            f"ip={ip}",
            f"window={row['window_id']}",
            f"packets={row['packet_count']}",
            f"pps={float(row['pps']):.2f}",
            f"decision={decision}",
            f"bad={str(is_bad).lower()}",
            f"bad_windows={self.bad_counts[ip]}",
        ]
        if score is not None and threshold is not None:
            details.extend([f"score={score:.8f}", f"threshold={threshold:.8f}"])
        print("[live-ml-block] " + " ".join(details))

        if self.bad_counts[ip] >= self.cfg.min_bad_windows:
            self._block_ip(ip)

    def _add_packet(self, packet: LivePacket) -> None:
        if packet.src_ip in self.blocked:
            return
        items = self.samples.setdefault(packet.src_ip, [])
        if items and packet.timestamp - items[0].timestamp >= self.cfg.window_s:
            self._evaluate_window(packet.src_ip, items)
            self.samples[packet.src_ip] = [packet]
            return
        items.append(packet)

    def run(self) -> None:
        command = [
            self.cfg.tcpdump,
            "-l",
            "-nn",
            "-tt",
            "-i",
            self.cfg.interface,
            f"dst port {self.cfg.port}",
        ]
        print(f"[live-ml-block] starting: {' '.join(command)} dry_run={self.cfg.dry_run}")
        proc = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )
        assert proc.stdout is not None
        try:
            for line in proc.stdout:
                packet = _parse_packet(line)
                if packet is not None:
                    self._add_packet(packet)
        finally:
            for ip, packets in list(self.samples.items()):
                self._evaluate_window(ip, packets)
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                proc.kill()
