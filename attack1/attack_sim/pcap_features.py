from __future__ import annotations

import json
import math
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Optional


@dataclass
class PcapStats:
    packets: int
    duration_s: float
    pps: float
    avg_pkt_size: float
    proto_dist: dict[str, int]
    src_ip_entropy: float
    syn_count: int
    ack_count: int
    syn_ack_ratio: float | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "packets": self.packets,
            "duration_s": self.duration_s,
            "pps": self.pps,
            "avg_pkt_size": self.avg_pkt_size,
            "proto_dist": dict(self.proto_dist),
            "src_ip_entropy": self.src_ip_entropy,
            "syn_count": self.syn_count,
            "ack_count": self.ack_count,
            "syn_ack_ratio": self.syn_ack_ratio,
        }


def _shannon_entropy(counts: Iterable[int]) -> float:
    total = sum(counts)
    if total <= 0:
        return 0.0
    ent = 0.0
    for c in counts:
        if c <= 0:
            continue
        p = c / total
        ent -= p * math.log2(p)
    return ent


def _compute_stats(
    *,
    times: list[float],
    sizes: list[int],
    l4_protos: list[str],
    src_ips: list[str],
    syn_flags: list[int],
    ack_flags: list[int],
) -> PcapStats:
    packets = len(times)
    if packets == 0:
        return PcapStats(
            packets=0,
            duration_s=0.0,
            pps=0.0,
            avg_pkt_size=0.0,
            proto_dist={},
            src_ip_entropy=0.0,
            syn_count=0,
            ack_count=0,
            syn_ack_ratio=None,
        )

    t0 = min(times)
    t1 = max(times)
    duration_s = max(1e-9, t1 - t0)
    pps = packets / duration_s

    avg_size = sum(sizes) / max(1, len(sizes))

    proto_dist: dict[str, int] = {}
    for p in l4_protos:
        proto_dist[p] = proto_dist.get(p, 0) + 1

    src_counts: dict[str, int] = {}
    for ip in src_ips:
        if not ip:
            continue
        src_counts[ip] = src_counts.get(ip, 0) + 1
    src_entropy = _shannon_entropy(src_counts.values())

    syn_count = sum(1 for x in syn_flags if x)
    ack_count = sum(1 for x in ack_flags if x)
    ratio = (syn_count / ack_count) if ack_count > 0 else None

    return PcapStats(
        packets=packets,
        duration_s=duration_s,
        pps=pps,
        avg_pkt_size=float(avg_size),
        proto_dist=proto_dist,
        src_ip_entropy=float(src_entropy),
        syn_count=syn_count,
        ack_count=ack_count,
        syn_ack_ratio=float(ratio) if ratio is not None else None,
    )


def _parse_tshark_rows(rows: list[str]) -> PcapStats:
    times: list[float] = []
    sizes: list[int] = []
    l4_protos: list[str] = []
    src_ips: list[str] = []
    syn_flags: list[int] = []
    ack_flags: list[int] = []

    def _to_bool_int(s: str) -> int:
        v = (s or "").strip().lower()
        return 1 if v in {"1", "true", "yes"} else 0

    for line in rows:
        # epoch\tlen\tip.src\tip.proto\ttcp.flags.syn\ttcp.flags.ack
        parts = line.split("\t")
        if len(parts) < 6:
            continue
        try:
            t = float(parts[0])
            ln = int(parts[1])
        except ValueError:
            continue

        ip_src = parts[2]
        ip_proto = parts[3]
        syn = _to_bool_int(parts[4])
        ack = _to_bool_int(parts[5])

        if ip_proto == "6":
            l4 = "TCP"
        elif ip_proto == "17":
            l4 = "UDP"
        elif ip_proto == "1":
            l4 = "ICMP"
        elif ip_proto:
            l4 = f"IP({ip_proto})"
        else:
            l4 = "OTHER"

        times.append(t)
        sizes.append(ln)
        src_ips.append(ip_src)
        l4_protos.append(l4)
        syn_flags.append(syn)
        ack_flags.append(ack)

    return _compute_stats(
        times=times,
        sizes=sizes,
        l4_protos=l4_protos,
        src_ips=src_ips,
        syn_flags=syn_flags,
        ack_flags=ack_flags,
    )


def _parse_tcpdump_rows(rows: list[str]) -> PcapStats:
    times: list[float] = []
    sizes: list[int] = []
    l4_protos: list[str] = []
    src_ips: list[str] = []
    syn_flags: list[int] = []
    ack_flags: list[int] = []

    for line in rows:
        if " IP " not in line and not line.startswith("IP "):
            continue
        parts = line.split()
        if not parts:
            continue
        timestamp = parts[0]
        if len(parts) > 1 and parts[0].count('-') == 2 and ':' in parts[1]:
            timestamp = parts[1]
        if "." in timestamp:
            base, frac = timestamp.split(".", 1)
        else:
            base, frac = timestamp, "0"
        try:
            h, m, s = map(int, base.split(':'))
            t = h * 3600 + m * 60 + s + int(frac[:6].ljust(6, '0')) / 1_000_000
        except ValueError:
            continue

        protocol = "OTHER"
        if "Flags" in line:
            protocol = "TCP"
        elif "UDP" in line:
            protocol = "UDP"
        elif "ICMP" in line:
            protocol = "ICMP"

        src_ip = ""
        if " > " in line:
            left = line.split(" > ", 1)[0]
            left = left.split()[-1]
            if "." in left:
                src_ip = left.rsplit(".", 1)[0]
            else:
                src_ip = left

        length = 0
        if " length " in line:
            try:
                length = int(line.rsplit(" length ", 1)[1].split()[0])
            except ValueError:
                length = 0

        flags_section = ""
        if "Flags [" in line:
            flags_section = line.split("Flags [", 1)[1].split("]", 1)[0]
        syn = 1 if "S" in flags_section else 0
        ack = 1 if "." in flags_section or "A" in flags_section else 0

        times.append(t)
        sizes.append(length)
        l4_protos.append(protocol)
        src_ips.append(src_ip)
        syn_flags.append(syn)
        ack_flags.append(ack)

    return _compute_stats(
        times=times,
        sizes=sizes,
        l4_protos=l4_protos,
        src_ips=src_ips,
        syn_flags=syn_flags,
        ack_flags=ack_flags,
    )


def extract_pcap_features(pcap_path: str | Path, *, max_packets: int | None = None) -> PcapStats:
    """Extract basic flow statistics from a PCAP.

    Features:
    - PPS (packets per second)
    - L4 protocol distribution (TCP/UDP/ICMP)
    - Source IP entropy (Shannon)
    - Avg packet size
    - SYN/ACK ratio (TCP)

    Implementation prefers `tshark` if available; falls back to `scapy`.
    """

    pcap = Path(pcap_path)
    if not pcap.exists():
        raise FileNotFoundError(str(pcap))

    proc = None
    tshark = shutil.which("tshark")
    if tshark:
        cmd = [
            tshark,
            "-r",
            str(pcap),
            "-T",
            "fields",
            "-E",
            "separator=\t",
            "-e",
            "frame.time_epoch",
            "-e",
            "frame.len",
            "-e",
            "ip.src",
            "-e",
            "ip.proto",
            "-e",
            "tcp.flags.syn",
            "-e",
            "tcp.flags.ack",
        ]
        if max_packets is not None and max_packets > 0:
            cmd.extend(["-c", str(max_packets)])

        proc = subprocess.run(cmd, check=False, capture_output=True, text=True)
    if proc is not None and proc.returncode == 0:
        rows = [ln for ln in proc.stdout.splitlines() if ln.strip()]
        return _parse_tshark_rows(rows)

    # If tshark fails due to file permission or environment, fall back to tcpdump output parsing.
    tcpdump = shutil.which("tcpdump")
    if tcpdump:
        proc2 = subprocess.run(
            [tcpdump, "-nn", "-tttt", "-r", str(pcap)],
            check=False,
            capture_output=True,
            text=True,
        )
        if proc2.returncode == 0:
            rows = [ln for ln in proc2.stdout.splitlines() if ln.strip()]
            return _parse_tcpdump_rows(rows)

    if proc.returncode != 0:
        raise RuntimeError(f"tshark failed: {proc.stderr.strip()}")

    # Fallback to scapy
    try:
        from scapy.layers.inet import IP, TCP, UDP, ICMP  # type: ignore
        from scapy.utils import PcapReader  # type: ignore
    except Exception as exc:  # pragma: no cover
        raise RuntimeError(
            "Neither 'tshark' nor 'tcpdump' nor 'scapy' is available. Install one of them: "
            "(1) sudo apt install tshark tcpdump   OR   (2) pip install scapy"
        ) from exc

    times: list[float] = []
    sizes: list[int] = []
    l4_protos: list[str] = []
    src_ips: list[str] = []
    syn_flags: list[int] = []
    ack_flags: list[int] = []

    with PcapReader(str(pcap)) as reader:
        for i, pkt in enumerate(reader):
            if max_packets is not None and max_packets > 0 and i >= max_packets:
                break

            try:
                times.append(float(pkt.time))
            except Exception:
                continue

            try:
                sizes.append(int(len(pkt)))
            except Exception:
                sizes.append(0)

            if IP in pkt:
                src_ips.append(str(pkt[IP].src))
            else:
                src_ips.append("")

            if TCP in pkt:
                l4_protos.append("TCP")
                flags = int(pkt[TCP].flags)
                syn_flags.append(1 if (flags & 0x02) else 0)
                ack_flags.append(1 if (flags & 0x10) else 0)
            elif UDP in pkt:
                l4_protos.append("UDP")
                syn_flags.append(0)
                ack_flags.append(0)
            elif ICMP in pkt:
                l4_protos.append("ICMP")
                syn_flags.append(0)
                ack_flags.append(0)
            else:
                l4_protos.append("OTHER")
                syn_flags.append(0)
                ack_flags.append(0)

    return _compute_stats(
        times=times,
        sizes=sizes,
        l4_protos=l4_protos,
        src_ips=src_ips,
        syn_flags=syn_flags,
        ack_flags=ack_flags,
    )


def format_human(stats: PcapStats) -> str:
    lines: list[str] = []
    lines.append("--- pcap features ---")
    lines.append(f"packets={stats.packets}")
    lines.append(f"duration_s={stats.duration_s:.6f}")
    lines.append(f"pps={stats.pps:.2f}")
    lines.append(f"avg_pkt_size={stats.avg_pkt_size:.1f}")
    lines.append(f"proto_dist={stats.proto_dist}")
    lines.append(f"src_ip_entropy={stats.src_ip_entropy:.4f}")
    lines.append(f"syn_count={stats.syn_count} ack_count={stats.ack_count}")
    if stats.syn_ack_ratio is None:
        lines.append("syn_ack_ratio=null")
    else:
        lines.append(f"syn_ack_ratio={stats.syn_ack_ratio:.4f}")
    return "\n".join(lines)


def format_json(stats: PcapStats) -> str:
    return json.dumps(stats.to_dict(), ensure_ascii=False, indent=2)
