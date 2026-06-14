#!/usr/bin/env python3
"""Unified defense entry point for the Mininet DDoS lab."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
ATTACK1_DIR = PROJECT_ROOT / "attack1"
if str(ATTACK1_DIR) not in sys.path:
    sys.path.insert(0, str(ATTACK1_DIR))

from attack_sim.auto_block import AutoBlockConfig, AutoBlocker
from attack_sim.defense import (
    apply_commands,
    build_iptables_blacklist,
    build_iptables_rate_limit,
    build_nft_http_port_filter,
)
from attack_sim.live_block import LiveBlockConfig, LiveBlocker
from attack_sim.live_ml_block import LiveMlBlockConfig, LiveMlBlocker
from attack_sim.ml_block import MlBlockConfig, parse_whitelist, run_ml_block


def build_demo_rules(port: int, rate: float, burst: int) -> list[str]:
    """Build the baseline rules used by the topology demo."""
    rules: list[str] = []
    rules.extend(build_iptables_rate_limit(port=port, rate_per_sec=rate, burst=burst))
    rules.extend(build_nft_http_port_filter(port=port, rate_per_sec=rate))
    return rules


def build_commands(args: argparse.Namespace) -> list[str]:
    if args.mode == "rate-limit":
        return build_iptables_rate_limit(args.port, args.rate, burst=args.burst)
    if args.mode == "blacklist":
        if not args.ip:
            raise SystemExit("--ip is required for blacklist mode")
        return build_iptables_blacklist(args.ip)
    if args.mode == "nft-http":
        return build_nft_http_port_filter(port=args.port, rate_per_sec=args.rate)
    if args.mode == "demo":
        return build_demo_rules(args.port, args.rate, args.burst)
    raise SystemExit(f"unknown mode: {args.mode}")


def _cmd_rules(args: argparse.Namespace) -> int:
    commands = build_commands(args)
    apply_commands(commands, dry_run=not args.apply)
    return 0


def _cmd_auto_block(args: argparse.Namespace) -> int:
    cfg = AutoBlockConfig(
        log_file=args.log_file,
        threshold=args.threshold,
        window_s=args.window,
        dry_run=not args.apply,
    )
    print(f"Starting auto-block monitor on {args.log_file} (dry_run={cfg.dry_run})")
    try:
        AutoBlocker(cfg).run()
    except KeyboardInterrupt:
        print("Auto-block monitor stopped")
    return 0


def _cmd_live_block(args: argparse.Namespace) -> int:
    cfg = LiveBlockConfig(
        interface=args.interface,
        port=args.port,
        threshold=args.threshold,
        window_s=args.window,
        dry_run=not args.apply,
    )
    try:
        LiveBlocker(cfg).run()
    except KeyboardInterrupt:
        print("Live block monitor stopped")
    return 0


def _model_path_for_detector(detector: str, model: Path | None) -> Path:
    if model is not None:
        return model
    if detector == "kmeans":
        return Path("detection/models/kmeans_anomaly.joblib")
    return Path("detection/models/ddos_mlp.joblib")


def _cmd_ml_block(args: argparse.Namespace) -> int:
    cfg = MlBlockConfig(
        detector=args.detector,
        model_path=_model_path_for_detector(args.detector, args.model),
        features_path=args.features,
        ip=args.ip,
        min_bad_windows=args.min_bad_windows,
        whitelist=parse_whitelist(args.whitelist),
        dry_run=not args.apply,
    )
    run_ml_block(cfg)
    return 0


def _cmd_live_ml_block(args: argparse.Namespace) -> int:
    cfg = LiveMlBlockConfig(
        detector=args.detector,
        model_path=_model_path_for_detector(args.detector, args.model),
        interface=args.interface,
        port=args.port,
        window_s=args.window,
        min_bad_windows=args.min_bad_windows,
        min_packets=args.min_packets,
        whitelist=parse_whitelist(args.whitelist),
        dry_run=not args.apply,
    )
    try:
        LiveMlBlocker(cfg).run()
    except KeyboardInterrupt:
        print("Live ML block monitor stopped")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="DDoS defense rule manager for the lab topology.")
    sub = parser.add_subparsers(dest="cmd", required=True)

    rules = sub.add_parser("rules", help="Print or apply iptables/nftables defense rules")
    rules.add_argument("--mode", choices=["rate-limit", "blacklist", "nft-http", "demo"], default="demo")
    rules.add_argument("--port", type=int, default=8080)
    rules.add_argument("--rate", type=float, default=50.0)
    rules.add_argument("--burst", type=int, default=50)
    rules.add_argument("--ip", default=None)
    rules.add_argument("--apply", action="store_true", help="Apply rules instead of dry-run printing them")
    rules.set_defaults(fn=_cmd_rules)

    block = sub.add_parser("auto-block", help="Monitor a log file and blacklist abusive source IPs")
    block.add_argument("--log-file", required=True)
    block.add_argument("--threshold", type=int, default=1000)
    block.add_argument("--window", type=int, default=60)
    block.add_argument("--apply", action="store_true", help="Actually apply blacklist rules")
    block.set_defaults(fn=_cmd_auto_block)

    live = sub.add_parser("live-block", help="Monitor tcpdump traffic and blacklist abusive source IPs")
    live.add_argument("--interface", required=True)
    live.add_argument("--port", type=int, default=8080)
    live.add_argument("--threshold", type=int, default=1000)
    live.add_argument("--window", type=int, default=60)
    live.add_argument("--apply", action="store_true", help="Actually apply blacklist rules")
    live.set_defaults(fn=_cmd_live_block)

    ml = sub.add_parser("ml-block", help="Use a trained ML detector to decide whether to blacklist a source IP")
    ml.add_argument("--detector", choices=["mlp", "kmeans"], default="mlp")
    ml.add_argument("--features", type=Path, default=Path("detection/data/features.csv"))
    ml.add_argument("--model", type=Path, default=None)
    ml.add_argument("--ip", required=True, help="Source IP to blacklist when ML detection crosses the threshold")
    ml.add_argument("--min-bad-windows", type=int, default=1)
    ml.add_argument("--whitelist", default="", help="Comma-separated source IPs that must never be blacklisted")
    ml.add_argument("--apply", action="store_true", help="Actually apply blacklist rules")
    ml.set_defaults(fn=_cmd_ml_block)

    live_ml = sub.add_parser(
        "live-ml-block",
        help="Monitor tcpdump traffic, classify per-source windows with ML, and blacklist attack sources",
    )
    live_ml.add_argument("--detector", choices=["mlp", "kmeans"], default="mlp")
    live_ml.add_argument("--model", type=Path, default=None)
    live_ml.add_argument("--interface", required=True)
    live_ml.add_argument("--port", type=int, default=8080)
    live_ml.add_argument("--window", type=float, default=1.0)
    live_ml.add_argument("--min-bad-windows", type=int, default=1)
    live_ml.add_argument("--min-packets", type=int, default=1)
    live_ml.add_argument("--whitelist", default="", help="Comma-separated source IPs that must never be blacklisted")
    live_ml.add_argument("--apply", action="store_true", help="Actually apply blacklist rules")
    live_ml.set_defaults(fn=_cmd_live_ml_block)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return int(args.fn(args))


if __name__ == "__main__":
    raise SystemExit(main())
