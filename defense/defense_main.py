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

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return int(args.fn(args))


if __name__ == "__main__":
    raise SystemExit(main())