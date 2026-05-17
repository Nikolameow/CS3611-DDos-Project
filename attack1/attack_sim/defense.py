from __future__ import annotations

import subprocess
from typing import Iterable


def build_iptables_rate_limit(port: int, rate_per_sec: float, burst: int = 50) -> list[str]:
    return [
        f"iptables -A INPUT -p tcp --dport {port} -m conntrack --ctstate NEW -m limit --limit {rate_per_sec}/second --limit-burst {burst} -j ACCEPT",
        f"iptables -A INPUT -p tcp --dport {port} -j DROP",
    ]


def build_iptables_blacklist(ip: str) -> list[str]:
    return [
        f"iptables -I INPUT -s {ip} -j DROP",
    ]


def build_nft_http_port_filter(
    table: str = "inet",
    chain: str = "input",
    port: int = 80,
    rate_per_sec: float = 50.0,
) -> list[str]:
    return [
        f"nft add table {table} ddos_filter",
        f"nft add chain {table} ddos_filter {chain} {{ type filter hook input priority 0 ; policy accept ; }}",
        f"nft add rule {table} ddos_filter {chain} tcp dport {port} ct state new limit rate {rate_per_sec}/second accept",
        f"nft add rule {table} ddos_filter {chain} tcp dport {port} drop",
    ]


def apply_commands(commands: Iterable[str], dry_run: bool = True) -> None:
    for cmd in commands:
        print(cmd)
        if not dry_run:
            subprocess.run(cmd, shell=True, check=True)
