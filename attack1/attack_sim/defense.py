from __future__ import annotations

import subprocess
import shlex
from typing import Iterable


def _quote_nft_rule(rule: str) -> str:
    return shlex.quote(rule)


def build_iptables_rate_limit(port: int, rate_per_sec: float, burst: int = 50) -> list[str]:
    return [
        f"iptables -A INPUT -p tcp --dport {port} -m conntrack --ctstate NEW -m hashlimit --hashlimit-name ddos_src_{port} --hashlimit-mode srcip --hashlimit-upto {rate_per_sec}/second --hashlimit-burst {burst} -j ACCEPT",
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
    chain_spec = _quote_nft_rule("{ type filter hook input priority 0 ; policy accept ; }")
    return [
        f"nft add table {table} ddos_filter 2>/dev/null || true",
        f"nft add chain {table} ddos_filter {chain} {chain_spec} 2>/dev/null || true",
        f"nft add rule {table} ddos_filter {chain} {_quote_nft_rule(f'tcp dport {port} ct state invalid drop')}",
        f"nft add rule {table} ddos_filter {chain} {_quote_nft_rule(f'tcp dport {port} tcp flags & (fin|syn|rst|ack) == 0 drop')}",
        f"nft add rule {table} ddos_filter {chain} {_quote_nft_rule(f'udp dport {port} drop')}",
        f"nft add rule {table} ddos_filter {chain} {_quote_nft_rule(f'tcp dport {port} ct state new limit rate over {rate_per_sec}/second drop')}",
        f"nft add rule {table} ddos_filter {chain} {_quote_nft_rule(f'tcp dport {port} accept')}",
    ]


def apply_commands(commands: Iterable[str], dry_run: bool = True) -> None:
    for cmd in commands:
        print(cmd)
        if not dry_run:
            subprocess.run(cmd, shell=True, check=True)
