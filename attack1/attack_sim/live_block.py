from __future__ import annotations

import re
import subprocess
import time
from dataclasses import dataclass

from .defense import apply_commands, build_iptables_blacklist


TCPDUMP_IP_PATTERN = re.compile(r"\bIP\s+([0-9]+(?:\.[0-9]+){3})(?:\.[0-9]+)?\s+>\s+")


@dataclass(frozen=True)
class LiveBlockConfig:
    interface: str
    port: int = 8080
    threshold: int = 1000
    window_s: int = 60
    dry_run: bool = True
    tcpdump: str = "tcpdump"


class LiveBlocker:
    def __init__(self, cfg: LiveBlockConfig) -> None:
        self.cfg = cfg
        self.samples: dict[str, list[float]] = {}
        self.blocked: set[str] = set()

    def _add_sample(self, ip: str, ts: float) -> bool:
        items = self.samples.setdefault(ip, [])
        items.append(ts)
        cutoff = ts - self.cfg.window_s
        while items and items[0] < cutoff:
            items.pop(0)
        return len(items) >= self.cfg.threshold

    def _block_ip(self, ip: str) -> None:
        if ip in self.blocked:
            return
        self.blocked.add(ip)
        print(f"[live-block] threshold exceeded for {ip}; blocking")
        apply_commands(build_iptables_blacklist(ip), dry_run=self.cfg.dry_run)

    def run(self) -> None:
        command = [
            self.cfg.tcpdump,
            "-l",
            "-nn",
            "-i",
            self.cfg.interface,
            f"tcp and dst port {self.cfg.port}",
        ]
        print(f"[live-block] starting: {' '.join(command)} dry_run={self.cfg.dry_run}")
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
                match = TCPDUMP_IP_PATTERN.search(line)
                if not match:
                    continue
                ip = match.group(1)
                if ip in self.blocked:
                    continue
                if self._add_sample(ip, time.time()):
                    self._block_ip(ip)
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                proc.kill()
