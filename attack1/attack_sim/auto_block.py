from __future__ import annotations

import os
import re
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

from .defense import apply_commands, build_iptables_blacklist


IP_PATTERN = re.compile(r"(?:SRC|src)=([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)")


@dataclass(frozen=True)
class AutoBlockConfig:
    log_file: str
    threshold: int = 100
    window_s: int = 60
    dry_run: bool = True


class AutoBlocker:
    def __init__(self, cfg: AutoBlockConfig) -> None:
        self.cfg = cfg
        self.counts: dict[str, list[float]] = {}
        self.blocked: set[str] = set()
        self.file_path = Path(cfg.log_file)

    def _parse_ip(self, line: str) -> str | None:
        match = IP_PATTERN.search(line)
        if match:
            return match.group(1)
        return None

    def _add_sample(self, ip: str, ts: float) -> bool:
        samples = self.counts.setdefault(ip, [])
        samples.append(ts)
        cutoff = ts - self.cfg.window_s
        while samples and samples[0] < cutoff:
            samples.pop(0)
        return len(samples) >= self.cfg.threshold

    def _block_ip(self, ip: str) -> None:
        if ip in self.blocked:
            return
        self.blocked.add(ip)
        commands = build_iptables_blacklist(ip)
        apply_commands(commands, dry_run=self.cfg.dry_run)

    def run(self) -> None:
        if not self.file_path.exists():
            raise FileNotFoundError(str(self.file_path))
        with open(self.file_path, "r", encoding="utf-8", errors="replace") as fh:
            fh.seek(0, os.SEEK_END)
            while True:
                line = fh.readline()
                if not line:
                    time.sleep(0.5)
                    continue
                ip = self._parse_ip(line)
                if not ip or ip in self.blocked:
                    continue
                if self._add_sample(ip, time.time()):
                    self._block_ip(ip)
