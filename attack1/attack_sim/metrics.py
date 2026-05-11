from __future__ import annotations

from dataclasses import dataclass, field
import statistics
import time
from typing import Iterable


@dataclass
class RunMetrics:
    start_ts: float = field(default_factory=time.perf_counter)
    sent: int = 0
    ok: int = 0
    errors: int = 0
    timeouts: int = 0
    latencies_ms: list[float] = field(default_factory=list)

    def record_ok(self, latency_ms: float) -> None:
        self.sent += 1
        self.ok += 1
        self.latencies_ms.append(latency_ms)

    def record_error(self) -> None:
        self.sent += 1
        self.errors += 1

    def record_timeout(self) -> None:
        self.sent += 1
        self.timeouts += 1

    def elapsed_s(self) -> float:
        return max(1e-9, time.perf_counter() - self.start_ts)

    def rps(self) -> float:
        return self.sent / self.elapsed_s()


def percentile(values: Iterable[float], p: float) -> float | None:
    data = sorted(values)
    if not data:
        return None
    if p <= 0:
        return data[0]
    if p >= 100:
        return data[-1]
    k = (len(data) - 1) * (p / 100.0)
    f = int(k)
    c = min(f + 1, len(data) - 1)
    if f == c:
        return data[f]
    d0 = data[f] * (c - k)
    d1 = data[c] * (k - f)
    return d0 + d1


def summarize_latencies_ms(latencies_ms: list[float]) -> dict[str, float]:
    if not latencies_ms:
        return {}
    out: dict[str, float] = {}
    out["avg"] = float(statistics.fmean(latencies_ms))
    out["p50"] = float(percentile(latencies_ms, 50) or 0.0)
    out["p95"] = float(percentile(latencies_ms, 95) or 0.0)
    out["p99"] = float(percentile(latencies_ms, 99) or 0.0)
    out["max"] = float(max(latencies_ms))
    return out
