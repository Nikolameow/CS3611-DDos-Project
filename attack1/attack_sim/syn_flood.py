from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass
from typing import Optional

from .guards import ensure_loopback_host
from .metrics import RunMetrics


@dataclass(frozen=True)
class SynFloodConfig:
    host: str = "127.0.0.1"
    port: int = 8080
    duration_s: float = 10.0
    concurrency: int = 50
    rate: Optional[float] = 500.0
    timeout_s: float = 0.5
    keep_open_s: float = 0.05


class _RateLimiter:
    def __init__(self, rate: float):
        self._rate = rate
        self._lock = asyncio.Lock()
        self._next_ts = time.perf_counter()

    async def acquire(self) -> None:
        async with self._lock:
            now = time.perf_counter()
            if now < self._next_ts:
                await asyncio.sleep(self._next_ts - now)
            self._next_ts = max(self._next_ts, time.perf_counter()) + (1.0 / self._rate)


async def _worker(
    host: str,
    port: int,
    timeout_s: float,
    keep_open_s: float,
    stop_evt: asyncio.Event,
    limiter: _RateLimiter | None,
    metrics: RunMetrics,
) -> None:
    while not stop_evt.is_set():
        if limiter is not None:
            await limiter.acquire()
        t0 = time.perf_counter()
        try:
            reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout_s)
            await asyncio.sleep(keep_open_s)
            writer.close()
            await writer.wait_closed()
            latency_ms = (time.perf_counter() - t0) * 1000.0
            metrics.record_ok(latency_ms)
        except asyncio.TimeoutError:
            metrics.record_timeout()
        except Exception:
            metrics.record_error()


async def run_syn_flood(cfg: SynFloodConfig) -> RunMetrics:
    if cfg.concurrency < 1:
        raise ValueError("concurrency must be >= 1")
    if cfg.concurrency > 200:
        raise ValueError("concurrency too high; max is 200")
    if cfg.duration_s <= 0:
        raise ValueError("duration_s must be > 0")

    ensure_loopback_host(cfg.host)
    limiter = _RateLimiter(cfg.rate) if (cfg.rate is not None and cfg.rate > 0) else None
    metrics = RunMetrics()
    stop_evt = asyncio.Event()

    async def _stopper() -> None:
        await asyncio.sleep(cfg.duration_s)
        stop_evt.set()

    workers = [
        asyncio.create_task(
            _worker(
                cfg.host,
                cfg.port,
                cfg.timeout_s,
                cfg.keep_open_s,
                stop_evt,
                limiter,
                metrics,
            )
        )
        for _ in range(cfg.concurrency)
    ]

    stopper = asyncio.create_task(_stopper())
    try:
        await asyncio.gather(*workers, stopper)
    finally:
        stop_evt.set()
        for task in workers:
            task.cancel()
        await asyncio.gather(*workers, return_exceptions=True)
        await asyncio.gather(stopper, return_exceptions=True)

    return metrics
