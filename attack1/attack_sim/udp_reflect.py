from __future__ import annotations

import asyncio
import socket
import threading
import time
from dataclasses import dataclass
from typing import Optional

from .guards import ensure_loopback_host
from .metrics import RunMetrics


@dataclass(frozen=True)
class UdpReflectConfig:
    host: str = "127.0.0.1"
    server_port: int = 4000
    client_port: int = 4001
    duration_s: float = 10.0
    rate: Optional[float] = 200.0
    timeout_s: float = 1.0
    request_size: int = 32
    response_size: int = 512


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


def _start_reflector_server(host: str, port: int, response_size: int, stop_evt: threading.Event) -> threading.Thread:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((host, port))
    sock.settimeout(0.5)
    payload = b"R" * response_size

    def _serve() -> None:
        try:
            while not stop_evt.is_set():
                try:
                    data, addr = sock.recvfrom(65535)
                except socket.timeout:
                    continue
                try:
                    sock.sendto(payload, addr)
                except Exception:
                    pass
        finally:
            sock.close()

    thread = threading.Thread(target=_serve, daemon=True)
    thread.start()
    return thread


async def run_udp_reflect(cfg: UdpReflectConfig) -> tuple[RunMetrics, int]:
    if cfg.duration_s <= 0:
        raise ValueError("duration_s must be > 0")
    if cfg.rate is not None and cfg.rate <= 0:
        raise ValueError("rate must be > 0 or None")

    ensure_loopback_host(cfg.host)
    limiter = _RateLimiter(cfg.rate) if cfg.rate is not None else None
    metrics = RunMetrics()
    total_response_bytes = 0
    stop_evt = asyncio.Event()
    thread_stop = threading.Event()
    server_thread = _start_reflector_server(cfg.host, cfg.server_port, cfg.response_size, thread_stop)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((cfg.host, cfg.client_port))
    sock.setblocking(False)
    loop = asyncio.get_running_loop()

    async def _worker() -> None:
        nonlocal total_response_bytes
        while not stop_evt.is_set():
            if limiter is not None:
                await limiter.acquire()
            t0 = time.perf_counter()
            request_payload = b"Q" * cfg.request_size
            try:
                await loop.sock_sendto(sock, request_payload, (cfg.host, cfg.server_port))
                data = await asyncio.wait_for(loop.sock_recv(sock, 65535), timeout=cfg.timeout_s)
                latency_ms = (time.perf_counter() - t0) * 1000.0
                metrics.record_ok(latency_ms)
                total_response_bytes += len(data)
            except asyncio.TimeoutError:
                metrics.record_timeout()
            except Exception:
                metrics.record_error()

    async def _stopper() -> None:
        await asyncio.sleep(cfg.duration_s)
        stop_evt.set()

    worker = asyncio.create_task(_worker())
    stopper = asyncio.create_task(_stopper())
    try:
        await asyncio.gather(worker, stopper)
    finally:
        stop_evt.set()
        thread_stop.set()
        worker.cancel()
        await asyncio.gather(worker, return_exceptions=True)
        await asyncio.gather(stopper, return_exceptions=True)
        sock.close()
        server_thread.join(timeout=1.0)

    return metrics, total_response_bytes
