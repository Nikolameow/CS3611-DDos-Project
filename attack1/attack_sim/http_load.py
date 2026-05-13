from __future__ import annotations

import asyncio
import random
import time
from dataclasses import dataclass
from typing import Literal, Optional

from .guards import ensure_loopback_url
from .metrics import RunMetrics


Method = Literal["GET", "POST"]


@dataclass(frozen=True)
class HttpLoadConfig:
    url: str
    method: Method = "GET"
    duration_s: float = 10.0
    concurrency: int = 10
    rate: Optional[float] = 50.0  # requests/sec overall; None = unthrottled
    timeout_s: float = 2.0
    keepalive: bool = False
    path: str | None = None
    paths: list[str] | None = None
    body: bytes | None = None
    body_size_range: tuple[int, int] | None = None
    post_ratio: float = 0.0
    user_agents: list[str] | None = None
    jitter_ms: float = 0.0
    randomize_requests: bool = False
    content_type: str = "application/octet-stream"


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


async def _read_http_response(reader: asyncio.StreamReader) -> int:
    # Read headers
    headers_blob = await reader.readuntil(b"\r\n\r\n")

    # Parse status line
    first_line = headers_blob.split(b"\r\n", 1)[0]
    parts = first_line.split()
    status = 0
    if len(parts) >= 2:
        try:
            status = int(parts[1])
        except ValueError:
            status = 0

    # Parse headers (lower-cased keys)
    header_lines = headers_blob.split(b"\r\n")[1:]
    headers: dict[str, str] = {}
    for line in header_lines:
        if not line:
            continue
        if b":" not in line:
            continue
        k, v = line.split(b":", 1)
        headers[k.decode(errors="ignore").strip().lower()] = v.decode(errors="ignore").strip()

    # Consume body to keep stream in sync (needed for keep-alive)
    transfer_encoding = headers.get("transfer-encoding", "").lower()
    if "chunked" in transfer_encoding:
        while True:
            size_line = await reader.readuntil(b"\r\n")
            size_str = size_line.strip().split(b";", 1)[0]
            try:
                size = int(size_str, 16)
            except ValueError:
                size = 0
            if size == 0:
                # trailing CRLF after last chunk + optional trailers
                await reader.readuntil(b"\r\n\r\n")
                break
            await reader.readexactly(size)
            await reader.readexactly(2)  # CRLF
    else:
        content_length = headers.get("content-length")
        if content_length is not None:
            try:
                length = int(content_length)
            except ValueError:
                length = 0
            if length > 0:
                await reader.readexactly(length)
        else:
            # Unknown length; best-effort drain without blocking forever.
            # For keep-alive servers this is uncommon; for close-after-response it's fine.
            try:
                while True:
                    chunk = await asyncio.wait_for(reader.read(8192), timeout=0.1)
                    if not chunk:
                        break
            except asyncio.TimeoutError:
                pass

    return status


def _build_request(
    host: str,
    path: str,
    method: Method,
    body: bytes | None,
    content_type: str,
    keepalive: bool,
    user_agent: str,
) -> bytes:
    if not path.startswith("/"):
        path = "/" + path

    lines: list[bytes] = []
    lines.append(f"{method} {path} HTTP/1.1".encode())
    lines.append(f"Host: {host}".encode())
    lines.append(f"User-Agent: {user_agent}".encode())
    lines.append(b"Accept: */*")
    lines.append(b"Connection: keep-alive" if keepalive else b"Connection: close")

    if body is not None:
        lines.append(f"Content-Type: {content_type}".encode())
        lines.append(f"Content-Length: {len(body)}".encode())

    raw = b"\r\n".join(lines) + b"\r\n\r\n"
    if body is not None:
        raw += body
    return raw


def _random_body(size: int) -> bytes:
    return bytes(
        random.choice(b"abcdefghijklmnopqrstuvwxyz0123456789") for _ in range(size)
    )


def _choose_path(cfg: HttpLoadConfig, default_path: str = "/") -> str:
    if cfg.paths:
        return random.choice(cfg.paths)
    if cfg.path:
        return cfg.path
    return default_path or "/"


def _choose_method(cfg: HttpLoadConfig) -> Method:
    if cfg.randomize_requests and cfg.post_ratio > 0:
        return "POST" if random.random() < cfg.post_ratio else "GET"
    return cfg.method


def _choose_body(cfg: HttpLoadConfig, method: Method) -> bytes | None:
    if cfg.body is not None and not cfg.randomize_requests:
        return cfg.body

    if method == "POST":
        if cfg.body is not None:
            return cfg.body
        if cfg.body_size_range is not None:
            lo, hi = cfg.body_size_range
            if lo > hi:
                lo, hi = hi, lo
            size = random.randint(lo, hi)
            return _random_body(size)
        return b""
    return None


def _choose_user_agent(cfg: HttpLoadConfig) -> str:
    if cfg.user_agents:
        return random.choice(cfg.user_agents)
    return "attack-sim-local/1.0"


async def _single_request(
    host: str,
    port: int,
    request_bytes: bytes,
    timeout_s: float,
) -> int:
    reader: asyncio.StreamReader
    writer: asyncio.StreamWriter
    reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout_s)
    try:
        writer.write(request_bytes)
        await asyncio.wait_for(writer.drain(), timeout=timeout_s)
        status = await asyncio.wait_for(_read_http_response(reader), timeout=timeout_s)
        return status
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass


async def _per_request_worker(
    *,
    host: str,
    port: int,
    cfg: HttpLoadConfig,
    request_bytes: bytes | None,
    timeout_s: float,
    stop_evt: asyncio.Event,
    limiter: _RateLimiter | None,
    metrics: RunMetrics,
    default_path: str,
) -> None:
    while not stop_evt.is_set():
        if limiter is not None:
            await limiter.acquire()
        t0 = time.perf_counter()
        try:
            if cfg.randomize_requests:
                method = _choose_method(cfg)
                request_bytes = _build_request(
                    host=host,
                    path=_choose_path(cfg, default_path),
                    method=method,
                    body=_choose_body(cfg, method),
                    content_type=cfg.content_type,
                    keepalive=cfg.keepalive,
                    user_agent=_choose_user_agent(cfg),
                )
            assert request_bytes is not None
            status = await _single_request(host, port, request_bytes, timeout_s)
            latency_ms = (time.perf_counter() - t0) * 1000.0
            if 200 <= status < 500:
                metrics.record_ok(latency_ms)
            else:
                metrics.record_error()
        except asyncio.TimeoutError:
            metrics.record_timeout()
        except Exception:
            metrics.record_error()
        if cfg.jitter_ms > 0 and not stop_evt.is_set():
            await asyncio.sleep(random.uniform(0.0, cfg.jitter_ms / 1000.0))


async def _keepalive_worker(
    *,
    host: str,
    port: int,
    cfg: HttpLoadConfig,
    request_bytes: bytes | None,
    timeout_s: float,
    stop_evt: asyncio.Event,
    limiter: _RateLimiter | None,
    metrics: RunMetrics,
    default_path: str,
) -> None:
    reader: asyncio.StreamReader | None = None
    writer: asyncio.StreamWriter | None = None

    async def _connect() -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        return await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout_s)

    async def _close() -> None:
        nonlocal reader, writer
        if writer is not None:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
        reader, writer = None, None

    try:
        reader, writer = await _connect()
        while not stop_evt.is_set():
            if limiter is not None:
                await limiter.acquire()
            t0 = time.perf_counter()
            try:
                assert writer is not None and reader is not None
                if cfg.randomize_requests:
                    method = _choose_method(cfg)
                    request_bytes = _build_request(
                        host=host,
                        path=_choose_path(cfg, default_path),
                        method=method,
                        body=_choose_body(cfg, method),
                        content_type=cfg.content_type,
                        keepalive=cfg.keepalive,
                        user_agent=_choose_user_agent(cfg),
                    )
                assert request_bytes is not None
                writer.write(request_bytes)
                await asyncio.wait_for(writer.drain(), timeout=timeout_s)
                status = await asyncio.wait_for(_read_http_response(reader), timeout=timeout_s)
                latency_ms = (time.perf_counter() - t0) * 1000.0
                if 200 <= status < 500:
                    metrics.record_ok(latency_ms)
                else:
                    metrics.record_error()
            except (ConnectionError, BrokenPipeError, EOFError):
                metrics.record_error()
                await _close()
                reader, writer = await _connect()
            except asyncio.TimeoutError:
                metrics.record_timeout()
                await _close()
                reader, writer = await _connect()
            except Exception:
                metrics.record_error()
                await _close()
                reader, writer = await _connect()
            if cfg.jitter_ms > 0 and not stop_evt.is_set():
                await asyncio.sleep(random.uniform(0.0, cfg.jitter_ms / 1000.0))
    finally:
        await _close()


async def run_http_load(cfg: HttpLoadConfig) -> RunMetrics:
    if cfg.concurrency < 1:
        raise ValueError("concurrency must be >= 1")
    if cfg.concurrency > 200:
        raise ValueError("concurrency too high; max is 200")
    if cfg.duration_s <= 0:
        raise ValueError("duration_s must be > 0")

    parsed = ensure_loopback_url(cfg.url)
    host = parsed.hostname
    port = parsed.port or 80
    limiter = _RateLimiter(cfg.rate) if (cfg.rate is not None and cfg.rate > 0) else None
    metrics = RunMetrics()
    stop_evt = asyncio.Event()

    default_path = cfg.path or (parsed.path if parsed.path else "/")
    if cfg.randomize_requests:
        request_bytes = None
    else:
        request_bytes = _build_request(
            host=host,
            path=_choose_path(cfg, default_path),
            method=_choose_method(cfg),
            body=_choose_body(cfg, cfg.method),
            content_type=cfg.content_type,
            keepalive=cfg.keepalive,
            user_agent=_choose_user_agent(cfg),
        )

    async def _stopper() -> None:
        await asyncio.sleep(cfg.duration_s)
        stop_evt.set()

    workers = [
        asyncio.create_task(
            _keepalive_worker(
                host=host,
                port=port,
                cfg=cfg,
                request_bytes=request_bytes,
                timeout_s=cfg.timeout_s,
                stop_evt=stop_evt,
                limiter=limiter,
                metrics=metrics,
                default_path=default_path,
            )
            if cfg.keepalive
            else _per_request_worker(
                host=host,
                port=port,
                cfg=cfg,
                request_bytes=request_bytes,
                timeout_s=cfg.timeout_s,
                stop_evt=stop_evt,
                limiter=limiter,
                metrics=metrics,
                default_path=default_path,
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
