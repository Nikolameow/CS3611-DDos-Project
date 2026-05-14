from __future__ import annotations

import argparse
import asyncio

from .demo_server import serve
from .capture_http import CaptureHttpConfig, capture_http_to_pcap
from .defense import apply_commands, build_iptables_blacklist, build_iptables_rate_limit, build_nft_http_port_filter
from .auto_block import AutoBlockConfig, AutoBlocker
from .http_load import HttpLoadConfig, run_http_load
from .metrics import summarize_latencies_ms


def _parse_csv(value: str | None) -> list[str] | None:
    if value is None:
        return None
    return [item.strip() for item in value.split(",") if item.strip()]


def _parse_size_range(value: str | None) -> tuple[int, int] | None:
    if value is None:
        return None
    sep = "," if "," in value else "-"
    parts = [item.strip() for item in value.split(sep, 1)]
    if len(parts) != 2:
        raise argparse.ArgumentTypeError("body size range must be MIN,MAX or MIN-MAX")
    return int(parts[0]), int(parts[1])


from .pcap_features import extract_pcap_features, format_human, format_json
from .pcap_synth import (
    NormalPcapConfig,
    ReflectPcapConfig,
    SynPcapConfig,
    generate_normal_http_pcap,
    generate_udp_reflect_spoof_pcap,
    generate_syn_spoof_pcap,
)
from .syn_flood import SynFloodConfig, run_syn_flood
from .udp_reflect import UdpReflectConfig, run_udp_reflect


def _cmd_demo_server(args: argparse.Namespace) -> int:
    serve(host=args.host, port=args.port)
    return 0


def _cmd_http(args: argparse.Namespace) -> int:
    body = args.body.encode() if args.body is not None else None
    cfg = HttpLoadConfig(
        url=args.url,
        method=args.method,
        duration_s=args.duration,
        concurrency=args.concurrency,
        rate=args.rate,
        timeout_s=args.timeout,
        keepalive=args.keepalive,
        path=args.path,
        paths=_parse_csv(args.paths),
        body=body,
        body_size_range=_parse_size_range(args.body_size_range),
        post_ratio=args.post_ratio,
        user_agents=_parse_csv(args.user_agents),
        jitter_ms=args.jitter_ms,
        randomize_requests=args.randomize,
        content_type=args.content_type,
    )

    metrics = asyncio.run(run_http_load(cfg))
    summary = summarize_latencies_ms(metrics.latencies_ms)

    print("--- run summary ---")
    print(f"sent={metrics.sent} ok={metrics.ok} errors={metrics.errors} timeouts={metrics.timeouts}")
    print(f"elapsed_s={metrics.elapsed_s():.2f} rps={metrics.rps():.1f}")
    if summary:
        print(
            "lat_ms="
            + " ".join(
                [
                    f"avg:{summary['avg']:.2f}",
                    f"p50:{summary['p50']:.2f}",
                    f"p95:{summary['p95']:.2f}",
                    f"p99:{summary['p99']:.2f}",
                    f"max:{summary['max']:.2f}",
                ]
            )
        )
    return 0


def _cmd_pcap_features(args: argparse.Namespace) -> int:
    stats = extract_pcap_features(args.pcap, max_packets=args.max_packets)
    if args.json:
        print(format_json(stats))
    else:
        print(format_human(stats))
    return 0


def _cmd_normal_http(args: argparse.Namespace) -> int:
    paths = _parse_csv(args.paths) or ["/", "/status", "/api/v1/data", "/search?q=test", "/login", "/submit"]
    user_agents = _parse_csv(args.user_agents) or [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
        "curl/7.85.0",
        "Python/3.11 aiohttp",
    ]
    cfg = HttpLoadConfig(
        url=args.url,
        duration_s=args.duration,
        concurrency=args.concurrency,
        rate=args.rate,
        timeout_s=args.timeout,
        keepalive=args.keepalive,
        paths=paths,
        body_size_range=_parse_size_range(args.body_size_range) or (0, args.max_body_size),
        post_ratio=args.post_ratio,
        user_agents=user_agents,
        jitter_ms=args.jitter_ms,
        randomize_requests=True,
        content_type=args.content_type,
    )

    metrics = asyncio.run(run_http_load(cfg))
    summary = summarize_latencies_ms(metrics.latencies_ms)

    print("--- normal traffic run summary ---")
    print(f"sent={metrics.sent} ok={metrics.ok} errors={metrics.errors} timeouts={metrics.timeouts}")
    print(f"elapsed_s={metrics.elapsed_s():.2f} rps={metrics.rps():.1f}")
    if summary:
        print(
            "lat_ms="
            + " ".join(
                [
                    f"avg:{summary['avg']:.2f}",
                    f"p50:{summary['p50']:.2f}",
                    f"p95:{summary['p95']:.2f}",
                    f"p99:{summary['p99']:.2f}",
                    f"max:{summary['max']:.2f}",
                ]
            )
        )
    return 0


def _cmd_capture_http(args: argparse.Namespace) -> int:
    cfg = CaptureHttpConfig(
        host=args.host,
        port=args.port,
        duration_s=args.duration,
        concurrency=args.concurrency,
        rate=args.rate,
        keepalive=args.keepalive,
        pcap_path=args.pcap,
    )
    pcap = capture_http_to_pcap(cfg)
    print(str(pcap))
    return 0


def _cmd_spoofed_syn(args: argparse.Namespace) -> int:
    cfg = SynPcapConfig(
        target_ip=args.target,
        target_port=args.port,
        packet_count=args.packets,
        pcap_path=args.pcap,
    )
    pcap = generate_syn_spoof_pcap(cfg)
    print(str(pcap))
    return 0


def _cmd_spoofed_udp_reflect(args: argparse.Namespace) -> int:
    cfg = ReflectPcapConfig(
        target_ip=args.target,
        target_port=args.port,
        packet_count=args.packets,
        request_size=args.request_size,
        response_size=args.response_size,
        pcap_path=args.pcap,
    )
    pcap = generate_udp_reflect_spoof_pcap(cfg)
    print(str(pcap))
    return 0


def _cmd_normal_http_pcap(args: argparse.Namespace) -> int:
    cfg = NormalPcapConfig(
        server_ip=args.server,
        server_port=args.port,
        session_count=args.sessions,
        pcap_path=args.pcap,
    )
    pcap = generate_normal_http_pcap(cfg)
    print(str(pcap))
    return 0


def _cmd_syn(args: argparse.Namespace) -> int:
    cfg = SynFloodConfig(
        host=args.host,
        port=args.port,
        duration_s=args.duration,
        concurrency=args.concurrency,
        rate=args.rate,
        timeout_s=args.timeout,
        keep_open_s=args.keep_open,
    )
    metrics = asyncio.run(run_syn_flood(cfg))
    summary = summarize_latencies_ms(metrics.latencies_ms)
    print("--- tcp connection flood-style summary ---")
    print(f"sent={metrics.sent} ok={metrics.ok} errors={metrics.errors} timeouts={metrics.timeouts}")
    print(f"elapsed_s={metrics.elapsed_s():.2f} rps={metrics.rps():.1f}")
    if summary:
        print(
            "lat_ms="
            + " ".join(
                [
                    f"avg:{summary['avg']:.2f}",
                    f"p50:{summary['p50']:.2f}",
                    f"p95:{summary['p95']:.2f}",
                    f"p99:{summary['p99']:.2f}",
                    f"max:{summary['max']:.2f}",
                ]
            )
        )
    return 0


def _cmd_udp_reflect(args: argparse.Namespace) -> int:
    cfg = UdpReflectConfig(
        host=args.host,
        server_port=args.server_port,
        client_port=args.client_port,
        duration_s=args.duration,
        rate=args.rate,
        timeout_s=args.timeout,
        request_size=args.request_size,
        response_size=args.response_size,
    )
    metrics, total_response_bytes = asyncio.run(run_udp_reflect(cfg))
    summary = summarize_latencies_ms(metrics.latencies_ms)
    print("--- udp reflector summary ---")
    print(f"requests={metrics.sent} ok={metrics.ok} errors={metrics.errors} timeouts={metrics.timeouts}")
    print(f"elapsed_s={metrics.elapsed_s():.2f} rps={metrics.rps():.1f}")
    print(f"response_bytes={total_response_bytes}")
    if metrics.sent:
        print(f"avg_amplification={total_response_bytes / (metrics.sent * cfg.request_size):.2f}")
    if summary:
        print(
            "lat_ms="
            + " ".join(
                [
                    f"avg:{summary['avg']:.2f}",
                    f"p50:{summary['p50']:.2f}",
                    f"p95:{summary['p95']:.2f}",
                    f"p99:{summary['p99']:.2f}",
                    f"max:{summary['max']:.2f}",
                ]
            )
        )
    return 0


def _cmd_defense(args: argparse.Namespace) -> int:
    if args.mode == "rate-limit":
        commands = build_iptables_rate_limit(args.port, args.rate, burst=args.burst)
    elif args.mode == "blacklist":
        if not args.ip:
            raise SystemExit("--ip is required for blacklist mode")
        commands = build_iptables_blacklist(args.ip)
    else:
        commands = build_nft_http_port_filter(port=args.port)

    apply_commands(commands, dry_run=not args.apply)
    return 0


def _cmd_auto_block(args: argparse.Namespace) -> int:
    cfg = AutoBlockConfig(
        log_file=args.log_file,
        threshold=args.threshold,
        window=args.window,
        dry_run=not args.apply,
    )
    blocker = AutoBlocker(cfg)
    print(f"Starting auto-block monitor on {args.log_file} (dry_run={cfg.dry_run})")
    try:
        blocker.run()
    except KeyboardInterrupt:
        print("Auto-block monitor stopped by user")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="attack_sim",
        description="Local-only traffic generator for defensive testing.",
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("demo-server", help="Start a local demo HTTP server")
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=8080)
    s.set_defaults(_fn=_cmd_demo_server)

    h = sub.add_parser("http", help="Generate local-only HTTP load")
    h.add_argument("--url", required=True, help="Must be http://localhost/127.0.0.1/::1")
    h.add_argument("--path", default=None, help="Optional request path override")
    h.add_argument("--paths", default=None, help="Comma-separated list of URL paths to randomize")
    h.add_argument("--method", choices=["GET", "POST"], default="GET")
    h.add_argument("--post-ratio", type=float, default=0.0, help="Fraction of randomized requests to use POST")
    h.add_argument("--body", default=None)
    h.add_argument("--body-size-range", default=None, help="Random request body size range, e.g. 0,128 or 0-128")
    h.add_argument("--user-agents", default=None, help="Comma-separated list of User-Agent values to rotate")
    h.add_argument("--jitter-ms", type=float, default=0.0, help="Add random jitter between requests")
    h.add_argument("--randomize", action="store_true", help="Randomize request path/method/body/user-agent per request")
    h.add_argument("--duration", type=float, default=10.0)
    h.add_argument("--concurrency", type=int, default=10)
    h.add_argument("--rate", type=float, default=50.0, help="Requests/sec overall; set <=0 for unthrottled")
    h.add_argument("--timeout", type=float, default=2.0)
    h.add_argument("--keepalive", action="store_true")
    h.add_argument("--content-type", default="text/plain")
    h.set_defaults(_fn=_cmd_http)

    n = sub.add_parser("normal-http", help="Generate benign-style HTTP traffic for mixed flow datasets")
    n.add_argument("--url", required=True, help="Must be http://localhost/127.0.0.1/::1")
    n.add_argument("--paths", default=None, help="Comma-separated list of normal URL paths")
    n.add_argument("--duration", type=float, default=10.0)
    n.add_argument("--concurrency", type=int, default=10)
    n.add_argument("--rate", type=float, default=20.0, help="Requests/sec overall; set <=0 for unthrottled")
    n.add_argument("--timeout", type=float, default=2.0)
    n.add_argument("--keepalive", action="store_true")
    n.add_argument("--post-ratio", type=float, default=0.2, help="Fraction of requests that use POST")
    n.add_argument("--body-size-range", default=None, help="Random benign request body size range, e.g. 0,256")
    n.add_argument("--max-body-size", type=int, default=256, help="Maximum random body size when no explicit range is provided")
    n.add_argument("--user-agents", default=None, help="Comma-separated list of User-Agent values to rotate")
    n.add_argument("--jitter-ms", type=float, default=25.0, help="Add random jitter between benign requests")
    n.add_argument("--content-type", default="text/plain")
    n.set_defaults(_fn=_cmd_normal_http)

    f = sub.add_parser("pcap-features", help="Extract PPS/protocol/IP-entropy/SYN-ACK stats from a PCAP")
    f.add_argument("--pcap", required=True, help="Path to .pcap/.pcapng")
    f.add_argument("--max-packets", type=int, default=None)
    f.add_argument("--json", action="store_true")
    f.set_defaults(_fn=_cmd_pcap_features)

    c = sub.add_parser("capture-http", help="Capture a loopback HTTP flood to PCAP (requires sudo)")
    c.add_argument("--host", default="127.0.0.1")
    c.add_argument("--port", type=int, default=8080)
    c.add_argument("--duration", type=float, default=3.0)
    c.add_argument("--concurrency", type=int, default=20)
    c.add_argument("--rate", type=float, default=200.0)
    c.add_argument("--keepalive", action="store_true")
    c.add_argument("--pcap", default="/tmp/attack_sim_loopback.pcap")
    c.set_defaults(_fn=_cmd_capture_http)

    t = sub.add_parser("syn", help="Generate local-only TCP connection flood to localhost (not raw SYN packets)")
    t.add_argument("--host", default="127.0.0.1")
    t.add_argument("--port", type=int, default=8080)
    t.add_argument("--duration", type=float, default=10.0)
    t.add_argument("--concurrency", type=int, default=100)
    t.add_argument("--rate", type=float, default=500.0)
    t.add_argument("--timeout", type=float, default=0.5)
    t.add_argument("--keep-open", type=float, default=0.05, help="Keep each connection open briefly")
    t.set_defaults(_fn=_cmd_syn)

    u = sub.add_parser("udp-reflect", help="Run a local UDP reflector and client to simulate amplification patterns")
    u.add_argument("--host", default="127.0.0.1")
    u.add_argument("--server-port", type=int, default=4000)
    u.add_argument("--client-port", type=int, default=4001)
    u.add_argument("--duration", type=float, default=10.0)
    u.add_argument("--rate", type=float, default=200.0)
    u.add_argument("--timeout", type=float, default=1.0)
    u.add_argument("--request-size", type=int, default=32)
    u.add_argument("--response-size", type=int, default=512)
    u.set_defaults(_fn=_cmd_udp_reflect)

    ss = sub.add_parser("spoofed-syn", help="Generate a local PCAP of SYN packets with spoofed source IPs")
    ss.add_argument("--target", default="127.0.0.1")
    ss.add_argument("--port", type=int, default=8080)
    ss.add_argument("--packets", type=int, default=1000)
    ss.add_argument("--pcap", default="/tmp/syn_spoof.pcap")
    ss.set_defaults(_fn=_cmd_spoofed_syn)

    su = sub.add_parser("spoofed-udp-reflect", help="Generate a local PCAP of UDP reflect traffic with spoofed source IPs")
    su.add_argument("--target", default="127.0.0.1")
    su.add_argument("--port", type=int, default=53)
    su.add_argument("--packets", type=int, default=500)
    su.add_argument("--request-size", type=int, default=32)
    su.add_argument("--response-size", type=int, default=256)
    su.add_argument("--pcap", default="/tmp/udp_reflect_spoof.pcap")
    su.set_defaults(_fn=_cmd_spoofed_udp_reflect)

    n = sub.add_parser("normal-http-pcap", help="Generate a benign TCP/HTTP-like PCAP for model training")
    n.add_argument("--server", default="127.0.0.1")
    n.add_argument("--port", type=int, default=8080)
    n.add_argument("--sessions", type=int, default=700)
    n.add_argument("--pcap", default="/tmp/generated_normal_http.pcap")
    n.set_defaults(_fn=_cmd_normal_http_pcap)

    d = sub.add_parser("defense", help="Print or apply local iptables/nftables defense commands")
    d.add_argument("--mode", choices=["rate-limit", "blacklist", "nft-http"], required=True)
    d.add_argument("--port", type=int, default=8080)
    d.add_argument("--rate", type=float, default=50.0)
    d.add_argument("--burst", type=int, default=50)
    d.add_argument("--ip", default=None)
    d.add_argument("--apply", action="store_true", help="Apply the commands instead of dry-run print")
    d.set_defaults(_fn=_cmd_defense)

    a = sub.add_parser("auto-block", help="Monitor a log file and auto-blacklist abusive IPs with iptables")
    a.add_argument("--log-file", required=True)
    a.add_argument("--threshold", type=int, default=100)
    a.add_argument("--window", type=int, default=60)
    a.add_argument("--apply", action="store_true", help="Actually apply blacklist rules")
    a.set_defaults(_fn=_cmd_auto_block)

    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args._fn(args))
