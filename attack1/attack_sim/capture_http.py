from __future__ import annotations

import os
import signal
import subprocess
import shutil
import threading
import time
from dataclasses import dataclass
from pathlib import Path

from .demo_server import DemoHandler, ThreadingHTTPServer
from .http_load import HttpLoadConfig, run_http_load


@dataclass(frozen=True)
class CaptureHttpConfig:
    host: str = "127.0.0.1"
    port: int = 8080
    duration_s: float = 3.0
    concurrency: int = 20
    rate: float = 200.0
    keepalive: bool = False
    pcap_path: str = "/tmp/attack_sim_loopback.pcap"


def _need_privileges() -> bool:
    return os.geteuid() != 0


def capture_http_to_pcap(cfg: CaptureHttpConfig) -> Path:
    """Capture a local-only HTTP flood (loopback) into a PCAP using tcpdump.

    This requires root/CAP_NET_RAW due to packet capture.
    """

    if _need_privileges():
        raise PermissionError(
            "Packet capture requires root/CAP_NET_RAW. Re-run with sudo, e.g.\n"
            "  sudo python3 -m attack_sim capture-http --pcap /tmp/attack_sim.pcap"
        )

    pcap = Path(cfg.pcap_path)
    if pcap.exists():
        pcap.unlink()

    httpd = ThreadingHTTPServer((cfg.host, cfg.port), DemoHandler)
    server_thr = threading.Thread(target=httpd.serve_forever, daemon=True)
    server_thr.start()

    # Capture only this server port on loopback.
    # -U: packet-buffered output (flush each packet) to reduce truncation risk on interrupt
    # -s 0: capture full packet
    cmd = ["tcpdump", "-i", "lo", "-U", "-s", "0", "-w", str(pcap), f"tcp port {cfg.port}"]
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    try:
        time.sleep(0.5)

        url = f"http://{cfg.host}:{cfg.port}/"
        load_cfg = HttpLoadConfig(
            url=url,
            duration_s=cfg.duration_s,
            concurrency=cfg.concurrency,
            rate=cfg.rate,
            keepalive=cfg.keepalive,
        )

        # run load generator
        import asyncio

        asyncio.run(run_http_load(load_cfg))

    finally:
        try:
            proc.send_signal(signal.SIGINT)
            proc.communicate(timeout=10)
        except Exception:
            try:
                proc.terminate()
                proc.communicate(timeout=5)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass
        try:
            httpd.shutdown()
            httpd.server_close()
        except Exception:
            pass

    if not pcap.exists() or pcap.stat().st_size == 0:
        raise RuntimeError("pcap capture failed; tcpdump produced no output")

    # Make result readable for non-root users.
    try:
        os.chmod(pcap, 0o644)
    except Exception:
        pass

    # Best-effort: fix truncated PCAPs (common when interrupting capture).
    editcap = shutil.which("editcap")
    if editcap:
        tmp = pcap.with_suffix(pcap.suffix + ".tmp")
        proc2 = subprocess.run([editcap, "-F", "pcap", str(pcap), str(tmp)], capture_output=True, text=True)
        if proc2.returncode == 0 and tmp.exists() and tmp.stat().st_size > 0:
            os.replace(tmp, pcap)
            try:
                os.chmod(pcap, 0o644)
            except Exception:
                pass
        else:
            try:
                if tmp.exists():
                    tmp.unlink()
            except Exception:
                pass

    return pcap
