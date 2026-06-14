#!/usr/bin/env python3
"""Mininet driver for the DDoS attack/defense/detection lab."""

from __future__ import annotations

import argparse
import csv
import os
import shutil
import struct
import subprocess
import sys
import time
from pathlib import Path

from mininet.cli import CLI
from mininet.log import setLogLevel
from mininet.net import Mininet
from mininet.node import OVSBridge
from mininet.topo import Topo


PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))
ATTACK1_DIR = PROJECT_ROOT / "attack1"
DETECTION_DIR = PROJECT_ROOT / "detection"
DEMO_PCAP = DETECTION_DIR / "data" / "demo_http_flood.pcap"
DEMO_LABELS = DEMO_PCAP.with_suffix(".labels.csv")
DEMO_FEATURES = DETECTION_DIR / "data" / "demo_features.csv"
DEMO_CLASSIFIER_LOG = DETECTION_DIR / "data" / "demo_classifier_predictions.csv"
DEMO_ANOMALY_LOG = DETECTION_DIR / "data" / "demo_anomaly_predictions.csv"
NGINX_CONFIG = DETECTION_DIR / "data" / "demo_cdn_nginx.conf"
NGINX_ACCESS_LOG = DETECTION_DIR / "data" / "demo_cdn_access.log"
NGINX_ERROR_LOG = DETECTION_DIR / "data" / "demo_cdn_error.log"
NGINX_PID = DETECTION_DIR / "data" / "demo_cdn_nginx.pid"
VICTIM_IP = "10.0.0.100"
VICTIM_PORT = 8080
VICTIM_CDN_BACKUP_PORT = 8081
CDN_PROXY_IP = "10.0.0.50"
CDN_PROXY_PORT = 80
ATTACKER_HTTP_IPS = {"10.0.0.1", "10.0.0.3"}
ATTACKER_SYN_IP = "10.0.0.2"
NORMAL_CLIENT_IP = "10.0.0.4"


class DDoSTopo(Topo):
    def build(self):
        s1 = self.addSwitch("s1")

        # 三台攻击者
        for i in range(1, 4):
            h = self.addHost(f"h{i}", ip=f"10.0.0.{i}/24")
            self.addLink(h, s1)

        # 正常用户（对照组）
        h4 = self.addHost("h4", ip="10.0.0.4/24")
        self.addLink(h4, s1)

        # 受害者 = 防御网关（合并节点，所有防御代码都跑在这）
        victim = self.addHost("victim", ip=f"{VICTIM_IP}/24")
        self.addLink(victim, s1)

        # CDN/反向代理边缘节点（--cdn 时启用 Nginx）
        proxy = self.addHost("proxy", ip=f"{CDN_PROXY_IP}/24")
        self.addLink(proxy, s1)


def _attack_cmd(command: str) -> str:
    return f"cd {ATTACK1_DIR} && python3 -m attack_sim {command}"


def _root_cmd(command: str) -> str:
    return f"cd {PROJECT_ROOT} && python3 {command}"


def _run_host_command(host, label: str, command: str) -> None:
    print(f"\n[{label}] {command}")
    output = host.cmd(command)
    if output.strip():
        print(output.strip())


def _start_host_process(host, label: str, command: str):
    print(f"\n[start:{label}] {command}")
    return host.popen(command, shell=True)


def _stop_process(proc, label: str) -> None:
    if proc.poll() is not None:
        return
    print(f"[stop:{label}]")
    proc.terminate()
    try:
        proc.wait(timeout=3)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=3)


def _host_has_command(host, command: str) -> bool:
    return bool(host.cmd(f"command -v {command}").strip())


def _python_has_detection_deps(python: str) -> bool:
    try:
        subprocess.run(
            [python, "-c", "import joblib, sklearn"],
            cwd=PROJECT_ROOT,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=True,
        )
    except (OSError, subprocess.CalledProcessError):
        return False
    return True


def _detection_python() -> str:
    candidates: list[str] = []
    if os.environ.get("DETECTION_PYTHON"):
        candidates.append(os.environ["DETECTION_PYTHON"])
    candidates.append(sys.executable)
    if os.environ.get("SUDO_USER"):
        candidates.append(f"/home/{os.environ['SUDO_USER']}/miniconda3/bin/python3")
    conda_python = shutil.which("python3")
    if conda_python:
        candidates.append(conda_python)

    seen: set[str] = set()
    for candidate in candidates:
        if candidate in seen:
            continue
        seen.add(candidate)
        if _python_has_detection_deps(candidate):
            return candidate

    print("[!] 未找到包含 joblib/sklearn 的 Python，使用当前解释器尝试检测")
    print("[!] 可通过 DETECTION_PYTHON=/path/to/python3 指定检测解释器")
    return sys.executable


def _write_nginx_config() -> None:
    NGINX_CONFIG.parent.mkdir(parents=True, exist_ok=True)
    NGINX_CONFIG.write_text(
        f"""
worker_processes  1;
pid {NGINX_PID};

events {{
    worker_connections  1024;
}}

http {{
    access_log {NGINX_ACCESS_LOG};
    error_log {NGINX_ERROR_LOG} info;

    limit_req_zone $binary_remote_addr zone=per_client_req:10m rate=80r/s;
    limit_conn_zone $binary_remote_addr zone=per_client_conn:10m;

    upstream ddos_origin {{
        server {VICTIM_IP}:{VICTIM_PORT};
        server {VICTIM_IP}:{VICTIM_CDN_BACKUP_PORT};
    }}

    server {{
        listen {CDN_PROXY_PORT};
        server_name _;

        limit_req zone=per_client_req burst=80 nodelay;
        limit_conn per_client_conn 40;

        location / {{
            proxy_pass http://ddos_origin;
            proxy_http_version 1.1;
            proxy_set_header Connection "";
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        }}
    }}
}}
""".lstrip(),
        encoding="utf-8",
    )


def _protect_origin_from_direct_clients(victim) -> None:
    commands = [
        f"iptables -I INPUT -p tcp --dport {VICTIM_PORT} ! -s {CDN_PROXY_IP} -j DROP",
        f"iptables -I INPUT -p tcp --dport {VICTIM_CDN_BACKUP_PORT} ! -s {CDN_PROXY_IP} -j DROP",
    ]
    _run_host_command(victim, "origin-guard", " && ".join(commands))


def _demo_label_for_packet(packet) -> str:
    endpoints = {packet.src_ip, packet.dst_ip}
    if NORMAL_CLIENT_IP in endpoints:
        return "normal"
    if ATTACKER_SYN_IP in endpoints:
        return "syn_flood"
    if endpoints & ATTACKER_HTTP_IPS:
        return "http_flood"
    if packet.dst_ip in {VICTIM_IP, CDN_PROXY_IP} and packet.protocol == "TCP" and packet.syn and not packet.ack:
        return "syn_flood"
    if VICTIM_IP in endpoints:
        return "http_flood"
    return "attack"


def _write_demo_packet_labels() -> None:
    if not DEMO_PCAP.exists() or DEMO_PCAP.stat().st_size == 0:
        return

    try:
        from detection.features import _parse_ipv4_packet, _pcap_endian
    except ImportError as exc:
        print(f"[!] 无法导入逐包标签工具，跳过 demo 标签生成: {exc}")
        return

    labels_written = 0
    with DEMO_PCAP.open("rb") as pcap_file, DEMO_LABELS.open("w", newline="", encoding="utf-8") as label_file:
        header = pcap_file.read(24)
        if len(header) != 24:
            print(f"[!] PCAP 文件不完整，跳过标签生成: {DEMO_PCAP}")
            return
        endian = _pcap_endian(header[:4])
        _, _, _, _, _, _, linktype = struct.unpack(f"{endian}IHHIIII", header)

        writer = csv.DictWriter(
            label_file,
            fieldnames=["packet_index", "label", "src_ip", "dst_ip", "protocol"],
        )
        writer.writeheader()
        packet_index = 0
        while True:
            packet_header = pcap_file.read(16)
            if not packet_header:
                break
            if len(packet_header) != 16:
                print(f"[!] PCAP packet header 截断，停止标签生成: {DEMO_PCAP}")
                break
            ts_sec, ts_frac, incl_len, _orig_len = struct.unpack(f"{endian}IIII", packet_header)
            frame = pcap_file.read(incl_len)
            if len(frame) != incl_len:
                print(f"[!] PCAP packet body 截断，停止标签生成: {DEMO_PCAP}")
                break
            packet = _parse_ipv4_packet(ts_sec + ts_frac / 1_000_000, frame, linktype)
            if packet is not None:
                writer.writerow(
                    {
                        "packet_index": packet_index,
                        "label": _demo_label_for_packet(packet),
                        "src_ip": packet.src_ip,
                        "dst_ip": packet.dst_ip,
                        "protocol": packet.protocol,
                    }
                )
                labels_written += 1
            packet_index += 1
    print(f"[*] demo 逐包标签: {DEMO_LABELS} ({labels_written} packets)")


def _run_detection() -> None:
    if not DEMO_PCAP.exists() or DEMO_PCAP.stat().st_size == 0:
        print(f"[!] 未生成有效 PCAP，跳过检测: {DEMO_PCAP}")
        return

    detection_python = _detection_python()
    print(f"[*] 检测 Python: {detection_python}")
    for output_path in (DEMO_FEATURES, DEMO_CLASSIFIER_LOG, DEMO_ANOMALY_LOG):
        output_path.unlink(missing_ok=True)
    commands = [
        [
            detection_python,
            "-m",
            "detection.features",
            "--input-dir",
            str(DEMO_PCAP.parent),
            "--output",
            str(DEMO_FEATURES),
            "--window-seconds",
            "0.05",
            "--group-by-origin-label",
        ],
        [
            detection_python,
            "-m",
            "detection.predict_classifier",
            "--features",
            str(DEMO_FEATURES),
            "--allow-low-rate-benign",
        ],
        [
            detection_python,
            "-m",
            "detection.predict_anomaly",
            "--features",
            str(DEMO_FEATURES),
            "--allow-low-rate-benign",
        ],
    ]

    print("\n[*] 开始离线检测")
    for index, command in enumerate(commands):
        try:
            result = subprocess.run(
                command,
                cwd=PROJECT_ROOT,
                text=True,
                capture_output=True,
                check=True,
            )
        except subprocess.CalledProcessError as exc:
            print(f"[!] 检测命令失败: {' '.join(command)}")
            if exc.stdout.strip():
                print(exc.stdout.strip())
            if exc.stderr.strip():
                print(exc.stderr.strip())
            return

        output = result.stdout.strip()
        if index == 1:
            DEMO_CLASSIFIER_LOG.write_text(result.stdout, encoding="utf-8")
        elif index == 2:
            DEMO_ANOMALY_LOG.write_text(result.stdout, encoding="utf-8")
        if output:
            print(output.splitlines()[0])
            for line in output.splitlines()[1:6]:
                print(line)
            if len(output.splitlines()) > 6:
                print("...")

    print(f"[*] 特征文件: {DEMO_FEATURES}")
    print(f"[*] 分类预测: {DEMO_CLASSIFIER_LOG}")
    print(f"[*] 异常预测: {DEMO_ANOMALY_LOG}")


def run_demo(duration: float, rate: float, use_nft: bool, live_ml: str, use_cdn: bool) -> None:
    setLogLevel("info")
    net = Mininet(topo=DDoSTopo(), switch=OVSBridge, controller=None)
    server_procs = []
    cdn_proc = None
    capture_proc = None
    live_block_proc = None
    live_ml_block_proc = None
    net.start()

    try:
        h1, h2, h3, h4, victim, proxy = [net.get(name) for name in ("h1", "h2", "h3", "h4", "victim", "proxy")]
        DETECTION_DIR.joinpath("data").mkdir(parents=True, exist_ok=True)
        DEMO_PCAP.unlink(missing_ok=True)
        DEMO_LABELS.unlink(missing_ok=True)
        for nginx_path in (NGINX_CONFIG, NGINX_ACCESS_LOG, NGINX_ERROR_LOG, NGINX_PID):
            nginx_path.unlink(missing_ok=True)

        print("\n[*] 拓扑就绪，开始一键攻防演示")
        _run_host_command(victim, "victim", f"ip addr show victim-eth0 | grep 'inet '")

        server_procs.append(_start_host_process(
            victim,
            "victim-http",
            _attack_cmd(f"demo-server --host 0.0.0.0 --port {VICTIM_PORT}"),
        ))
        cdn_enabled = False
        if use_cdn:
            server_procs.append(_start_host_process(
                victim,
                "victim-http-backup",
                _attack_cmd(f"demo-server --host 0.0.0.0 --port {VICTIM_CDN_BACKUP_PORT}"),
            ))
            if _host_has_command(proxy, "nginx"):
                _write_nginx_config()
                cdn_proc = _start_host_process(
                    proxy,
                    "cdn-nginx",
                    f"nginx -c {NGINX_CONFIG} -g 'daemon off;'",
                )
                time.sleep(0.5)
                if cdn_proc.poll() is None:
                    cdn_enabled = True
                    _run_host_command(proxy, "proxy", f"ip addr show proxy-eth0 | grep 'inet '")
                    print(f"[*] CDN/Nginx 启用: http://{CDN_PROXY_IP}:{CDN_PROXY_PORT}/ -> {VICTIM_IP}:{VICTIM_PORT},{VICTIM_CDN_BACKUP_PORT}")
                    if _host_has_command(victim, "iptables"):
                        _protect_origin_from_direct_clients(victim)
                else:
                    print("[!] Nginx 启动失败，回退为直接访问 victim")
            else:
                print("[!] proxy namespace 内找不到 nginx，回退为直接访问 victim")

        defense_host = proxy if cdn_enabled else victim
        defense_port = CDN_PROXY_PORT if cdn_enabled else VICTIM_PORT
        defense_interface = "proxy-eth0" if cdn_enabled else "victim-eth0"
        if _host_has_command(defense_host, "iptables"):
            _run_host_command(
                defense_host,
                "defense",
                _root_cmd(f"defense/defense_main.py rules --mode rate-limit --port {defense_port} --rate 80 --burst 80 --apply"),
            )
        else:
            print("[!] 防御节点 namespace 内找不到 iptables，跳过防火墙限速和自动封禁")
        if use_nft and _host_has_command(defense_host, "nft"):
            _run_host_command(
                defense_host,
                "defense-nft",
                _root_cmd(f"defense/defense_main.py rules --mode nft-http --port {defense_port} --rate 80 --apply || true"),
            )
        elif use_nft:
            print("[!] 防御节点 namespace 内找不到 nft，跳过 nftables 清洗规则")

        time.sleep(1.0)

        if _host_has_command(defense_host, "tcpdump"):
            capture_proc = _start_host_process(
                defense_host,
                "tcpdump",
                f"tcpdump -i {defense_interface} -w {DEMO_PCAP} tcp port {defense_port}",
            )
            if _host_has_command(defense_host, "iptables"):
                live_block_proc = _start_host_process(
                    defense_host,
                    "live-block",
                    _root_cmd(f"defense/defense_main.py live-block --interface {defense_interface} --port {defense_port} --threshold 250 --window 3 --apply"),
                )
                if live_ml != "none":
                    live_ml_block_proc = _start_host_process(
                        defense_host,
                        "live-ml-block",
                        _root_cmd(
                            "defense/defense_main.py "
                            f"live-ml-block --detector {live_ml} --interface {defense_interface} "
                            f"--port {defense_port} --window 1 --min-packets 5 --apply"
                        ),
                    )
            else:
                print("[!] 缺少 iptables，实时统计封禁只可在安装后演示")
            time.sleep(1.0)
        else:
            print("[!] 防御节点 namespace 内找不到 tcpdump，跳过抓包和后续模型检测")

        target_host = CDN_PROXY_IP if cdn_enabled else VICTIM_IP
        target_port = CDN_PROXY_PORT if cdn_enabled else VICTIM_PORT
        target_url = f"http://{target_host}:{target_port}/"
        procs = [
            _start_host_process(
                h1,
                "h1-http-flood",
                _attack_cmd(f"http --url {target_url} --duration {duration} --concurrency 80 --rate {rate} --randomize --keepalive"),
            ),
            _start_host_process(
                h2,
                "h2-raw-syn-flood",
                _attack_cmd(f"raw-syn --target {target_host} --port {target_port} --duration {duration} --rate {rate * 8} || python3 -m attack_sim syn --host {target_host} --port {target_port} --duration {duration} --concurrency 120 --rate {rate * 2}"),
            ),
            _start_host_process(
                h3,
                "h3-post-flood",
                _attack_cmd(f"http --url {target_url} --duration {duration} --concurrency 60 --rate {rate} --method POST --body attack --randomize"),
            ),
            _start_host_process(
                h4,
                "h4-normal",
                _attack_cmd(f"normal-http --url {target_url} --duration {duration} --concurrency 8 --rate 20 --keepalive"),
            ),
        ]

        for proc in procs:
            proc.wait()

        time.sleep(1.0)
        if live_ml_block_proc is not None:
            _stop_process(live_ml_block_proc, "live-ml-block")
        if live_block_proc is not None:
            _stop_process(live_block_proc, "live-block")
        if capture_proc is not None:
            _stop_process(capture_proc, "tcpdump")
            _write_demo_packet_labels()
        _run_detection()
    finally:
        if live_ml_block_proc is not None:
            _stop_process(live_ml_block_proc, "live-ml-block")
        if live_block_proc is not None:
            _stop_process(live_block_proc, "live-block")
        if capture_proc is not None:
            _stop_process(capture_proc, "tcpdump")
        if cdn_proc is not None:
            _stop_process(cdn_proc, "cdn-nginx")
        for index, server_proc in enumerate(server_procs):
            _stop_process(server_proc, f"victim-http-{index}")
        net.stop()


def run_cli() -> None:
    setLogLevel("info")
    net = Mininet(topo=DDoSTopo(), switch=OVSBridge, controller=None)
    net.start()
    print(f"\n[*] 拓扑就绪。项目根目录 = {PROJECT_ROOT}")
    print("[*] 可运行: sudo python3 topology/topo.py --demo")
    print("[*] CDN 演示: sudo python3 topology/topo.py --demo --cdn")
    print("[*] 或在 CLI 中运行 'xterm victim proxy h1 h2 h3 h4' 手动演示\n")
    try:
        CLI(net)
    finally:
        net.stop()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run the CS3611 DDoS Mininet lab.")
    parser.add_argument("--demo", action="store_true", help="Run the full automated attack/defense/detection demo")
    parser.add_argument("--cli", action="store_true", help="Start Mininet CLI only")
    parser.add_argument("--duration", type=float, default=8.0, help="Traffic duration in seconds for demo mode")
    parser.add_argument("--rate", type=float, default=120.0, help="Base attack request/connection rate for demo mode")
    parser.add_argument("--nft", action="store_true", help="Also try nftables HTTP filtering in demo mode")
    parser.add_argument("--live-ml", choices=["none", "mlp", "kmeans"], default="none", help="Also run live ML blocking during demo mode")
    parser.add_argument("--cdn", action="store_true", help="Run clients through an Nginx reverse-proxy/CDN edge node")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    if args.cli:
        run_cli()
    else:
        run_demo(duration=args.duration, rate=args.rate, use_nft=args.nft, live_ml=args.live_ml, use_cdn=args.cdn)


if __name__ == "__main__":
    main()
