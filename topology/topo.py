#!/usr/bin/env python3
"""Mininet driver for the DDoS attack/defense/detection lab."""

from __future__ import annotations

import argparse
import os
import shutil
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
ATTACK1_DIR = PROJECT_ROOT / "attack1"
DETECTION_DIR = PROJECT_ROOT / "detection"
DEMO_PCAP = DETECTION_DIR / "data" / "demo_http_flood.pcap"
DEMO_FEATURES = DETECTION_DIR / "data" / "demo_features.csv"
DEMO_CLASSIFIER_LOG = DETECTION_DIR / "data" / "demo_classifier_predictions.csv"
DEMO_ANOMALY_LOG = DETECTION_DIR / "data" / "demo_anomaly_predictions.csv"
VICTIM_IP = "10.0.0.100"
VICTIM_PORT = 8080


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
        ],
        [
            detection_python,
            "-m",
            "detection.predict_classifier",
            "--features",
            str(DEMO_FEATURES),
        ],
        [
            detection_python,
            "-m",
            "detection.predict_anomaly",
            "--features",
            str(DEMO_FEATURES),
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


def run_demo(duration: float, rate: float, use_nft: bool) -> None:
    setLogLevel("info")
    net = Mininet(topo=DDoSTopo(), switch=OVSBridge, controller=None)
    server_proc = None
    capture_proc = None
    live_block_proc = None
    net.start()

    try:
        h1, h2, h3, h4, victim = [net.get(name) for name in ("h1", "h2", "h3", "h4", "victim")]
        DETECTION_DIR.joinpath("data").mkdir(parents=True, exist_ok=True)
        DEMO_PCAP.unlink(missing_ok=True)

        print("\n[*] 拓扑就绪，开始一键攻防演示")
        _run_host_command(victim, "victim", f"ip addr show victim-eth0 | grep 'inet '")
        if _host_has_command(victim, "iptables"):
            _run_host_command(victim, "defense", _root_cmd(f"defense/defense_main.py rules --mode rate-limit --port {VICTIM_PORT} --rate 80 --burst 80 --apply"))
        else:
            print("[!] victim namespace 内找不到 iptables，跳过防火墙限速和自动封禁")
        if use_nft and _host_has_command(victim, "nft"):
            _run_host_command(victim, "defense-nft", _root_cmd(f"defense/defense_main.py rules --mode nft-http --port {VICTIM_PORT} --rate 80 --apply || true"))
        elif use_nft:
            print("[!] victim namespace 内找不到 nft，跳过 nftables 清洗规则")

        server_proc = _start_host_process(
            victim,
            "victim-http",
            _attack_cmd(f"demo-server --host 0.0.0.0 --port {VICTIM_PORT}"),
        )
        time.sleep(1.0)

        if _host_has_command(victim, "tcpdump"):
            capture_proc = _start_host_process(
                victim,
                "tcpdump",
                f"tcpdump -i victim-eth0 -w {DEMO_PCAP} tcp port {VICTIM_PORT}",
            )
            if _host_has_command(victim, "iptables"):
                live_block_proc = _start_host_process(
                    victim,
                    "live-block",
                    _root_cmd(f"defense/defense_main.py live-block --interface victim-eth0 --port {VICTIM_PORT} --threshold 250 --window 3 --apply"),
                )
            else:
                print("[!] 缺少 iptables，实时统计封禁只可在安装后演示")
            time.sleep(1.0)
        else:
            print("[!] victim namespace 内找不到 tcpdump，跳过抓包和后续模型检测")

        target_url = f"http://{VICTIM_IP}:{VICTIM_PORT}/"
        procs = [
            _start_host_process(
                h1,
                "h1-http-flood",
                _attack_cmd(f"http --url {target_url} --duration {duration} --concurrency 80 --rate {rate} --randomize --keepalive"),
            ),
            _start_host_process(
                h2,
                "h2-raw-syn-flood",
                _attack_cmd(f"raw-syn --target {VICTIM_IP} --port {VICTIM_PORT} --duration {duration} --rate {rate * 8} || python3 -m attack_sim syn --host {VICTIM_IP} --port {VICTIM_PORT} --duration {duration} --concurrency 120 --rate {rate * 2}"),
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
        if live_block_proc is not None:
            _stop_process(live_block_proc, "live-block")
        if capture_proc is not None:
            _stop_process(capture_proc, "tcpdump")
        _run_detection()
    finally:
        if live_block_proc is not None:
            _stop_process(live_block_proc, "live-block")
        if capture_proc is not None:
            _stop_process(capture_proc, "tcpdump")
        if server_proc is not None:
            _stop_process(server_proc, "victim-http")
        net.stop()


def run_cli() -> None:
    setLogLevel("info")
    net = Mininet(topo=DDoSTopo(), switch=OVSBridge, controller=None)
    net.start()
    print(f"\n[*] 拓扑就绪。项目根目录 = {PROJECT_ROOT}")
    print("[*] 可运行: sudo python3 topology/topo.py --demo")
    print("[*] 或在 CLI 中运行 'xterm victim h1 h2 h3 h4' 手动演示\n")
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
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    if args.cli:
        run_cli()
    else:
        run_demo(duration=args.duration, rate=args.rate, use_nft=args.nft)


if __name__ == "__main__":
    main()
