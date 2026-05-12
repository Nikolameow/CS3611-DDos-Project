# Attack Simulation (Local Only)

This folder contains a **local-only** traffic generator intended for defensive testing on your own machine.
It **refuses** to target anything except loopback addresses (`localhost`, `127.0.0.1`, `::1`).

## Requirements

- Linux
- Python 3.10+ (no conda required)

Optional (only for PCAP feature extraction):

- `tshark` (preferred) or `scapy` (`pip install -r requirements.txt`)

## Quick start

1) Start a local demo server:

```bash
cd /home/leo/ddos
python3 -m attack_sim demo-server --host 127.0.0.1 --port 8080
```

2) In another terminal, generate HTTP load (GET):

```bash
cd /home/leo/ddos
python3 -m attack_sim http --url http://127.0.0.1:8080/ --duration 10 --concurrency 20 --rate 200
```

`--keepalive` will reuse one TCP connection per worker (more stable RPS, less connect churn):

```bash
python3 -m attack_sim http --url http://127.0.0.1:8080/ --duration 10 --concurrency 20 --rate 200 --keepalive
```

3) POST example:

```bash
python3 -m attack_sim http --url http://127.0.0.1:8080/ --method POST --body "hello" --content-type text/plain --duration 5 --concurrency 10 --rate 100
```

4) Simulate a local TCP connection flood (safe to localhost):

```bash
python3 -m attack_sim syn --host 127.0.0.1 --port 8080 --duration 10 --concurrency 100 --rate 500
```

This mode opens many short-lived TCP connections. It is useful for connection churn and backlog pressure testing, but it is not a raw SYN packet generator.

5) Simulate a local UDP reflector/amplifier pattern:

```bash
python3 -m attack_sim udp-reflect --host 127.0.0.1 --server-port 4000 --client-port 4001 --duration 10 --rate 200 --request-size 32 --response-size 512
```

6) Print example defense commands for local rules (dry-run):

```bash
python3 -m attack_sim defense --mode rate-limit --port 8080 --rate 50 --burst 50
```

7) Generate a spoofed-source SYN Flood PCAP locally:

```bash
python3 -m attack_sim spoofed-syn --target 127.0.0.1 --port 8080 --packets 1000 --pcap /tmp/syn_spoof.pcap
```

8) Generate a spoofed-source UDP reflect/amplifier PCAP locally:

```bash
python3 -m attack_sim spoofed-udp-reflect --target 127.0.0.1 --port 53 --packets 500 --request-size 32 --response-size 256 --pcap /tmp/udp_reflect_spoof.pcap
```

9) Monitor a log file and auto-block abusive sources:

```bash
python3 -m attack_sim auto-block --log-file /path/to/attack.log --threshold 100 --window 60
```

## Safety

- Only `http://` is accepted (no HTTPS).
- Only loopback targets are accepted.
- Concurrency is capped at 200 to avoid accidental overload.
- All new attack modes in this repository are local-only simulations and do not target external hosts.

Example guardrail (will refuse):

```bash
python3 -m attack_sim http --url http://example.com:80/ --duration 1
```

If you need additional patterns for your course project (within local-only scope), say what your defense module expects to observe (RPS bursts, connection churn, payload size changes), and we can extend this safely.

## PCAP features

If you capture traffic into a PCAP (e.g., via Wireshark/tcpdump), you can extract basic statistics:

```bash
python3 -m attack_sim pcap-features --pcap /path/to/capture.pcap
```

JSON output:

```bash
python3 -m attack_sim pcap-features --pcap /path/to/capture.pcap --json
```

To capture a loopback HTTP flood into a PCAP in one step (requires sudo due to tcpdump permissions):

```bash
sudo python3 -m attack_sim capture-http --host 127.0.0.1 --port 8080 --duration 3 --concurrency 20 --rate 200 --pcap /tmp/http_flood.pcap
python3 -m attack_sim pcap-features --pcap /tmp/http_flood.pcap
```

## Repository data artifacts

Sample attack data and feature summaries are available under `data/`.

The following files are included:

- `data/http_flood.pcap`
- `data/http_flood_fixed.pcap`
- `data/syn_spoof_test.pcap`
- `data/udp_reflect_spoof_test.pcap`
- `data/features_summary.json`
- `data/features_summary.csv`

This allows downstream work (including model training or statistical analysis) to use the generated data directly without rerunning the attack generation scripts.
