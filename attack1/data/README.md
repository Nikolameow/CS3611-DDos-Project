# Data Artifacts

This directory contains generated sample PCAP files and extracted feature summaries for model training or report use.

Different traffic types are intentionally produced so the model can learn from distinct feature patterns. For example:

- `generated_normal_http.pcap` — benign HTTP traffic with varied paths, user agents, and request bodies
- `generated_http_attack.pcap` — HTTP flood-style attack traffic with higher request rate and more POST/body variability
- `generated_syn_flood.pcap` — SYN flood-style attack traffic with many SYN-only TCP packets and high PPS
- `generated_udp_reflect.pcap` — UDP reflector/amplifier traffic with request/response UDP packets and spoofed source IPs

Files:

- `http_flood.pcap` — captured local HTTP flood traffic
- `http_flood_fixed.pcap` — fixed copy of the HTTP flood capture
- `syn_spoof_test.pcap` — generated spoofed-source SYN flood PCAP
- `udp_reflect_spoof_test.pcap` — generated spoofed-source UDP reflect PCAP
- `generated_normal_http.pcap` — generated benign HTTP traffic for normal flow data
- `generated_http_attack.pcap` — generated diversified HTTP attack traffic
- `generated_syn_flood.pcap` — generated SYN flood attack traffic
- `generated_udp_reflect.pcap` — generated UDP reflect attack traffic
- `http_flood.json` — feature summary for `http_flood.pcap`
- `http_flood_fixed.json` — feature summary for `http_flood_fixed.pcap`
- `syn_spoof_test.json` — feature summary for `syn_spoof_test.pcap`
- `udp_reflect_spoof_test.json` — feature summary for `udp_reflect_spoof_test.pcap`
- `features_summary.json` — combined feature summaries for all PCAPs
- `features_summary.csv` — combined feature summaries in CSV format

These files are intended to support downstream model or analysis work without rerunning attack generation.
