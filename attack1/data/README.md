# Data Artifacts

This directory contains generated sample PCAP files and extracted feature summaries for model training or report use.

Files:

- `http_flood.pcap` — captured local HTTP flood traffic
- `http_flood_fixed.pcap` — fixed copy of the HTTP flood capture
- `syn_spoof_test.pcap` — generated spoofed-source SYN flood PCAP
- `udp_reflect_spoof_test.pcap` — generated spoofed-source UDP reflect PCAP
- `http_flood.json` — feature summary for `http_flood.pcap`
- `http_flood_fixed.json` — feature summary for `http_flood_fixed.pcap`
- `syn_spoof_test.json` — feature summary for `syn_spoof_test.pcap`
- `udp_reflect_spoof_test.json` — feature summary for `udp_reflect_spoof_test.pcap`
- `features_summary.json` — combined feature summaries for all PCAPs
- `features_summary.csv` — combined feature summaries in CSV format

These files are intended to support downstream model or analysis work without rerunning attack generation.
