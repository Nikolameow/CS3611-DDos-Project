# Data Artifacts

This directory contains generated sample PCAP files and extracted feature
summaries for model training or report use.

The canonical generated dataset uses these traffic captures:

- `generated_normal_http.pcap` - benign HTTP traffic for normal flow data
- `generated_http_attack.pcap` - diversified HTTP flood-style attack traffic
- `generated_syn_flood.pcap` - SYN flood-style attack traffic
- `generated_udp_reflect.pcap` - UDP reflection/amplification-style traffic

Derived summaries:

- `*.json` - feature summary for the matching PCAP
- `features_summary.json` - combined feature summaries
- `features_summary.csv` - combined feature summaries in CSV format

These files support downstream model and analysis work without rerunning traffic
generation.
