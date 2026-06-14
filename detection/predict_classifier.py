#!/usr/bin/env python3
"""Predict traffic labels using the trained detection MLP model."""

from __future__ import annotations

import argparse
import csv
from pathlib import Path

import joblib


DEFAULT_MODEL = Path("detection/models/ddos_mlp.joblib")
DEFAULT_FEATURES = Path("detection/data/features.csv")


def _as_float(row: dict[str, str], key: str) -> float:
    try:
        return float(row.get(key, "0") or 0)
    except ValueError:
        return 0.0


def is_low_rate_benign(row: dict[str, str]) -> bool:
    """Conservative pre-filter for sparse single-client demo traffic."""
    packet_count = _as_float(row, "packet_count")
    pps = _as_float(row, "pps")
    unique_src_ips = _as_float(row, "unique_src_ips")
    unique_dst_ips = _as_float(row, "unique_dst_ips")
    unique_src_ports = _as_float(row, "unique_src_ports")
    src_ip_entropy = _as_float(row, "src_ip_entropy")
    dst_ip_entropy = _as_float(row, "dst_ip_entropy")
    flow_count = _as_float(row, "flow_count")
    ack_ratio = _as_float(row, "ack_ratio")
    syn_ack_ratio = _as_float(row, "syn_ack_ratio")

    low_rate_single_flow = (
        packet_count <= 3
        and pps <= 80
        and unique_src_ips <= 1
        and src_ip_entropy <= 0.01
        and flow_count <= 3
    )
    bounded_bidirectional_burst = (
        pps <= 500
        and unique_src_ips <= 2
        and unique_dst_ips <= 2
        and src_ip_entropy <= 1.05
        and dst_ip_entropy <= 1.05
        and flow_count <= 16
        and unique_src_ports <= 9
        and ack_ratio >= 0.5
        and syn_ack_ratio <= 1.0
    )
    return low_rate_single_flow or bounded_bidirectional_burst


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Predict DDoS traffic labels from feature rows.")
    parser.add_argument("--model", type=Path, default=DEFAULT_MODEL)
    parser.add_argument("--features", type=Path, default=DEFAULT_FEATURES)
    parser.add_argument(
        "--allow-low-rate-benign",
        action="store_true",
        help="Classify clearly low-rate single-client windows as normal before applying the ML model.",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    bundle = joblib.load(args.model)
    model = bundle["model"]
    feature_names = bundle["feature_names"]
    target_column = bundle.get("target_column", "binary_label")

    with args.features.open("r", newline="", encoding="utf-8") as file:
        rows = list(csv.DictReader(file))

    x_rows = [[float(row[name]) for name in feature_names] for row in rows]
    predictions = model.predict(x_rows)

    print("window_id,source_pcap,predicted_label,actual_label,target_column")
    for row, prediction in zip(rows, predictions):
        if args.allow_low_rate_benign and is_low_rate_benign(row):
            prediction = "normal"
        actual = row.get(target_column)
        if not actual and target_column == "binary_label":
            actual = "normal" if row.get("label") == "normal" else "abnormal"
        print(f"{row['window_id']},{row.get('source_pcap', '')},{prediction},{actual or ''},{target_column}")


if __name__ == "__main__":
    main()
