#!/usr/bin/env python3
"""Predict traffic labels using the trained detection MLP model."""

from __future__ import annotations

import argparse
import csv
from pathlib import Path

import joblib


DEFAULT_MODEL = Path("detection/models/ddos_mlp.joblib")
DEFAULT_FEATURES = Path("detection/data/features.csv")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Predict DDoS traffic labels from feature rows.")
    parser.add_argument("--model", type=Path, default=DEFAULT_MODEL)
    parser.add_argument("--features", type=Path, default=DEFAULT_FEATURES)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    bundle = joblib.load(args.model)
    model = bundle["model"]
    feature_names = bundle["feature_names"]

    with args.features.open("r", newline="", encoding="utf-8") as file:
        rows = list(csv.DictReader(file))

    x_rows = [[float(row[name]) for name in feature_names] for row in rows]
    predictions = model.predict(x_rows)

    print("window_id,source_pcap,predicted_label,actual_label")
    for row, prediction in zip(rows, predictions):
        print(f"{row['window_id']},{row.get('source_pcap', '')},{prediction},{row.get('label', '')}")


if __name__ == "__main__":
    main()
