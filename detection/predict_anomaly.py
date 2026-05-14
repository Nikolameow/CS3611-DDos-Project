#!/usr/bin/env python3
"""Predict normal/anomaly states using the trained K-Means detector."""

from __future__ import annotations

import argparse
import csv
import os
from pathlib import Path

os.environ.setdefault("OMP_NUM_THREADS", "1")

import joblib


DEFAULT_MODEL = Path("detection/models/kmeans_anomaly.joblib")
DEFAULT_FEATURES = Path("detection/data/features.csv")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Predict anomaly states from feature rows.")
    parser.add_argument("--model", type=Path, default=DEFAULT_MODEL)
    parser.add_argument("--features", type=Path, default=DEFAULT_FEATURES)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    bundle = joblib.load(args.model)
    model = bundle["model"]
    feature_names = bundle["feature_names"]
    threshold = bundle["threshold"]

    with args.features.open("r", newline="", encoding="utf-8") as file:
        rows = list(csv.DictReader(file))

    x_rows = [[float(row[name]) for name in feature_names] for row in rows]
    transformed = model.named_steps["scaler"].transform(x_rows)
    distances = model.named_steps["kmeans"].transform(transformed)

    print("window_id,source_pcap,anomaly_score,threshold,predicted_state,actual_label")
    for row, distance_row in zip(rows, distances):
        score = float(min(distance_row))
        predicted = "anomaly" if score > threshold else "normal"
        print(
            f"{row['window_id']},{row.get('source_pcap', '')},"
            f"{score:.8f},{threshold:.8f},{predicted},{row.get('label', '')}"
        )


if __name__ == "__main__":
    main()
