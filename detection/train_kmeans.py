#!/usr/bin/env python3
"""Train a K-Means anomaly detector on normal feature windows."""

from __future__ import annotations

import argparse
import csv
import json
import os
from pathlib import Path

os.environ.setdefault("OMP_NUM_THREADS", "1")

import joblib
from sklearn.cluster import KMeans
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler


DEFAULT_FEATURES = Path("detection/data/features.csv")
DEFAULT_MODEL = Path("detection/models/kmeans_anomaly.joblib")
DEFAULT_SCORES = Path("detection/data/anomaly_scores.csv")
DEFAULT_METRICS = Path("detection/models/anomaly_metrics.json")
METADATA_COLUMNS = {
    "window_id",
    "source_pcap",
    "label",
    "binary_label",
    "normal_ratio",
    "http_flood_ratio",
    "syn_flood_ratio",
    "udp_reflection_ratio",
    "attack_ratio",
    "dominant_attack",
    "severity",
}


def load_features(path: Path) -> tuple[list[dict[str, str]], list[str]]:
    with path.open("r", newline="", encoding="utf-8") as file:
        rows = list(csv.DictReader(file))
    if not rows:
        raise ValueError(f"no feature rows found in {path}")
    feature_names = [name for name in rows[0] if name not in METADATA_COLUMNS]
    return rows, feature_names


def vectorize(rows: list[dict[str, str]], feature_names: list[str]) -> list[list[float]]:
    return [[float(row[name]) for name in feature_names] for row in rows]


def percentile(values: list[float], percent: float) -> float:
    sorted_values = sorted(values)
    index = (len(sorted_values) - 1) * percent / 100
    lower = int(index)
    upper = min(lower + 1, len(sorted_values) - 1)
    weight = index - lower
    return sorted_values[lower] * (1 - weight) + sorted_values[upper] * weight


def anomaly_scores(model: Pipeline, x_rows: list[list[float]]) -> list[float]:
    transformed = model.named_steps["scaler"].transform(x_rows)
    distances = model.named_steps["kmeans"].transform(transformed)
    return [float(min(row)) for row in distances]


def row_binary_label(row: dict[str, str]) -> str:
    return row.get("binary_label") or ("normal" if row["label"] == "normal" else "abnormal")


def train_detector(
    rows: list[dict[str, str]],
    feature_names: list[str],
    clusters: int,
    threshold_percentile: float,
    seed: int,
    normal_label: str,
) -> tuple[Pipeline, float, list[dict[str, str | float | int]], dict[str, object]]:
    normal_rows = [row for row in rows if row_binary_label(row) == normal_label]
    if not normal_rows:
        labels = sorted({row["label"] for row in rows})
        raise ValueError(
            "no normal traffic rows found for anomaly training. "
            f"Expected binary label '{normal_label}', found labels: {labels}. "
            "Add benign/normal PCAPs under attack1/data or pass --normal-label."
        )
    if len(normal_rows) < clusters:
        raise ValueError("not enough normal rows to fit the requested number of clusters")

    normal_x = vectorize(normal_rows, feature_names)
    model = Pipeline(
        steps=[
            ("scaler", StandardScaler()),
            ("kmeans", KMeans(n_clusters=clusters, n_init=20, random_state=seed)),
        ]
    )
    model.fit(normal_x)

    normal_scores = anomaly_scores(model, normal_x)
    threshold = percentile(normal_scores, threshold_percentile)

    all_x = vectorize(rows, feature_names)
    all_scores = anomaly_scores(model, all_x)
    score_rows: list[dict[str, str | float | int]] = []
    y_true: list[str] = []
    y_pred: list[str] = []

    for row, score in zip(rows, all_scores):
        predicted = "anomaly" if score > threshold else "normal"
        actual = "normal" if row_binary_label(row) == normal_label else "anomaly"
        y_true.append(actual)
        y_pred.append(predicted)
        score_rows.append(
            {
                "window_id": int(row["window_id"]),
                "source_pcap": row.get("source_pcap", ""),
                "label": row["label"],
                "binary_label": row_binary_label(row),
                "anomaly_score": round(score, 8),
                "threshold": round(threshold, 8),
                "predicted_state": predicted,
            }
        )

    labels = ["normal", "anomaly"]
    metrics: dict[str, object] = {
        "method": "kmeans_distance_to_normal_clusters",
        "clusters": clusters,
        "threshold_percentile": threshold_percentile,
        "threshold": threshold,
        "normal_label": normal_label,
        "train_normal_windows": len(normal_rows),
        "evaluated_windows": len(rows),
        "classification_report": classification_report(
            y_true,
            y_pred,
            labels=labels,
            output_dict=True,
            zero_division=0,
        ),
        "confusion_matrix": confusion_matrix(y_true, y_pred, labels=labels).tolist(),
        "labels": labels,
    }
    return model, threshold, score_rows, metrics


def write_scores(rows: list[dict[str, str | float | int]], output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(
            file,
            fieldnames=[
                "window_id",
                "source_pcap",
                "label",
                "binary_label",
                "anomaly_score",
                "threshold",
                "predicted_state",
            ],
        )
        writer.writeheader()
        writer.writerows(rows)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Train a K-Means anomaly detector.")
    parser.add_argument("--features", type=Path, default=DEFAULT_FEATURES)
    parser.add_argument("--model-output", type=Path, default=DEFAULT_MODEL)
    parser.add_argument("--scores-output", type=Path, default=DEFAULT_SCORES)
    parser.add_argument("--metrics-output", type=Path, default=DEFAULT_METRICS)
    parser.add_argument("--clusters", type=int, default=3)
    parser.add_argument("--threshold-percentile", type=float, default=99.0)
    parser.add_argument("--normal-label", default="normal")
    parser.add_argument("--seed", type=int, default=3611)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    rows, feature_names = load_features(args.features)
    model, threshold, score_rows, metrics = train_detector(
        rows=rows,
        feature_names=feature_names,
        clusters=args.clusters,
        threshold_percentile=args.threshold_percentile,
        seed=args.seed,
        normal_label=args.normal_label,
    )

    args.model_output.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(
        {"model": model, "feature_names": feature_names, "threshold": threshold},
        args.model_output,
    )
    write_scores(score_rows, args.scores_output)

    args.metrics_output.parent.mkdir(parents=True, exist_ok=True)
    with args.metrics_output.open("w", encoding="utf-8") as file:
        json.dump(metrics, file, ensure_ascii=False, indent=2)

    report = metrics["classification_report"]
    print(f"saved anomaly detector to {args.model_output}")
    print(f"saved anomaly scores to {args.scores_output}")
    print(f"saved metrics to {args.metrics_output}")
    print(f"threshold: {threshold:.6f}")
    print(f"anomaly recall: {report['anomaly']['recall']:.4f}")
    print(f"normal recall: {report['normal']['recall']:.4f}")


if __name__ == "__main__":
    main()
