#!/usr/bin/env python3
"""Generate report/poster figures from detection experiment outputs."""

from __future__ import annotations

import argparse
import csv
import json
from collections import Counter, defaultdict
from pathlib import Path

import matplotlib.pyplot as plt


DEFAULT_FEATURES = Path("detection/data/features.csv")
DEFAULT_ANOMALY_SCORES = Path("detection/data/anomaly_scores.csv")
DEFAULT_CLASSIFIER_METRICS = Path("detection/models/metrics.json")
DEFAULT_ANOMALY_METRICS = Path("detection/models/anomaly_metrics.json")
DEFAULT_OUTPUT_DIR = Path("docs/figures")


LABEL_NAMES = {
    "normal": "Normal",
    "syn_flood": "SYN Flood",
    "http_flood": "HTTP Flood",
    "udp_reflection": "UDP Reflection",
    "anomaly": "Anomaly",
}


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open("r", newline="", encoding="utf-8") as file:
        return list(csv.DictReader(file))


def read_json(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as file:
        return json.load(file)


def style_axes(ax) -> None:
    ax.grid(axis="y", color="#d9d9d9", linewidth=0.8, alpha=0.8)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)


def save(fig, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fig.tight_layout()
    fig.savefig(path, dpi=220, bbox_inches="tight")
    plt.close(fig)
    print(f"wrote {path}")


def remove_stale(path: Path) -> None:
    if path.exists():
        path.unlink()
        print(f"removed stale {path}")


def plot_pipeline(output_dir: Path) -> None:
    fig, ax = plt.subplots(figsize=(11.5, 3.2))
    ax.axis("off")
    steps = [
        ("attack1 PCAP\nCaptures", "#4c78a8"),
        ("Windowed Feature\nExtraction", "#f58518"),
        ("MLP Attack\nClassifier", "#54a24b"),
        ("Optional K-Means\nAnomaly Detection", "#b279a2"),
        ("Metrics + Poster\nFigures", "#e45756"),
    ]
    x_positions = [0.08, 0.29, 0.50, 0.71, 0.91]
    for index, ((label, color), x) in enumerate(zip(steps, x_positions)):
        ax.text(
            x,
            0.55,
            label,
            ha="center",
            va="center",
            fontsize=12,
            color="white",
            bbox={"boxstyle": "round,pad=0.55", "facecolor": color, "edgecolor": "none"},
            transform=ax.transAxes,
        )
        if index < len(steps) - 1:
            ax.annotate(
                "",
                xy=(x_positions[index + 1] - 0.08, 0.55),
                xytext=(x + 0.08, 0.55),
                arrowprops={"arrowstyle": "->", "lw": 1.8, "color": "#333333"},
                xycoords=ax.transAxes,
            )
    ax.set_title("DDoS Detection Experiment Pipeline", fontsize=16, pad=18)
    save(fig, output_dir / "system_pipeline.png")


def plot_class_counts(features: list[dict[str, str]], output_dir: Path) -> None:
    counts = Counter(row["label"] for row in features)
    labels = list(LABEL_NAMES)
    values = [counts[label] for label in labels if label in counts]
    names = [LABEL_NAMES[label] for label in labels if label in counts]

    fig, ax = plt.subplots(figsize=(8, 4.5))
    ax.bar(names, values, color=["#4c78a8", "#e45756", "#f58518", "#72b7b2"])
    ax.set_title("Feature Windows by Traffic Class")
    ax.set_ylabel("Windows")
    style_axes(ax)
    save(fig, output_dir / "class_distribution.png")


def plot_feature_summary(features: list[dict[str, str]], output_dir: Path) -> None:
    grouped: dict[str, list[dict[str, str]]] = defaultdict(list)
    for row in features:
        grouped[row["label"]].append(row)

    labels = [label for label in LABEL_NAMES if label in grouped]
    names = [LABEL_NAMES[label] for label in labels]
    pps = [sum(float(row["pps"]) for row in grouped[label]) / len(grouped[label]) for label in labels]
    syn_ratio = [
        sum(float(row["syn_ratio"]) for row in grouped[label]) / len(grouped[label]) for label in labels
    ]
    entropy = [
        sum(float(row["src_ip_entropy"]) for row in grouped[label]) / len(grouped[label])
        for label in labels
    ]

    fig, axes = plt.subplots(1, 3, figsize=(13.5, 4.2))
    metrics = [
        ("Average PPS", pps, "#4c78a8"),
        ("Average SYN Ratio", syn_ratio, "#e45756"),
        ("Average Source IP Entropy", entropy, "#54a24b"),
    ]
    for ax, (title, values, color) in zip(axes, metrics):
        ax.bar(names, values, color=color)
        ax.set_title(title)
        ax.tick_params(axis="x", rotation=20)
        style_axes(ax)
    save(fig, output_dir / "traffic_feature_summary.png")


def plot_confusion_matrix(metrics: dict, output_dir: Path) -> None:
    labels = metrics["labels"]
    matrix = metrics["confusion_matrix"]

    fig, ax = plt.subplots(figsize=(6, 5.4))
    image = ax.imshow(matrix, cmap="Blues")
    ax.set_title("MLP Classifier Confusion Matrix")
    ax.set_xlabel("Predicted Label")
    ax.set_ylabel("True Label")
    ax.set_xticks(range(len(labels)), [LABEL_NAMES.get(label, label) for label in labels], rotation=25)
    ax.set_yticks(range(len(labels)), [LABEL_NAMES.get(label, label) for label in labels])
    for i, row in enumerate(matrix):
        for j, value in enumerate(row):
            ax.text(j, i, str(value), ha="center", va="center", color="#111111")
    fig.colorbar(image, ax=ax, fraction=0.046, pad=0.04)
    save(fig, output_dir / "mlp_confusion_matrix.png")


def plot_mlp_train_test_split(metrics: dict, output_dir: Path) -> None:
    labels = metrics["labels"]
    train_counts = metrics.get("train_class_counts", {})
    test_counts = metrics.get("test_class_counts", {})
    names = [LABEL_NAMES.get(label, label) for label in labels]
    train_values = [train_counts.get(label, 0) for label in labels]
    test_values = [test_counts.get(label, 0) for label in labels]
    x_positions = list(range(len(labels)))
    width = 0.36

    fig, ax = plt.subplots(figsize=(8.8, 4.8))
    ax.bar([x - width / 2 for x in x_positions], train_values, width=width, color="#4c78a8", label="Train")
    ax.bar([x + width / 2 for x in x_positions], test_values, width=width, color="#f58518", label="Test")
    ax.set_title("MLP Train/Test Split by Class")
    ax.set_ylabel("Feature Windows")
    ax.set_xticks(x_positions, names, rotation=20)
    ax.legend()
    for x, value in zip([x - width / 2 for x in x_positions], train_values):
        ax.text(x, value, str(value), ha="center", va="bottom", fontsize=9)
    for x, value in zip([x + width / 2 for x in x_positions], test_values):
        ax.text(x, value, str(value), ha="center", va="bottom", fontsize=9)
    style_axes(ax)
    save(fig, output_dir / "mlp_train_test_split.png")


def plot_mlp_training_loss(metrics: dict, output_dir: Path) -> None:
    loss_curve = metrics.get("loss_curve", [])
    if not loss_curve:
        remove_stale(output_dir / "mlp_training_loss.png")
        return

    fig, ax = plt.subplots(figsize=(8.8, 4.6))
    ax.plot(range(1, len(loss_curve) + 1), loss_curve, color="#54a24b", linewidth=2.0)
    ax.set_title("MLP Training Loss Curve")
    ax.set_xlabel("Iteration")
    ax.set_ylabel("Loss")
    style_axes(ax)
    save(fig, output_dir / "mlp_training_loss.png")


def plot_mlp_classification_report(metrics: dict, output_dir: Path) -> None:
    labels = metrics["labels"]
    report = metrics["classification_report"]
    columns = ["precision", "recall", "f1-score"]
    values = [[float(report[label][column]) for column in columns] for label in labels]

    fig, ax = plt.subplots(figsize=(7.8, 4.8))
    image = ax.imshow(values, cmap="Greens", vmin=0.0, vmax=1.0)
    ax.set_title("MLP Test Classification Metrics")
    ax.set_xticks(range(len(columns)), ["Precision", "Recall", "F1"])
    ax.set_yticks(range(len(labels)), [LABEL_NAMES.get(label, label) for label in labels])
    for row_index, row in enumerate(values):
        for col_index, value in enumerate(row):
            ax.text(col_index, row_index, f"{value:.2f}", ha="center", va="center", color="#111111")
    fig.colorbar(image, ax=ax, fraction=0.046, pad=0.04)
    save(fig, output_dir / "mlp_classification_report.png")


def plot_anomaly_scores(scores: list[dict[str, str]], output_dir: Path) -> None:
    fig, ax = plt.subplots(figsize=(11, 4.6))
    colors = {
        "normal": "#4c78a8",
        "syn_flood": "#e45756",
        "http_flood": "#f58518",
        "udp_reflection": "#72b7b2",
    }
    grouped: dict[str, list[tuple[int, float]]] = defaultdict(list)
    for row in scores:
        grouped[row["label"]].append((int(row["window_id"]), float(row["anomaly_score"])))
    for label, points in grouped.items():
        points.sort()
        ax.scatter(
            [item[0] for item in points],
            [item[1] for item in points],
            s=14,
            alpha=0.75,
            color=colors.get(label, "#333333"),
            label=LABEL_NAMES.get(label, label),
        )
    threshold = float(scores[0]["threshold"]) if scores else 0.0
    ax.axhline(threshold, color="#222222", linestyle="--", linewidth=1.4, label="Threshold")
    ax.set_title("K-Means Anomaly Scores by Window")
    ax.set_xlabel("Window ID")
    ax.set_ylabel("Anomaly Score")
    ax.legend(ncols=3, fontsize=9)
    style_axes(ax)
    save(fig, output_dir / "anomaly_scores.png")


def plot_anomaly_confusion_matrix(metrics: dict, output_dir: Path) -> None:
    labels = metrics["labels"]
    matrix = metrics["confusion_matrix"]

    fig, ax = plt.subplots(figsize=(5.4, 4.8))
    image = ax.imshow(matrix, cmap="Purples")
    ax.set_title("K-Means Anomaly Detection Matrix")
    ax.set_xlabel("Predicted State")
    ax.set_ylabel("True State")
    ax.set_xticks(range(len(labels)), [LABEL_NAMES.get(label, label) for label in labels])
    ax.set_yticks(range(len(labels)), [LABEL_NAMES.get(label, label) for label in labels])
    for i, row in enumerate(matrix):
        for j, value in enumerate(row):
            ax.text(j, i, str(value), ha="center", va="center", color="#111111")
    fig.colorbar(image, ax=ax, fraction=0.046, pad=0.04)
    save(fig, output_dir / "anomaly_confusion_matrix.png")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate DDoS report/poster figures.")
    parser.add_argument("--features", type=Path, default=DEFAULT_FEATURES)
    parser.add_argument("--anomaly-scores", type=Path, default=DEFAULT_ANOMALY_SCORES)
    parser.add_argument("--classifier-metrics", type=Path, default=DEFAULT_CLASSIFIER_METRICS)
    parser.add_argument("--anomaly-metrics", type=Path, default=DEFAULT_ANOMALY_METRICS)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    features = read_csv(args.features)
    classifier_metrics = read_json(args.classifier_metrics)

    plot_pipeline(args.output_dir)
    plot_class_counts(features, args.output_dir)
    plot_feature_summary(features, args.output_dir)
    plot_confusion_matrix(classifier_metrics, args.output_dir)
    plot_mlp_train_test_split(classifier_metrics, args.output_dir)
    plot_mlp_training_loss(classifier_metrics, args.output_dir)
    plot_mlp_classification_report(classifier_metrics, args.output_dir)

    if args.anomaly_scores.exists() and args.anomaly_metrics.exists():
        anomaly_scores = read_csv(args.anomaly_scores)
        anomaly_metrics = read_json(args.anomaly_metrics)
        plot_anomaly_scores(anomaly_scores, args.output_dir)
        plot_anomaly_confusion_matrix(anomaly_metrics, args.output_dir)
    else:
        remove_stale(args.output_dir / "anomaly_scores.png")
        remove_stale(args.output_dir / "anomaly_confusion_matrix.png")
        print("skipped anomaly figures because anomaly detector outputs are missing")


if __name__ == "__main__":
    main()
