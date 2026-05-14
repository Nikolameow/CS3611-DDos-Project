#!/usr/bin/env python3
"""Train an MLP classifier on detection feature rows."""

from __future__ import annotations

import argparse
import csv
import json
import random
from collections import Counter
from pathlib import Path

import joblib
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
from sklearn.neural_network import MLPClassifier
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler


DEFAULT_FEATURES = Path("detection/data/features.csv")
DEFAULT_MODEL = Path("detection/models/ddos_mlp.joblib")
DEFAULT_METRICS = Path("detection/models/metrics.json")
DROP_COLUMNS = {"window_id", "source_pcap", "label"}


def load_features(path: Path) -> tuple[list[list[float]], list[str], list[str]]:
    with path.open("r", newline="", encoding="utf-8") as file:
        reader = csv.DictReader(file)
        feature_names = [name for name in reader.fieldnames or [] if name not in DROP_COLUMNS]
        x_rows: list[list[float]] = []
        y_rows: list[str] = []
        for row in reader:
            x_rows.append([float(row[name]) for name in feature_names])
            y_rows.append(row["label"])
    if not x_rows:
        raise ValueError(f"no feature rows found in {path}")
    return x_rows, y_rows, feature_names


def split_by_label(
    x_rows: list[list[float]],
    y_rows: list[str],
    *,
    test_fraction: float,
    seed: int,
) -> tuple[list[list[float]], list[list[float]], list[str], list[str]]:
    by_label: dict[str, list[int]] = {}
    for index, label in enumerate(y_rows):
        by_label.setdefault(label, []).append(index)

    rng = random.Random(seed)
    train_indices: list[int] = []
    test_indices: list[int] = []
    for label_indices in by_label.values():
        rng.shuffle(label_indices)
        if len(label_indices) == 1:
            train_indices.extend(label_indices)
            continue
        test_count = max(1, round(len(label_indices) * test_fraction))
        test_count = min(test_count, len(label_indices) - 1)
        test_indices.extend(label_indices[:test_count])
        train_indices.extend(label_indices[test_count:])

    if not test_indices:
        raise ValueError("need at least two feature rows to create a test split")
    rng.shuffle(train_indices)
    rng.shuffle(test_indices)
    return (
        [x_rows[index] for index in train_indices],
        [x_rows[index] for index in test_indices],
        [y_rows[index] for index in train_indices],
        [y_rows[index] for index in test_indices],
    )


def train_model(x_rows: list[list[float]], y_rows: list[str], seed: int) -> tuple[Pipeline, dict[str, object]]:
    labels = sorted(set(y_rows))
    class_counts = Counter(y_rows)
    test_fraction = 0.25
    x_train, x_test, y_train, y_test = split_by_label(
        x_rows,
        y_rows,
        test_fraction=test_fraction,
        seed=seed,
    )

    model = Pipeline(
        steps=[
            ("scaler", StandardScaler()),
            (
                "mlp",
                MLPClassifier(
                    hidden_layer_sizes=(64, 32),
                    activation="relu",
                    alpha=0.0005,
                    learning_rate_init=0.001,
                    max_iter=600,
                    random_state=seed,
                    early_stopping=False,
                ),
            ),
        ]
    )
    model.fit(x_train, y_train)
    train_predictions = model.predict(x_train)
    test_predictions = model.predict(x_test)
    mlp = model.named_steps["mlp"]

    metrics: dict[str, object] = {
        "accuracy": accuracy_score(y_test, test_predictions),
        "train_accuracy": accuracy_score(y_train, train_predictions),
        "test_accuracy": accuracy_score(y_test, test_predictions),
        "labels": labels,
        "classification_report": classification_report(
            y_test,
            test_predictions,
            labels=labels,
            output_dict=True,
            zero_division=0,
        ),
        "confusion_matrix": confusion_matrix(y_test, test_predictions, labels=labels).tolist(),
        "train_size": len(x_train),
        "test_size": len(x_test),
        "test_fraction": test_fraction,
        "class_counts": dict(class_counts),
        "train_class_counts": dict(Counter(y_train)),
        "test_class_counts": dict(Counter(y_test)),
        "loss_curve": [float(value) for value in getattr(mlp, "loss_curve_", [])],
        "n_iter": int(getattr(mlp, "n_iter_", 0)),
    }
    return model, metrics


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Train the DDoS MLP classifier.")
    parser.add_argument("--features", type=Path, default=DEFAULT_FEATURES)
    parser.add_argument("--model-output", type=Path, default=DEFAULT_MODEL)
    parser.add_argument("--metrics-output", type=Path, default=DEFAULT_METRICS)
    parser.add_argument("--seed", type=int, default=3611)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    x_rows, y_rows, feature_names = load_features(args.features)
    model, metrics = train_model(x_rows, y_rows, seed=args.seed)

    args.model_output.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump({"model": model, "feature_names": feature_names}, args.model_output)

    args.metrics_output.parent.mkdir(parents=True, exist_ok=True)
    with args.metrics_output.open("w", encoding="utf-8") as file:
        json.dump(metrics, file, ensure_ascii=False, indent=2)

    print(f"saved model to {args.model_output}")
    print(f"saved metrics to {args.metrics_output}")
    print(f"train size: {metrics['train_size']} test size: {metrics['test_size']}")
    print(f"train accuracy: {metrics['train_accuracy']:.4f}")
    print(f"test accuracy: {metrics['test_accuracy']:.4f}")


if __name__ == "__main__":
    main()
