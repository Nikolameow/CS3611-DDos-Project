#!/usr/bin/env python3
"""Train an MLP classifier on detection feature rows."""

from __future__ import annotations

import argparse
import csv
import json
import random
import re
from collections import Counter
from pathlib import Path

import joblib
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix, log_loss
from sklearn.neural_network import MLPClassifier
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler


DEFAULT_FEATURES = Path("detection/data/features.csv")
DEFAULT_MODEL = Path("detection/models/ddos_mlp.joblib")
DEFAULT_METRICS = Path("detection/models/metrics.json")
DEFAULT_TARGET_COLUMN = "binary_label"
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


def binary_label_from_legacy(label: str) -> str:
    return "normal" if label == "normal" else "abnormal"


def load_features(path: Path, target_column: str) -> tuple[list[list[float]], list[str], list[str], list[str]]:
    with path.open("r", newline="", encoding="utf-8") as file:
        reader = csv.DictReader(file)
        fieldnames = reader.fieldnames or []
        if target_column not in fieldnames and target_column != "binary_label":
            raise ValueError(f"target column '{target_column}' not found in {path}")
        feature_names = [name for name in fieldnames if name not in METADATA_COLUMNS and name != target_column]
        x_rows: list[list[float]] = []
        y_rows: list[str] = []
        groups: list[str] = []
        for row in reader:
            x_rows.append([float(row[name]) for name in feature_names])
            groups.append(row.get("source_pcap", f"row-{len(groups)}"))
            if target_column in row and row[target_column]:
                y_rows.append(row[target_column])
            elif target_column == "binary_label":
                y_rows.append(binary_label_from_legacy(row["label"]))
            else:
                raise ValueError(f"target column '{target_column}' is empty")
    if not x_rows:
        raise ValueError(f"no feature rows found in {path}")
    return x_rows, y_rows, groups, feature_names


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


def seed_group_from_source(source_pcap: str) -> str:
    match = re.search(r"_seed(\d+)", source_pcap)
    return f"seed{match.group(1)}" if match else source_pcap


def grouped_indices(
    groups: list[str],
    *,
    split_mode: str,
    seed: int,
    train_fraction: float,
    validation_fraction: float,
) -> tuple[list[int], list[int], list[int], dict[str, object]]:
    if split_mode == "seed":
        split_groups = [seed_group_from_source(group) for group in groups]
    elif split_mode == "source":
        split_groups = groups
    else:
        raise ValueError(f"unsupported split mode: {split_mode}")

    by_group: dict[str, list[int]] = {}
    for index, group in enumerate(split_groups):
        by_group.setdefault(group, []).append(index)

    group_names = sorted(by_group)
    metadata: dict[str, object] = {
        "requested_split_mode": split_mode,
        "actual_split_mode": split_mode,
        "group_count": len(group_names),
        "groups": group_names,
    }
    if len(group_names) < 3:
        metadata["actual_split_mode"] = "label_stratified_row_fallback"
        metadata["warning"] = (
            "fewer than 3 independent groups were available; "
            "falling back to label-stratified row split"
        )
        return [], [], [], metadata

    rng = random.Random(seed)
    rng.shuffle(group_names)
    train_count = max(1, round(len(group_names) * train_fraction))
    validation_count = max(1, round(len(group_names) * validation_fraction))
    if train_count + validation_count >= len(group_names):
        train_count = max(1, len(group_names) - 2)
        validation_count = 1

    train_groups = set(group_names[:train_count])
    validation_groups = set(group_names[train_count : train_count + validation_count])
    test_groups = set(group_names[train_count + validation_count :])
    metadata.update(
        {
            "train_groups": sorted(train_groups),
            "validation_groups": sorted(validation_groups),
            "test_groups": sorted(test_groups),
        }
    )

    return (
        [index for index, group in enumerate(split_groups) if group in train_groups],
        [index for index, group in enumerate(split_groups) if group in validation_groups],
        [index for index, group in enumerate(split_groups) if group in test_groups],
        metadata,
    )


def split_train_validation_test(
    x_rows: list[list[float]],
    y_rows: list[str],
    groups: list[str],
    *,
    split_mode: str,
    seed: int,
    train_fraction: float = 0.60,
    validation_fraction: float = 0.20,
) -> tuple[list[list[float]], list[list[float]], list[list[float]], list[str], list[str], list[str], dict[str, object]]:
    train_indices, validation_indices, test_indices, split_metadata = grouped_indices(
        groups,
        split_mode=split_mode,
        seed=seed,
        train_fraction=train_fraction,
        validation_fraction=validation_fraction,
    )
    if split_metadata["actual_split_mode"] == "label_stratified_row_fallback":
        x_train_validation, x_test, y_train_validation, y_test = split_by_label(
            x_rows,
            y_rows,
            test_fraction=1.0 - train_fraction - validation_fraction,
            seed=seed,
        )
        x_train, x_validation, y_train, y_validation = split_by_label(
            x_train_validation,
            y_train_validation,
            test_fraction=validation_fraction / (train_fraction + validation_fraction),
            seed=seed + 1,
        )
        return x_train, x_validation, x_test, y_train, y_validation, y_test, split_metadata

    return (
        [x_rows[index] for index in train_indices],
        [x_rows[index] for index in validation_indices],
        [x_rows[index] for index in test_indices],
        [y_rows[index] for index in train_indices],
        [y_rows[index] for index in validation_indices],
        [y_rows[index] for index in test_indices],
        split_metadata,
    )


def fit_loss_curves(
    x_train: list[list[float]],
    y_train: list[str],
    labels: list[str],
    seed: int,
    *,
    epochs: int = 160,
) -> tuple[list[float], list[float]]:
    x_fit, x_val, y_fit, y_val = split_by_label(
        x_train,
        y_train,
        test_fraction=0.20,
        seed=seed + 1,
    )
    scaler = StandardScaler()
    x_fit_scaled = scaler.fit_transform(x_fit)
    x_val_scaled = scaler.transform(x_val)

    mlp = MLPClassifier(
        hidden_layer_sizes=(64, 32),
        activation="relu",
        alpha=0.0005,
        learning_rate_init=0.001,
        max_iter=1,
        random_state=seed,
        warm_start=False,
    )

    train_loss: list[float] = []
    validation_loss: list[float] = []
    for epoch in range(epochs):
        if epoch == 0:
            mlp.partial_fit(x_fit_scaled, y_fit, classes=labels)
        else:
            mlp.partial_fit(x_fit_scaled, y_fit)
        train_loss.append(float(mlp.loss_))
        validation_probabilities = mlp.predict_proba(x_val_scaled)
        validation_loss.append(float(log_loss(y_val, validation_probabilities, labels=labels)))
    return train_loss, validation_loss


def evaluation_metrics(y_true: list[str], y_pred: list[str], labels: list[str]) -> dict[str, object]:
    matrix = confusion_matrix(y_true, y_pred, labels=labels)
    result: dict[str, object] = {
        "accuracy": accuracy_score(y_true, y_pred),
        "classification_report": classification_report(
            y_true,
            y_pred,
            labels=labels,
            output_dict=True,
            zero_division=0,
        ),
        "confusion_matrix": matrix.tolist(),
    }
    if labels == ["abnormal", "normal"]:
        abnormal_index = labels.index("abnormal")
        normal_index = labels.index("normal")
        normal_total = int(matrix[normal_index].sum())
        abnormal_total = int(matrix[abnormal_index].sum())
        false_positives = int(matrix[normal_index][abnormal_index])
        false_negatives = int(matrix[abnormal_index][normal_index])
        result["false_positive_rate"] = false_positives / normal_total if normal_total else 0.0
        result["false_negative_rate"] = false_negatives / abnormal_total if abnormal_total else 0.0
    return result


def train_model(
    x_rows: list[list[float]],
    y_rows: list[str],
    groups: list[str],
    seed: int,
    *,
    target_column: str,
    split_mode: str,
) -> tuple[Pipeline, dict[str, object]]:
    labels = sorted(set(y_rows))
    class_counts = Counter(y_rows)
    x_train, x_validation, x_test, y_train, y_validation, y_test, split_metadata = split_train_validation_test(
        x_rows,
        y_rows,
        groups,
        split_mode=split_mode,
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
    validation_predictions = model.predict(x_validation)
    test_predictions = model.predict(x_test)
    mlp = model.named_steps["mlp"]
    train_loss_curve, validation_loss_curve = fit_loss_curves(x_train + x_validation, y_train + y_validation, labels, seed)

    metrics: dict[str, object] = {
        "target_column": target_column,
        "split": split_metadata,
        "accuracy": accuracy_score(y_test, test_predictions),
        "train_accuracy": accuracy_score(y_train, train_predictions),
        "validation_accuracy": accuracy_score(y_validation, validation_predictions),
        "test_accuracy": accuracy_score(y_test, test_predictions),
        "labels": labels,
        "train_metrics": evaluation_metrics(y_train, train_predictions, labels),
        "validation_metrics": evaluation_metrics(y_validation, validation_predictions, labels),
        "test_metrics": evaluation_metrics(y_test, test_predictions, labels),
        "classification_report": evaluation_metrics(y_test, test_predictions, labels)["classification_report"],
        "confusion_matrix": evaluation_metrics(y_test, test_predictions, labels)["confusion_matrix"],
        "train_size": len(x_train),
        "validation_size": len(x_validation),
        "test_size": len(x_test),
        "train_fraction": 0.60,
        "validation_fraction": 0.20,
        "test_fraction": 0.20,
        "class_counts": dict(class_counts),
        "train_class_counts": dict(Counter(y_train)),
        "validation_class_counts": dict(Counter(y_validation)),
        "test_class_counts": dict(Counter(y_test)),
        "loss_curve": train_loss_curve,
        "validation_loss_curve": validation_loss_curve,
        "final_fit_loss_curve": [float(value) for value in getattr(mlp, "loss_curve_", [])],
        "n_iter": int(getattr(mlp, "n_iter_", 0)),
    }
    return model, metrics


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Train the DDoS MLP classifier.")
    parser.add_argument("--features", type=Path, default=DEFAULT_FEATURES)
    parser.add_argument("--model-output", type=Path, default=DEFAULT_MODEL)
    parser.add_argument("--metrics-output", type=Path, default=DEFAULT_METRICS)
    parser.add_argument("--target-column", default=DEFAULT_TARGET_COLUMN)
    parser.add_argument("--split-mode", choices=["seed", "source"], default="seed")
    parser.add_argument("--seed", type=int, default=3611)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    x_rows, y_rows, groups, feature_names = load_features(args.features, args.target_column)
    model, metrics = train_model(
        x_rows,
        y_rows,
        groups,
        seed=args.seed,
        target_column=args.target_column,
        split_mode=args.split_mode,
    )

    args.model_output.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(
        {"model": model, "feature_names": feature_names, "target_column": args.target_column},
        args.model_output,
    )

    args.metrics_output.parent.mkdir(parents=True, exist_ok=True)
    with args.metrics_output.open("w", encoding="utf-8") as file:
        json.dump(metrics, file, ensure_ascii=False, indent=2)

    print(f"saved model to {args.model_output}")
    print(f"saved metrics to {args.metrics_output}")
    print(
        f"train size: {metrics['train_size']} "
        f"validation size: {metrics['validation_size']} "
        f"test size: {metrics['test_size']}"
    )
    print(f"train accuracy: {metrics['train_accuracy']:.4f}")
    print(f"validation accuracy: {metrics['validation_accuracy']:.4f}")
    print(f"test accuracy: {metrics['test_accuracy']:.4f}")


if __name__ == "__main__":
    main()
