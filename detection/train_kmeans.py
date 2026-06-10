#!/usr/bin/env python3
"""Train a seed-split K-Means anomaly detector on normal feature windows."""

from __future__ import annotations

import argparse
import csv
import json
import os
import random
import re
from collections import Counter
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
DEFAULT_CLUSTER_CANDIDATES = "1,2,3,5,8,10"
DEFAULT_THRESHOLD_PERCENTILES = "90,92.5,95,97.5,99"
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


def parse_int_list(value: str) -> list[int]:
    result = [int(item.strip()) for item in value.split(",") if item.strip()]
    if not result:
        raise ValueError("expected at least one integer candidate")
    return result


def parse_float_list(value: str) -> list[float]:
    result = [float(item.strip()) for item in value.split(",") if item.strip()]
    if not result:
        raise ValueError("expected at least one float candidate")
    return result


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


def seed_group_from_source(source_pcap: str) -> str:
    match = re.search(r"_seed(\d+)", source_pcap)
    return f"seed{match.group(1)}" if match else source_pcap


def split_rows_by_seed(
    rows: list[dict[str, str]],
    *,
    seed: int,
    train_fraction: float = 0.60,
    validation_fraction: float = 0.20,
) -> tuple[list[dict[str, str]], list[dict[str, str]], list[dict[str, str]], dict[str, object]]:
    by_group: dict[str, list[dict[str, str]]] = {}
    for row in rows:
        by_group.setdefault(seed_group_from_source(row.get("source_pcap", "")), []).append(row)

    groups = sorted(by_group)
    if len(groups) < 3:
        raise ValueError("K-Means seed split needs at least 3 generated seed groups")

    rng = random.Random(seed)
    rng.shuffle(groups)
    train_count = max(1, round(len(groups) * train_fraction))
    validation_count = max(1, round(len(groups) * validation_fraction))
    if train_count + validation_count >= len(groups):
        train_count = max(1, len(groups) - 2)
        validation_count = 1

    train_groups = set(groups[:train_count])
    validation_groups = set(groups[train_count : train_count + validation_count])
    test_groups = set(groups[train_count + validation_count :])
    metadata = {
        "split_mode": "seed",
        "group_count": len(groups),
        "groups": groups,
        "train_groups": sorted(train_groups),
        "validation_groups": sorted(validation_groups),
        "test_groups": sorted(test_groups),
    }

    return (
        [row for row in rows if seed_group_from_source(row.get("source_pcap", "")) in train_groups],
        [row for row in rows if seed_group_from_source(row.get("source_pcap", "")) in validation_groups],
        [row for row in rows if seed_group_from_source(row.get("source_pcap", "")) in test_groups],
        metadata,
    )


def fit_model(
    normal_rows: list[dict[str, str]],
    feature_names: list[str],
    *,
    clusters: int,
    seed: int,
) -> Pipeline:
    if len(normal_rows) < clusters:
        raise ValueError("not enough normal rows to fit the requested number of clusters")
    model = Pipeline(
        steps=[
            ("scaler", StandardScaler()),
            ("kmeans", KMeans(n_clusters=clusters, n_init=20, random_state=seed)),
        ]
    )
    model.fit(vectorize(normal_rows, feature_names))
    return model


def actual_state(row: dict[str, str], normal_label: str) -> str:
    return "normal" if row_binary_label(row) == normal_label else "anomaly"


def predictions_from_scores(scores: list[float], threshold: float) -> list[str]:
    return ["anomaly" if score > threshold else "normal" for score in scores]


def evaluate_states(y_true: list[str], y_pred: list[str]) -> dict[str, object]:
    labels = ["normal", "anomaly"]
    matrix = confusion_matrix(y_true, y_pred, labels=labels)
    report = classification_report(
        y_true,
        y_pred,
        labels=labels,
        output_dict=True,
        zero_division=0,
    )
    normal_total = int(matrix[0].sum())
    anomaly_total = int(matrix[1].sum())
    false_positives = int(matrix[0][1])
    false_negatives = int(matrix[1][0])
    macro_f1 = float(report["macro avg"]["f1-score"])
    return {
        "classification_report": report,
        "confusion_matrix": matrix.tolist(),
        "labels": labels,
        "accuracy": float(report["accuracy"]),
        "macro_f1": macro_f1,
        "false_positive_rate": false_positives / normal_total if normal_total else 0.0,
        "false_negative_rate": false_negatives / anomaly_total if anomaly_total else 0.0,
        "normal_count": normal_total,
        "anomaly_count": anomaly_total,
    }


def evaluate_model(
    model: Pipeline,
    rows: list[dict[str, str]],
    feature_names: list[str],
    threshold: float,
    normal_label: str,
) -> tuple[list[float], dict[str, object]]:
    scores = anomaly_scores(model, vectorize(rows, feature_names))
    y_true = [actual_state(row, normal_label) for row in rows]
    y_pred = predictions_from_scores(scores, threshold)
    return scores, evaluate_states(y_true, y_pred)


def candidate_sort_key(candidate: dict[str, object], max_fpr: float) -> tuple[int, float, float, float]:
    metrics = candidate["validation_metrics"]
    assert isinstance(metrics, dict)
    report = metrics["classification_report"]
    assert isinstance(report, dict)
    anomaly = report["anomaly"]
    assert isinstance(anomaly, dict)
    fpr = float(metrics["false_positive_rate"])
    satisfies_fpr = 1 if fpr <= max_fpr else 0
    return (
        satisfies_fpr,
        float(anomaly["recall"]),
        float(metrics["macro_f1"]),
        -fpr,
    )


def select_model(
    train_rows: list[dict[str, str]],
    validation_rows: list[dict[str, str]],
    feature_names: list[str],
    *,
    cluster_candidates: list[int],
    threshold_percentiles: list[float],
    max_fpr: float,
    normal_label: str,
    seed: int,
) -> tuple[Pipeline, float, dict[str, object], list[dict[str, object]]]:
    train_normal_rows = [row for row in train_rows if row_binary_label(row) == normal_label]
    if not train_normal_rows:
        raise ValueError("no normal rows in training split")

    candidates: list[dict[str, object]] = []
    models: dict[int, Pipeline] = {}
    for clusters in cluster_candidates:
        if len(train_normal_rows) < clusters:
            continue
        model = fit_model(train_normal_rows, feature_names, clusters=clusters, seed=seed)
        models[clusters] = model
        train_normal_scores = anomaly_scores(model, vectorize(train_normal_rows, feature_names))
        for threshold_percentile in threshold_percentiles:
            threshold = percentile(train_normal_scores, threshold_percentile)
            _scores, validation_metrics = evaluate_model(
                model,
                validation_rows,
                feature_names,
                threshold,
                normal_label,
            )
            candidates.append(
                {
                    "clusters": clusters,
                    "threshold_percentile": threshold_percentile,
                    "threshold": threshold,
                    "validation_metrics": validation_metrics,
                }
            )

    if not candidates:
        raise ValueError("no valid K-Means candidates could be evaluated")

    best = max(candidates, key=lambda candidate: candidate_sort_key(candidate, max_fpr))
    return models[int(best["clusters"])], float(best["threshold"]), best, candidates


def score_rows_for_output(
    rows: list[dict[str, str]],
    scores: list[float],
    threshold: float,
    normal_label: str,
) -> list[dict[str, str | float | int]]:
    output_rows: list[dict[str, str | float | int]] = []
    for row, score in zip(rows, scores):
        output_rows.append(
            {
                "window_id": int(row["window_id"]),
                "source_pcap": row.get("source_pcap", ""),
                "label": row["label"],
                "binary_label": row_binary_label(row),
                "anomaly_score": round(score, 8),
                "threshold": round(threshold, 8),
                "predicted_state": "anomaly" if score > threshold else "normal",
            }
        )
    return output_rows


def unknown_attack_evaluation(
    rows: list[dict[str, str]],
    feature_names: list[str],
    split: dict[str, object],
    *,
    cluster_candidates: list[int],
    threshold_percentiles: list[float],
    max_fpr: float,
    normal_label: str,
    seed: int,
) -> dict[str, object]:
    train_groups = set(split["train_groups"])
    validation_groups = set(split["validation_groups"])
    test_groups = set(split["test_groups"])
    attack_labels = sorted({row["label"] for row in rows if row_binary_label(row) != normal_label})
    results: dict[str, object] = {}

    for holdout_label in attack_labels:
        train_rows = [
            row
            for row in rows
            if seed_group_from_source(row.get("source_pcap", "")) in train_groups
            and row_binary_label(row) == normal_label
        ]
        validation_rows = [
            row
            for row in rows
            if seed_group_from_source(row.get("source_pcap", "")) in validation_groups
            and (row_binary_label(row) == normal_label or row["label"] != holdout_label)
        ]
        test_rows = [
            row
            for row in rows
            if seed_group_from_source(row.get("source_pcap", "")) in test_groups
            and (row_binary_label(row) == normal_label or row["label"] == holdout_label)
        ]
        if not validation_rows or not test_rows or not any(row["label"] == holdout_label for row in test_rows):
            results[holdout_label] = {"skipped": True, "reason": "not enough validation/test rows"}
            continue

        model, threshold, best, _candidates = select_model(
            train_rows,
            validation_rows,
            feature_names,
            cluster_candidates=cluster_candidates,
            threshold_percentiles=threshold_percentiles,
            max_fpr=max_fpr,
            normal_label=normal_label,
            seed=seed,
        )
        _scores, test_metrics = evaluate_model(model, test_rows, feature_names, threshold, normal_label)
        results[holdout_label] = {
            "skipped": False,
            "clusters": best["clusters"],
            "threshold_percentile": best["threshold_percentile"],
            "threshold": threshold,
            "validation_rows": len(validation_rows),
            "test_rows": len(test_rows),
            "test_label_counts": dict(Counter(row["label"] for row in test_rows)),
            "test_metrics": test_metrics,
        }

    return results


def train_detector(
    rows: list[dict[str, str]],
    feature_names: list[str],
    cluster_candidates: list[int],
    threshold_percentiles: list[float],
    max_fpr: float,
    seed: int,
    normal_label: str,
) -> tuple[Pipeline, float, list[dict[str, str | float | int]], dict[str, object]]:
    train_rows, validation_rows, test_rows, split = split_rows_by_seed(rows, seed=seed)
    model, threshold, best, candidates = select_model(
        train_rows,
        validation_rows,
        feature_names,
        cluster_candidates=cluster_candidates,
        threshold_percentiles=threshold_percentiles,
        max_fpr=max_fpr,
        normal_label=normal_label,
        seed=seed,
    )

    train_normal_rows = [row for row in train_rows if row_binary_label(row) == normal_label]
    train_scores, train_metrics = evaluate_model(model, train_rows, feature_names, threshold, normal_label)
    validation_scores, validation_metrics = evaluate_model(model, validation_rows, feature_names, threshold, normal_label)
    test_scores, test_metrics = evaluate_model(model, test_rows, feature_names, threshold, normal_label)
    score_rows = score_rows_for_output(test_rows, test_scores, threshold, normal_label)

    unknown_results = unknown_attack_evaluation(
        rows,
        feature_names,
        split,
        cluster_candidates=cluster_candidates,
        threshold_percentiles=threshold_percentiles,
        max_fpr=max_fpr,
        normal_label=normal_label,
        seed=seed,
    )

    labels = ["normal", "anomaly"]
    metrics: dict[str, object] = {
        "method": "kmeans_distance_to_normal_clusters_seed_split",
        "normal_label": normal_label,
        "split": split,
        "cluster_candidates": cluster_candidates,
        "threshold_percentile_candidates": threshold_percentiles,
        "selection_rule": f"maximize anomaly recall with validation FPR <= {max_fpr}, tie by macro-F1",
        "clusters": best["clusters"],
        "threshold_percentile": best["threshold_percentile"],
        "threshold": threshold,
        "train_size": len(train_rows),
        "validation_size": len(validation_rows),
        "test_size": len(test_rows),
        "train_normal_windows": len(train_normal_rows),
        "train_class_counts": dict(Counter(actual_state(row, normal_label) for row in train_rows)),
        "validation_class_counts": dict(Counter(actual_state(row, normal_label) for row in validation_rows)),
        "test_class_counts": dict(Counter(actual_state(row, normal_label) for row in test_rows)),
        "train_metrics": train_metrics,
        "validation_metrics": validation_metrics,
        "test_metrics": test_metrics,
        "classification_report": test_metrics["classification_report"],
        "confusion_matrix": test_metrics["confusion_matrix"],
        "labels": labels,
        "evaluated_windows": len(test_rows),
        "candidate_results": candidates,
        "unknown_attack_evaluation": unknown_results,
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
    parser = argparse.ArgumentParser(description="Train the K-Means anomaly detector.")
    parser.add_argument("--features", type=Path, default=DEFAULT_FEATURES)
    parser.add_argument("--model-output", type=Path, default=DEFAULT_MODEL)
    parser.add_argument("--scores-output", type=Path, default=DEFAULT_SCORES)
    parser.add_argument("--metrics-output", type=Path, default=DEFAULT_METRICS)
    parser.add_argument("--cluster-candidates", default=DEFAULT_CLUSTER_CANDIDATES)
    parser.add_argument("--threshold-percentiles", default=DEFAULT_THRESHOLD_PERCENTILES)
    parser.add_argument("--max-validation-fpr", type=float, default=0.05)
    parser.add_argument("--normal-label", default="normal")
    parser.add_argument("--seed", type=int, default=3611)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    rows, feature_names = load_features(args.features)
    model, threshold, score_rows, metrics = train_detector(
        rows=rows,
        feature_names=feature_names,
        cluster_candidates=parse_int_list(args.cluster_candidates),
        threshold_percentiles=parse_float_list(args.threshold_percentiles),
        max_fpr=args.max_validation_fpr,
        seed=args.seed,
        normal_label=args.normal_label,
    )

    args.model_output.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(
        {
            "model": model,
            "feature_names": feature_names,
            "threshold": threshold,
            "split": metrics["split"],
            "clusters": metrics["clusters"],
            "threshold_percentile": metrics["threshold_percentile"],
        },
        args.model_output,
    )
    write_scores(score_rows, args.scores_output)

    args.metrics_output.parent.mkdir(parents=True, exist_ok=True)
    with args.metrics_output.open("w", encoding="utf-8") as file:
        json.dump(metrics, file, ensure_ascii=False, indent=2)

    report = metrics["classification_report"]
    print(f"saved anomaly detector to {args.model_output}")
    print(f"saved test anomaly scores to {args.scores_output}")
    print(f"saved metrics to {args.metrics_output}")
    print(f"selected clusters: {metrics['clusters']}")
    print(f"threshold percentile: {metrics['threshold_percentile']}")
    print(f"threshold: {threshold:.6f}")
    print(f"test anomaly recall: {report['anomaly']['recall']:.4f}")
    print(f"test normal recall: {report['normal']['recall']:.4f}")


if __name__ == "__main__":
    main()
