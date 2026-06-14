from __future__ import annotations

import csv
import ipaddress
import os
from dataclasses import dataclass
from pathlib import Path

os.environ.setdefault("OMP_NUM_THREADS", "1")

import joblib

from .defense import apply_commands, build_iptables_blacklist


@dataclass(frozen=True)
class MlBlockConfig:
    detector: str
    model_path: Path
    features_path: Path
    ip: str
    min_bad_windows: int = 1
    whitelist: frozenset[str] = frozenset()
    dry_run: bool = True


@dataclass(frozen=True)
class MlWindowDecision:
    window_id: str
    source_pcap: str
    decision: str
    is_bad: bool
    score: float | None = None
    threshold: float | None = None


@dataclass(frozen=True)
class MlBlockResult:
    total_windows: int
    bad_windows: int
    blocked: bool
    blocked_ip: str | None


def parse_whitelist(value: str | None) -> frozenset[str]:
    if not value:
        return frozenset()
    return frozenset(item.strip() for item in value.split(",") if item.strip())


def validate_ip(value: str) -> str:
    try:
        return str(ipaddress.ip_address(value))
    except ValueError as exc:
        raise ValueError(f"invalid IP address: {value}") from exc


def _load_feature_rows(path: Path) -> list[dict[str, str]]:
    with path.open("r", newline="", encoding="utf-8") as file:
        rows = list(csv.DictReader(file))
    if not rows:
        raise ValueError(f"no feature rows found in {path}")
    return rows


def _vectorize(rows: list[dict[str, str]], feature_names: list[str]) -> list[list[float]]:
    missing = [name for name in feature_names if name not in rows[0]]
    if missing:
        raise ValueError(f"feature file is missing model columns: {', '.join(missing)}")
    return [[float(row[name]) for name in feature_names] for row in rows]


def _mlp_decisions(bundle: dict[str, object], rows: list[dict[str, str]]) -> list[MlWindowDecision]:
    model = bundle["model"]
    feature_names = list(bundle["feature_names"])
    x_rows = _vectorize(rows, feature_names)
    predictions = model.predict(x_rows)

    decisions: list[MlWindowDecision] = []
    for row, prediction in zip(rows, predictions):
        predicted_label = str(prediction)
        decisions.append(
            MlWindowDecision(
                window_id=row.get("window_id", ""),
                source_pcap=row.get("source_pcap", ""),
                decision=predicted_label,
                is_bad=predicted_label == "abnormal",
            )
        )
    return decisions


def _kmeans_decisions(bundle: dict[str, object], rows: list[dict[str, str]]) -> list[MlWindowDecision]:
    model = bundle["model"]
    feature_names = list(bundle["feature_names"])
    threshold = float(bundle["threshold"])
    x_rows = _vectorize(rows, feature_names)
    transformed = model.named_steps["scaler"].transform(x_rows)
    distances = model.named_steps["kmeans"].transform(transformed)

    decisions: list[MlWindowDecision] = []
    for row, distance_row in zip(rows, distances):
        score = float(min(distance_row))
        is_bad = score > threshold
        decisions.append(
            MlWindowDecision(
                window_id=row.get("window_id", ""),
                source_pcap=row.get("source_pcap", ""),
                decision="anomaly" if is_bad else "normal",
                is_bad=is_bad,
                score=score,
                threshold=threshold,
            )
        )
    return decisions


def _print_decision(decision: MlWindowDecision) -> None:
    parts = [
        f"window={decision.window_id}",
        f"source={decision.source_pcap}",
        f"decision={decision.decision}",
        f"bad={str(decision.is_bad).lower()}",
    ]
    if decision.score is not None and decision.threshold is not None:
        parts.extend([f"score={decision.score:.8f}", f"threshold={decision.threshold:.8f}"])
    print("[ml-block] " + " ".join(parts))


def run_ml_block(cfg: MlBlockConfig) -> MlBlockResult:
    ip = validate_ip(cfg.ip)
    if cfg.min_bad_windows < 1:
        raise ValueError("--min-bad-windows must be at least 1")

    rows = _load_feature_rows(cfg.features_path)
    bundle = joblib.load(cfg.model_path)
    if cfg.detector == "mlp":
        decisions = _mlp_decisions(bundle, rows)
    elif cfg.detector == "kmeans":
        decisions = _kmeans_decisions(bundle, rows)
    else:
        raise ValueError(f"unsupported detector: {cfg.detector}")

    for decision in decisions:
        _print_decision(decision)

    bad_windows = sum(decision.is_bad for decision in decisions)
    should_block = bad_windows >= cfg.min_bad_windows
    print(
        "[ml-block] "
        f"total_windows={len(decisions)} bad_windows={bad_windows} "
        f"min_bad_windows={cfg.min_bad_windows} dry_run={cfg.dry_run}"
    )

    if not should_block:
        print("[ml-block] no blacklist action triggered")
        return MlBlockResult(len(decisions), bad_windows, False, None)

    if ip in cfg.whitelist:
        print(f"[ml-block] {ip} is whitelisted; blacklist action skipped")
        return MlBlockResult(len(decisions), bad_windows, False, None)

    print(f"[ml-block] threshold reached; blocking {ip}")
    apply_commands(build_iptables_blacklist(ip), dry_run=cfg.dry_run)
    return MlBlockResult(len(decisions), bad_windows, True, ip)
