# Detection Model Development

This directory contains the model-development workflow. It now uses scenario
PCAP captures under `attack1/data/scenarios` as the default data source.

Feature extraction defaults to 0.05-second time windows, treats TCP traffic on
ports `80`, `443`, and `8080` as HTTP-like traffic, and skips byte-identical
duplicate PCAP files unless `--include-duplicates` is passed.

`detection.mix_pcaps` now writes multiple seeds of each scenario by default.
Each seed contains the same scenario names but uses different packet counts,
durations, time-varying traffic profiles, and packet schedules. Normal traffic
has several distinct profiles (`steady`, `bursty`, `low_rate`, `high_rate`,
and low-noise background variants), so the normal class is expanded without
simply copying one benign capture.

The underlying HTTP PCAP generators also use long-tail sampling for client
addresses, request paths, and User-Agent strings. A few clients/paths/agents
therefore appear frequently while most appear rarely, which is closer to web
traffic than uniform random selection.

The feature CSV keeps the legacy traffic-family `label`, but supervised MLP
training now defaults to the binary `binary_label` target:

- `normal` for benign windows.
- `abnormal` for attack windows.

Additional ratio columns (`normal_ratio`, `http_flood_ratio`,
`syn_flood_ratio`, `udp_reflection_ratio`, `attack_ratio`) are exported as
label/explanation metadata for mixed-flow datasets. They are deliberately
excluded from model input features to avoid label leakage.

```bash
python -m detection.mix_pcaps
python -m detection.features
python -m detection.train_mlp
python -m detection.train_kmeans
python -m detection.plot_results
python -m detection.predict_classifier
python -m detection.predict_anomaly
```

Outputs are written under `detection/data` and `detection/models`.

`detection.mix_pcaps` writes a default suite of noisy/mixed scenario PCAPs
under `attack1/data/scenarios` plus same-stem `.labels.csv` sidecars. Feature
extraction reads those sidecars and computes per-window traffic composition, so
mixed windows can have fractional `attack_ratio` values instead of only `0` or
`1`. The original pure `attack1/data/generated_*.pcap` files remain source
material for the mixer, but are not the default training input.

MLP training is a binary `normal` / `abnormal` task by default and uses seed
groups for train/validation/test splitting (`--split-mode seed`). Windows from
the same generated seed are kept in the same split, which avoids evaluating on
adjacent windows from the same synthetic capture. The metrics file still reports
one aggregate binary classification report for the test split, plus separate
train, validation, and test metrics with false-positive and false-negative
rates.

K-Means anomaly detection follows the same seed split. It trains cluster centers
only on normal windows from the training seeds, searches `k` and the anomaly
threshold percentile on the validation seed, and reports final normal/anomaly
metrics on the held-out test seed. The default selection rule maximizes anomaly
recall subject to validation false-positive rate not exceeding 5%, then breaks
ties by macro-F1.

The K-Means metrics file also includes leave-one-attack-type-out evaluations.
For each attack family, threshold tuning excludes that family from validation
and the final test contains normal windows plus the held-out attack family.
This is intended to show how well the normal-only detector handles attacks not
used while selecting the anomaly threshold.
