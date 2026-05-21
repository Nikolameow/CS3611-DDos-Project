# Detection Model Development

This directory contains the model-development workflow. It now uses scenario
PCAP captures under `attack1/data/scenarios` as the default data source.

Feature extraction defaults to 0.05-second time windows, treats TCP traffic on
ports `80`, `443`, and `8080` as HTTP-like traffic, and skips byte-identical
duplicate PCAP files unless `--include-duplicates` is passed.

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
