# Detection Model Development

This directory contains the model-development workflow. It now uses the PCAP
captures under `attack1/data` as the default data source.

Feature extraction defaults to 0.05-second time windows, treats TCP traffic on
ports `80`, `443`, and `8080` as HTTP-like traffic, and skips byte-identical
duplicate PCAP files unless `--include-duplicates` is passed.

```bash
python -m detection.features
python -m detection.train_mlp
python -m detection.train_kmeans
python -m detection.plot_results
python -m detection.predict_classifier
python -m detection.predict_anomaly
```

Outputs are written under `detection/data` and `detection/models`.
