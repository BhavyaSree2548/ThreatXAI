"""Render the Phase 2 report exclusively from saved real training artifacts."""

from __future__ import annotations

import json
from pathlib import Path

import joblib
import pandas as pd


ROOT = Path(__file__).resolve().parents[2]
ARTIFACTS = ROOT / "ml-service" / "artifacts"
REPORT = ROOT / "ml-service" / "reports" / "training_report.md"


def main() -> None:
    schema = json.loads((ARTIFACTS / "model_feature_schema.json").read_text(encoding="utf-8"))
    metrics = json.loads((ARTIFACTS / "lightgbm_metrics.json").read_text(encoding="utf-8"))
    model = joblib.load(ARTIFACTS / "lightgbm_model.joblib")
    imputer = joblib.load(ARTIFACTS / "median_imputer.joblib")
    encoder = joblib.load(ARTIFACTS / "label_encoder.joblib")
    class_names = metrics["class_names"]
    report = metrics["classification_report"]
    matrix = metrics["confusion_matrix"]
    source = metrics["source_rows"]
    split = metrics["split_sizes"]

    if model.n_features_in_ != 78 or imputer.n_features_in_ != 78 or len(schema["features"]) != 78:
        raise RuntimeError("Saved artifacts do not consistently require exactly 78 features.")
    if encoder.classes_.tolist() != class_names:
        raise RuntimeError("Saved label encoder does not match recorded class order.")

    lines = [
        "# LightGBM Training Report",
        "",
        "## Integrity",
        "",
        "- Training used only the eight real local CIC-IDS2017 CSV files; no synthetic data was generated or used.",
        "- The original CIC-IDS2017 files were opened read-only and were not modified.",
        "- Input feature order came exclusively from `artifacts/feature_schema.json` and was preserved in `artifacts/model_feature_schema.json`.",
        "",
        "## Dataset and split",
        "",
        f"- Source rows: {source['raw_row_count']:,}",
        f"- Exact duplicate full records removed before splitting: {source['removed_duplicate_rows']:,}",
        f"- Rows used for split/training: {source['deduplicated_row_count']:,}",
        "- Features: 78 (all retained, including both physical ` Fwd Header Length` positions)",
        f"- Label column: `{schema['label_column']}`",
        f"- Train / validation / test: {split['train']:,} / {split['validation']:,} / {split['test']:,}",
        "- Split strategy: two fixed-seed stratified splits (70% / 15% / 15%). Full-record deduplication was performed before splitting to reduce identical-record leakage.",
        "",
        "## Preprocessing",
        "",
        "- Positive and negative infinity were converted to `NaN`.",
        "- `SimpleImputer(strategy='median')` was fit only on the training partition, then applied to validation and test partitions.",
        "- `LabelEncoder` was fit on training labels and saved with its exact class order.",
        "- No scaling or feature selection was applied. LightGBM does not require feature scaling.",
        "- `class_weight='balanced'` was used during training; no synthetic oversampling was used.",
        "",
        "## LightGBM configuration",
        "",
        "```json",
        json.dumps(metrics['model_config'], indent=2),
        "```",
        f"- Best iteration selected by validation multi-logloss / early stopping: {metrics['best_iteration']}",
        "",
        "## Held-out test metrics",
        "",
    ]
    lines.extend(f"- {name}: {value:.6f}" for name, value in metrics['test_metrics'].items())
    lines.extend(["", "## Per-class held-out results", "", "| Class | Precision | Recall | F1-score | Support |", "| --- | ---: | ---: | ---: | ---: |"])
    for index, name in enumerate(class_names):
        row = report.get(name, report[str(index)])
        lines.append(f"| `{name}` | {row['precision']:.6f} | {row['recall']:.6f} | {row['f1-score']:.6f} | {int(row['support']):,} |")
    lines.extend(["", "## Confusion matrix", "", "Rows are actual classes; columns are predicted classes. Class order:", "", "```text"])
    lines.extend(f"{index}: {name}" for index, name in enumerate(class_names))
    lines.extend(["```", "", "```text"])
    lines.extend(" ".join(map(str, row)) for row in matrix)
    lines.extend([
        "```",
        "",
        "## Warnings and limitations",
        "",
        "- Very rare classes (especially Heartbleed, Infiltration, and Web Attack SQL Injection) have tiny held-out supports. Their per-class metrics are reported above and must be interpreted with caution.",
        "- Full-record deduplication reduces identical-record leakage but does not alter the original files or the 78-feature schema.",
        "- This phase does not implement prediction APIs, SHAP, packet capture, a frontend, or real-time monitoring.",
        "",
        "## Artifact validation",
        "",
        f"- Reloaded model reports `n_features_in_ = {model.n_features_in_}`.",
        f"- Reloaded median imputer reports `n_features_in_ = {imputer.n_features_in_}`.",
        f"- Reloaded label encoder contains {len(encoder.classes_)} classes in the recorded order.",
        "- The training run also transformed and predicted a real five-row held-out batch before artifacts were written.",
    ])
    REPORT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"Wrote {REPORT}")


if __name__ == "__main__":
    main()
