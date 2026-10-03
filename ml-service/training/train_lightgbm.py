"""Train the Phase 2 LightGBM classifier on the complete local CIC-IDS2017 corpus.

The source CSV files are opened read-only.  Input names/order come exclusively
from artifacts/feature_schema.json, including the explicit duplicate-header
disambiguation established in Phase 1.
"""

from __future__ import annotations

import json
import random
from collections import Counter
from pathlib import Path

import joblib
import lightgbm as lgb
import numpy as np
import pandas as pd
from sklearn.impute import SimpleImputer
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix, precision_recall_fscore_support
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder


ROOT = Path(__file__).resolve().parents[2]
DATA_DIR = ROOT / "data" / "raw" / "MachineLearningCSV" / "MachineLearningCVE"
ARTIFACTS = ROOT / "ml-service" / "artifacts"
REPORTS = ROOT / "ml-service" / "reports"
SEED = 20260817
TEST_SIZE = 0.15
VALIDATION_SIZE = 0.15


def load_schema() -> dict[str, object]:
    schema = json.loads((ARTIFACTS / "feature_schema.json").read_text(encoding="utf-8"))
    if schema.get("feature_count") != 78 or len(schema.get("features", [])) != 78:
        raise ValueError("The authoritative Phase 1 schema must contain exactly 78 features.")
    return schema


def load_complete_corpus(schema: dict[str, object]) -> tuple[pd.DataFrame, pd.Series, dict[str, int]]:
    feature_names = [feature["model_name"] for feature in schema["features"]]
    label_name = schema["label_column"]
    columns = feature_names + [label_name]
    frames: list[pd.DataFrame] = []
    input_rows: dict[str, int] = {}

    for path in sorted(DATA_DIR.glob("*.csv")):
        frame = pd.read_csv(path, header=None, names=columns, skiprows=1, low_memory=False)
        if list(frame.columns) != columns:
            raise ValueError(f"Column ordering mismatch while loading {path.name}")
        input_rows[path.name] = len(frame)
        frames.append(frame)

    data = pd.concat(frames, ignore_index=True)
    raw_row_count = len(data)
    # Full-record deduplication happens before any split to prevent identical
    # feature+label records from appearing in both train and held-out sets.
    data = data.drop_duplicates(ignore_index=True)
    if data.empty:
        raise ValueError("No rows remain after deduplication.")
    data.attrs["raw_row_count"] = raw_row_count
    data.attrs["deduplicated_row_count"] = len(data)
    data.attrs["removed_duplicate_rows"] = raw_row_count - len(data)

    X = data[feature_names].apply(pd.to_numeric, errors="raise")
    X = X.replace([np.inf, -np.inf], np.nan)
    y = data[label_name].astype(str)
    if y.isna().any():
        raise ValueError("The target label column contains missing values.")
    return X, y, {**input_rows, **data.attrs}


def metric_summary(y_true: np.ndarray, y_pred: np.ndarray, labels: np.ndarray) -> tuple[dict[str, float], dict[str, object], list[list[int]]]:
    precision_macro, recall_macro, f1_macro, _ = precision_recall_fscore_support(
        y_true, y_pred, labels=labels, average="macro", zero_division=0
    )
    precision_weighted, recall_weighted, f1_weighted, _ = precision_recall_fscore_support(
        y_true, y_pred, labels=labels, average="weighted", zero_division=0
    )
    metrics = {
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "macro_precision": float(precision_macro),
        "macro_recall": float(recall_macro),
        "macro_f1": float(f1_macro),
        "weighted_precision": float(precision_weighted),
        "weighted_recall": float(recall_weighted),
        "weighted_f1": float(f1_weighted),
    }
    report = classification_report(y_true, y_pred, labels=labels, output_dict=True, zero_division=0)
    matrix = confusion_matrix(y_true, y_pred, labels=labels).tolist()
    return metrics, report, matrix


def markdown_table(report: dict[str, object], class_names: list[str]) -> list[str]:
    lines = ["| Class | Precision | Recall | F1-score | Support |", "| --- | ---: | ---: | ---: | ---: |"]
    for index, name in enumerate(class_names):
        # sklearn reports encoded classes as string IDs unless target_names is
        # supplied.  Accept both forms so persisted evaluation artifacts remain
        # renderable and never remap labels incorrectly.
        row = report.get(name, report[str(index)])
        lines.append(
            f"| `{name}` | {row['precision']:.6f} | {row['recall']:.6f} | {row['f1-score']:.6f} | {int(row['support']):,} |"
        )
    return lines


def main() -> None:
    random.seed(SEED)
    np.random.seed(SEED)
    schema = load_schema()
    X, y, load_details = load_complete_corpus(schema)
    feature_names = [feature["model_name"] for feature in schema["features"]]

    # Two stratified operations produce 70/15/15 train/validation/test splits.
    X_train, X_holdout, y_train_text, y_holdout_text = train_test_split(
        X, y, test_size=TEST_SIZE + VALIDATION_SIZE, random_state=SEED, stratify=y
    )
    X_validation, X_test, y_validation_text, y_test_text = train_test_split(
        X_holdout, y_holdout_text, test_size=0.5, random_state=SEED, stratify=y_holdout_text
    )

    imputer = SimpleImputer(strategy="median")
    X_train_imputed = imputer.fit_transform(X_train)
    X_validation_imputed = imputer.transform(X_validation)
    X_test_imputed = imputer.transform(X_test)

    encoder = LabelEncoder()
    y_train = encoder.fit_transform(y_train_text)
    y_validation = encoder.transform(y_validation_text)
    y_test = encoder.transform(y_test_text)
    class_ids = np.arange(len(encoder.classes_))

    model_config = {
        "objective": "multiclass",
        "num_class": len(encoder.classes_),
        "n_estimators": 400,
        "learning_rate": 0.08,
        "num_leaves": 31,
        "max_depth": -1,
        "subsample": 0.9,
        "colsample_bytree": 0.9,
        "reg_lambda": 1.0,
        "class_weight": "balanced",
        "random_state": SEED,
        "n_jobs": -1,
        "deterministic": True,
        "force_col_wise": True,
        "verbosity": -1,
    }
    model = lgb.LGBMClassifier(**model_config)
    model.fit(
        X_train_imputed,
        y_train,
        eval_set=[(X_validation_imputed, y_validation)],
        eval_metric="multi_logloss",
        callbacks=[lgb.early_stopping(stopping_rounds=30, verbose=False)],
    )

    y_pred = model.predict(X_test_imputed)
    metrics, report, matrix = metric_summary(y_test, y_pred, class_ids)

    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    REPORTS.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, ARTIFACTS / "lightgbm_model.joblib")
    joblib.dump(imputer, ARTIFACTS / "median_imputer.joblib")
    joblib.dump(encoder, ARTIFACTS / "label_encoder.joblib")

    final_schema = dict(schema)
    final_schema["model"] = {
        "type": "lightgbm.LGBMClassifier",
        "expected_feature_count": int(model.n_features_in_),
        "feature_order_verified": feature_names,
        "training_seed": SEED,
    }
    (ARTIFACTS / "model_feature_schema.json").write_text(json.dumps(final_schema, indent=2) + "\n", encoding="utf-8")

    metrics_artifact = {
        "test_metrics": metrics,
        "class_names": encoder.classes_.tolist(),
        "classification_report": report,
        "confusion_matrix": matrix,
        "split_sizes": {"train": len(X_train), "validation": len(X_validation), "test": len(X_test)},
        "source_rows": load_details,
        "model_config": model_config,
        "best_iteration": int(model.best_iteration_ or model.n_estimators),
    }
    (ARTIFACTS / "lightgbm_metrics.json").write_text(json.dumps(metrics_artifact, indent=2) + "\n", encoding="utf-8")

    # Post-training artifact validation: reload every persisted object and run
    # a real transformed test batch through the saved model.
    loaded_model = joblib.load(ARTIFACTS / "lightgbm_model.joblib")
    loaded_imputer = joblib.load(ARTIFACTS / "median_imputer.joblib")
    loaded_encoder = joblib.load(ARTIFACTS / "label_encoder.joblib")
    validation_batch = loaded_imputer.transform(X_test.iloc[:5])
    validation_predictions = loaded_model.predict(validation_batch)
    decoded_predictions = loaded_encoder.inverse_transform(validation_predictions).tolist()
    if loaded_model.n_features_in_ != len(feature_names) or validation_batch.shape[1] != len(feature_names):
        raise RuntimeError("Saved artifacts do not accept exactly the authoritative 78-feature schema.")
    if len(decoded_predictions) != 5:
        raise RuntimeError("Saved model post-training prediction validation failed.")

    lines = [
        "# LightGBM Training Report",
        "",
        "## Integrity",
        "",
        "- Training used only the eight real local CIC-IDS2017 CSV files; no synthetic data was generated or used.",
        "- The original CIC-IDS2017 files were opened read-only and were not modified.",
        "- Input feature order came exclusively from `artifacts/feature_schema.json`.",
        "",
        "## Dataset and split",
        "",
        f"- Source rows: {load_details['raw_row_count']:,}",
        f"- Exact duplicate full records removed before splitting: {load_details['removed_duplicate_rows']:,}",
        f"- Rows used for split/training: {load_details['deduplicated_row_count']:,}",
        f"- Features: {len(feature_names)} (all retained, including both physical ` Fwd Header Length` positions)",
        f"- Label column: `{schema['label_column']}`",
        f"- Train / validation / test: {len(X_train):,} / {len(X_validation):,} / {len(X_test):,}",
        "- Split strategy: two fixed-seed stratified splits (70% / 15% / 15%). Full-record deduplication was performed before splitting to reduce identical-record leakage.",
        "",
        "## Class distribution after deduplication",
        "",
    ]
    lines.extend(f"- `{name}`: {count:,}" for name, count in sorted(Counter(y).items()))
    lines.extend([
        "",
        "## Preprocessing",
        "",
        "- Positive and negative infinity were converted to `NaN`.",
        "- `SimpleImputer(strategy='median')` was fit only on the training partition, then applied to validation and test partitions.",
        "- `LabelEncoder` was fit only on training labels; all observed classes were present in the stratified training split.",
        "- No scaling or feature selection was applied. LightGBM does not require feature scaling.",
        "- `class_weight='balanced'` was used in training to address the observed imbalance; no synthetic oversampling was used.",
        "",
        "## LightGBM configuration",
        "",
        "```json",
        json.dumps(model_config, indent=2),
        "```",
        f"- Best iteration selected by validation multi-logloss / early stopping: {int(model.best_iteration_ or model.n_estimators)}",
        "",
        "## Held-out test metrics",
        "",
    ])
    lines.extend(f"- {name}: {value:.6f}" for name, value in metrics.items())
    lines.extend(["", "## Per-class held-out results", ""])
    lines.extend(markdown_table(report, encoder.classes_.tolist()))
    lines.extend(["", "## Confusion matrix", "", "Rows are actual classes; columns are predicted classes. Class order:", "", "```text"])
    lines.extend(f"{index}: {name}" for index, name in enumerate(encoder.classes_))
    lines.extend(["```", "", "```text"])
    lines.extend(" ".join(map(str, row)) for row in matrix)
    lines.extend([
        "```",
        "",
        "## Warnings and limitations",
        "",
        "- Very rare classes (especially Heartbleed, Infiltration, and the Web Attack SQL Injection class) have tiny held-out supports. Their per-class metrics must be interpreted with caution and are intentionally reported rather than hidden.",
        "- Deduplication removes identical full source records before splitting. It does not alter the original files or the 78-feature schema.",
        "- This phase does not implement prediction APIs, SHAP, packet capture, a frontend, or real-time monitoring.",
        "",
        "## Artifact validation",
        "",
        f"- Reloaded model reports `n_features_in_ = {loaded_model.n_features_in_}`.",
        f"- Reloaded median imputer transformed a real five-row held-out batch to {validation_batch.shape[1]} features.",
        f"- Reloaded label encoder decoded {len(decoded_predictions)} model outputs successfully.",
    ])
    (REPORTS / "training_report.md").write_text("\n".join(lines) + "\n", encoding="utf-8")

    print(json.dumps({"metrics": metrics, "best_iteration": metrics_artifact["best_iteration"], "splits": metrics_artifact["split_sizes"]}, indent=2))


if __name__ == "__main__":
    main()
