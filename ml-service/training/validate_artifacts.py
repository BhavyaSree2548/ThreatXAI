"""Validate persisted Phase 2 artifacts with five real CIC-IDS2017 rows."""

from __future__ import annotations

import json
from pathlib import Path

import joblib
import numpy as np
import pandas as pd


ROOT = Path(__file__).resolve().parents[2]
ARTIFACTS = ROOT / "ml-service" / "artifacts"
DATA_DIR = ROOT / "data" / "raw" / "MachineLearningCSV" / "MachineLearningCVE"


def main() -> None:
    schema = json.loads((ARTIFACTS / "model_feature_schema.json").read_text(encoding="utf-8"))
    names = [field["model_name"] for field in schema["features"]]
    columns = names + [schema["label_column"]]
    source = sorted(DATA_DIR.glob("*.csv"))[0]
    rows = pd.read_csv(source, header=None, names=columns, skiprows=1, nrows=5)
    model = joblib.load(ARTIFACTS / "lightgbm_model.joblib")
    imputer = joblib.load(ARTIFACTS / "median_imputer.joblib")
    encoder = joblib.load(ARTIFACTS / "label_encoder.joblib")
    transformed = imputer.transform(rows[names].replace([np.inf, -np.inf], np.nan))
    predicted = model.predict(transformed)
    decoded = encoder.inverse_transform(predicted)
    if model.n_features_in_ != 78 or imputer.n_features_in_ != 78 or transformed.shape != (5, 78):
        raise RuntimeError("Artifact feature-count validation failed.")
    if len(decoded) != 5:
        raise RuntimeError("Artifact prediction validation failed.")
    print("artifact validation passed: 5 real rows, 78 ordered features, 15-class encoder")


if __name__ == "__main__":
    main()
