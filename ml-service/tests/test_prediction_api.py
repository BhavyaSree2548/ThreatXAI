"""Integration check for a running ThreatXAI API using a real source CSV row."""

from __future__ import annotations

import json
import os
from pathlib import Path

import httpx
import numpy as np
import pandas as pd


ROOT = Path(__file__).resolve().parents[2]
ARTIFACTS = ROOT / "ml-service" / "artifacts"
DATA_DIR = ROOT / "data" / "raw" / "MachineLearningCSV" / "MachineLearningCVE"
BASE_URL = os.getenv("THREATXAI_API_URL", "http://127.0.0.1:8000")


def real_payload() -> dict[str, object]:
    schema = json.loads((ARTIFACTS / "model_feature_schema.json").read_text(encoding="utf-8"))
    names = [feature["model_name"] for feature in schema["features"]]
    columns = names + [schema["label_column"]]
    row = pd.read_csv(sorted(DATA_DIR.glob("*.csv"))[0], header=None, names=columns, skiprows=1, nrows=1).iloc[0]
    features: dict[str, float | None] = {}
    for name in names:
        value = row[name]
        features[name] = None if pd.isna(value) else float(value)
    return {"features": features}


def main() -> None:
    expected_classes = set(json.loads((ARTIFACTS / "lightgbm_metrics.json").read_text(encoding="utf-8"))["class_names"])
    with httpx.Client(base_url=BASE_URL, timeout=30.0) as client:
        health = client.get("/health")
        health.raise_for_status()
        assert health.json()["model_loaded"] is True
        response = client.post("/predict", json=real_payload())
        response.raise_for_status()
    body = response.json()
    assert body["prediction"] in expected_classes
    assert 0.0 <= body["confidence"] <= 1.0
    assert len(body["class_probabilities"]) == 15
    assert body["status"] in {"BENIGN", "MALICIOUS"}
    print(json.dumps(body, indent=2))


if __name__ == "__main__":
    main()
