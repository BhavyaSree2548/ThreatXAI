"""Verify real multiclass SHAP explanations for real BENIGN, DDoS, and PortScan rows."""

from __future__ import annotations

import csv
import json
import os
from pathlib import Path

import httpx


ROOT = Path(__file__).resolve().parents[2]
SAMPLE = ROOT / "frontend" / "public" / "samples" / "cic-ids2017-real-sample.csv"
SCHEMA = ROOT / "ml-service" / "artifacts" / "model_feature_schema.json"
BASE_URL = os.getenv("THREATXAI_API_URL", "http://127.0.0.1:8000")
EXPECTED_PREDICTIONS = ("BENIGN", "DDoS", "PortScan")


def main() -> None:
    feature_names = [item["model_name"] for item in json.loads(SCHEMA.read_text(encoding="utf-8"))["features"]]
    with SAMPLE.open(newline="", encoding="utf-8") as source:
        reader = csv.DictReader(source)
        assert reader.fieldnames == feature_names
        records = list(reader)
    assert len(records) == 3

    checked = []
    with httpx.Client(base_url=BASE_URL, timeout=60.0) as client:
        for source_row, expected_prediction in zip(records, EXPECTED_PREDICTIONS, strict=True):
            payload = {"features": {name: float(source_row[name]) for name in feature_names}}
            prediction = client.post("/predict", json=payload)
            explanation = client.post("/explain", json=payload)
            prediction.raise_for_status()
            explanation.raise_for_status()
            predicted_body = prediction.json()
            explained_body = explanation.json()
            assert predicted_body["prediction"] == explained_body["prediction"] == expected_prediction
            assert predicted_body["confidence"] == explained_body["confidence"]
            contributions = explained_body["explanation"]
            assert len(contributions) == 10
            assert all(item["feature"] in feature_names for item in contributions)
            magnitudes = [abs(item["shap_value"]) for item in contributions]
            assert magnitudes == sorted(magnitudes, reverse=True)
            checked.append({"prediction": explained_body["prediction"], "top_feature": contributions[0]["feature"], "top_shap_value": contributions[0]["shap_value"]})
    print(json.dumps(checked, indent=2))


if __name__ == "__main__":
    main()
