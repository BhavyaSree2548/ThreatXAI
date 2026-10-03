"""End-to-end check for the frontend's generated real sample CSV."""

from __future__ import annotations

import csv
import json
import os
from pathlib import Path

import httpx


ROOT = Path(__file__).resolve().parents[2]
SAMPLE = ROOT / "frontend" / "public" / "samples" / "cic-ids2017-real-sample.csv"
SCHEMA = ROOT / "ml-service" / "artifacts" / "model_feature_schema.json"
METRICS = ROOT / "ml-service" / "artifacts" / "lightgbm_metrics.json"
BASE_URL = os.getenv("THREATXAI_API_URL", "http://127.0.0.1:8000")


def main() -> None:
    feature_names = [feature["model_name"] for feature in json.loads(SCHEMA.read_text(encoding="utf-8"))["features"]]
    expected_classes = set(json.loads(METRICS.read_text(encoding="utf-8"))["class_names"])
    with SAMPLE.open(newline="", encoding="utf-8") as source:
        reader = csv.DictReader(source)
        assert reader.fieldnames == feature_names
        records = list(reader)
    assert records, "The real sample CSV has no records."

    responses = []
    with httpx.Client(base_url=BASE_URL, timeout=30.0) as client:
        for row_number, record in enumerate(records, start=2):
            features = {name: float(record[name]) for name in feature_names}
            response = client.post("/predict", json={"features": features})
            response.raise_for_status()
            body = response.json()
            assert body["prediction"] in expected_classes
            assert body["status"] in {"BENIGN", "MALICIOUS"}
            assert 0.0 <= body["confidence"] <= 1.0
            responses.append({"row": row_number, "prediction": body["prediction"], "status": body["status"], "confidence": body["confidence"]})
    print(json.dumps(responses, indent=2))


if __name__ == "__main__":
    main()
