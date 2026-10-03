"""Export schema and real CIC-IDS2017 rows for the frontend CSV workflow."""

from __future__ import annotations

import csv
import json
from pathlib import Path

import pandas as pd


ROOT = Path(__file__).resolve().parents[2]
ARTIFACTS = ROOT / "ml-service" / "artifacts"
DATA_DIR = ROOT / "data" / "raw" / "MachineLearningCSV" / "MachineLearningCVE"
FRONTEND = ROOT / "frontend"


def first_row_for_label(path: Path, columns: list[str], label_column: str, wanted_label: str) -> list[object]:
    for chunk in pd.read_csv(path, header=None, names=columns, skiprows=1, chunksize=100_000, low_memory=False):
        match = chunk[chunk[label_column] == wanted_label]
        if not match.empty:
            return match.iloc[0].tolist()
    raise RuntimeError(f"No {wanted_label!r} row found in {path.name}")


def main() -> None:
    schema = json.loads((ARTIFACTS / "model_feature_schema.json").read_text(encoding="utf-8"))
    feature_names = [feature["model_name"] for feature in schema["features"]]
    label_column = schema["label_column"]
    columns = feature_names + [label_column]
    if len(feature_names) != 78:
        raise RuntimeError("Frontend export requires the persisted 78-feature schema.")

    # These are real rows selected from the original corpus. Labels are used
    # only to select diverse source records and are not included in the CSV.
    sample_sources = [
        (DATA_DIR / "Monday-WorkingHours.pcap_ISCX.csv", "BENIGN"),
        (DATA_DIR / "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv", "DDoS"),
        (DATA_DIR / "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv", "PortScan"),
    ]
    rows = [first_row_for_label(path, columns, label_column, label)[:-1] for path, label in sample_sources]

    schema_destination = FRONTEND / "src" / "modelFeatureSchema.json"
    sample_destination = FRONTEND / "public" / "samples" / "cic-ids2017-real-sample.csv"
    schema_destination.parent.mkdir(parents=True, exist_ok=True)
    sample_destination.parent.mkdir(parents=True, exist_ok=True)
    schema_destination.write_text(json.dumps(schema, indent=2) + "\n", encoding="utf-8")
    with sample_destination.open("w", newline="", encoding="utf-8") as destination:
        writer = csv.writer(destination)
        writer.writerow(feature_names)
        writer.writerows(rows)
    print(f"Exported {len(rows)} real source rows to {sample_destination}")


if __name__ == "__main__":
    main()
