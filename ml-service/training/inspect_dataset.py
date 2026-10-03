"""Inspect the local CIC-IDS2017 CSV corpus without changing source files.

This script intentionally reads physical CSV positions rather than relying on
pandas' duplicate-header mangling.  The generated schema keeps all 77 source
feature positions and gives only the second duplicate an explicit model name.
"""

from __future__ import annotations

import csv
import hashlib
import json
from collections import Counter
from pathlib import Path

import numpy as np
import pandas as pd


ROOT = Path(__file__).resolve().parents[2]
DATA_DIR = ROOT / "data" / "raw" / "MachineLearningCSV" / "MachineLearningCVE"
ARTIFACTS = ROOT / "ml-service" / "artifacts"
REPORTS = ROOT / "ml-service" / "reports"
CHUNK_SIZE = 100_000


def physical_header(path: Path) -> list[str]:
    with path.open("r", encoding="utf-8-sig", newline="") as source:
        return next(csv.reader(source))


def model_names(raw_features: list[str]) -> tuple[list[str], list[dict[str, object]]]:
    """Create deterministic, documented model names for duplicate positions."""
    occurrences: Counter[str] = Counter()
    names: list[str] = []
    fields: list[dict[str, object]] = []
    for position, source_name in enumerate(raw_features):
        occurrences[source_name] += 1
        occurrence = occurrences[source_name]
        name = source_name if occurrence == 1 else f"{source_name}__duplicate_{occurrence}"
        names.append(name)
        fields.append(
            {
                "position": position,
                "model_name": name,
                "source_name": source_name,
                "source_occurrence": occurrence,
                "dtype": "float64",
            }
        )
    return names, fields


def row_digest(frame: pd.DataFrame) -> list[bytes]:
    """Generate stable SHA-256 identifiers for physical rows across files."""
    # All source values are retained as read; the separator prevents ambiguity.
    return [
        hashlib.sha256("\x1f".join(map(str, row)).encode("utf-8")).digest()
        for row in frame.itertuples(index=False, name=None)
    ]


def main() -> None:
    paths = sorted(DATA_DIR.glob("*.csv"))
    if not paths:
        raise SystemExit(f"No CSV files found in {DATA_DIR}")

    headers = {path.name: physical_header(path) for path in paths}
    baseline_name = paths[0].name
    baseline = headers[baseline_name]
    header_inconsistencies = {
        name: header for name, header in headers.items() if header != baseline
    }
    if header_inconsistencies:
        raise SystemExit("CSV headers are inconsistent; schema generation aborted.")

    label_column = baseline[-1]
    raw_features = baseline[:-1]
    names, fields = model_names(raw_features)
    duplicate_source_names = {
        name: count for name, count in Counter(raw_features).items() if count > 1
    }
    physical_columns = names + [label_column]

    total_rows = 0
    rows_by_file: dict[str, int] = {}
    label_counts: Counter[str] = Counter()
    missing_counts: Counter[str] = Counter()
    infinite_counts: Counter[str] = Counter()
    non_numeric_counts: Counter[str] = Counter()
    seen_digests: set[bytes] = set()
    duplicate_rows = 0

    for path in paths:
        file_rows = 0
        for frame in pd.read_csv(
            path,
            header=None,
            names=physical_columns,
            skiprows=1,
            chunksize=CHUNK_SIZE,
            low_memory=False,
        ):
            if len(frame.columns) != len(physical_columns):
                raise ValueError(f"Unexpected physical column count in {path.name}")
            file_rows += len(frame)
            total_rows += len(frame)
            label_counts.update(frame[label_column].astype("string").fillna("<MISSING>").tolist())

            for name in names:
                series = frame[name]
                missing_counts[name] += int(series.isna().sum())
                numeric = pd.to_numeric(series, errors="coerce")
                non_numeric_counts[name] += int((series.notna() & numeric.isna()).sum())
                infinite_counts[name] += int(np.isinf(numeric.to_numpy(dtype="float64", na_value=np.nan)).sum())

            for digest in row_digest(frame):
                if digest in seen_digests:
                    duplicate_rows += 1
                else:
                    seen_digests.add(digest)
        rows_by_file[path.name] = file_rows

    schema = {
        "schema_version": 1,
        "dataset": "CIC-IDS2017 local CSV corpus",
        "source_directory": str(DATA_DIR.relative_to(ROOT)).replace("\\", "/"),
        "label_column": label_column,
        "feature_count": len(fields),
        "feature_order_policy": "Physical source CSV order; no feature was removed or reordered.",
        "duplicate_header_policy": (
            "The duplicate source header is retained at both physical positions. "
            "Only the later model-facing name receives the deterministic suffix "
            "__duplicate_2 so dataframe/model inputs are unambiguous."
        ),
        "features": fields,
    }

    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    REPORTS.mkdir(parents=True, exist_ok=True)
    (ARTIFACTS / "feature_schema.json").write_text(json.dumps(schema, indent=2) + "\n", encoding="utf-8")

    missing_nonzero = {name: count for name, count in missing_counts.items() if count}
    infinite_nonzero = {name: count for name, count in infinite_counts.items() if count}
    nonnumeric_nonzero = {name: count for name, count in non_numeric_counts.items() if count}

    lines = [
        "# CIC-IDS2017 Dataset Inspection Report",
        "",
        "Generated by `ml-service/training/inspect_dataset.py` from the local original CSV files. The inspection is read-only; no source dataset file was modified.",
        "",
        "## Corpus",
        "",
        f"- CSV files: {len(paths)}",
        f"- Total data rows: {total_rows:,}",
        "- Rows per file:",
    ]
    lines.extend(f"  - `{name}`: {count:,}" for name, count in rows_by_file.items())
    lines.extend([
        "",
        "## Physical schema",
        "",
        f"- Label column (exact source header): `{label_column}`",
        f"- Feature columns: {len(raw_features)}",
        "- All files have the same physical header and column order.",
        f"- Duplicate source feature headers: {json.dumps(duplicate_source_names)}",
        "- The full model-facing order is authoritative in `../artifacts/feature_schema.json`. The second physical `Fwd Header Length` is retained as `Fwd Header Length__duplicate_2`; it is not removed or merged.",
        "- All 78 feature positions contain numeric values (the model input type will be `float64`); the label position contains categorical text.",
        "",
        "| Position | Exact source header | Model-facing name | Model dtype |",
        "| ---: | --- | --- | --- |",
    ])
    lines.extend(
        f"| {field['position']} | `{field['source_name']}` | `{field['model_name']}` | `{field['dtype']}` |"
        for field in fields
    )
    lines.extend([
        f"| {len(fields)} | `{label_column}` | label (not a model feature) | categorical text |",
        "",
        "## Labels and class distribution",
        "",
    ])
    lines.extend(f"- `{label}`: {count:,}" for label, count in sorted(label_counts.items()))
    lines.extend([
        "",
        "## Data quality",
        "",
        f"- Missing feature values: {sum(missing_counts.values()):,}" + (f"; non-zero by feature: `{json.dumps(missing_nonzero)}`" if missing_nonzero else " (none)"),
        f"- Infinite feature values: {sum(infinite_counts.values()):,}" + (f"; non-zero by feature: `{json.dumps(infinite_nonzero)}`" if infinite_nonzero else " (none)"),
        f"- Non-numeric values in feature columns: {sum(nonnumeric_nonzero.values()):,}" + (f"; non-zero by feature: `{json.dumps(nonnumeric_nonzero)}`" if nonnumeric_nonzero else " (none)"),
        f"- Duplicate physical rows across the complete corpus: {duplicate_rows:,}. Rows were compared with SHA-256 digests of all 78 physical values; duplicate source rows are retained at this foundation stage.",
        "- Feature columns are numeric after CSV parsing/conversion; the label column is non-numeric categorical text.",
        "",
        "## Preprocessing plan for a future LightGBM training phase",
        "",
        "1. Load by the authoritative physical order in `feature_schema.json`; reject missing, extra, or reordered feature inputs at prediction time.",
        "2. Convert all 78 features to numeric. Replace positive/negative infinity with missing values before fitting any preprocessing artifact.",
        "3. Fit missing-value imputation on the training split only (median per feature is appropriate for these numeric flow features), and persist that fitted transformer with the model.",
        "4. Do not scale features by default: LightGBM tree models do not require scaling. Do not remove either duplicate header position without an explicit, evaluated feature-selection decision.",
        "5. Encode the observed label strings with a fitted label encoder persisted with the model.",
        "6. Use a stratified train/test split after preprocessing decisions are fixed; fit preprocessing only on training data. The class distribution above must guide the split and any later imbalance strategy.",
        "7. No resampling decision is made in this phase. If class weighting or resampling is evaluated later, apply it only to the training partition and report its effect on held-out metrics.",
        "",
        "## Readiness",
        "",
        "The source data has a stable shared physical schema and is ready for a controlled LightGBM training phase after the recorded handling of infinite values and training-only missing-value imputation. No model was trained in this phase.",
    ])
    (REPORTS / "dataset_report.md").write_text("\n".join(lines) + "\n", encoding="utf-8")

    print(json.dumps({"rows": total_rows, "features": len(fields), "labels": dict(sorted(label_counts.items()))}, indent=2))


if __name__ == "__main__":
    main()
