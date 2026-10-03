"""Validation logic enforcing strict 78-feature schema compliance."""

from __future__ import annotations

import math
from .constants import FEATURE_NAMES, FEATURE_COUNT


def validate_78_features(features_dict: dict[str, float | None]) -> tuple[bool, str | None]:
    """
    Validate that a feature map matches the required 78-feature schema exactly:
    - Count == 78
    - Exact names and exact order
    - All values numeric and finite (or None/null)
    """
    if not isinstance(features_dict, dict):
        return False, "Feature payload must be a dictionary."

    supplied_names = tuple(features_dict.keys())
    if len(supplied_names) != FEATURE_COUNT:
        missing = [name for name in FEATURE_NAMES if name not in features_dict]
        extra = [name for name in supplied_names if name not in FEATURE_NAMES]
        return False, f"Feature count mismatch: expected {FEATURE_COUNT}, received {len(supplied_names)}. Missing: {missing[:3]}, Extra: {extra[:3]}."

    if supplied_names != FEATURE_NAMES:
        return False, "Feature order does not strictly match model_feature_schema.json."

    for idx, (name, val) in enumerate(features_dict.items()):
        if val is None:
            continue
        if not isinstance(val, (int, float)):
            return False, f"Feature '{name}' (position {idx}) is non-numeric: {type(val)}."
        if not math.isfinite(val):
            return False, f"Feature '{name}' (position {idx}) contains non-finite value: {val}."

    return True, None
