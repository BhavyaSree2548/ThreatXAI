# ThreatXAI ML Prediction Service

This Phase 3 service loads the persisted Phase 2 LightGBM model, median imputer, label encoder, and 78-feature schema. It does not train or alter any model artifact.

## Start

From `ml-service`:

```powershell
python -m uvicorn app.main:app --reload --port 8000
```

For a non-reloading service bound only to the local machine:

```powershell
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

## API

`GET /health` confirms the artifacts loaded and reports the expected feature and class counts.

`POST /predict` accepts one object containing `features`. Its keys must be the 78 `model_name` values in [`artifacts/model_feature_schema.json`](artifacts/model_feature_schema.json), in exactly that order. This includes the leading spaces in source-derived names and ` Fwd Header Length__duplicate_2` at position 55. Extra, missing, reordered, or non-numeric features are rejected with HTTP 422. A `null` feature value is passed to the saved median imputer; infinity is converted to missing before imputation.

The `/predict` response contains the decoded real model prediction, derived status, model probability for the selected class, and the actual probability for every trained class. Use `/explain` when a real per-record SHAP explanation is required.

## SHAP explanations

`POST /explain` accepts the same request contract as `/predict` and returns the prediction plus the top ten per-record features ranked by absolute SHAP contribution for the actual predicted class. The service uses `shap.TreeExplainer` with the persisted LightGBM booster and the same infinity-to-missing and saved-median-imputer preprocessing path as prediction.

Each item includes the exact model feature name, its post-imputation model input value, its real SHAP value, and whether it increased or decreased the score for the displayed class. These are model contributions, not proof that a network property caused an attack. SHAP is a local explanation and its runtime/cost grows with request volume.

Example response shape (values are generated at request time):

```json
{
  "prediction": "<trained class>",
  "status": "BENIGN|MALICIOUS",
  "confidence": 0.0,
  "explanation": [{"feature": "<schema feature>", "value": 0.0, "shap_value": 0.0, "direction": "increases_prediction"}]
}
```

## CORS

The default development origin is `http://localhost:5173`. Set `THREATXAI_CORS_ORIGINS` to a comma-separated list when another frontend origin is needed.

## Real-row API check

Start the service, then from the project root run:

```powershell
python ml-service/tests/test_prediction_api.py
```

The test reads one real local CIC-IDS2017 row, submits its schema-aligned 78 features, and verifies the returned class, confidence, status, and class probabilities.
