"""FastAPI service for real predictions from the saved Phase 2 artifacts."""

from __future__ import annotations

import asyncio
import json
import os
from contextlib import asynccontextmanager
from dataclasses import dataclass

from pathlib import Path

import csv
import io

import tempfile
import joblib
import numpy as np
import pandas as pd
import shap
from fastapi import FastAPI, HTTPException, Request, WebSocket, WebSocketDisconnect, status, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, ConfigDict, Field, StrictFloat, StrictInt

from app.feature_extractor.pcap_processor import process_pcap
from app.feature_extractor.schema_validator import validate_78_features
from app.db.h2_manager import H2Database


from app.monitoring import (
    InterfaceInfo,
    MonitorManager,
    MonitoringEvent,
    MonitorState,
    MonitorStatusResponse,
    StartMonitorRequest,
    get_available_interfaces,
)



SERVICE_ROOT = Path(__file__).resolve().parents[1]
ARTIFACTS = SERVICE_ROOT / "artifacts"
MODEL_VERSION = "lightgbm-cic-ids2017"
FeatureValue = StrictFloat | StrictInt | None


@dataclass(frozen=True)
class ModelArtifacts:
    model: object
    imputer: object
    label_encoder: object
    schema: dict[str, object]
    feature_names: tuple[str, ...]
    classes: tuple[str, ...]
    explainer: object


class PredictionRequest(BaseModel):
    """One traffic flow keyed by the exact model-facing feature names and order."""

    model_config = ConfigDict(extra="forbid")
    features: dict[str, FeatureValue] = Field(
        ..., description="All 78 schema features in their exact documented order. Null is imputed with the saved median imputer."
    )


class PredictionResponse(BaseModel):
    prediction: str
    status: str
    confidence: float = Field(ge=0.0, le=1.0)
    model_version: str
    class_probabilities: dict[str, float]


class ExplainedFeature(BaseModel):
    feature: str
    value: float
    shap_value: float
    direction: str


class ExplanationResponse(PredictionResponse):
    explanation: list[ExplainedFeature]
    summary: str
    supporting_features: list[ExplainedFeature] = Field(default_factory=list)
    opposing_features: list[ExplainedFeature] = Field(default_factory=list)


class HealthResponse(BaseModel):
    status: str
    model_loaded: bool
    model_version: str
    feature_count: int
    class_count: int


class UserRegisterRequest(BaseModel):
    full_name: str
    username: str
    email: str
    password: str


class UserLoginRequest(BaseModel):
    username: str
    password: str


class UserResponse(BaseModel):
    id: int
    username: str
    email: str
    full_name: str
    role: str


class AuthResponse(BaseModel):
    status: str
    message: str
    user: UserResponse
    token: str | None = None


def load_artifacts() -> ModelArtifacts:
    schema_path = ARTIFACTS / "model_feature_schema.json"
    model_path = ARTIFACTS / "lightgbm_model.joblib"
    imputer_path = ARTIFACTS / "median_imputer.joblib"
    encoder_path = ARTIFACTS / "label_encoder.joblib"
    required = (schema_path, model_path, imputer_path, encoder_path)
    missing = [str(path) for path in required if not path.is_file()]
    if missing:
        raise RuntimeError(f"Required trained artifact(s) missing: {', '.join(missing)}")

    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    features = schema.get("features")
    if not isinstance(features, list):
        raise RuntimeError("Model feature schema has no feature list.")
    feature_names = tuple(feature["model_name"] for feature in features)
    model = joblib.load(model_path)
    imputer = joblib.load(imputer_path)
    label_encoder = joblib.load(encoder_path)
    # TreeExplainer is constructed from the persisted trained booster. It does
    # not fit, update, or otherwise alter the model.
    explainer = shap.TreeExplainer(model.booster_)
    classes = tuple(str(item) for item in label_encoder.classes_)

    expected_count = schema.get("model", {}).get("expected_feature_count", schema.get("feature_count"))
    model_classes = np.asarray(model.classes_)
    if (
        len(feature_names) != 78
        or expected_count != 78
        or model.n_features_in_ != 78
        or imputer.n_features_in_ != 78
        or len(classes) != 15
        or not np.array_equal(model_classes, np.arange(len(classes)))
    ):
        raise RuntimeError("Saved artifacts are incompatible with the required 78-feature, 15-class model contract.")
    return ModelArtifacts(model, imputer, label_encoder, schema, feature_names, classes, explainer)


@asynccontextmanager
async def lifespan(app: FastAPI):
    artifacts = load_artifacts()
    app.state.artifacts = artifacts
    monitor_manager = MonitorManager(artifacts)
    try:
        monitor_manager.set_event_loop(asyncio.get_running_loop())
    except RuntimeError:
        pass
    app.state.monitor_manager = monitor_manager

    # Initialize H2 Database for user authentication
    h2_db = H2Database()
    try:
        h2_db.init_db()
    except Exception as e:
        print(f"Warning initializing H2 database: {e}")
    app.state.h2_db = h2_db

    yield
    monitor_manager.stop_monitoring()



app = FastAPI(
    title="ThreatXAI ML Prediction Service",
    version="1.0.0",
    lifespan=lifespan,
)

cors_env = (
    os.getenv("CORS_ORIGINS")
    or os.getenv("THREATXAI_CORS_ORIGINS")
    or os.getenv("ALLOWED_ORIGINS")
    or "http://localhost:5173,http://127.0.0.1:5173,http://localhost:3000"
)

if cors_env.strip() == "*":
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=False,
        allow_methods=["*"],
        allow_headers=["*"],
    )
else:
    allowed_origins = [origin.strip() for origin in cors_env.split(",") if origin.strip()]
    for local_dev in ("http://localhost:5173", "http://127.0.0.1:5173", "http://localhost:3000"):
        if local_dev not in allowed_origins:
            allowed_origins.append(local_dev)

    app.add_middleware(
        CORSMiddleware,
        allow_origins=allowed_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )


def get_artifacts(request: Request = None) -> ModelArtifacts:
    if request is not None and hasattr(request, "app") and hasattr(request.app.state, "artifacts"):
        return request.app.state.artifacts
    return load_artifacts()


def get_h2_db(request: Request = None) -> H2Database:
    if request is not None and hasattr(request, "app") and hasattr(request.app.state, "h2_db"):
        return request.app.state.h2_db
    db = H2Database()
    try:
        db.init_db()
    except Exception:
        pass
    return db




@app.get("/health", response_model=HealthResponse)
def health(request: Request) -> HealthResponse:
    artifacts = get_artifacts(request)
    return HealthResponse(
        status="ok",
        model_loaded=True,
        model_version=MODEL_VERSION,
        feature_count=len(artifacts.feature_names),
        class_count=len(artifacts.classes),
    )


def validate_and_preprocess(payload: PredictionRequest, artifacts: ModelArtifacts) -> np.ndarray:
    supplied_names = tuple(payload.features.keys())
    expected_names = artifacts.feature_names
    supplied_set = set(supplied_names)
    expected_set = set(expected_names)
    missing = [name for name in expected_names if name not in supplied_set]
    unexpected = [name for name in supplied_names if name not in expected_set]
    if missing or unexpected:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={"message": "Feature schema mismatch.", "missing_features": missing, "unexpected_features": unexpected},
        )
    if supplied_names != expected_names:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={"message": "Feature order does not match model_feature_schema.json."},
        )

    values = np.asarray([payload.features[name] for name in expected_names], dtype=np.float64).reshape(1, -1)
    # This is the same infinity-to-missing handling performed before the saved
    # training imputer was fitted. Null values are represented as NaN here.
    values[np.isinf(values)] = np.nan
    try:
        return artifacts.imputer.transform(values)
    except (TypeError, ValueError) as error:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail={"message": "Feature values could not be preprocessed.", "reason": str(error)}) from error


def prediction_response(processed: np.ndarray, artifacts: ModelArtifacts) -> tuple[PredictionResponse, int]:
    probabilities = artifacts.model.predict_proba(processed)[0]
    predicted_index = int(np.argmax(probabilities))
    prediction = artifacts.label_encoder.inverse_transform(np.array([predicted_index]))[0]
    probability_map = {class_name: float(probabilities[index]) for index, class_name in enumerate(artifacts.classes)}
    return PredictionResponse(
        prediction=str(prediction),
        status="BENIGN" if prediction == "BENIGN" else "MALICIOUS",
        confidence=float(probabilities[predicted_index]),
        model_version=MODEL_VERSION,
        class_probabilities=probability_map,
    ), predicted_index


def select_predicted_class_shap_values(shap_values: object, predicted_index: int, feature_count: int, class_count: int) -> np.ndarray:
    """Normalize SHAP's supported multiclass layouts to one predicted-class row."""
    values = np.asarray(shap_values)
    if isinstance(shap_values, list):
        if len(shap_values) != class_count:
            raise ValueError("Unexpected multiclass SHAP output length.")
        selected = np.asarray(shap_values[predicted_index])[0]
    elif values.ndim == 3 and values.shape == (1, feature_count, class_count):
        # SHAP >= 0.45: (samples, features, outputs).
        selected = values[0, :, predicted_index]
    elif values.ndim == 3 and values.shape == (class_count, 1, feature_count):
        # Compatibility with the older list-like class-first layout.
        selected = values[predicted_index, 0, :]
    else:
        raise ValueError(f"Unexpected multiclass SHAP output shape: {values.shape}")
    if selected.shape != (feature_count,):
        raise ValueError("Selected SHAP values do not match the 78-feature schema.")
    return selected


@app.post("/predict", response_model=PredictionResponse)
def predict(payload: PredictionRequest, request: Request) -> PredictionResponse:
    artifacts = get_artifacts(request)
    processed = validate_and_preprocess(payload, artifacts)
    response, _ = prediction_response(processed, artifacts)
    return response


@app.post("/explain", response_model=ExplanationResponse)
def explain(payload: PredictionRequest, request: Request) -> ExplanationResponse:
    artifacts = get_artifacts(request)
    processed = validate_and_preprocess(payload, artifacts)
    prediction, predicted_index = prediction_response(processed, artifacts)
    try:
        shap_values = select_predicted_class_shap_values(
            artifacts.explainer.shap_values(processed),
            predicted_index,
            len(artifacts.feature_names),
            len(artifacts.classes),
        )
    except (TypeError, ValueError) as error:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail={"message": "SHAP explanation could not be generated from the saved model."}) from error

    ranked_indices = sorted(range(len(artifacts.feature_names)), key=lambda index: abs(float(shap_values[index])), reverse=True)[:10]
    explanation = [
        ExplainedFeature(
            feature=artifacts.feature_names[index],
            value=float(processed[0, index]),
            shap_value=float(shap_values[index]),
            direction=("increases_prediction" if shap_values[index] > 0 else "decreases_prediction" if shap_values[index] < 0 else "neutral"),
        )
        for index in ranked_indices
    ]
    supporting = [f for f in explanation if f.shap_value > 0]
    opposing = [f for f in explanation if f.shap_value < 0]

    top_pos_features = [f.feature.strip() for f in supporting[:3]]
    if prediction.status == "MALICIOUS":
        top_str = f" ({', '.join(top_pos_features)})" if top_pos_features else ""
        summary = (
            f"Threat Detected: {prediction.prediction}. The model classified this network traffic flow as "
            f"{prediction.prediction} with {prediction.confidence * 100:.2f}% confidence. "
            f"The primary network characteristics driving this alert{top_str} contributed strongly toward the {prediction.prediction} attack pattern."
        )
    else:
        top_str = f" ({', '.join(top_pos_features)})" if top_pos_features else ""
        summary = (
            f"Traffic Status: BENIGN. The model classified this network traffic flow as normal BENIGN traffic with "
            f"{prediction.confidence * 100:.2f}% confidence. Observed network flow attributes{top_str} "
            f"are consistent with normal baseline traffic patterns in the CIC-IDS2017 dataset."
        )

    return ExplanationResponse(
        **prediction.model_dump(),
        explanation=explanation,
        summary=summary,
        supporting_features=supporting,
        opposing_features=opposing,
    )


def get_monitor_manager(app_instance: FastAPI) -> MonitorManager:
    """Helper to lazily ensure MonitorManager is available on app.state."""
    if not hasattr(app_instance.state, "artifacts"):
        app_instance.state.artifacts = load_artifacts()
    if not hasattr(app_instance.state, "monitor_manager"):
        app_instance.state.monitor_manager = MonitorManager(app_instance.state.artifacts)
    return app_instance.state.monitor_manager


# --- Real-Time Monitoring Endpoints (Phase 5) ---

@app.get("/monitor/interfaces", response_model=list[InterfaceInfo])
def list_interfaces() -> list[InterfaceInfo]:
    """List available network interfaces on the system."""
    return get_available_interfaces()


@app.get("/monitor/status", response_model=MonitorStatusResponse)
def monitor_status(request: Request) -> MonitorStatusResponse:
    """Get current real-time monitoring status and flow counters."""
    manager: MonitorManager = get_monitor_manager(request.app)
    return manager.get_status()


@app.post("/monitor/start", response_model=MonitorStatusResponse)
def start_monitoring_endpoint(payload: StartMonitorRequest, request: Request) -> MonitorStatusResponse:
    """Start real-time packet capture and flow monitoring on the specified interface."""
    manager: MonitorManager = get_monitor_manager(request.app)
    try:
        manager.start_monitoring(payload.interface)
    except ValueError as val_err:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(val_err)) from val_err
    except Exception as err:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(err)) from err
    return manager.get_status()


@app.post("/monitor/stop", response_model=MonitorStatusResponse)
def stop_monitoring_endpoint(request: Request) -> MonitorStatusResponse:
    """Stop real-time network monitoring cleanly."""
    manager: MonitorManager = get_monitor_manager(request.app)
    manager.stop_monitoring()
    return manager.get_status()


@app.get("/monitor/events", response_model=list[MonitoringEvent])
def get_monitor_events(request: Request, limit: int = 50) -> list[MonitoringEvent]:
    """Retrieve recent monitoring prediction and threat alert events."""
    manager: MonitorManager = get_monitor_manager(request.app)
    return manager.get_recent_events(limit=limit)


@app.websocket("/ws/monitor")
async def websocket_monitor_endpoint(websocket: WebSocket):
    """Live WebSocket stream for real-time monitoring events and status updates."""
    await websocket.accept()
    manager: MonitorManager = get_monitor_manager(websocket.app)
    manager.register_ws(websocket)

    try:
        # Send initial status and recent event backlog upon connection
        await websocket.send_json({
            "type": "INIT_STATE",
            "status": manager.get_status().model_dump(),
            "events": [ev.model_dump() for ev in manager.get_recent_events(limit=30)]
        })
        while True:
            _ = await websocket.receive_text()
    except WebSocketDisconnect:
        pass
    except Exception:
        pass
    finally:
        manager.unregister_ws(websocket)


# --- Authentication & User Registration (H2 Database) ---

@app.post("/auth/register", response_model=AuthResponse)
def register(payload: UserRegisterRequest, request: Request = None) -> AuthResponse:
    """Register a new user account with secure scrypt password hash in persistent H2 Database."""
    fn = payload.full_name.strip()
    u = payload.username.strip()
    e = payload.email.strip()
    p = payload.password

    if not fn or not u or not e or not p:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="All fields are required.")
    if len(p) < 6:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Password must be at least 6 characters.")
    if "@" not in e or "." not in e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Please enter a valid email address.")

    db = get_h2_db(request)
    try:
        user = db.create_user(full_name=fn, username=u, email=e, password=p)
    except ValueError as val_err:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(val_err)) from val_err
    except Exception as err:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Database error: {err}") from err

    return AuthResponse(
        status="success",
        message="Account registered successfully in H2 Database.",
        user=UserResponse(**user),
        token=f"h2_session_{user['id']}_{user['username']}",
    )


@app.post("/auth/login", response_model=AuthResponse)
def login(payload: UserLoginRequest, request: Request = None) -> AuthResponse:
    """Authenticate user credentials against H2 Database."""
    u = payload.username.strip()
    p = payload.password

    if not u or not p:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Please enter username/email and password.")

    db = get_h2_db(request)
    user = db.authenticate(u, p)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid username/email or password.")

    return AuthResponse(
        status="success",
        message="Authentication successful.",
        user=UserResponse(**user),
        token=f"h2_session_{user['id']}_{user['username']}",
    )


@app.get("/auth/users", response_model=list[UserResponse])
def list_users(request: Request = None) -> list[UserResponse]:
    """Retrieve list of registered users (safe fields only) from H2 Database."""
    db = get_h2_db(request)
    return [UserResponse(**u) for u in db.list_users()]


# --- Model Metrics & Catalog Endpoints ---

@app.get("/model/metrics")
def get_model_metrics() -> dict[str, object]:
    """Retrieve actual LightGBM training and test evaluation metrics."""
    metrics_path = ARTIFACTS / "lightgbm_metrics.json"
    if not metrics_path.is_file():
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Model metrics artifact not found.")
    return json.loads(metrics_path.read_text(encoding="utf-8"))


@app.get("/samples/catalog")
def get_samples_catalog() -> list[dict[str, object]]:
    """Return catalog of authentic CIC-IDS2017 test attack and normal traffic samples."""
    return [
        {
            "id": "ddos",
            "name": "DDoS (Distributed Denial of Service)",
            "category": "Denial of Service",
            "description": "Volumetric attack flow targeting destination port 80. Extracted from authentic CIC-IDS2017 Friday dataset.",
            "expected_class": "DDoS",
            "csv_file": "/samples/cic-ids2017-ddos-sample.csv",
            "csv_available": True,
            "pcap_available": False,
            "status": "Available & Verified",
            "external_dataset_source": "CIC-IDS2017 (Friday-WorkingHours-Afternoon-DDos)",
        },
        {
            "id": "dos-hulk",
            "name": "DoS Hulk",
            "category": "Application Layer DoS",
            "description": "Application Layer DoS",
            "expected_class": "DoS Hulk",
            "csv_file": None,
            "csv_available": False,
            "pcap_available": False,
            "status": "External CIC Reference",
            "external_dataset_source": "CIC-IDS2017 (Wednesday-WorkingHours)",
        },
        {
            "id": "portscan",
            "name": "PortScan Reconnaissance Probe",
            "category": "Reconnaissance / Probe",
            "description": "Systematic TCP SYN scanning probing consecutive destination ports. Extracted from authentic CIC-IDS2017 Friday dataset.",
            "expected_class": "PortScan",
            "csv_file": "/samples/cic-ids2017-portscan-sample.csv",
            "csv_available": True,
            "pcap_available": False,
            "status": "Available & Verified",
            "external_dataset_source": "CIC-IDS2017 (Friday-WorkingHours-Afternoon-PortScan)",
        },
        {
            "id": "ssh-patator",
            "name": "SSH-Patator",
            "category": "Credential Access / Brute Force",
            "description": "Credential Access / Brute Force",
            "expected_class": "SSH-Patator",
            "csv_file": None,
            "csv_available": False,
            "pcap_available": False,
            "status": "External CIC Reference",
            "external_dataset_source": "CIC-IDS2017 (Tuesday-WorkingHours)",
        },
        {
            "id": "web-attack",
            "name": "Web Attack (Brute Force / XSS / SQLi)",
            "category": "Web Application Attack",
            "description": "Web Application Attack",
            "expected_class": "Web Attack \ufffd Brute Force",
            "csv_file": None,
            "csv_available": False,
            "pcap_available": False,
            "status": "External CIC Reference",
            "external_dataset_source": "CIC-IDS2017 (Thursday-WorkingHours)",
        },
        {
            "id": "benign",
            "name": "Benign Baseline Traffic",
            "category": "Normal Traffic",
            "description": "Authentic normal HTTP/HTTPS web browsing and standard network baseline flow from CIC-IDS2017 Monday dataset.",
            "expected_class": "BENIGN",
            "csv_file": "/samples/cic-ids2017-benign-sample.csv",
            "csv_available": True,
            "pcap_available": False,
            "status": "Available & Verified",
            "external_dataset_source": "CIC-IDS2017 (Monday-WorkingHours)",
        },
        {
            "id": "multi-flow",
            "name": "Multi-Flow Test Suite (Benign + DDoS + PortScan)",
            "category": "Multi-Threat Evaluation",
            "description": "Combined authentic test capture containing verified Normal traffic, DDoS attack, and PortScan probe for multi-threat evaluation and comparison.",
            "expected_class": "Multi-Class (BENIGN, DDoS, PortScan)",
            "csv_file": "/samples/cic-ids2017-multi-flow-sample.csv",
            "csv_available": True,
            "pcap_available": False,
            "status": "Available & Verified",
            "external_dataset_source": "CIC-IDS2017 (Monday + Friday Datasets)",
        },
    ]




def extract_flows_from_csv(content_str: str, expected_feature_names: tuple[str, ...]) -> tuple[list[dict[str, float]], str | None]:
    """Parse CSV text with 78-feature schema alignment, handling BOM, duplicate headers, and whitespace variants."""
    if content_str.startswith("\ufeff"):
        content_str = content_str[1:]

    lines = [line for line in content_str.splitlines() if line.strip()]
    if not lines:
        return [], "Uploaded CSV file is empty."

    reader = csv.reader(io.StringIO(content_str))
    try:
        header = next(reader, None)
    except Exception as e:
        return [], f"Failed to parse CSV header: {e}"

    if not header or not any(header):
        return [], "Uploaded CSV file has an empty header."

    header_clean = [col.strip() for col in header]

    # Detect duplicate headers such as "Fwd Header Length"
    fwd_hdr_indices = [i for i, h in enumerate(header_clean) if h == "Fwd Header Length"]

    feature_to_col_idx: dict[str, int] = {}
    missing_features: list[str] = []

    for pos, feat in enumerate(expected_feature_names):
        feat_clean = feat.strip()
        if feat == " Fwd Header Length__duplicate_2":
            if len(fwd_hdr_indices) >= 2:
                feature_to_col_idx[feat] = fwd_hdr_indices[1]
            elif "Fwd Header Length__duplicate_2" in header_clean:
                feature_to_col_idx[feat] = header_clean.index("Fwd Header Length__duplicate_2")
            elif " Fwd Header Length__duplicate_2" in header:
                feature_to_col_idx[feat] = header.index(" Fwd Header Length__duplicate_2")
            elif len(fwd_hdr_indices) == 1:
                feature_to_col_idx[feat] = fwd_hdr_indices[0]
            elif pos < len(header) and header_clean[pos].lower() != "label":
                feature_to_col_idx[feat] = pos
            else:
                missing_features.append(feat)
        elif feat in header:
            feature_to_col_idx[feat] = header.index(feat)
        elif feat_clean in header_clean:
            feature_to_col_idx[feat] = header_clean.index(feat_clean)
        elif pos < len(header) and header_clean[pos].lower() != "label" and len(header) >= len(expected_feature_names):
            feature_to_col_idx[feat] = pos
        else:
            missing_features.append(feat)

    if missing_features:
        return [], f"CSV is missing required 78-feature columns (missing {len(missing_features)} features, e.g. {missing_features[:3]})."

    extracted_flows: list[dict[str, float]] = []
    for row_idx, row in enumerate(reader):
        if not row or not any(row):
            continue
        flow_dict: dict[str, float] = {}
        for feat in expected_feature_names:
            col_idx = feature_to_col_idx.get(feat)
            if col_idx is not None and col_idx < len(row):
                val_str = row[col_idx].strip()
                if val_str == "" or val_str.lower() in ("nan", "null", "none", "infinity", "inf", "+inf", "-infinity", "-inf"):
                    flow_dict[feat] = np.nan
                else:
                    try:
                        flow_dict[feat] = float(val_str)
                    except ValueError:
                        flow_dict[feat] = np.nan
            else:
                flow_dict[feat] = np.nan
        extracted_flows.append(flow_dict)

    if not extracted_flows:
        return [], "No valid network flow data rows found in the uploaded CSV file."

    return extracted_flows, None


@app.post("/upload/traffic")
async def upload_traffic(file: UploadFile = File(...), request: Request = None) -> list[dict[str, object]]:
    """Accept PCAP, PCAPNG, or CSV file, process through exact 78-feature extractor, and return predictions with SHAP explanations."""
    artifacts = get_artifacts(request)
    filename = file.filename or "uploaded_traffic"
    lower_name = filename.lower()

    if not (lower_name.endswith(".pcap") or lower_name.endswith(".pcapng") or lower_name.endswith(".csv")):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Unsupported file format. Please upload a .pcap, .pcapng, or a supported 78-feature .csv file.",
        )

    file_bytes = await file.read()
    if len(file_bytes) == 0:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Uploaded file is empty.")

    extracted_flows: list[dict[str, float]] = []

    if lower_name.endswith(".csv"):
        try:
            content_str = file_bytes.decode("utf-8", errors="ignore")
            extracted_flows, parse_err = extract_flows_from_csv(content_str, artifacts.feature_names)
            if parse_err:
                raise HTTPException(
                    status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                    detail=parse_err,
                )
        except HTTPException:
            raise
        except Exception as csv_err:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"Failed to parse CSV file: {csv_err}",
            ) from csv_err

    else:
        # PCAP / PCAPNG processing
        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tmp:
            tmp.write(file_bytes)
            tmp_path = Path(tmp.name)

        try:
            extracted_flows = process_pcap(tmp_path)
        except Exception as pcap_err:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"Failed to extract flows from PCAP file: {pcap_err}",
            ) from pcap_err
        finally:
            if tmp_path.exists():
                tmp_path.unlink()

    if not extracted_flows:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="No valid completed network flows could be extracted from the uploaded file.",
        )

    results: list[dict[str, object]] = []

    # Run predictions and SHAP explanations on each extracted flow
    for idx, features in enumerate(extracted_flows):
        val_arr = np.asarray([features[name] for name in artifacts.feature_names], dtype=np.float64).reshape(1, -1)
        val_arr[np.isinf(val_arr)] = np.nan
        df = pd.DataFrame(val_arr, columns=artifacts.feature_names)
        processed = artifacts.imputer.transform(df)

        probs = artifacts.model.predict_proba(processed)[0]
        pred_idx = int(np.argmax(probs))
        pred_label = str(artifacts.label_encoder.inverse_transform(np.array([pred_idx]))[0])
        status_label = "BENIGN" if pred_label == "BENIGN" else "MALICIOUS"
        confidence = float(probs[pred_idx])
        prob_map = {class_name: float(probs[i]) for i, class_name in enumerate(artifacts.classes)}

        try:
            shap_values = select_predicted_class_shap_values(
                artifacts.explainer.shap_values(processed),
                pred_idx,
                len(artifacts.feature_names),
                len(artifacts.classes),
            )
            ranked_indices = sorted(
                range(len(artifacts.feature_names)),
                key=lambda i: abs(float(shap_values[i])),
                reverse=True,
            )[:10]

            explanation = [
                {
                    "feature": artifacts.feature_names[i],
                    "value": float(processed[0, i]),
                    "shap_value": float(shap_values[i]),
                    "direction": "increases_prediction" if shap_values[i] > 0 else "decreases_prediction" if shap_values[i] < 0 else "neutral",
                }
                for i in ranked_indices
            ]
            supporting = [f for f in explanation if f["shap_value"] > 0]
            opposing = [f for f in explanation if f["shap_value"] < 0]
            top_pos = [f["feature"].strip() for f in supporting[:3]]
            top_str = f" ({', '.join(top_pos)})" if top_pos else ""

            if status_label == "MALICIOUS":
                summary = (
                    f"Threat Detected: {pred_label}. The model classified this network traffic flow as {pred_label} "
                    f"with {confidence * 100:.2f}% confidence. Primary contributing factors{top_str} "
                    f"strongly match the {pred_label} attack pattern."
                )
            else:
                summary = (
                    f"Traffic Status: BENIGN. The model classified this network traffic flow as normal BENIGN traffic with "
                    f"{confidence * 100:.2f}% confidence. Observed network attributes{top_str} "
                    f"align with standard baseline behavior in the CIC-IDS2017 dataset."
                )
        except Exception:
            explanation = []
            supporting = []
            opposing = []
            summary = f"Classification: {pred_label} ({confidence * 100:.2f}% confidence)."

        dst_val = features.get(" Destination Port", 0)
        dst_port = int(dst_val) if dst_val is not None and not np.isnan(dst_val) else 0

        dur_val = features.get(" Flow Duration", 0.0)
        duration = float(dur_val) if dur_val is not None and not np.isnan(dur_val) else 0.0

        fwd_val = features.get(" Total Fwd Packets", 0)
        fwd_pkts = int(fwd_val) if fwd_val is not None and not np.isnan(fwd_val) else 0

        bwd_val = features.get(" Total Backward Packets", 0)
        bwd_pkts = int(bwd_val) if bwd_val is not None and not np.isnan(bwd_val) else 0

        results.append({
            "flow_index": idx + 1,
            "filename": filename,
            "prediction": pred_label,
            "status": status_label,
            "confidence": confidence,
            "class_probabilities": prob_map,
            "explanation": explanation,
            "supporting_features": supporting,
            "opposing_features": opposing,
            "summary": summary,
            "metadata": {
                "destination_port": dst_port,
                "flow_duration_us": duration,
                "total_fwd_packets": fwd_pkts,
                "total_bwd_packets": bwd_pkts,
                "protocol": "TCP" if dst_port in (80, 443, 22, 21) else "UDP" if dst_port == 53 else "IP",
            },
            "features": features,
        })

    return results




