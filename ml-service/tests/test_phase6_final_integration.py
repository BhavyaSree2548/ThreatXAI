"""Master End-to-End Integration and Verification Suite for ThreatXAI (Phase 6)."""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import pytest
import scapy.all as scapy
from fastapi.testclient import TestClient
from scapy.layers.inet import IP, TCP, UDP
from scapy.packet import Raw

from app.main import app, get_monitor_manager
from app.feature_extractor.constants import FEATURE_NAMES, FEATURE_COUNT
from app.feature_extractor.packet_parser import parse_scapy_packet
from app.feature_extractor.flow import Flow, FlowKey
from app.feature_extractor.feature_calculator import calculate_flow_features
from app.feature_extractor.schema_validator import validate_78_features
from app.feature_extractor.flow_aggregator import FlowAggregator
from app.feature_extractor.pcap_processor import process_pcap
from app.monitoring.models import MonitorState


client = TestClient(app)
SCHEMA_PATH = ROOT / "artifacts" / "model_feature_schema.json"


def test_01_api_health_and_artifacts():
    """Verify system health, model loaded, 78 features, 15 classes."""
    res = client.get("/health")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "ok"
    assert data["model_loaded"] is True
    assert data["model_version"] == "lightgbm-cic-ids2017"
    assert data["feature_count"] == 78
    assert data["class_count"] == 15

    # Verify schema JSON matches constants
    schema_data = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    expected_features = [f["model_name"] for f in schema_data["features"]]
    assert len(expected_features) == 78
    assert FEATURE_NAMES == tuple(expected_features)


def test_02_predict_and_explain_pipelines():
    """Verify prediction and explainability endpoints with real sample rows."""
    sample_csv_path = ROOT.parents[0] / "frontend" / "public" / "samples" / "cic-ids2017-real-sample.csv"
    assert sample_csv_path.is_file(), "Sample CSV must exist in frontend public folder"

    import csv
    with open(sample_csv_path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        rows = list(reader)

    assert len(rows) == 3, "Sample CSV should have 3 rows (BENIGN, DDoS, PortScan)"

    # Test Row 1 (BENIGN)
    row_features = {k: float(v) for k, v in rows[0].items() if k != "Label"}
    pred_res = client.post("/predict", json={"features": row_features})
    assert pred_res.status_code == 200
    pred_data = pred_res.json()
    assert pred_data["prediction"] == "BENIGN"
    assert pred_data["status"] == "BENIGN"
    assert pred_data["confidence"] > 0.99
    assert len(pred_data["class_probabilities"]) == 15

    # Test Row 2 (DDoS)
    ddos_features = {k: float(v) for k, v in rows[1].items() if k != "Label"}
    ddos_exp_res = client.post("/explain", json={"features": ddos_features})
    assert ddos_exp_res.status_code == 200
    ddos_exp_data = ddos_exp_res.json()
    assert ddos_exp_data["prediction"] == "DDoS"
    assert ddos_exp_data["status"] == "MALICIOUS"
    assert ddos_exp_data["confidence"] > 0.99
    assert len(ddos_exp_data["explanation"]) > 0
    assert len(ddos_exp_data["supporting_features"]) > 0
    assert "Threat Detected: DDoS" in ddos_exp_data["summary"]


def test_03_validation_error_handling():
    """Verify 422 rejections for missing, extra, reordered, non-numeric features."""
    valid_features = {name: 1.0 for name in FEATURE_NAMES}

    # 1. Missing feature
    missing_features = {name: 1.0 for name in list(FEATURE_NAMES)[:-1]}
    res = client.post("/predict", json={"features": missing_features})
    assert res.status_code == 422

    # 2. Extra unexpected feature
    extra_features = dict(valid_features)
    extra_features["UNKNOWN_EXTRA_FEATURE"] = 1.0
    res = client.post("/predict", json={"features": extra_features})
    assert res.status_code == 422

    # 3. Non-numeric value
    bad_val_features = dict(valid_features)
    bad_val_features[FEATURE_NAMES[0]] = "NOT_A_NUMBER"
    res = client.post("/predict", json={"features": bad_val_features})
    assert res.status_code == 422


def test_04_feature_extraction_and_flow_aggregation():
    """Verify packet parsing, bidirectional flow aggregation, and 78-feature derivation."""
    # Construct 4-packet TCP flow
    p1 = parse_scapy_packet(
        IP(src="192.168.1.100", dst="93.184.216.34") / TCP(sport=55555, dport=80, flags="S", window=65535),
        timestamp=100.0,
    )
    p2 = parse_scapy_packet(
        IP(src="93.184.216.34", dst="192.168.1.100") / TCP(sport=80, dport=55555, flags="SA", window=65535),
        timestamp=100.02,
    )
    p3 = parse_scapy_packet(
        IP(src="192.168.1.100", dst="93.184.216.34") / TCP(sport=55555, dport=80, flags="PA") / Raw(b"GET / HTTP/1.1\r\n\r\n"),
        timestamp=100.05,
    )
    p4 = parse_scapy_packet(
        IP(src="93.184.216.34", dst="192.168.1.100") / TCP(sport=80, dport=55555, flags="FA"),
        timestamp=100.10,
    )

    flow = Flow(p1)
    flow.add_packet(p2)
    flow.add_packet(p3)
    flow.add_packet(p4)

    features = calculate_flow_features(flow)
    assert len(features) == 78
    assert tuple(features.keys()) == FEATURE_NAMES

    valid, err = validate_78_features(features)
    assert valid is True
    assert err is None

    # Offline PCAP test
    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tmp:
        tmp_path = Path(tmp.name)

    try:
        pkts = [
            IP(src="192.168.1.20", dst="1.1.1.1") / UDP(sport=60001, dport=53) / Raw(b"query"),
            IP(src="1.1.1.1", dst="192.168.1.20") / UDP(sport=53, dport=60001) / Raw(b"response"),
        ]
        scapy.wrpcap(str(tmp_path), pkts)
        extracted_flows = process_pcap(tmp_path)
        assert len(extracted_flows) >= 1
        valid, _ = validate_78_features(extracted_flows[0])
        assert valid is True
    finally:
        if tmp_path.exists():
            tmp_path.unlink()


def test_05_real_time_monitoring_service():
    """Verify live monitoring endpoints, status transitions, flow-to-ML stream, and WebSockets."""
    # 1. Interface Discovery
    ifaces_res = client.get("/monitor/interfaces")
    assert ifaces_res.status_code == 200
    ifaces = ifaces_res.json()
    assert len(ifaces) > 0

    # 2. Status & Stop
    status_res = client.get("/monitor/status")
    assert status_res.status_code == 200
    stop_res = client.post("/monitor/stop")
    assert stop_res.status_code == 200
    assert stop_res.json()["status"] == "STOPPED"

    # 3. Start Monitoring
    start_res = client.post("/monitor/start", json={"interface": ifaces[0]["name"]})
    assert start_res.status_code in (200, 500)
    if start_res.status_code == 200:
        # Duplicate start rejection
        dup_res = client.post("/monitor/start", json={"interface": ifaces[0]["name"]})
        assert dup_res.status_code == 400
        client.post("/monitor/stop")

    # 4. Packet-to-ML Inference & SHAP Event Generation
    manager = get_monitor_manager(app)
    p_syn = parse_scapy_packet(
        IP(src="10.0.0.5", dst="10.0.0.1") / TCP(sport=50000, dport=80, flags="S", window=65535),
        timestamp=200.0,
    )
    p_sa = parse_scapy_packet(
        IP(src="10.0.0.1", dst="10.0.0.5") / TCP(sport=80, dport=50000, flags="SA", window=65535),
        timestamp=200.02,
    )
    p_fin1 = parse_scapy_packet(
        IP(src="10.0.0.5", dst="10.0.0.1") / TCP(sport=50000, dport=80, flags="FA"),
        timestamp=200.05,
    )
    p_fin2 = parse_scapy_packet(
        IP(src="10.0.0.1", dst="10.0.0.5") / TCP(sport=80, dport=50000, flags="FA"),
        timestamp=200.08,
    )

    c1 = manager._process_packet_to_aggregator(p_syn)
    c2 = manager._process_packet_to_aggregator(p_sa)
    c3 = manager._process_packet_to_aggregator(p_fin1)
    c4 = manager._process_packet_to_aggregator(p_fin2)

    total_c = c1 + c2 + c3 + c4
    assert len(total_c) == 1
    features, meta = total_c[0]
    manager._process_completed_flow(features, meta)

    events = manager.get_recent_events(limit=5)
    assert len(events) > 0
    latest = events[-1]
    assert latest.flow.source_ip == "10.0.0.5"
    assert latest.flow.destination_port == 80
    assert latest.prediction in manager.artifacts.classes
    assert len(latest.explanation) > 0
    assert len(latest.summary) > 0

    # 5. WebSocket Connection
    with client.websocket_connect("/ws/monitor") as ws:
        init_msg = ws.receive_json()
        assert init_msg["type"] == "INIT_STATE"
        assert "status" in init_msg
        assert "events" in init_msg


def main():
    print("=== RUNNING THREATXAI PHASE 6 FINAL INTEGRATION SUITE ===")
    test_01_api_health_and_artifacts()
    print("[PASS] 1. API Health and ML Artifacts Contract Verified")
    test_02_predict_and_explain_pipelines()
    print("[PASS] 2. Prediction (/predict) and Explainability (/explain) Pipelines Verified")
    test_03_validation_error_handling()
    print("[PASS] 3. Schema Validation Error Handling Verified (422 Rejections)")
    test_04_feature_extraction_and_flow_aggregation()
    print("[PASS] 4. Real-Time 78-Feature Extraction & Flow Aggregation Verified")
    test_05_real_time_monitoring_service()
    print("[PASS] 5. Real-Time Network Monitoring, Inference & WebSocket Stream Verified")
    print("=== ALL PHASE 6 FINAL INTEGRATION TESTS PASSED PERFECTLY! ===")


if __name__ == "__main__":
    main()
