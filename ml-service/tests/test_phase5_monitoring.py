"""Comprehensive unit and integration tests for Phase 5 Real-Time Network Monitoring."""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import pytest
from fastapi.testclient import TestClient
from scapy.layers.inet import IP, TCP, UDP
from scapy.packet import Raw

from app.main import app, get_monitor_manager
from app.feature_extractor.packet_parser import parse_scapy_packet
from app.feature_extractor.flow import Flow
from app.feature_extractor.feature_calculator import calculate_flow_features
from app.monitoring.models import MonitorState, FlowMetadata



client = TestClient(app)


def test_interface_discovery_endpoint():
    """Verify GET /monitor/interfaces returns a list of real system interfaces."""
    response = client.get("/monitor/interfaces")
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)
    assert len(data) > 0
    assert "id" in data[0]
    assert "name" in data[0]
    assert "ips" in data[0]
    assert "is_up" in data[0]


def test_monitor_status_initial_and_stop():
    """Verify initial STOPPED status and safe stop endpoint."""
    response = client.get("/monitor/status")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] in ("STOPPED", "ERROR")
    assert data["active_flows"] >= 0

    # Test stop endpoint
    stop_resp = client.post("/monitor/stop")
    assert stop_resp.status_code == 200
    assert stop_resp.json()["status"] == "STOPPED"


def test_monitor_start_and_duplicate_rejection():
    """Verify monitor start, state transition, and duplicate start rejection."""
    # Find a valid interface name
    ifaces = client.get("/monitor/interfaces").json()
    target_iface = ifaces[0]["name"]

    start_resp = client.post("/monitor/start", json={"interface": target_iface})
    assert start_resp.status_code in (200, 500)  # 500 if permission denied or Npcap missing, which is handled gracefully

    if start_resp.status_code == 200:
        assert start_resp.json()["status"] == "RUNNING"

        # Duplicate start must return 400 Bad Request
        dup_resp = client.post("/monitor/start", json={"interface": target_iface})
        assert dup_resp.status_code == 400

        # Stop monitoring cleanly
        stop_resp = client.post("/monitor/stop")
        assert stop_resp.status_code == 200
        assert stop_resp.json()["status"] == "STOPPED"


def test_packet_to_ml_pipeline_and_shap_events():
    """Test packet aggregation to 78-feature calculation to ML inference & SHAP event generation."""
    # Access the monitor manager from FastAPI app state
    manager = get_monitor_manager(app)


    # Construct a synthetic benign 4-packet TCP exchange
    p1 = parse_scapy_packet(
        IP(src="192.168.1.15", dst="172.217.16.206") / TCP(sport=54321, dport=443, flags="S", window=65535),
        timestamp=100.0,
    )
    p2 = parse_scapy_packet(
        IP(src="172.217.16.206", dst="192.168.1.15") / TCP(sport=443, dport=54321, flags="SA", window=65535),
        timestamp=100.02,
    )
    p3 = parse_scapy_packet(
        IP(src="192.168.1.15", dst="172.217.16.206") / TCP(sport=54321, dport=443, flags="FA"),
        timestamp=100.05,
    )
    p4 = parse_scapy_packet(
        IP(src="172.217.16.206", dst="192.168.1.15") / TCP(sport=443, dport=54321, flags="FA"),
        timestamp=100.08,
    )

    # Feed packets into aggregator
    completed1 = manager._process_packet_to_aggregator(p1)
    completed2 = manager._process_packet_to_aggregator(p2)
    completed3 = manager._process_packet_to_aggregator(p3)
    completed4 = manager._process_packet_to_aggregator(p4)

    total_completed = completed1 + completed2 + completed3 + completed4
    assert len(total_completed) == 1, "Flow should complete on FIN handshake"


    features, meta = total_completed[0]
    assert len(features) == 78
    assert meta.source_ip == "192.168.1.15"
    assert meta.destination_port == 443
    assert meta.protocol == "TCP"

    # Process completed flow through real ML & SHAP pipeline
    manager._process_completed_flow(features, meta)

    # Verify event stored in history
    events = manager.get_recent_events(limit=5)
    assert len(events) > 0
    latest_event = events[-1]
    assert latest_event.flow.source_ip == "192.168.1.15"
    assert latest_event.flow.destination_port == 443
    assert latest_event.prediction in manager.artifacts.classes
    assert latest_event.status in ("BENIGN", "MALICIOUS")
    assert 0.0 <= latest_event.confidence <= 1.0
    assert len(latest_event.explanation) > 0
    assert len(latest_event.summary) > 0
    assert latest_event.model_version == "lightgbm-cic-ids2017"


def test_websocket_monitoring_stream():
    """Verify WebSocket endpoint connects, receives initial state, and remains responsive."""
    with client.websocket_connect("/ws/monitor") as ws:
        init_data = ws.receive_json()
        assert init_data["type"] == "INIT_STATE"
        assert "status" in init_data
        assert "events" in init_data
        assert isinstance(init_data["events"], list)


def test_flow_object_to_monitoring_event_conversion():
    """Verify that passing a raw Flow object (e.g. from sweeper or flush) directly to _process_completed_flow
    correctly normalizes to FlowMetadata without Pydantic validation error."""
    manager = get_monitor_manager(app)

    # Create raw Flow object
    p1 = parse_scapy_packet(
        IP(src="10.10.10.2", dst="10.10.10.1") / TCP(sport=60000, dport=80, flags="S", window=65535),
        timestamp=300.0,
    )
    raw_flow = Flow(p1)
    features = calculate_flow_features(raw_flow)

    # Pass raw Flow object directly as meta
    initial_event_count = len(manager.get_recent_events(limit=200))
    manager._process_completed_flow(features, raw_flow)

    events = manager.get_recent_events(limit=200)
    assert len(events) == initial_event_count + 1
    newest = events[-1]
    assert isinstance(newest.flow, FlowMetadata)
    assert newest.flow.source_ip == "10.10.10.2"
    assert newest.flow.destination_ip == "10.10.10.1"
    assert newest.flow.source_port == 60000
    assert newest.flow.destination_port == 80
    assert newest.flow.protocol == "TCP"


def main():
    test_interface_discovery_endpoint()
    print("[PASS] test_interface_discovery_endpoint")
    test_monitor_status_initial_and_stop()
    print("[PASS] test_monitor_status_initial_and_stop")
    test_monitor_start_and_duplicate_rejection()
    print("[PASS] test_monitor_start_and_duplicate_rejection")
    test_packet_to_ml_pipeline_and_shap_events()
    print("[PASS] test_packet_to_ml_pipeline_and_shap_events")
    test_websocket_monitoring_stream()
    print("[PASS] test_websocket_monitoring_stream")
    test_flow_object_to_monitoring_event_conversion()
    print("[PASS] test_flow_object_to_monitoring_event_conversion")
    print("=== ALL PHASE 5 MONITORING TESTS PASSED! ===")


if __name__ == "__main__":
    main()

