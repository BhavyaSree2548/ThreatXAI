"""Comprehensive unit tests for Phase 4 CIC-IDS2017 feature extraction."""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import pytest
import scapy.all as scapy
from scapy.layers.inet import IP, TCP, UDP
from scapy.packet import Raw

from app.feature_extractor.constants import FEATURE_NAMES, FEATURE_COUNT

from app.feature_extractor.packet_parser import parse_scapy_packet, ParsedPacket
from app.feature_extractor.flow import Flow, FlowKey
from app.feature_extractor.feature_calculator import calculate_flow_features
from app.feature_extractor.schema_validator import validate_78_features
from app.feature_extractor.flow_aggregator import FlowAggregator
from app.feature_extractor.pcap_processor import process_pcap


ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = ROOT / "artifacts" / "model_feature_schema.json"


def test_schema_loading_and_count():
    """Verify exact 78-feature schema loaded."""
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    expected_names = [f["model_name"] for f in schema["features"]]
    assert len(expected_names) == 78
    assert len(FEATURE_NAMES) == 78
    assert FEATURE_NAMES == tuple(expected_names)


def test_packet_parser_tcp_and_udp():
    """Verify parsing of TCP and UDP packets."""
    # 1. TCP Packet with SYN
    tcp_pkt = IP(src="192.168.1.50", dst="10.0.0.1", proto=6) / TCP(sport=49152, dport=80, flags="S", window=64240)
    parsed_tcp = parse_scapy_packet(tcp_pkt, timestamp=100.0)
    assert parsed_tcp is not None
    assert parsed_tcp.src_ip == "192.168.1.50"
    assert parsed_tcp.dst_ip == "10.0.0.1"
    assert parsed_tcp.src_port == 49152
    assert parsed_tcp.dst_port == 80
    assert parsed_tcp.protocol == 6
    assert parsed_tcp.is_tcp is True
    assert parsed_tcp.tcp_flags["SYN"] == 1
    assert parsed_tcp.tcp_flags["ACK"] == 0
    assert parsed_tcp.window_size == 64240

    # 2. UDP Packet with Payload
    udp_pkt = IP(src="192.168.1.50", dst="8.8.8.8", proto=17) / UDP(sport=53000, dport=53) / Raw(b"DNS_QUERY_PAYLOAD_TEST")
    parsed_udp = parse_scapy_packet(udp_pkt, timestamp=100.5)
    assert parsed_udp is not None
    assert parsed_udp.is_udp is True
    assert parsed_udp.src_port == 53000
    assert parsed_udp.dst_port == 53
    assert parsed_udp.payload_length == 22


def test_flow_construction_and_direction():
    """Verify forward and backward packet tracking."""
    # Fwd Packet (Client -> Server SYN)
    p1 = parse_scapy_packet(
        IP(src="10.0.0.5", dst="10.0.0.1") / TCP(sport=50000, dport=443, flags="S", window=65535),
        timestamp=100.0,
    )
    flow = Flow(p1)
    assert flow.fwd_src_ip == "10.0.0.5"
    assert flow.fwd_dst_port == 443
    assert len(flow.fwd_packet_lengths) == 1
    assert len(flow.bwd_packet_lengths) == 0

    # Bwd Packet (Server -> Client SYN+ACK)
    p2 = parse_scapy_packet(
        IP(src="10.0.0.1", dst="10.0.0.5") / TCP(sport=443, dport=50000, flags="SA", window=28960),
        timestamp=100.02,
    )
    assert flow.is_forward(p2) is False
    flow.add_packet(p2)
    assert len(flow.fwd_packet_lengths) == 1
    assert len(flow.bwd_packet_lengths) == 1
    assert flow.syn_count == 2
    assert flow.ack_count == 1
    assert flow.init_win_bytes_fwd == 65535
    assert flow.init_win_bytes_bwd == 28960


def test_feature_calculator_78_features():
    """Verify exact 78 features calculation and zero-division protection."""
    # Construct a complete 4-packet flow
    p1 = parse_scapy_packet(
        IP(src="192.168.1.10", dst="93.184.216.34") / TCP(sport=55000, dport=80, flags="S", window=65535),
        timestamp=100.0,
    )
    p2 = parse_scapy_packet(
        IP(src="93.184.216.34", dst="192.168.1.10") / TCP(sport=80, dport=55000, flags="SA", window=65535),
        timestamp=100.05,
    )
    p3 = parse_scapy_packet(
        IP(src="192.168.1.10", dst="93.184.216.34") / TCP(sport=55000, dport=80, flags="PA") / Raw(b"GET / HTTP/1.1\r\n\r\n"),
        timestamp=100.08,
    )
    p4 = parse_scapy_packet(
        IP(src="93.184.216.34", dst="192.168.1.10") / TCP(sport=80, dport=55000, flags="FA"),
        timestamp=100.12,
    )

    flow = Flow(p1)
    flow.add_packet(p2)
    flow.add_packet(p3)
    flow.add_packet(p4)

    features = calculate_flow_features(flow)

    assert len(features) == 78
    assert tuple(features.keys()) == FEATURE_NAMES

    # Verify specific feature calculations
    assert features[" Destination Port"] == 80.0
    assert features[" Total Fwd Packets"] == 2.0
    assert features[" Total Backward Packets"] == 2.0
    assert features[" Flow Duration"] == pytest.approx(120000.0, rel=1e-3)  # 0.12s in us
    assert features["Flow Bytes/s"] > 0.0
    assert features[" Flow Packets/s"] > 0.0
    assert features["FIN Flag Count"] == 1.0
    assert features[" SYN Flag Count"] == 2.0
    assert features[" ACK Flag Count"] == 3.0
    assert features[" PSH Flag Count"] == 1.0
    assert features["Init_Win_bytes_forward"] == 65535.0
    assert features[" Init_Win_bytes_backward"] == 65535.0
    assert features[" act_data_pkt_fwd"] == 1.0

    # Schema validation
    valid, err = validate_78_features(features)
    assert valid is True
    assert err is None


def test_schema_validator_rejections():
    """Verify validation errors for missing, extra, reordered, or invalid values."""
    valid_features = {name: 1.0 for name in FEATURE_NAMES}

    # Valid check
    valid, err = validate_78_features(valid_features)
    assert valid is True

    # 1. Missing feature
    missing_one = {name: 1.0 for name in list(FEATURE_NAMES)[:-1]}
    valid, err = validate_78_features(missing_one)
    assert valid is False
    assert "count mismatch" in err

    # 2. Reordered features
    shuffled = dict(valid_features)
    keys = list(shuffled.keys())
    shuffled_dict = {keys[1]: 1.0, keys[0]: 1.0, **{k: 1.0 for k in keys[2:]}}
    valid, err = validate_78_features(shuffled_dict)
    assert valid is False
    assert "order does not strictly match" in err

    # 3. Non-numeric value
    bad_val = dict(valid_features)
    bad_val[FEATURE_NAMES[0]] = "string_value"
    valid, err = validate_78_features(bad_val)
    assert valid is False
    assert "non-numeric" in err


def test_flow_aggregator_and_pcap_processing():
    """Verify offline PCAP processing with FlowAggregator."""
    pkts = [
        IP(src="192.168.1.20", dst="1.1.1.1") / UDP(sport=60001, dport=53) / Raw(b"query1"),
        IP(src="1.1.1.1", dst="192.168.1.20") / UDP(sport=53, dport=60001) / Raw(b"resp1"),
        IP(src="192.168.1.20", dst="1.1.1.1") / UDP(sport=60002, dport=53) / Raw(b"query2"),
    ]

    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tmp:
        tmp_path = Path(tmp.name)

    try:
        scapy.wrpcap(str(tmp_path), pkts)
        flows = process_pcap(tmp_path)
        assert len(flows) >= 2
        for f in flows:
            valid, err = validate_78_features(f)
            assert valid is True
            assert err is None
            assert len(f) == 78
    finally:
        if tmp_path.exists():
            tmp_path.unlink()


def test_compatibility_with_existing_model_pipeline():
    """Verify extracted 78 features can be preprocessed and passed to the trained LightGBM model."""
    import joblib
    import numpy as np

    model = joblib.load(ROOT / "artifacts" / "lightgbm_model.joblib")
    imputer = joblib.load(ROOT / "artifacts" / "median_imputer.joblib")
    label_encoder = joblib.load(ROOT / "artifacts" / "label_encoder.joblib")

    # Construct synthetic flow
    p1 = parse_scapy_packet(
        IP(src="192.168.1.100", dst="172.217.16.206") / TCP(sport=51234, dport=443, flags="S", window=65535),
        timestamp=100.0,
    )
    p2 = parse_scapy_packet(
        IP(src="172.217.16.206", dst="192.168.1.100") / TCP(sport=443, dport=51234, flags="SA", window=65535),
        timestamp=100.03,
    )
    flow = Flow(p1)
    flow.add_packet(p2)
    features = calculate_flow_features(flow)

    assert len(features) == 78
    assert tuple(features.keys()) == FEATURE_NAMES

    # Transform through median imputer
    values = np.asarray([features[name] for name in FEATURE_NAMES], dtype=np.float64).reshape(1, -1)
    values[np.isinf(values)] = np.nan
    processed = imputer.transform(values)
    assert processed.shape == (1, 78)

    # Predict with trained LightGBM model
    probs = model.predict_proba(processed)[0]
    assert len(probs) == 15
    pred_idx = int(np.argmax(probs))
    pred_class = label_encoder.inverse_transform(np.array([pred_idx]))[0]
    assert pred_class in label_encoder.classes_
    assert 0.0 <= float(probs[pred_idx]) <= 1.0


def main():
    test_schema_loading_and_count()
    print("[PASS] test_schema_loading_and_count")
    test_packet_parser_tcp_and_udp()
    print("[PASS] test_packet_parser_tcp_and_udp")
    test_flow_construction_and_direction()
    print("[PASS] test_flow_construction_and_direction")
    test_feature_calculator_78_features()
    print("[PASS] test_feature_calculator_78_features")
    test_schema_validator_rejections()
    print("[PASS] test_schema_validator_rejections")
    test_flow_aggregator_and_pcap_processing()
    print("[PASS] test_flow_aggregator_and_pcap_processing")
    test_compatibility_with_existing_model_pipeline()
    print("[PASS] test_compatibility_with_existing_model_pipeline")
    print("=== ALL PHASE 4 FEATURE EXTRACTION TESTS PASSED! ===")


if __name__ == "__main__":
    main()

