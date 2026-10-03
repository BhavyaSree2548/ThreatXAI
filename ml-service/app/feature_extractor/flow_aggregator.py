"""Real-time flow aggregator tracking active connections and emitting completed flows."""

from __future__ import annotations

import time
from typing import Any
from .flow import Flow, FlowKey
from .packet_parser import parse_scapy_packet, ParsedPacket
from .feature_calculator import calculate_flow_features
from .schema_validator import validate_78_features


class FlowAggregator:
    """Manages active network flows and produces 78-feature records upon flow completion."""

    def __init__(self):
        self.active_flows: dict[FlowKey, Flow] = {}

    def process_scapy_packet(self, scapy_pkt: Any, timestamp: float | None = None) -> list[dict[str, float]]:
        """Parse packet, update flow table, and return any completed flow feature vectors."""
        parsed = parse_scapy_packet(scapy_pkt, timestamp=timestamp)
        if not parsed:
            return []
        return self.process_parsed_packet(parsed)

    def process_parsed_packet(self, parsed: ParsedPacket) -> list[dict[str, float]]:
        """Update flow state with a ParsedPacket and emit terminated/expired flows."""
        completed_records: list[dict[str, float]] = []
        flow_key = FlowKey.from_packet(parsed)

        if flow_key not in self.active_flows:
            flow = Flow(parsed)
            self.active_flows[flow_key] = flow
        else:
            flow = self.active_flows[flow_key]
            flow.add_packet(parsed)

        # Check if flow terminated (FIN/RST) or expired
        if flow.is_terminated_flag or flow.is_expired(parsed.timestamp_us):
            features = calculate_flow_features(flow)
            valid, err = validate_78_features(features)
            if valid:
                completed_records.append(features)
            del self.active_flows[flow_key]

        return completed_records

    def sweep_expired_flows(self, current_time_us: int | None = None) -> list[tuple[dict[str, float], Flow]]:
        """Sweep and finalize any flows that exceeded inactivity or duration timeouts."""
        now_us = current_time_us if current_time_us is not None else int(time.time() * 1_000_000)
        expired_keys = [k for k, flow in self.active_flows.items() if flow.is_expired(now_us)]
        completed: list[tuple[dict[str, float], Flow]] = []

        for k in expired_keys:
            flow = self.active_flows.pop(k)
            features = calculate_flow_features(flow)
            valid, _ = validate_78_features(features)
            if valid:
                completed.append((features, flow))

        return completed

    def flush_all(self) -> list[tuple[dict[str, float], Flow]]:
        """Flush all active flows into completed (features, flow) tuples."""
        completed: list[tuple[dict[str, float], Flow]] = []
        for flow in self.active_flows.values():
            features = calculate_flow_features(flow)
            valid, _ = validate_78_features(features)
            if valid:
                completed.append((features, flow))
        self.active_flows.clear()
        return completed

