"""Offline PCAP file processor for testing and validating feature extraction."""

from __future__ import annotations

from pathlib import Path
from typing import Generator
import scapy.all as scapy
from .flow_aggregator import FlowAggregator


def process_pcap(pcap_path: str | Path) -> list[dict[str, float]]:
    """Process an offline PCAP/PCAPNG file and return all extracted 78-feature flows."""
    path = Path(pcap_path)
    if not path.is_file():
        raise FileNotFoundError(f"PCAP file not found: {path}")

    aggregator = FlowAggregator()
    completed_flows: list[dict[str, float]] = []

    # Stream packets through PcapReader
    with scapy.PcapReader(str(path)) as reader:
        for pkt in reader:
            flows = aggregator.process_scapy_packet(pkt)
            completed_flows.extend(flows)

    # Flush any remaining unexpired flows
    completed_flows.extend([item[0] for item in aggregator.flush_all()])
    return completed_flows

