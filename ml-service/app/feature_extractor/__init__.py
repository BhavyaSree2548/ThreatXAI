"""CIC-IDS2017 Real-Time Flow Feature Extractor Package."""

from .constants import FEATURE_NAMES, FEATURE_COUNT
from .packet_parser import ParsedPacket, parse_scapy_packet
from .flow import Flow, FlowKey
from .feature_calculator import calculate_flow_features
from .schema_validator import validate_78_features
from .flow_aggregator import FlowAggregator
from .pcap_processor import process_pcap

__all__ = [
    "FEATURE_NAMES",
    "FEATURE_COUNT",
    "ParsedPacket",
    "parse_scapy_packet",
    "Flow",
    "FlowKey",
    "calculate_flow_features",
    "validate_78_features",
    "FlowAggregator",
    "process_pcap",
]
