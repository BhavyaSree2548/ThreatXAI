"""Bidirectional Flow representation for CIC-IDS2017 feature aggregation."""

from __future__ import annotations

from dataclasses import dataclass, field
from .constants import IDLE_THRESHOLD_US, FLOW_TIMEOUT_US, ACTIVITY_TIMEOUT_US
from .packet_parser import ParsedPacket


@dataclass(frozen=True)
class FlowKey:
    """Bidirectional 5-tuple key canonicalized for fast table lookups."""
    ip1: str
    ip2: str
    port1: int
    port2: int
    protocol: int

    @classmethod
    def from_packet(cls, pkt: ParsedPacket) -> FlowKey:
        if (pkt.src_ip, pkt.src_port) <= (pkt.dst_ip, pkt.dst_port):
            return cls(pkt.src_ip, pkt.dst_ip, pkt.src_port, pkt.dst_port, pkt.protocol)
        return cls(pkt.dst_ip, pkt.src_ip, pkt.dst_port, pkt.src_port, pkt.protocol)


class Flow:
    """Aggregates bidirectional packet streams into a CICFlowMeter-compliant flow."""

    def __init__(self, initial_packet: ParsedPacket):
        self.flow_key = FlowKey.from_packet(initial_packet)
        # Establish the forward direction from the initial packet
        self.fwd_src_ip = initial_packet.src_ip
        self.fwd_dst_ip = initial_packet.dst_ip
        self.fwd_src_port = initial_packet.src_port
        self.fwd_dst_port = initial_packet.dst_port
        self.protocol = initial_packet.protocol

        self.start_time_us = initial_packet.timestamp_us
        self.last_seen_time_us = initial_packet.timestamp_us

        # Packet length trackers
        self.fwd_packet_lengths: list[int] = []
        self.bwd_packet_lengths: list[int] = []
        self.all_packet_lengths: list[int] = []

        # Timestamp trackers (in microseconds)
        self.fwd_timestamps: list[int] = []
        self.bwd_timestamps: list[int] = []
        self.all_timestamps: list[int] = []

        # Header lengths (in bytes)
        self.fwd_header_lengths: list[int] = []
        self.bwd_header_lengths: list[int] = []

        # TCP Flag counts
        self.fin_count = 0
        self.syn_count = 0
        self.rst_count = 0
        self.psh_count = 0
        self.ack_count = 0
        self.urg_count = 0
        self.cwe_count = 0
        self.ece_count = 0

        # Directional PSH and URG
        self.fwd_psh_flags = 0
        self.bwd_psh_flags = 0
        self.fwd_urg_flags = 0
        self.bwd_urg_flags = 0

        # TCP Window & Segment metrics
        self.init_win_bytes_fwd = -1
        self.init_win_bytes_bwd = -1
        self.act_data_pkt_fwd = 0
        self.min_seg_size_fwd = 0

        # Active & Idle period tracking (CICFlowMeter methodology)
        self.active_periods: list[float] = []
        self.idle_periods: list[float] = []
        self.current_active_start_us = initial_packet.timestamp_us
        self.last_active_packet_us = initial_packet.timestamp_us

        self.is_terminated_flag = False

        # Add the first packet
        self.add_packet(initial_packet)

    def is_forward(self, pkt: ParsedPacket) -> bool:
        return (pkt.src_ip == self.fwd_src_ip and pkt.src_port == self.fwd_src_port)

    def add_packet(self, pkt: ParsedPacket) -> None:
        """Incorporate a parsed packet into the ongoing flow state."""
        ts = pkt.timestamp_us
        pkt_len = pkt.packet_length
        is_fwd = self.is_forward(pkt)

        # Track Active / Idle periods
        gap_us = ts - self.last_active_packet_us
        if gap_us > IDLE_THRESHOLD_US:
            active_duration = max(0.0, float(self.last_active_packet_us - self.current_active_start_us))
            if active_duration > 0:
                self.active_periods.append(active_duration)
            self.idle_periods.append(float(gap_us))
            self.current_active_start_us = ts

        self.last_active_packet_us = ts
        self.last_seen_time_us = ts

        # Aggregate lengths and timestamps
        self.all_packet_lengths.append(pkt_len)
        self.all_timestamps.append(ts)

        if is_fwd:
            self.fwd_packet_lengths.append(pkt_len)
            self.fwd_timestamps.append(ts)
            self.fwd_header_lengths.append(pkt.header_length)
            if self.init_win_bytes_fwd == -1 and pkt.is_tcp:
                self.init_win_bytes_fwd = pkt.window_size
            if pkt.is_tcp and pkt.payload_length > 0:
                self.act_data_pkt_fwd += 1
            if self.min_seg_size_fwd == 0 or (pkt.min_seg_size > 0 and pkt.min_seg_size < self.min_seg_size_fwd):
                self.min_seg_size_fwd = pkt.min_seg_size
            if pkt.tcp_flags.get("PSH", 0) == 1:
                self.fwd_psh_flags += 1
            if pkt.tcp_flags.get("URG", 0) == 1:
                self.fwd_urg_flags += 1
        else:
            self.bwd_packet_lengths.append(pkt_len)
            self.bwd_timestamps.append(ts)
            self.bwd_header_lengths.append(pkt.header_length)
            if self.init_win_bytes_bwd == -1 and pkt.is_tcp:
                self.init_win_bytes_bwd = pkt.window_size
            if pkt.tcp_flags.get("PSH", 0) == 1:
                self.bwd_psh_flags += 1
            if pkt.tcp_flags.get("URG", 0) == 1:
                self.bwd_urg_flags += 1

        # Global TCP Flags
        self.fin_count += pkt.tcp_flags.get("FIN", 0)
        self.syn_count += pkt.tcp_flags.get("SYN", 0)
        self.rst_count += pkt.tcp_flags.get("RST", 0)
        self.psh_count += pkt.tcp_flags.get("PSH", 0)
        self.ack_count += pkt.tcp_flags.get("ACK", 0)
        self.urg_count += pkt.tcp_flags.get("URG", 0)
        self.cwe_count += pkt.tcp_flags.get("CWR", 0)
        self.ece_count += pkt.tcp_flags.get("ECE", 0)

        # Termination check (TCP FIN or RST)
        if pkt.tcp_flags.get("RST", 0) == 1 or self.fin_count >= 2:
            self.is_terminated_flag = True

    def finalize_active_period(self) -> None:
        """Finalize the current active period when completing the flow."""
        active_duration = max(0.0, float(self.last_active_packet_us - self.current_active_start_us))
        if active_duration > 0 and (not self.active_periods or active_duration != self.active_periods[-1]):
            self.active_periods.append(active_duration)

    def is_expired(self, current_time_us: int) -> bool:
        if self.is_terminated_flag:
            return True
        if (current_time_us - self.last_seen_time_us) > ACTIVITY_TIMEOUT_US:
            return True
        if (current_time_us - self.start_time_us) > FLOW_TIMEOUT_US:
            return True
        return False
