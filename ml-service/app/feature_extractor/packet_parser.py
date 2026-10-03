"""Packet parsing module extracting key transport & network layer attributes."""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class ParsedPacket:
    timestamp_us: int
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: int
    packet_length: int
    header_length: int
    payload_length: int
    tcp_flags: dict[str, int]
    window_size: int
    min_seg_size: int
    is_tcp: bool
    is_udp: bool


def parse_scapy_packet(pkt: Any, timestamp: float | None = None) -> ParsedPacket | None:
    """Parse a Scapy packet into a normalized ParsedPacket representation."""
    # Check for IP layer (IPv4)
    if not pkt.haslayer("IP"):
        return None

    ip_layer = pkt["IP"]
    src_ip = str(ip_layer.src)
    dst_ip = str(ip_layer.dst)
    protocol = int(ip_layer.proto)
    ip_hdr_len = int(ip_layer.ihl) * 4 if (hasattr(ip_layer, "ihl") and ip_layer.ihl is not None) else 20
    total_len = int(ip_layer.len) if (hasattr(ip_layer, "len") and ip_layer.len is not None) else len(pkt)

    ts = timestamp if timestamp is not None else getattr(pkt, "time", time.time())
    timestamp_us = int(float(ts) * 1_000_000)

    tcp_flags = {"FIN": 0, "SYN": 0, "RST": 0, "PSH": 0, "ACK": 0, "URG": 0, "ECE": 0, "CWR": 0}
    window_size = 0
    min_seg_size = 0
    header_length = ip_hdr_len
    payload_length = 0
    is_tcp = False
    is_udp = False
    src_port = 0
    dst_port = 0

    if pkt.haslayer("TCP"):
        is_tcp = True
        tcp_layer = pkt["TCP"]
        src_port = int(tcp_layer.sport) if hasattr(tcp_layer, "sport") and tcp_layer.sport is not None else 0
        dst_port = int(tcp_layer.dport) if hasattr(tcp_layer, "dport") and tcp_layer.dport is not None else 0
        tcp_hdr_len = int(tcp_layer.dataofs) * 4 if (hasattr(tcp_layer, "dataofs") and tcp_layer.dataofs is not None) else 20
        header_length = ip_hdr_len + tcp_hdr_len
        min_seg_size = tcp_hdr_len
        window_size = int(tcp_layer.window) if (hasattr(tcp_layer, "window") and tcp_layer.window is not None) else 0


        # Flags extraction
        raw_flags = int(tcp_layer.flags) if hasattr(tcp_layer, "flags") else 0
        tcp_flags["FIN"] = 1 if (raw_flags & 0x01) else 0
        tcp_flags["SYN"] = 1 if (raw_flags & 0x02) else 0
        tcp_flags["RST"] = 1 if (raw_flags & 0x04) else 0
        tcp_flags["PSH"] = 1 if (raw_flags & 0x08) else 0
        tcp_flags["ACK"] = 1 if (raw_flags & 0x10) else 0
        tcp_flags["URG"] = 1 if (raw_flags & 0x20) else 0
        tcp_flags["ECE"] = 1 if (raw_flags & 0x40) else 0
        tcp_flags["CWR"] = 1 if (raw_flags & 0x80) else 0

        # Payload calculation
        if hasattr(tcp_layer, "payload") and tcp_layer.payload:
            payload_length = len(bytes(tcp_layer.payload))
        else:
            payload_length = max(0, total_len - header_length)

    elif pkt.haslayer("UDP"):
        is_udp = True
        udp_layer = pkt["UDP"]
        src_port = int(udp_layer.sport) if hasattr(udp_layer, "sport") and udp_layer.sport is not None else 0
        dst_port = int(udp_layer.dport) if hasattr(udp_layer, "dport") and udp_layer.dport is not None else 0
        udp_hdr_len = 8
        header_length = ip_hdr_len + udp_hdr_len
        min_seg_size = udp_hdr_len
        window_size = 0


        if hasattr(udp_layer, "payload") and udp_layer.payload:
            payload_length = len(bytes(udp_layer.payload))
        else:
            payload_length = max(0, total_len - header_length)
    else:
        # Other IP protocols (e.g. ICMP)
        src_port = 0
        dst_port = 0
        min_seg_size = ip_hdr_len
        payload_length = max(0, total_len - ip_hdr_len)

    return ParsedPacket(
        timestamp_us=timestamp_us,
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        protocol=protocol,
        packet_length=total_len,
        header_length=header_length,
        payload_length=payload_length,
        tcp_flags=tcp_flags,
        window_size=window_size,
        min_seg_size=min_seg_size,
        is_tcp=is_tcp,
        is_udp=is_udp,
    )
