"""Calculate exact 78 CIC-IDS2017 features from a finalized Flow object."""

from __future__ import annotations

import math
import numpy as np
from .constants import FEATURE_NAMES, MICROSECONDS_PER_SECOND
from .flow import Flow


def _stats_1d(values: list[int] | list[float]) -> tuple[float, float, float, float, float]:
    """Return (min, max, mean, std, var) with safe zero handling."""
    if not values:
        return 0.0, 0.0, 0.0, 0.0, 0.0
    arr = np.asarray(values, dtype=np.float64)
    min_v = float(np.min(arr))
    max_v = float(np.max(arr))
    mean_v = float(np.mean(arr))
    std_v = float(np.std(arr))
    var_v = float(np.var(arr))
    return min_v, max_v, mean_v, std_v, var_v


def _iat_stats(timestamps_us: list[int]) -> tuple[float, float, float, float, float]:
    """Return (total, mean, std, max, min) for inter-arrival times in microseconds."""
    if len(timestamps_us) < 2:
        return 0.0, 0.0, 0.0, 0.0, 0.0
    iats = [float(timestamps_us[i] - timestamps_us[i - 1]) for i in range(1, len(timestamps_us))]
    arr = np.asarray(iats, dtype=np.float64)
    total_v = float(np.sum(arr))
    mean_v = float(np.mean(arr))
    std_v = float(np.std(arr))
    max_v = float(np.max(arr))
    min_v = float(np.min(arr))
    return total_v, mean_v, std_v, max_v, min_v


def calculate_flow_features(flow: Flow) -> dict[str, float]:
    """Convert an aggregated Flow instance into the exact 78 CIC-IDS2017 feature vector."""
    flow.finalize_active_period()

    # Flow Duration (microseconds)
    duration_us = max(0.0, float(flow.last_seen_time_us - flow.start_time_us))
    duration_sec = duration_us / MICROSECONDS_PER_SECOND

    # Packet counts
    total_fwd_pkts = float(len(flow.fwd_packet_lengths))
    total_bwd_pkts = float(len(flow.bwd_packet_lengths))
    total_pkts = total_fwd_pkts + total_bwd_pkts

    # Packet lengths
    total_fwd_bytes = float(sum(flow.fwd_packet_lengths))
    total_bwd_bytes = float(sum(flow.bwd_packet_lengths))
    total_bytes = total_fwd_bytes + total_bwd_bytes

    fwd_min, fwd_max, fwd_mean, fwd_std, _ = _stats_1d(flow.fwd_packet_lengths)
    bwd_min, bwd_max, bwd_mean, bwd_std, _ = _stats_1d(flow.bwd_packet_lengths)
    all_min, all_max, all_mean, all_std, all_var = _stats_1d(flow.all_packet_lengths)

    # Rates (protected against zero division)
    if duration_sec > 0:
        flow_bytes_s = total_bytes / duration_sec
        flow_pkts_s = total_pkts / duration_sec
        fwd_pkts_s = total_fwd_pkts / duration_sec
        bwd_pkts_s = total_bwd_pkts / duration_sec
    else:
        flow_bytes_s = 0.0
        flow_pkts_s = 0.0
        fwd_pkts_s = 0.0
        bwd_pkts_s = 0.0

    # Inter-Arrival Times (IAT)
    flow_iat_total, flow_iat_mean, flow_iat_std, flow_iat_max, flow_iat_min = _iat_stats(flow.all_timestamps)
    fwd_iat_total, fwd_iat_mean, fwd_iat_std, fwd_iat_max, fwd_iat_min = _iat_stats(flow.fwd_timestamps)
    bwd_iat_total, bwd_iat_mean, bwd_iat_std, bwd_iat_max, bwd_iat_min = _iat_stats(flow.bwd_timestamps)

    # Header lengths
    fwd_header_len = float(sum(flow.fwd_header_lengths))
    bwd_header_len = float(sum(flow.bwd_header_lengths))

    # Ratios and Segment Averages
    down_up_ratio = math.floor(total_bwd_pkts / total_fwd_pkts) if total_fwd_pkts > 0 else 0.0
    avg_pkt_size = total_bytes / total_pkts if total_pkts > 0 else 0.0
    avg_fwd_seg_size = fwd_mean
    avg_bwd_seg_size = bwd_mean

    # Active & Idle Statistics
    act_min, act_max, act_mean, act_std, _ = _stats_1d(flow.active_periods)
    idle_min, idle_max, idle_mean, idle_std, _ = _stats_1d(flow.idle_periods)

    raw_features: dict[str, float] = {
        " Destination Port": float(flow.fwd_dst_port),
        " Flow Duration": duration_us,
        " Total Fwd Packets": total_fwd_pkts,
        " Total Backward Packets": total_bwd_pkts,
        "Total Length of Fwd Packets": total_fwd_bytes,
        " Total Length of Bwd Packets": total_bwd_bytes,
        " Fwd Packet Length Max": fwd_max,
        " Fwd Packet Length Min": fwd_min,
        " Fwd Packet Length Mean": fwd_mean,
        " Fwd Packet Length Std": fwd_std,
        "Bwd Packet Length Max": bwd_max,
        " Bwd Packet Length Min": bwd_min,
        " Bwd Packet Length Mean": bwd_mean,
        " Bwd Packet Length Std": bwd_std,
        "Flow Bytes/s": flow_bytes_s,
        " Flow Packets/s": flow_pkts_s,
        " Flow IAT Mean": flow_iat_mean,
        " Flow IAT Std": flow_iat_std,
        " Flow IAT Max": flow_iat_max,
        " Flow IAT Min": flow_iat_min,
        "Fwd IAT Total": fwd_iat_total,
        " Fwd IAT Mean": fwd_iat_mean,
        " Fwd IAT Std": fwd_iat_std,
        " Fwd IAT Max": fwd_iat_max,
        " Fwd IAT Min": fwd_iat_min,
        "Bwd IAT Total": bwd_iat_total,
        " Bwd IAT Mean": bwd_iat_mean,
        " Bwd IAT Std": bwd_iat_std,
        " Bwd IAT Max": bwd_iat_max,
        " Bwd IAT Min": bwd_iat_min,
        "Fwd PSH Flags": float(flow.fwd_psh_flags),
        " Bwd PSH Flags": float(flow.bwd_psh_flags),
        " Fwd URG Flags": float(flow.fwd_urg_flags),
        " Bwd URG Flags": float(flow.bwd_urg_flags),
        " Fwd Header Length": fwd_header_len,
        " Bwd Header Length": bwd_header_len,
        "Fwd Packets/s": fwd_pkts_s,
        " Bwd Packets/s": bwd_pkts_s,
        " Min Packet Length": all_min,
        " Max Packet Length": all_max,
        " Packet Length Mean": all_mean,
        " Packet Length Std": all_std,
        " Packet Length Variance": all_var,
        "FIN Flag Count": float(flow.fin_count),
        " SYN Flag Count": float(flow.syn_count),
        " RST Flag Count": float(flow.rst_count),
        " PSH Flag Count": float(flow.psh_count),
        " ACK Flag Count": float(flow.ack_count),
        " URG Flag Count": float(flow.urg_count),
        " CWE Flag Count": float(flow.cwe_count),
        " ECE Flag Count": float(flow.ece_count),
        " Down/Up Ratio": float(down_up_ratio),
        " Average Packet Size": avg_pkt_size,
        " Avg Fwd Segment Size": avg_fwd_seg_size,
        " Avg Bwd Segment Size": avg_bwd_seg_size,
        " Fwd Header Length__duplicate_2": fwd_header_len,
        "Fwd Avg Bytes/Bulk": 0.0,
        " Fwd Avg Packets/Bulk": 0.0,
        " Fwd Avg Bulk Rate": 0.0,
        " Bwd Avg Bytes/Bulk": 0.0,
        " Bwd Avg Packets/Bulk": 0.0,
        "Bwd Avg Bulk Rate": 0.0,
        "Subflow Fwd Packets": total_fwd_pkts,
        " Subflow Fwd Bytes": total_fwd_bytes,
        " Subflow Bwd Packets": total_bwd_pkts,
        " Subflow Bwd Bytes": total_bwd_bytes,
        "Init_Win_bytes_forward": float(flow.init_win_bytes_fwd),
        " Init_Win_bytes_backward": float(flow.init_win_bytes_bwd),
        " act_data_pkt_fwd": float(flow.act_data_pkt_fwd),
        " min_seg_size_forward": float(flow.min_seg_size_fwd),
        "Active Mean": act_mean,
        " Active Std": act_std,
        " Active Max": act_max,
        " Active Min": act_min,
        "Idle Mean": idle_mean,
        " Idle Std": idle_std,
        " Idle Max": idle_max,
        " Idle Min": idle_min,
    }

    # Construct ordered output strictly mapped to the 78-feature schema
    ordered_features: dict[str, float] = {}
    for name in FEATURE_NAMES:
        val = raw_features.get(name, 0.0)
        # Ensure finite floats
        ordered_features[name] = float(val) if math.isfinite(val) else 0.0

    return ordered_features
