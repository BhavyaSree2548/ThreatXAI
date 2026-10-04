"""ThreatXAI Windows Real-Time Packet Sniffer and Flow Ingestion Agent.

Captures real network packets on your Windows machine using Npcap + Scapy,
aggregates packets into bidirectional flows, extracts all 78 statistical features
in exact schema order, and streams them to the ThreatXAI backend for LightGBM + SHAP inference.

Usage:
    python local_agent.py
    python local_agent.py --backend http://127.0.0.1:8000
    python local_agent.py --backend https://threatxai-backend.onrender.com --interface "Wi-Fi"
"""

from __future__ import annotations

import argparse
import datetime
import json
import os
import sys
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

# Ensure ml-service package is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent
ML_SERVICE_DIR = PROJECT_ROOT / "ml-service"
if ML_SERVICE_DIR.exists() and str(ML_SERVICE_DIR) not in sys.path:
    sys.path.insert(0, str(ML_SERVICE_DIR))

# Import authentic feature extractor modules from existing codebase
try:
    from app.feature_extractor.feature_calculator import calculate_flow_features
    from app.feature_extractor.flow import Flow, FlowKey
    from app.feature_extractor.flow_aggregator import FlowAggregator
    from app.feature_extractor.packet_parser import ParsedPacket, parse_scapy_packet
    from app.feature_extractor.schema_validator import validate_78_features
    from app.monitoring.interface_discovery import get_available_interfaces
except ImportError as imp_err:
    print(f"[ERROR] Could not import ThreatXAI feature extraction modules: {imp_err}")
    print("Please make sure you run this script from the ThreatXAI project root directory.")
    sys.exit(1)


class ThreatXAISnifferAgent:
    """Real-time packet sniffer capturing Windows network traffic and streaming genuine 78-feature flows."""

    def __init__(self, backend_url: str, interface: str | None = None, agent_key: str | None = None):
        self.backend_url = backend_url.rstrip("/")
        self.interface = interface
        self.agent_key = agent_key or os.getenv("THREATXAI_AGENT_KEY")
        self.aggregator = FlowAggregator()
        self.lock = threading.RLock()
        self.stop_event = threading.Event()

        self.packets_captured = 0
        self.flows_ingested = 0
        self.threats_detected = 0
        self.normal_flows = 0

    def select_interface(self) -> str:
        """Discover and let user select an active network interface."""
        if self.interface:
            return self.interface

        interfaces = get_available_interfaces()
        if not interfaces:
            print("[!] No network interfaces discovered. Falling back to default.")
            return "Wi-Fi"

        print("\n" + "=" * 65)
        print("  ThreatXAI - Available Windows Network Interfaces")
        print("=" * 65)
        default_idx = 0
        for idx, iface in enumerate(interfaces):
            status_tag = "[ACTIVE/UP]" if iface.is_up else "[DOWN]"
            ip_str = ", ".join(iface.ips) if iface.ips else "No IP"
            print(f" [{idx + 1}] {status_tag:<11} {iface.name}")
            print(f"     Description : {iface.description}")
            print(f"     IPs         : {ip_str}\n")
            if iface.is_up and ("wi-fi" in iface.name.lower() or "wireless" in iface.name.lower() or "ethernet" in iface.name.lower()):
                default_idx = idx

        recommended = interfaces[default_idx].name
        print(f"Recommended interface: [{default_idx + 1}] {recommended}")
        prompt = f"Select interface [1-{len(interfaces)}] (Default: {default_idx + 1}): "
        
        try:
            choice = input(prompt).strip()
            if choice:
                chosen_idx = int(choice) - 1
                if 0 <= chosen_idx < len(interfaces):
                    return interfaces[chosen_idx].name
        except (ValueError, EOFError, KeyboardInterrupt):
            pass

        return recommended

    def send_flow_to_backend(self, features: dict[str, float], meta: dict[str, Any]) -> None:
        """Transmit real 78-feature flow record to the ThreatXAI backend /monitor/ingest endpoint."""
        valid, err = validate_78_features(features)
        if not valid:
            print(f"[!] Invalid flow skipped: {err}")
            return

        payload = {
            "features": features,
            "metadata": meta,
        }
        data_bytes = json.dumps(payload).encode("utf-8")
        ingest_url = f"{self.backend_url}/monitor/ingest"

        req = urllib.request.Request(
            ingest_url,
            data=data_bytes,
            headers={
                "Content-Type": "application/json",
                "User-Agent": "ThreatXAI-LocalAgent/1.0",
                **({"X-Agent-Key": self.agent_key} if self.agent_key else {}),
            },
            method="POST",
        )

        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                if resp.status == 200:
                    resp_data = json.loads(resp.read().decode("utf-8"))
                    pred = resp_data.get("prediction", "UNKNOWN")
                    status_lbl = resp_data.get("status", "UNKNOWN")
                    conf = resp_data.get("confidence", 0.0) * 100

                    with self.lock:
                        self.flows_ingested += 1
                        if status_lbl == "MALICIOUS":
                            self.threats_detected += 1
                        else:
                            self.normal_flows += 1

                    timestamp = datetime.datetime.now().strftime("%H:%M:%S")
                    proto = meta.get("protocol", "IP")
                    s_ip = meta.get("source_ip", "?")
                    s_port = meta.get("source_port", 0)
                    d_ip = meta.get("destination_ip", "?")
                    d_port = meta.get("destination_port", 0)
                    
                    status_symbol = "[MALICIOUS ALERT]" if status_lbl == "MALICIOUS" else "[BENIGN]"
                    print(
                        f"[{timestamp}] {status_symbol:<17} {proto:<4} {s_ip}:{s_port} -> {d_ip}:{d_port} | "
                        f"Prediction: {pred:<12} ({conf:.1f}%) | Total Flows: {self.flows_ingested}"
                    )
        except urllib.error.HTTPError as http_err:
            err_body = http_err.read().decode("utf-8", errors="ignore")
            print(f"[!] Ingestion error (HTTP {http_err.code}): {err_body}")
        except urllib.error.URLError as url_err:
            print(f"[!] Network error connecting to {ingest_url}: {url_err.reason}")
        except Exception as e:
            print(f"[!] Unexpected error sending flow: {e}")

    def process_packet(self, pkt: Any) -> None:
        """Handler called by Scapy on each captured real packet."""
        if self.stop_event.is_set():
            return

        with self.lock:
            self.packets_captured += 1

        parsed = parse_scapy_packet(pkt)
        if not parsed:
            return

        flow_key = FlowKey.from_packet(parsed)
        completed_flows: list[tuple[dict[str, float], dict[str, Any]]] = []

        with self.lock:
            if flow_key not in self.aggregator.active_flows:
                flow = Flow(parsed)
                self.aggregator.active_flows[flow_key] = flow
            else:
                flow = self.aggregator.active_flows[flow_key]
                flow.add_packet(parsed)

            if flow.is_terminated_flag or flow.is_expired(parsed.timestamp_us):
                features = calculate_flow_features(flow)
                meta = {
                    "source_ip": flow.fwd_src_ip,
                    "destination_ip": flow.fwd_dst_ip,
                    "source_port": flow.fwd_src_port,
                    "destination_port": flow.fwd_dst_port,
                    "protocol": "TCP" if flow.protocol == 6 else "UDP" if flow.protocol == 17 else f"PROTO-{flow.protocol}",
                }
                completed_flows.append((features, meta))
                del self.aggregator.active_flows[flow_key]

        for feat_dict, meta_dict in completed_flows:
            self.send_flow_to_backend(feat_dict, meta_dict)

    def sweeper_worker(self) -> None:
        """Periodically sweep and flush completed expired flows."""
        while not self.stop_event.is_set():
            time.sleep(1.0)
            now_us = int(time.time() * 1_000_000)
            with self.lock:
                expired = self.aggregator.sweep_expired_flows(now_us)

            for flow_features, flow_meta in expired:
                meta = {
                    "source_ip": getattr(flow_meta, "source_ip", getattr(flow_meta, "fwd_src_ip", "0.0.0.0")),
                    "destination_ip": getattr(flow_meta, "destination_ip", getattr(flow_meta, "fwd_dst_ip", "0.0.0.0")),
                    "source_port": getattr(flow_meta, "source_port", getattr(flow_meta, "fwd_src_port", 0)),
                    "destination_port": getattr(flow_meta, "destination_port", getattr(flow_meta, "fwd_dst_port", 0)),
                    "protocol": getattr(flow_meta, "protocol", "TCP"),
                }
                self.send_flow_to_backend(flow_features, meta)

    def start(self) -> None:
        """Start real packet capture and telemetry ingestion."""
        import scapy.all as scapy

        # Explicitly configure Npcap / pcap backend
        scapy.conf.use_pcap = True
        if hasattr(scapy.conf, "use_npcap"):
            scapy.conf.use_npcap = True

        selected_iface = self.select_interface()
        target_iface = selected_iface
        try:
            if hasattr(scapy.conf, "ifaces"):
                resolved = scapy.conf.ifaces.dev_from_name(selected_iface)
                if resolved:
                    target_iface = resolved
        except Exception:
            pass

        print("\n" + "=" * 65)
        print("  ThreatXAI Real-Time Network Intrusion Monitoring Agent")
        print("=" * 65)
        print(f" Interface   : {selected_iface}")
        print(f" Backend URL : {self.backend_url}")
        print(f" Target Path : {self.backend_url}/monitor/ingest")
        print(" Features    : Exact 78 statistical network flow features")
        print(" Mode        : Real packet capture (Npcap + Scapy)")
        print("=" * 65)
        print(" Capturing live packets... Press Ctrl+C to stop.\n")

        # Start background sweeper thread
        sweeper_thread = threading.Thread(target=self.sweeper_worker, daemon=True, name="Agent-SweeperThread")
        sweeper_thread.start()

        try:
            scapy.sniff(
                iface=target_iface,
                prn=self.process_packet,
                stop_filter=lambda _: self.stop_event.is_set(),
                store=False,
            )
        except PermissionError:
            print("\n[ERROR] Permission denied to capture packets.")
            print("Please run this command in an Administrator Command Prompt or PowerShell.")
        except KeyboardInterrupt:
            print("\n[INFO] Capture interrupted by user.")
        except Exception as e:
            print(f"\n[ERROR] Packet capture error: {e}")
            print("Please ensure Npcap is installed with 'WinPcap API-compatible Mode' enabled.")
        finally:
            self.stop()

    def stop(self) -> None:
        """Stop packet capture cleanly and print session summary."""
        self.stop_event.set()
        
        # Flush any remaining active flows
        with self.lock:
            remaining = self.aggregator.flush_all()
        for flow_features, flow_meta in remaining:
            meta = {
                "source_ip": getattr(flow_meta, "source_ip", getattr(flow_meta, "fwd_src_ip", "0.0.0.0")),
                "destination_ip": getattr(flow_meta, "destination_ip", getattr(flow_meta, "fwd_dst_ip", "0.0.0.0")),
                "source_port": getattr(flow_meta, "source_port", getattr(flow_meta, "fwd_src_port", 0)),
                "destination_port": getattr(flow_meta, "destination_port", getattr(flow_meta, "fwd_dst_port", 0)),
                "protocol": getattr(flow_meta, "protocol", "TCP"),
            }
            self.send_flow_to_backend(flow_features, meta)

        print("\n" + "=" * 65)
        print("  ThreatXAI Monitoring Session Summary")
        print("=" * 65)
        print(f" Total Real Packets Captured : {self.packets_captured}")
        print(f" Total 78-Feature Flows Ingested : {self.flows_ingested}")
        print(f" Normal (BENIGN) Flows       : {self.normal_flows}")
        print(f" Threats Detected (MALICIOUS): {self.threats_detected}")
        print("=" * 65 + "\n")


def main():
    parser = argparse.ArgumentParser(
        description="ThreatXAI Windows Real-Time Packet Sniffer and Flow Ingestion Agent"
    )
    parser.add_argument(
        "--backend",
        "-b",
        default="https://threatxai-backend.onrender.com",
        help="Backend API URL (default: https://threatxai-backend.onrender.com or http://127.0.0.1:8000)",
    )
    parser.add_argument(
        "--interface",
        "-i",
        default=None,
        help="Network interface name to sniff (e.g., 'Wi-Fi', 'Ethernet'). If omitted, interactive selection is shown.",
    )
    parser.add_argument(
        "--agent-key",
        "-k",
        default=None,
        help="Optional X-Agent-Key authentication token if configured on the backend.",
    )

    args = parser.parse_args()
    agent = ThreatXAISnifferAgent(backend_url=args.backend, interface=args.interface, agent_key=args.agent_key)
    agent.start()


if __name__ == "__main__":
    main()
