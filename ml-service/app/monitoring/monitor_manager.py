"""Real-time network monitoring manager coordinating packet capture and ML inference."""

from __future__ import annotations

import asyncio
import datetime
import math
import threading
import time
import uuid
from collections import deque
from typing import Any, Callable

import numpy as np
from fastapi import WebSocket

from app.feature_extractor.constants import FEATURE_NAMES
from app.feature_extractor.feature_calculator import calculate_flow_features
from app.feature_extractor.flow import Flow, FlowKey
from app.feature_extractor.flow_aggregator import FlowAggregator
from app.feature_extractor.packet_parser import parse_scapy_packet, ParsedPacket
from app.feature_extractor.schema_validator import validate_78_features
from .models import (
    ExplainedFeatureItem,
    FlowMetadata,
    InterfaceInfo,
    MonitoringEvent,
    MonitorState,
    MonitorStatusResponse,
)


class MonitorManager:
    """Central singleton managing real-time packet capture, flow extraction, and live event streaming."""

    def __init__(self, artifacts: Any):
        self.artifacts = artifacts
        self._state = MonitorState.STOPPED
        self._interface: str | None = None
        self._started_at: str | None = None
        self._error_message: str | None = None

        self._active_flows_count = 0
        self._processed_flows_count = 0
        self._normal_flows_count = 0
        self._threats_detected_count = 0

        self._events_history: deque[MonitoringEvent] = deque(maxlen=200)
        self._ws_clients: set[WebSocket] = set()

        self._lock = threading.RLock()
        self._stop_event = threading.Event()
        self._capture_thread: threading.Thread | None = None
        self._sweeper_thread: threading.Thread | None = None

        self._aggregator = FlowAggregator()
        self._loop: asyncio.AbstractEventLoop | None = None

    def set_event_loop(self, loop: asyncio.AbstractEventLoop) -> None:
        self._loop = loop

    def get_status(self) -> MonitorStatusResponse:
        with self._lock:
            active_count = len(self._aggregator.active_flows)
            return MonitorStatusResponse(

                status=self._state,
                interface=self._interface,
                started_at=self._started_at,
                active_flows=active_count,
                processed_flows=self._processed_flows_count,
                normal_flows=self._normal_flows_count,
                threats_detected=self._threats_detected_count,
                error_message=self._error_message,
            )

    def get_recent_events(self, limit: int = 50) -> list[MonitoringEvent]:
        with self._lock:
            events_list = list(self._events_history)
            return events_list[-limit:]

    def register_ws(self, ws: WebSocket) -> None:
        with self._lock:
            self._ws_clients.add(ws)

    def unregister_ws(self, ws: WebSocket) -> None:
        with self._lock:
            self._ws_clients.discard(ws)

    def _broadcast_event_sync(self, event: MonitoringEvent) -> None:
        """Schedule WebSocket broadcast across active UI clients."""
        if not self._ws_clients:
            return
        payload = {
            "type": "MONITOR_EVENT",
            "event": event.model_dump(),
            "status": self.get_status().model_dump(),
        }
        if self._loop and self._loop.is_running():
            asyncio.run_coroutine_threadsafe(self._broadcast_json(payload), self._loop)
        else:
            try:
                loop = asyncio.get_event_loop()
                if loop.is_running():
                    asyncio.run_coroutine_threadsafe(self._broadcast_json(payload), loop)
                else:
                    loop.run_until_complete(self._broadcast_json(payload))
            except Exception:
                pass

    def _broadcast_status_sync(self) -> None:
        """Schedule WebSocket status broadcast."""
        if not self._ws_clients:
            return
        payload = {"type": "MONITOR_STATUS", "status": self.get_status().model_dump()}
        if self._loop and self._loop.is_running():
            asyncio.run_coroutine_threadsafe(self._broadcast_json(payload), self._loop)
        else:
            try:
                loop = asyncio.get_event_loop()
                if loop.is_running():
                    asyncio.run_coroutine_threadsafe(self._broadcast_json(payload), loop)
                else:
                    loop.run_until_complete(self._broadcast_json(payload))
            except Exception:
                pass

    async def _broadcast_json(self, data: dict[str, Any]) -> None:
        with self._lock:
            clients = list(self._ws_clients)
        for ws in clients:
            try:
                await ws.send_json(data)
            except Exception:
                with self._lock:
                    self._ws_clients.discard(ws)

    def start_monitoring(self, interface: str) -> None:
        with self._lock:
            if self._state in (MonitorState.RUNNING, MonitorState.STARTING):
                raise ValueError(f"Monitoring is already active on interface '{self._interface}'. Stop current session first.")
            self._state = MonitorState.STARTING
            self._interface = interface
            self._started_at = datetime.datetime.now().isoformat()
            self._error_message = None
            self._processed_flows_count = 0
            self._normal_flows_count = 0
            self._threats_detected_count = 0
            self._events_history.clear()
            self._stop_event.clear()
            self._aggregator = FlowAggregator()

        # Start capture and sweeper threads
        try:
            self._capture_thread = threading.Thread(
                target=self._capture_worker, args=(interface,), daemon=True, name="ThreatXAI-CaptureThread"
            )
            self._sweeper_thread = threading.Thread(
                target=self._sweeper_worker, daemon=True, name="ThreatXAI-SweeperThread"
            )
            self._capture_thread.start()
            self._sweeper_thread.start()
            with self._lock:
                self._state = MonitorState.RUNNING
            self._broadcast_status_sync()
        except Exception as start_err:
            with self._lock:
                self._state = MonitorState.RUNNING
                self._error_message = f"Live monitoring active. Stream real packets via local_agent.py."
            self._broadcast_status_sync()

    def stop_monitoring(self) -> None:
        with self._lock:
            if self._state in (MonitorState.STOPPED, MonitorState.STOPPING):
                return
            self._state = MonitorState.STOPPING

        self._stop_event.set()

        # Flush any remaining flows
        if self._aggregator:
            flushed_flows = self._aggregator.flush_all()
            for flow_features, flow_meta in flushed_flows:
                self._process_completed_flow(flow_features, flow_meta)

        if self._capture_thread and self._capture_thread.is_alive():
            self._capture_thread.join(timeout=2.0)
        if self._sweeper_thread and self._sweeper_thread.is_alive():
            self._sweeper_thread.join(timeout=1.0)

        with self._lock:
            self._state = MonitorState.STOPPED
        self._broadcast_status_sync()

    def _capture_worker(self, interface: str) -> None:
        """Background thread running live packet capture via Scapy."""
        import scapy.all as scapy

        # Explicitly ensure Scapy uses the pcap backend for packet capture
        scapy.conf.use_pcap = True
        if hasattr(scapy.conf, "use_npcap"):
            scapy.conf.use_npcap = True

        target_iface = interface
        try:
            if hasattr(scapy.conf, "ifaces"):
                resolved = scapy.conf.ifaces.dev_from_name(interface)
                if resolved:
                    target_iface = resolved
        except Exception:
            pass

        def packet_handler(pkt: Any) -> None:
            if self._stop_event.is_set():
                return
            parsed = parse_scapy_packet(pkt)
            if not parsed:
                return

            completed_flows = self._process_packet_to_aggregator(parsed)
            for flow_features, flow_meta in completed_flows:
                self._process_completed_flow(flow_features, flow_meta)

        try:
            # Check Scapy sniffing
            scapy.sniff(
                iface=target_iface,
                prn=packet_handler,
                stop_filter=lambda _: self._stop_event.is_set(),
                store=False,
                timeout=None,
            )

        except PermissionError:
            with self._lock:
                self._state = MonitorState.RUNNING
                self._error_message = (
                    "Server packet sniffing inactive. Run local_agent.py on Windows to capture packets."
                )
            self._broadcast_status_sync()
        except Exception as cap_err:
            if not self._stop_event.is_set():
                with self._lock:
                    self._state = MonitorState.RUNNING
                    self._error_message = f"Server capture inactive ({cap_err}). Listening for local_agent.py flows via /monitor/ingest."
                self._broadcast_status_sync()

    def _sweeper_worker(self) -> None:
        """Periodically sweeps and flushes expired flows."""
        while not self._stop_event.is_set():
            time.sleep(1.0)
            now_us = int(time.time() * 1_000_000)
            completed_flows = self._aggregator.sweep_expired_flows(now_us)
            for flow_features, flow_meta in completed_flows:
                self._process_completed_flow(flow_features, flow_meta)

    def _process_packet_to_aggregator(self, parsed: ParsedPacket) -> list[tuple[dict[str, float], FlowMetadata]]:
        """Add packet to active flow table and return completed flows."""
        completed: list[tuple[dict[str, float], FlowMetadata]] = []
        flow_key = FlowKey.from_packet(parsed)

        with self._lock:
            if flow_key not in self._aggregator.active_flows:
                flow = Flow(parsed)
                self._aggregator.active_flows[flow_key] = flow
            else:
                flow = self._aggregator.active_flows[flow_key]
                flow.add_packet(parsed)

            if flow.is_terminated_flag or flow.is_expired(parsed.timestamp_us):
                features = calculate_flow_features(flow)
                meta = FlowMetadata(
                    source_ip=flow.fwd_src_ip,
                    destination_ip=flow.fwd_dst_ip,
                    source_port=flow.fwd_src_port,
                    destination_port=flow.fwd_dst_port,
                    protocol="TCP" if flow.protocol == 6 else "UDP" if flow.protocol == 17 else f"PROTO-{flow.protocol}",
                )
                valid, _ = validate_78_features(features)
                if valid:
                    completed.append((features, meta))
                del self._aggregator.active_flows[flow_key]

        return completed

    def _process_completed_flow(self, features: dict[str, float], meta: FlowMetadata | Flow) -> None:
        """Perform ML prediction and SHAP explanation on validated 78-feature flow."""
        try:
            # 0. Normalize meta to FlowMetadata instance
            if isinstance(meta, FlowMetadata):
                flow_meta = meta
            elif isinstance(meta, Flow):
                proto_str = "TCP" if meta.protocol == 6 else "UDP" if meta.protocol == 17 else f"PROTO-{meta.protocol}"
                flow_meta = FlowMetadata(
                    source_ip=str(meta.fwd_src_ip),
                    destination_ip=str(meta.fwd_dst_ip),
                    source_port=int(meta.fwd_src_port),
                    destination_port=int(meta.fwd_dst_port),
                    protocol=proto_str,
                )
            elif isinstance(meta, dict):
                flow_meta = FlowMetadata(**meta)
            else:
                proto_val = getattr(meta, "protocol", 6)
                proto_str = "TCP" if proto_val == 6 else "UDP" if proto_val == 17 else str(proto_val)
                flow_meta = FlowMetadata(
                    source_ip=str(getattr(meta, "fwd_src_ip", getattr(meta, "source_ip", "0.0.0.0"))),
                    destination_ip=str(getattr(meta, "fwd_dst_ip", getattr(meta, "destination_ip", "0.0.0.0"))),
                    source_port=int(getattr(meta, "fwd_src_port", getattr(meta, "source_port", 0))),
                    destination_port=int(getattr(meta, "fwd_dst_port", getattr(meta, "destination_port", 0))),
                    protocol=proto_str,
                )

            # 1. Preprocess with median imputer
            import pandas as pd

            ordered_values = [features[name] for name in self.artifacts.feature_names]
            val_arr = np.asarray(ordered_values, dtype=np.float64).reshape(1, -1)
            val_arr[np.isinf(val_arr)] = np.nan
            df = pd.DataFrame(val_arr, columns=self.artifacts.feature_names)
            processed = self.artifacts.imputer.transform(df)

            # 2. Predict with LightGBM
            probs = self.artifacts.model.predict_proba(processed)[0]
            pred_idx = int(np.argmax(probs))
            prediction = str(self.artifacts.label_encoder.inverse_transform(np.array([pred_idx]))[0])
            status = "BENIGN" if prediction == "BENIGN" else "MALICIOUS"
            confidence = float(probs[pred_idx])
            prob_map = {cls_name: float(probs[i]) for i, cls_name in enumerate(self.artifacts.classes)}

            # 3. SHAP Explanation
            from app.main import select_predicted_class_shap_values

            shap_values = select_predicted_class_shap_values(
                self.artifacts.explainer.shap_values(processed),
                pred_idx,
                len(self.artifacts.feature_names),
                len(self.artifacts.classes),
            )

            ranked_indices = sorted(
                range(len(self.artifacts.feature_names)), key=lambda i: abs(float(shap_values[i])), reverse=True
            )[:10]

            explanation = [
                ExplainedFeatureItem(
                    feature=self.artifacts.feature_names[i],
                    value=float(processed[0, i]),
                    shap_value=float(shap_values[i]),
                    direction=("increases_prediction" if shap_values[i] > 0 else "decreases_prediction" if shap_values[i] < 0 else "neutral"),
                )
                for i in ranked_indices
            ]
            supporting = [f for f in explanation if f.shap_value > 0]
            opposing = [f for f in explanation if f.shap_value < 0]

            top_pos = [f.feature.strip() for f in supporting[:3]]
            top_str = f" ({', '.join(top_pos)})" if top_pos else ""
            if status == "MALICIOUS":
                summary = (
                    f"Threat Detected: {prediction}. The model classified this network flow as {prediction} "
                    f"with {confidence * 100:.2f}% confidence. Primary contributing factors{top_str} "
                    f"strongly match the {prediction} attack pattern."
                )
            else:
                summary = (
                    f"Traffic Status: BENIGN. Normal traffic pattern with {confidence * 100:.2f}% confidence. "
                    f"Flow characteristics{top_str} align with standard baseline behavior."
                )

            # 4. Construct Event with guaranteed FlowMetadata instance
            event = MonitoringEvent(
                id=str(uuid.uuid4())[:8],
                timestamp=datetime.datetime.now().strftime("%H:%M:%S"),
                flow=flow_meta,
                prediction=prediction,
                status=status,
                confidence=confidence,
                class_probabilities=prob_map,
                explanation=explanation,
                supporting_features=supporting,
                opposing_features=opposing,
                summary=summary,
                model_version=self.artifacts.schema.get("model_version", "lightgbm-cic-ids2017"),
            )


            # 5. Store in history & update counters
            with self._lock:
                self._processed_flows_count += 1
                if status == "BENIGN":
                    self._normal_flows_count += 1
                else:
                    self._threats_detected_count += 1
                self._events_history.append(event)

            # 6. Broadcast event to UI
            self._broadcast_event_sync(event)
            return event

        except Exception as flow_err:
            # Safe catch to ensure monitoring continues
            import traceback
            traceback.print_exc()
            print(f"Error evaluating completed flow: {flow_err}")
            return None

    def ingest_external_flow(self, features: dict[str, float], meta: FlowMetadata | dict[str, Any] | None = None) -> MonitoringEvent:
        """Process a real captured flow received from a network sensor/agent."""
        valid, err = validate_78_features(features)
        if not valid:
            raise ValueError(f"Flow does not match required 78-feature schema: {err}")

        with self._lock:
            if self._state != MonitorState.RUNNING:
                self._state = MonitorState.RUNNING
                if not self._started_at:
                    self._started_at = datetime.datetime.now().isoformat()
                self._broadcast_status_sync()

        if meta is None or not meta:
            dst_port = int(features.get(" Destination Port", 0))
            meta = FlowMetadata(
                source_ip="127.0.0.1",
                destination_ip="127.0.0.1",
                source_port=0,
                destination_port=dst_port,
                protocol="TCP" if dst_port in (80, 443, 22, 21) else "UDP" if dst_port == 53 else "IP",
            )

        event = self._process_completed_flow(features, meta)
        if event is None:
            raise RuntimeError("Failed to generate prediction event for flow.")
        return event

