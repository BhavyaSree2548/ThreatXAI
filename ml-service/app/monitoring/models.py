"""Data models for real-time network monitoring."""

from __future__ import annotations

from enum import Enum
from typing import Any
from pydantic import BaseModel, Field


class MonitorState(str, Enum):
    STOPPED = "STOPPED"
    STARTING = "STARTING"
    RUNNING = "RUNNING"
    STOPPING = "STOPPING"
    ERROR = "ERROR"


class InterfaceInfo(BaseModel):
    id: str
    name: str
    description: str
    ips: list[str] = Field(default_factory=list)
    is_up: bool = False


class FlowMetadata(BaseModel):
    source_ip: str
    destination_ip: str
    source_port: int
    destination_port: int
    protocol: str


class ExplainedFeatureItem(BaseModel):
    feature: str
    value: float
    shap_value: float
    direction: str


class MonitoringEvent(BaseModel):
    id: str
    timestamp: str
    flow: FlowMetadata
    prediction: str
    status: str
    confidence: float
    class_probabilities: dict[str, float] = Field(default_factory=dict)
    explanation: list[ExplainedFeatureItem] = Field(default_factory=list)
    supporting_features: list[ExplainedFeatureItem] = Field(default_factory=list)
    opposing_features: list[ExplainedFeatureItem] = Field(default_factory=list)
    summary: str
    model_version: str


class MonitorStatusResponse(BaseModel):
    status: MonitorState
    interface: str | None = None
    started_at: str | None = None
    active_flows: int = 0
    processed_flows: int = 0
    normal_flows: int = 0
    threats_detected: int = 0
    error_message: str | None = None


class StartMonitorRequest(BaseModel):
    interface: str


class IngestFlowRequest(BaseModel):
    features: dict[str, float]
    metadata: FlowMetadata | dict[str, Any] = Field(default_factory=dict)

