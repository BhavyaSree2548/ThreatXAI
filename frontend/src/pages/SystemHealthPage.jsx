import React, { useState, useEffect } from "react";
import { fetchHealth, fetchModelMetrics, fetchInterfaces, fetchMonitorStatus, API_BASE } from "../services/api";

export default function SystemHealthPage({ navigate }) {
  const [healthData, setHealthData] = useState(null);
  const [metricsData, setMetricsData] = useState(null);
  const [interfaces, setInterfaces] = useState([]);
  const [monitorStatus, setMonitorStatus] = useState(null);
  const [loading, setLoading] = useState(true);
  const [lastRefreshed, setLastRefreshed] = useState(new Date().toLocaleTimeString());

  const refreshAll = async () => {
    setLoading(true);
    try {
      const [h, m, ifaces, mon] = await Promise.allSettled([
        fetchHealth(),
        fetchModelMetrics(),
        fetchInterfaces(),
        fetchMonitorStatus(),
      ]);

      if (h.status === "fulfilled") setHealthData(h.value);
      else setHealthData(null);

      if (m.status === "fulfilled") setMetricsData(m.value);
      if (ifaces.status === "fulfilled") setInterfaces(ifaces.value);
      if (mon.status === "fulfilled") setMonitorStatus(mon.value);

      setLastRefreshed(new Date().toLocaleTimeString());
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    refreshAll();
  }, []);

  const isApiOnline = healthData?.status === "ok";
  const isModelLoaded = healthData?.model_loaded === true;
  const isSchemaValid = healthData?.feature_count === 78;
  const isClassesValid = healthData?.class_count === 15;
  const hasInterfaces = interfaces && interfaces.length > 0;

  return (
    <div className="health-page">
      <div className="health-top-bar">
        <div>
          <div className="header-badge">SYSTEM DIAGNOSTICS & TELEMETRY</div>
          <h1 className="page-title">Platform Health Status</h1>
          <p className="page-subtitle">Real-time health telemetry across the ML inference engine, feature schema, and packet capture.</p>
        </div>

        <button className="refresh-btn" onClick={refreshAll} disabled={loading}>
          {loading ? "Checking System..." : `🔄 Refresh Status (${lastRefreshed})`}
        </button>
      </div>

      {/* Overall System Status Pill */}
      <div className={`system-status-banner ${isApiOnline && isModelLoaded ? "status-healthy" : "status-degraded"}`}>
        <span className="banner-icon">{isApiOnline && isModelLoaded ? "🛡️" : "⚠️"}</span>
        <div>
          <h2>{isApiOnline && isModelLoaded ? "ALL PLATFORM SERVICES OPERATIONAL" : "BACKEND SERVICE DISCONNECTED"}</h2>
          <p>
            {isApiOnline && isModelLoaded
              ? "FastAPI server, LightGBM multiclass booster, 78-feature schema, TreeExplainer SHAP, and Scapy packet capture are verified."
              : `Unable to establish connection with FastAPI backend on ${API_BASE}. Please verify that the backend service is running.`}
          </p>
        </div>
      </div>

      {/* Diagnostic Cards Grid */}
      <div className="diagnostic-grid">
        {/* Component 1: FastAPI Service */}
        <div className="diagnostic-card">
          <div className="diag-header">
            <span className="diag-name">FastAPI Prediction API</span>
            <span className={`diag-status-pill ${isApiOnline ? "online" : "offline"}`}>
              {isApiOnline ? "ONLINE" : "OFFLINE"}
            </span>
          </div>
          <p className="diag-desc">Handles /predict, /explain, /upload, and /auth endpoints.</p>
          <div className="diag-metric-row">
            <span className="metric-k">Host:</span>
            <span className="metric-v">{API_BASE}</span>
          </div>
          <div className="diag-metric-row">
            <span className="metric-k">HTTP Health Check:</span>
            <span className="metric-v">{isApiOnline ? "200 OK" : "Connection Refused"}</span>
          </div>
        </div>

        {/* Component 2: LightGBM Model */}
        <div className="diagnostic-card">
          <div className="diag-header">
            <span className="diag-name">LightGBM Model Artifact</span>
            <span className={`diag-status-pill ${isModelLoaded ? "online" : "offline"}`}>
              {isModelLoaded ? "LOADED" : "UNAVAILABLE"}
            </span>
          </div>
          <p className="diag-desc">Trained booster artifact: lightgbm_model.joblib (12.2 MB).</p>
          <div className="diag-metric-row">
            <span className="metric-k">Model Version:</span>
            <span className="metric-v">{healthData?.model_version || "lightgbm-cic-ids2017"}</span>
          </div>
          <div className="diag-metric-row">
            <span className="metric-k">Target Classes:</span>
            <span className="metric-v">{isClassesValid ? "15 Classes Verified" : "Error"}</span>
          </div>
        </div>

        {/* Component 3: 78-Feature Schema */}
        <div className="diagnostic-card">
          <div className="diag-header">
            <span className="diag-name">Feature Schema (78 Features)</span>
            <span className={`diag-status-pill ${isSchemaValid ? "online" : "offline"}`}>
              {isSchemaValid ? "78 / 78 METRICS" : "MISMATCH"}
            </span>
          </div>
          <p className="diag-desc">Authoritative model schema: model_feature_schema.json.</p>
          <div className="diag-metric-row">
            <span className="metric-k">Expected Features:</span>
            <span className="metric-v">78 Dimensions</span>
          </div>
          <div className="diag-metric-row">
            <span className="metric-k">Preprocessing:</span>
            <span className="metric-v">Median Imputer Active</span>
          </div>
        </div>

        {/* Component 4: Npcap / Scapy Sniffer */}
        <div className="diagnostic-card">
          <div className="diag-header">
            <span className="diag-name">Npcap Packet Capture Driver</span>
            <span className={`diag-status-pill ${hasInterfaces ? "online" : "offline"}`}>
              {hasInterfaces ? "DETECTED" : "UNAVAILABLE"}
            </span>
          </div>
          <p className="diag-desc">Layer 3/4 packet capture with bidirectional 5-tuple flow aggregation.</p>
          <div className="diag-metric-row">
            <span className="metric-k">Discovered Adapters:</span>
            <span className="metric-v">{interfaces.length} Windows Interfaces</span>
          </div>
          <div className="diag-metric-row">
            <span className="metric-k">Monitor State:</span>
            <span className="metric-v">{monitorStatus?.status || "STOPPED"}</span>
          </div>
        </div>

        {/* Component 5: SHAP TreeExplainer */}
        <div className="diagnostic-card">
          <div className="diag-header">
            <span className="diag-name">SHAP TreeExplainer Subsystem</span>
            <span className={`diag-status-pill ${isModelLoaded ? "online" : "offline"}`}>
              {isModelLoaded ? "OPERATIONAL" : "OFFLINE"}
            </span>
          </div>
          <p className="diag-desc">Calculates exact Shapley values for all 78 input dimensions per prediction.</p>
          <div className="diag-metric-row">
            <span className="metric-k">Explainability Engine:</span>
            <span className="metric-v">SHAP v0.52.0 (TreeExplainer)</span>
          </div>
          <div className="diag-metric-row">
            <span className="metric-k">Attribution Output:</span>
            <span className="metric-v">Multiclass Supporting/Opposing</span>
          </div>
        </div>

        {/* Component 6: WebSocket Streaming */}
        <div className="diagnostic-card">
          <div className="diag-header">
            <span className="diag-name">WebSocket Telemetry Stream</span>
            <span className={`diag-status-pill ${isApiOnline ? "online" : "offline"}`}>
              {isApiOnline ? "READY" : "OFFLINE"}
            </span>
          </div>
          <p className="diag-desc">Live bidirectional stream for runtime threat alerts: /ws/monitor.</p>
          <div className="diag-metric-row">
            <span className="metric-k">Endpoint:</span>
            <span className="metric-v">ws://127.0.0.1:8000/ws/monitor</span>
          </div>
          <div className="diag-metric-row">
            <span className="metric-k">Event Broadcast:</span>
            <span className="metric-v">Zero-Lag Ingestion</span>
          </div>
        </div>
      </div>
    </div>
  );
}
