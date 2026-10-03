import React, { useState, useEffect } from "react";
import { fetchModelMetrics, fetchMonitorStatus } from "../services/api";

export default function DashboardHome({ navigate }) {
  const [metrics, setMetrics] = useState(null);
  const [monitorStatus, setMonitorStatus] = useState(null);

  useEffect(() => {
    fetchModelMetrics().then(setMetrics).catch(() => {});
    fetchMonitorStatus().then(setMonitorStatus).catch(() => {});
  }, []);

  const accPercent =
    metrics?.test_metrics?.accuracy != null
      ? `${(metrics.test_metrics.accuracy * 100).toFixed(2)}%`
      : "Unavailable";
  const f1Percent =
    metrics?.test_metrics?.macro_f1 != null
      ? `${(metrics.test_metrics.macro_f1 * 100).toFixed(2)}%`
      : "Unavailable";

  return (
    <div className="dashboard-page">
      {/* Welcome Hero Section */}
      <div className="dashboard-hero">
        <div className="hero-content">
          <div className="hero-badge">⚡ EXPLAINABLE AI INTRUSION DETECTION</div>
          <h1 className="hero-title">Welcome to ThreatXAI</h1>
          <p className="hero-description">
            Analyze network traffic, detect cyber threats, understand model decisions with SHAP
            TreeExplainer, and generate comprehensive security reports.
          </p>
        </div>

        {/* Live Quick Telemetry Bar */}
        <div className="telemetry-bar">
          <div className="telemetry-item">
            <span className="telemetry-label">MODEL ARCHITECTURE</span>
            <span className="telemetry-value">LightGBM (15 Classes)</span>
          </div>
          <div className="telemetry-item">
            <span className="telemetry-label">CIC-IDS2017 ACCURACY</span>
            <span className="telemetry-value accent-green">{accPercent}</span>
          </div>
          <div className="telemetry-item">
            <span className="telemetry-label">MACRO F1-SCORE</span>
            <span className="telemetry-value accent-blue">{f1Percent}</span>
          </div>
          <div className="telemetry-item">
            <span className="telemetry-label">FEATURE MATRIX</span>
            <span className="telemetry-value">78 Network Metrics</span>
          </div>
        </div>
      </div>

      {/* THREE PROMINENT ACTION CARDS */}
      <div className="action-cards-section">
        <h2 className="section-title">PRIMARY SOC WORKFLOWS</h2>
        <div className="action-cards-grid">
          {/* Card 1 — Test Working Samples */}
          <div className="action-card card-samples" onClick={() => navigate("/test-samples")}>
            <div className="card-icon-wrap">
              <span className="card-icon">🧪</span>
            </div>
            <div className="card-body">
              <h3 className="card-title">Working Test Samples</h3>
              <p className="card-desc">
                Download verified CIC-IDS2017 attack and normal traffic samples for testing ThreatXAI with pre-validated flows.
              </p>
              <div className="card-tags">
                <span className="tag">DDoS</span>
                <span className="tag">PortScan</span>
                <span className="tag">Benign</span>
                <span className="tag">Multi-Flow Suite</span>
              </div>
            </div>
            <div className="card-footer">
              <button className="primary-card-btn">Test Working Samples →</button>
            </div>
          </div>

          {/* Card 2 — Upload Traffic */}
          <div className="action-card card-upload" onClick={() => navigate("/upload")}>
            <div className="card-icon-wrap">
              <span className="card-icon">📂</span>
            </div>
            <div className="card-body">
              <h3 className="card-title">Upload Traffic</h3>
              <p className="card-desc">
                Upload PCAP/PCAPNG or supported flow CSV for automated 78-feature extraction and AI evaluation.
              </p>
              <div className="card-tags">
                <span className="tag">.pcap</span>
                <span className="tag">.pcapng</span>
                <span className="tag">.csv</span>
                <span className="tag">Multi-Flow Batch</span>
              </div>
            </div>
            <div className="card-footer">
              <button className="primary-card-btn">Upload Traffic →</button>
            </div>
          </div>

          {/* Card 3 — Start Monitoring */}
          <div className="action-card card-monitor" onClick={() => navigate("/monitoring")}>
            <div className="card-icon-wrap">
              <span className="card-icon">📡</span>
            </div>
            <div className="card-body">
              <h3 className="card-title">Real-Time Monitoring</h3>
              <p className="card-desc">
                Monitor your live network interface (Wi-Fi/Ethernet) and stream detected threats in real time.
              </p>
              <div className="card-tags">
                <span className="tag">Npcap Driver</span>
                <span className="tag">Live WebSocket</span>
                <span className="tag">Real-Time SHAP</span>
              </div>
            </div>
            <div className="card-footer">
              <button className="primary-card-btn">Start Monitoring →</button>
            </div>
          </div>
        </div>
      </div>

      {/* Secondary Quick Navigation Grid */}
      <div className="dashboard-subsections-grid">
        <div className="sub-panel" onClick={() => navigate("/history")}>
          <div className="sub-panel-icon">🕒</div>
          <div className="sub-panel-text">
            <h4>Threat History & Logs</h4>
            <p>Review and filter past analyzed flows, attack alerts, and SHAP breakdowns.</p>
          </div>
          <span className="arrow-icon">→</span>
        </div>

        <div className="sub-panel" onClick={() => navigate("/reports")}>
          <div className="sub-panel-icon">📑</div>
          <div className="sub-panel-text">
            <h4>Security Reports Hub</h4>
            <p>Export executive PDF security assessments with complete SHAP attributions.</p>
          </div>
          <span className="arrow-icon">→</span>
        </div>

        <div className="sub-panel" onClick={() => navigate("/assistant")}>
          <div className="sub-panel-icon">🤖</div>
          <div className="sub-panel-text">
            <h4>ThreatXAI SOC Assistant</h4>
            <p>Query model reasoning, threat classifications, and real-time telemetry.</p>
          </div>
          <span className="arrow-icon">→</span>
        </div>

        <div className="sub-panel" onClick={() => navigate("/system-health")}>
          <div className="sub-panel-icon">🛡️</div>
          <div className="sub-panel-text">
            <h4>System Health & Diagnostics</h4>
            <p>Verify FastAPI status, LightGBM artifact, 78-feature schema, and Npcap.</p>
          </div>
          <span className="arrow-icon">→</span>
        </div>
      </div>
    </div>
  );
}
