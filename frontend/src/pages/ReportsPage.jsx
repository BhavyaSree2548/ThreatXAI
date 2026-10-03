import React, { useState, useEffect } from "react";
import { fetchMonitorStatus, fetchMonitorEvents } from "../services/api";
import { generateSecurityReport } from "../services/pdfGenerator";

export default function ReportsPage({ navigate, activeResult }) {
  const [monitorStatus, setMonitorStatus] = useState(null);
  const [recentEvents, setRecentEvents] = useState([]);

  useEffect(() => {
    fetchMonitorStatus().then(setMonitorStatus).catch(() => {});
    fetchMonitorEvents(20).then(setRecentEvents).catch(() => {});
  }, []);

  const [exportNotice, setExportNotice] = useState("");

  const handleGenerateSummaryReport = () => {
    const targetData = activeResult || recentEvents[0];
    if (!targetData) {
      setExportNotice("No analyzed flow or live event is currently available to export. Please analyze a traffic sample or launch live monitoring first.");
      return;
    }
    setExportNotice("");
    generateSecurityReport(targetData);
  };

  return (
    <div className="reports-page">
      <div className="page-header">
        <div className="header-badge">SECURITY AUDIT & GOVERNANCE</div>
        <h1 className="page-title">Executive Security Reports</h1>
        <p className="page-subtitle">
          Export audit-ready PDF assessment reports incorporating exact LightGBM model telemetry,
          5-tuple network flow characteristics, and SHAP TreeExplainer attributions.
        </p>
      </div>

      {exportNotice && <div className="alert-box error" style={{ marginBottom: "20px" }}>ℹ️ {exportNotice}</div>}

      <div className="reports-grid">
        {/* Report Card 1 — Active Result Report */}
        <div className="report-card">
          <div className="report-card-header">
            <span className="report-badge-icon">📑</span>
            <div>
              <h3>Single Flow Assessment Report</h3>
              <span className="report-type">Detailed XAI Audit</span>
            </div>
          </div>
          <p className="report-card-desc">
            Complete vector PDF report for the active analyzed network flow. Includes top 10 SHAP feature attributions,
            model confidence metrics, and baseline traffic comparisons.
          </p>

          <div className="report-meta-pills">
            <span className="pill">Vector PDF</span>
            <span className="pill">SHAP Bar Chart</span>
            <span className="pill">5-Tuple Headers</span>
          </div>

          <button className="primary-btn full-width" onClick={handleGenerateSummaryReport}>
            📑 Export Flow PDF Report
          </button>
        </div>

        {/* Report Card 2 — Live Session Report */}
        <div className="report-card">
          <div className="report-card-header">
            <span className="report-badge-icon">📡</span>
            <div>
              <h3>Live Monitoring Session Summary</h3>
              <span className="report-type">Real-Time Telemetry</span>
            </div>
          </div>
          <p className="report-card-desc">
            Aggregated statistics for real-time packet capture on active Windows network adapters:
            total processed flows, threat detection rate, and attack class distribution.
          </p>

          <div className="report-meta-pills">
            <span className="pill">Active Flows: {monitorStatus?.active_flows || 0}</span>
            <span className="pill">Threats: {monitorStatus?.threats_detected || 0}</span>
          </div>

          <button className="secondary-btn full-width" onClick={() => navigate("/monitoring")}>
            View Live Monitoring Feed →
          </button>
        </div>
      </div>

      {/* Model Governance Specifications */}
      <div className="governance-panel">
        <h3 className="governance-title">AI Security Governance Standards</h3>
        <div className="gov-items-grid">
          <div className="gov-item">
            <span className="gov-icon">🔒</span>
            <h4>Deterministic Prediction Pipeline</h4>
            <p>Predictions are derived exclusively from the trained LightGBM multiclass model without artificial or synthetic overrides.</p>
          </div>
          <div className="gov-item">
            <span className="gov-icon">💡</span>
            <h4>Mathematical Explainability</h4>
            <p>TreeExplainer computes exact Shapley marginal values for each of the 78 features to guarantee audit transparency.</p>
          </div>
          <div className="gov-item">
            <span className="gov-icon">📊</span>
            <h4>Zero Data Hallucination</h4>
            <p>Only authentic network flow metrics and real model probability distributions are visualized in reports.</p>
          </div>
        </div>
      </div>
    </div>
  );
}
