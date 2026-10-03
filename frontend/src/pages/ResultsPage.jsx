import React, { useState } from "react";
import ShapVisualizer from "../components/ShapVisualizer";
import ClassProbabilitiesChart from "../components/ClassProbabilitiesChart";
import { generateSecurityReport } from "../services/pdfGenerator";

export default function ResultsPage({ result, navigate, onOpenChatbot }) {
  const [selectedFlowIdx, setSelectedFlowIdx] = useState(0);

  if (!result) {
    return (
      <div className="empty-results-page">
        <div className="empty-card">
          <span className="empty-icon">📊</span>
          <h2>No Active Prediction Result</h2>
          <p>Upload a network capture file or select a test sample to generate real-time AI security analysis.</p>
          <div className="empty-actions">
            <button className="primary-btn" onClick={() => navigate("/upload")}>
              📂 Upload Traffic File
            </button>
            <button className="secondary-btn" onClick={() => navigate("/test-samples")}>
              🧪 Browse Test Samples
            </button>
          </div>
        </div>
      </div>
    );
  }

  // Handle multi-flow batch results if available
  const batchList = result.batch_results || [result];
  const activeFlow = batchList[selectedFlowIdx] || result;

  const isMalicious = activeFlow.status === "MALICIOUS";
  const confidencePercent = (activeFlow.confidence * 100).toFixed(2);
  const flowMeta = activeFlow.flow || activeFlow.metadata || {};

  // Compute Batch Summary Metrics
  const totalFlows = batchList.length;
  const normalFlows = batchList.filter((f) => f.status === "BENIGN").length;
  const threatFlows = batchList.filter((f) => f.status === "MALICIOUS");
  const threatCount = threatFlows.length;
  const threatRate = totalFlows > 0 ? ((threatCount / totalFlows) * 100).toFixed(1) : "0.0";
  const uniqueDetectedClasses = Array.from(new Set(batchList.map((f) => f.prediction)));

  const handleDownloadCSV = () => {
    if (!activeFlow.features) return;
    const headers = Object.keys(activeFlow.features).join(",");
    const values = Object.values(activeFlow.features).join(",");
    const csvContent = "data:text/csv;charset=utf-8," + headers + "\n" + values;
    const encodedUri = encodeURI(csvContent);
    const link = document.createElement("a");
    link.setAttribute("href", encodedUri);
    link.setAttribute("download", `ThreatXAI_Flow_${activeFlow.prediction}_${Date.now()}.csv`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  return (
    <div className="results-page">
      {/* Top Action Bar */}
      <div className="results-top-bar">
        <button className="back-link-btn" onClick={() => navigate("/dashboard")}>
          ← Back to Dashboard
        </button>

        <div className="results-actions-group">
          <button className="pdf-download-btn" onClick={() => generateSecurityReport(activeFlow)}>
            📑 Download PDF Report
          </button>
          <button className="secondary-btn" onClick={handleDownloadCSV}>
            ⬇️ Download CSV
          </button>
          <button className="chat-trigger-btn" onClick={() => onOpenChatbot && onOpenChatbot(activeFlow)}>
            🤖 Ask AI Assistant
          </button>
        </div>
      </div>

      {/* 1. TRAFFIC ANALYSIS SUMMARY (Batch & Multi-Flow) */}
      {batchList.length > 1 && (
        <div className="traffic-summary-panel">
          <div className="summary-panel-header">
            <div>
              <span className="summary-badge">BATCH INGESTION TELEMETRY</span>
              <h3 className="summary-title">Traffic Analysis Summary</h3>
            </div>
            <div className="detected-classes-tags">
              {uniqueDetectedClasses.map((cls) => (
                <span
                  key={cls}
                  className={`class-tag-pill ${cls === "BENIGN" ? "benign-tag" : "threat-tag"}`}
                >
                  {cls === "BENIGN" ? "✓" : "🚨"} {cls}
                </span>
              ))}
            </div>
          </div>

          <div className="summary-metrics-grid">
            <div className="summary-metric-card">
              <span className="metric-k">TOTAL FLOWS EVALUATED</span>
              <span className="metric-v">{totalFlows}</span>
              <span className="metric-hint">Extracted 5-tuple flows</span>
            </div>
            <div className="summary-metric-card">
              <span className="metric-k">NORMAL / BENIGN FLOWS</span>
              <span className="metric-v accent-green">{normalFlows}</span>
              <span className="metric-hint">Baseline traffic</span>
            </div>
            <div className="summary-metric-card">
              <span className="metric-k">THREAT FLOWS DETECTED</span>
              <span className={`metric-v ${threatCount > 0 ? "accent-red" : ""}`}>{threatCount}</span>
              <span className="metric-hint">Malicious signatures</span>
            </div>
            <div className="summary-metric-card">
              <span className="metric-k">THREAT DETECTION RATE</span>
              <span className={`metric-v ${parseFloat(threatRate) > 0 ? "accent-amber" : ""}`}>{threatRate}%</span>
              <span className="metric-hint">Threat / Total ratio</span>
            </div>
          </div>
        </div>
      )}

      {/* 2. DEDICATED ATTACK EXPLANATIONS SECTION */}
      {threatFlows.length > 0 && (
        <div className="attack-explanations-section">
          <div className="section-header-soc">
            <span className="section-icon">🛡️</span>
            <div>
              <h3 className="section-heading">Detected Attack Explanations</h3>
              <p className="section-subheading">
                Individual threat classifications evaluated by the trained LightGBM model with SHAP TreeExplainer attributions.
              </p>
            </div>
          </div>

          <div className="attack-cards-grid">
            {threatFlows.map((atk, idx) => {
              const originalIdx = batchList.findIndex((f) => f === atk);
              const isSelected = selectedFlowIdx === originalIdx;
              const meta = atk.flow || atk.metadata || {};
              const topShap = atk.supporting_features?.[0];

              return (
                <div
                  key={idx}
                  className={`attack-card-soc ${isSelected ? "selected-attack-card" : ""}`}
                >
                  <div className="attack-card-top">
                    <div className="attack-badge-row">
                      <span className="attack-number-badge">ATTACK #{idx + 1}</span>
                      <span className="attack-conf-pill">{(atk.confidence * 100).toFixed(1)}% Conf</span>
                    </div>
                    <h4 className="attack-class-name">{atk.prediction}</h4>
                    <p className="attack-meta-line">
                      Port: <strong>{meta.destination_port || "N/A"}</strong> ({meta.protocol || "TCP"}) • Duration: <strong>{meta.flow_duration_us ? `${meta.flow_duration_us.toLocaleString()} μs` : "Captured"}</strong>
                    </p>
                  </div>

                  <div className="attack-card-shap-preview">
                    <span className="shap-preview-label">Top Contributing Feature:</span>
                    <span className="shap-preview-val">
                      {topShap ? `${topShap.feature.trim()} (SHAP: +${topShap.shap_value.toFixed(4)})` : "Feature attributions active"}
                    </span>
                  </div>

                  <div className="attack-card-actions">
                    <button
                      className={`why-detected-btn ${isSelected ? "active" : ""}`}
                      onClick={() => {
                        setSelectedFlowIdx(originalIdx);
                        const el = document.getElementById("detailed-flow-inspection");
                        if (el) el.scrollIntoView({ behavior: "smooth" });
                      }}
                    >
                      {isSelected ? "✓ Viewing Explanation Below" : "🔍 Why was this detected?"}
                    </button>
                    <button
                      className="download-attack-pdf-btn"
                      onClick={() => generateSecurityReport(atk)}
                    >
                      📑 Download PDF
                    </button>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* 3. ATTACK COMPARISON SECTION (When 2 or more attacks detected) */}
      {threatFlows.length >= 2 && (
        <div className="attack-comparison-section">
          <div className="section-header-soc">
            <span className="section-icon">⚖️</span>
            <div>
              <h3 className="section-heading">Attack Comparison Analysis</h3>
              <p className="section-subheading">
                Side-by-side comparison of detected threat flows, network signatures, and top SHAP feature attributions.
              </p>
            </div>
          </div>

          <div className="table-responsive">
            <table className="comparison-table">
              <thead>
                <tr>
                  <th>EVALUATION PROPERTY</th>
                  <th>ATTACK 1: {threatFlows[0].prediction}</th>
                  <th>ATTACK 2: {threatFlows[1].prediction}</th>
                </tr>
              </thead>
              <tbody>
                <tr>
                  <td className="prop-name">Predicted Attack Class</td>
                  <td className="prop-val accent-red"><strong>{threatFlows[0].prediction}</strong></td>
                  <td className="prop-val accent-red"><strong>{threatFlows[1].prediction}</strong></td>
                </tr>
                <tr>
                  <td className="prop-name">Model Confidence</td>
                  <td className="prop-val">{(threatFlows[0].confidence * 100).toFixed(2)}%</td>
                  <td className="prop-val">{(threatFlows[1].confidence * 100).toFixed(2)}%</td>
                </tr>
                <tr>
                  <td className="prop-name">Primary Supporting Feature (SHAP #1)</td>
                  <td className="prop-val accent-cyan">
                    {threatFlows[0].supporting_features?.[0]
                      ? `${threatFlows[0].supporting_features[0].feature.trim()} (+${threatFlows[0].supporting_features[0].shap_value.toFixed(4)})`
                      : "N/A"}
                  </td>
                  <td className="prop-val accent-cyan">
                    {threatFlows[1].supporting_features?.[0]
                      ? `${threatFlows[1].supporting_features[0].feature.trim()} (+${threatFlows[1].supporting_features[0].shap_value.toFixed(4)})`
                      : "N/A"}
                  </td>
                </tr>
                <tr>
                  <td className="prop-name">Secondary Supporting Feature (SHAP #2)</td>
                  <td className="prop-val accent-cyan">
                    {threatFlows[0].supporting_features?.[1]
                      ? `${threatFlows[0].supporting_features[1].feature.trim()} (+${threatFlows[0].supporting_features[1].shap_value.toFixed(4)})`
                      : "N/A"}
                  </td>
                  <td className="prop-val accent-cyan">
                    {threatFlows[1].supporting_features?.[1]
                      ? `${threatFlows[1].supporting_features[1].feature.trim()} (+${threatFlows[1].supporting_features[1].shap_value.toFixed(4)})`
                      : "N/A"}
                  </td>
                </tr>
                <tr>
                  <td className="prop-name">Flow Duration</td>
                  <td className="prop-val">
                    {threatFlows[0].metadata?.flow_duration_us != null
                      ? `${threatFlows[0].metadata.flow_duration_us.toLocaleString()} μs`
                      : "Captured"}
                  </td>
                  <td className="prop-val">
                    {threatFlows[1].metadata?.flow_duration_us != null
                      ? `${threatFlows[1].metadata.flow_duration_us.toLocaleString()} μs`
                      : "Captured"}
                  </td>
                </tr>
                <tr>
                  <td className="prop-name">Total Packet Count</td>
                  <td className="prop-val">
                    {(threatFlows[0].metadata?.total_fwd_packets || 0) + (threatFlows[0].metadata?.total_bwd_packets || 0)} Packets
                  </td>
                  <td className="prop-val">
                    {(threatFlows[1].metadata?.total_fwd_packets || 0) + (threatFlows[1].metadata?.total_bwd_packets || 0)} Packets
                  </td>
                </tr>
                <tr>
                  <td className="prop-name">Destination Port & Protocol</td>
                  <td className="prop-val">
                    Port {threatFlows[0].metadata?.destination_port || 80} ({threatFlows[0].metadata?.protocol || "TCP"})
                  </td>
                  <td className="prop-val">
                    Port {threatFlows[1].metadata?.destination_port || 80} ({threatFlows[1].metadata?.protocol || "TCP"})
                  </td>
                </tr>
                <tr>
                  <td className="prop-name">Security Report Export</td>
                  <td className="prop-val">
                    <button
                      className="pdf-download-btn small-btn"
                      onClick={() => generateSecurityReport(threatFlows[0])}
                    >
                      📑 Download {threatFlows[0].prediction} PDF
                    </button>
                  </td>
                  <td className="prop-val">
                    <button
                      className="pdf-download-btn small-btn"
                      onClick={() => generateSecurityReport(threatFlows[1])}
                    >
                      📑 Download {threatFlows[1].prediction} PDF
                    </button>
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Multi-Flow Selector Tabs if batch */}
      {batchList.length > 1 && (
        <div className="batch-flow-tabs" id="detailed-flow-inspection">
          <span className="batch-label">Inspect Flow Details ({batchList.length} Flows):</span>
          <div className="batch-chips-list">
            {batchList.map((f, idx) => (
              <button
                key={idx}
                className={`batch-chip ${selectedFlowIdx === idx ? "active" : ""} ${f.status === "MALICIOUS" ? "threat-chip" : "benign-chip"}`}
                onClick={() => setSelectedFlowIdx(idx)}
              >
                Flow #{idx + 1}: {f.prediction} ({(f.confidence * 100).toFixed(0)}%)
              </button>
            ))}
          </div>
        </div>
      )}

      {/* HERO STATUS BANNER */}
      <div className={`hero-verdict-banner ${isMalicious ? "threat-banner" : "benign-banner"}`}>
        <div className="banner-glow-effect"></div>
        <div className="verdict-icon-wrap">
          <span className="verdict-icon">{isMalicious ? "🚨" : "✓"}</span>
        </div>
        <div className="verdict-content">
          <div className="verdict-tag">
            {isMalicious ? "MALICIOUS CLASSIFICATION" : "NORMAL TRAFFIC VERIFIED"}
          </div>
          <h1 className="verdict-title">
            {isMalicious ? `THREAT DETECTED: ${activeFlow.prediction}` : "TRAFFIC STATUS: BENIGN"}
          </h1>
          <p className="verdict-subtitle">
            Evaluated by trained LightGBM multiclass booster against 78 statistical network features.
          </p>
        </div>
        <div className="verdict-confidence-box">
          <span className="conf-label">MODEL CONFIDENCE</span>
          <span className="conf-value">{confidencePercent}%</span>
          <div className="conf-meter">
            <div className="conf-fill" style={{ width: `${confidencePercent}%` }}></div>
          </div>
        </div>
      </div>

      {/* FLOW METADATA & TELEMETRY GRID */}
      <div className="flow-meta-grid">
        <div className="meta-card">
          <span className="meta-card-label">SOURCE IP</span>
          <span className="meta-card-value accent-cyan">{flowMeta.source_ip || "N/A"}</span>
        </div>
        <div className="meta-card">
          <span className="meta-card-label">DESTINATION IP</span>
          <span className="meta-card-value accent-cyan">{flowMeta.destination_ip || "N/A"}</span>
        </div>
        <div className="meta-card">
          <span className="meta-card-label">DESTINATION PORT</span>
          <span className="meta-card-value">{flowMeta.destination_port != null ? flowMeta.destination_port : "N/A"}</span>
        </div>
        <div className="meta-card">
          <span className="meta-card-label">PROTOCOL</span>
          <span className="meta-card-value">{flowMeta.protocol || "N/A"}</span>
        </div>
        <div className="meta-card">
          <span className="meta-card-label">FLOW DURATION</span>
          <span className="meta-card-value">
            {flowMeta.flow_duration_us != null ? `${flowMeta.flow_duration_us.toLocaleString()} μs` : "N/A"}
          </span>
        </div>
        <div className="meta-card">
          <span className="meta-card-label">TOTAL PACKETS</span>
          <span className="meta-card-value">
            {flowMeta.total_fwd_packets != null || flowMeta.total_bwd_packets != null
              ? (flowMeta.total_fwd_packets || 0) + (flowMeta.total_bwd_packets || 0)
              : "N/A"}
          </span>
        </div>
      </div>

      {/* SHAP EXPLAINABILITY COMPONENT */}
      <ShapVisualizer
        explanation={activeFlow.explanation}
        supporting={activeFlow.supporting_features}
        opposing={activeFlow.opposing_features}
        summary={activeFlow.summary}
      />

      {/* 15-CLASS PROBABILITY DISTRIBUTION */}
      <ClassProbabilitiesChart
        probabilities={activeFlow.class_probabilities}
        predictedClass={activeFlow.prediction}
      />

      {/* Bottom Actions */}
      <div className="results-bottom-actions">
        <button className="primary-btn" onClick={() => navigate("/upload")}>
          📂 Analyze Another File
        </button>
        <button className="secondary-btn" onClick={() => navigate("/monitoring")}>
          📡 Launch Live Network Monitor
        </button>
        <button className="secondary-btn" onClick={() => navigate("/dashboard")}>
          Back to Dashboard
        </button>
      </div>
    </div>
  );
}
