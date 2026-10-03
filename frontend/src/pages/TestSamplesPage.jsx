import React, { useState, useEffect } from "react";
import { fetchSamplesCatalog } from "../services/api";

export default function TestSamplesPage({ navigate }) {
  const [catalog, setCatalog] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    fetchSamplesCatalog()
      .then((data) => {
        setCatalog(data);
        setLoading(false);
      })
      .catch((err) => {
        setError(err.message || "Failed to load test samples catalog.");
        setLoading(false);
      });
  }, []);

  return (
    <div className="test-samples-page">
      <div className="page-header">
        <div className="header-badge">CIC-IDS2017 BENCHMARK SUITE</div>
        <h1 className="page-title">Download Attack & Traffic Samples</h1>
        <p className="page-subtitle">
          Explore and download authentic Canadian Institute for Cybersecurity (CIC-IDS2017) network traffic flow samples.
          Download a sample CSV below and upload it via the Upload Traffic page for real-time LightGBM and SHAP analysis.
        </p>
      </div>

      {error && <div className="alert-box error">⚠️ {error}</div>}

      {loading ? (
        <div className="loading-container">
          <div className="spinner"></div>
          <p>Loading test attack samples catalog...</p>
        </div>
      ) : (
        <div className="samples-grid">
          {catalog
            .filter((sample) => !["dos-hulk", "ssh-patator", "web-attack"].includes(sample.id))
            .map((sample) => {
              const isBenign = sample.expected_class === "BENIGN";

            return (
              <div
                key={sample.id}
                className={`sample-card ${isBenign ? "benign-sample-card" : "attack-sample-card"}`}
              >
                <div className="sample-card-header">
                  <div className="sample-icon-title">
                    <div>
                      <h3 className="sample-name">{sample.name}</h3>
                      <span className="sample-category">{sample.category}</span>
                    </div>
                  </div>
                  <span className={`sample-class-pill ${isBenign ? "benign" : "malicious"}`}>
                    {sample.expected_class}
                  </span>
                </div>

                {sample.description && sample.description !== sample.category && (
                  <p className="sample-desc">{sample.description}</p>
                )}

                <div className="sample-meta-box">
                  <div className="meta-item">
                    <span className="meta-label">Dataset Source:</span>
                    <span className="meta-val">{sample.external_dataset_source || "CIC-IDS2017"}</span>
                  </div>
                  <div className="meta-item">
                    <span className="meta-label">Feature Schema:</span>
                    <span className="meta-val">78 Exact Metrics</span>
                  </div>
                </div>


                <div className="sample-card-actions">
                  {sample.csv_available ? (
                    <a
                      href={sample.csv_file}
                      download={`cic-ids2017-${sample.id}-sample.csv`}
                      className="download-btn"
                    >
                      ⬇️ Download Sample CSV
                    </a>
                  ) : (
                    <span className="unavailable-pill" title="Part of the external CIC-IDS2017 benchmark dataset">
                      CSV: External Dataset
                    </span>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      )}

      {/* Action to proceed to Upload */}
      <div className="samples-cta-card" style={{ marginTop: "2rem", padding: "1.5rem", background: "rgba(30, 41, 59, 0.6)", borderRadius: "12px", border: "1px solid rgba(56, 189, 248, 0.2)", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
        <div>
          <h3 style={{ margin: "0 0 0.5rem 0", color: "#f8fafc" }}>Ready to Analyze a Sample?</h3>
          <p style={{ margin: 0, color: "#94a3b8", fontSize: "0.9rem" }}>Upload any downloaded sample CSV or PCAP file into the real-time AI ingestion pipeline.</p>
        </div>
        <button className="primary-btn" onClick={() => navigate("/upload")}>
          📂 Go to Upload Traffic →
        </button>
      </div>


      {/* Dataset Attribution Note */}
      <div className="dataset-attribution-card">
        <span className="info-icon">ℹ️</span>
        <div className="attribution-text">
          <h4>Authentic CIC-IDS2017 Dataset Governance</h4>
          <p>
            All test flows are derived from the official Canadian Institute for Cybersecurity (CIC-IDS2017) evaluation dataset.
            Predictions are generated dynamically by the pre-trained LightGBM booster without fabricated values or hardcoded classifications.
          </p>
        </div>
      </div>
    </div>
  );
}
