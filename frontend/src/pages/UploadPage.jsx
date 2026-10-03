import React, { useState } from "react";
import { uploadTrafficFile } from "../services/api";

export default function UploadPage({ navigate, onSelectResult }) {
  const [selectedFile, setSelectedFile] = useState(null);
  const [dragActive, setDragActive] = useState(false);
  const [uploading, setUploading] = useState(false);
  const [currentStep, setCurrentStep] = useState(0);
  const [error, setError] = useState("");

  const steps = [
    "Uploading file to ThreatXAI backend...",
    "Parsing Layer 3/4 packet headers...",
    "Aggregating 5-tuple bidirectional flows...",
    "Calculating exact 78 statistical features...",
    "Evaluating with LightGBM Multiclass Model...",
    "Computing TreeExplainer SHAP attributions...",
    "Finalizing security assessment...",
  ];

  const handleDrag = (e) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.type === "dragenter" || e.type === "dragover") {
      setDragActive(true);
    } else if (e.type === "dragleave") {
      setDragActive(false);
    }
  };

  const handleDrop = (e) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(false);
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      validateAndSetFile(e.dataTransfer.files[0]);
    }
  };

  const handleChange = (e) => {
    if (e.target.files && e.target.files[0]) {
      validateAndSetFile(e.target.files[0]);
    }
  };

  const validateAndSetFile = (file) => {
    setError("");
    const lower = file.name.toLowerCase();
    const validExtensions = [".pcap", ".pcapng", ".csv"];
    const isValid = validExtensions.some((ext) => lower.endsWith(ext));

    if (!isValid) {
      setError("Unsupported file format. Please upload a .pcap, .pcapng, or a supported 78-feature .csv file.");
      setSelectedFile(null);
      return;
    }

    if (file.size > 50 * 1024 * 1024) {
      setError("File size exceeds 50 MB limit. Please upload a smaller traffic capture sample.");
      setSelectedFile(null);
      return;
    }

    setSelectedFile(file);
  };

  const handleAnalyze = async () => {
    if (!selectedFile) return;
    setError("");
    setUploading(true);
    setCurrentStep(0);

    // Realistic step progression timer
    const stepInterval = setInterval(() => {
      setCurrentStep((prev) => Math.min(prev + 1, steps.length - 2));
    }, 600);

    try {
      const results = await uploadTrafficFile(selectedFile);
      clearInterval(stepInterval);
      setCurrentStep(steps.length - 1);

      if (!results || results.length === 0) {
        throw new Error("No completed network flows could be extracted from the uploaded file.");
      }

      // Take the most significant/first flow result
      const topResult = results[0];
      topResult.batch_results = results;
      onSelectResult(topResult);

      setTimeout(() => {
        navigate("/results");
      }, 500);
    } catch (err) {
      clearInterval(stepInterval);
      setError(err.message || "Failed to analyze uploaded traffic file.");
      setUploading(false);
    }
  };

  return (
    <div className="upload-page">
      <div className="page-header">
        <div className="header-badge">OFFLINE TRAFFIC INGESTION</div>
        <h1 className="page-title">Upload & Analyze Network Traffic</h1>
        <p className="page-subtitle">
          Upload raw packet capture captures (.pcap, .pcapng) or model-compatible flow CSV files.
          The pipeline extracts 78 statistical metrics, classifies threats with LightGBM, and generates SHAP attributions.
        </p>
      </div>

      {error && <div className="alert-box error">⚠️ {error}</div>}

      <div className="upload-container">
        {/* Drag & Drop Zone */}
        {!uploading && (
          <div
            className={`drop-zone ${dragActive ? "active" : ""} ${selectedFile ? "has-file" : ""}`}
            onDragEnter={handleDrag}
            onDragLeave={handleDrag}
            onDragOver={handleDrag}
            onDrop={handleDrop}
          >
            <input
              type="file"
              id="file-upload"
              className="file-input-hidden"
              accept=".pcap,.pcapng,.csv"
              onChange={handleChange}
            />

            <div className="drop-zone-content">
              <span className="upload-icon">📁</span>
              <h3 className="drop-title">
                {selectedFile ? selectedFile.name : "Drag & Drop Network Traffic File"}
              </h3>
              <p className="drop-hint">
                Supported formats: <strong>.pcap</strong> • <strong>.pcapng</strong> • <strong>.csv</strong> (Max 50MB)
              </p>

              <label htmlFor="file-upload" className="choose-file-btn">
                {selectedFile ? "Change File" : "Choose File from Computer"}
              </label>
            </div>
          </div>
        )}

        {/* Selected File Details Box */}
        {selectedFile && !uploading && (
          <div className="selected-file-card">
            <div className="file-info-left">
              <span className="file-type-badge">
                {selectedFile.name.endsWith(".csv") ? "CSV FLOWS" : "PCAP CAPTURE"}
              </span>
              <div>
                <h4 className="file-name">{selectedFile.name}</h4>
                <span className="file-size">{(selectedFile.size / 1024).toFixed(1)} KB</span>
              </div>
            </div>

            <button className="analyze-action-btn" onClick={handleAnalyze}>
              ⚡ Analyze Traffic with LightGBM →
            </button>
          </div>
        )}

        {/* Multi-Step Pipeline Loading Animation */}
        {uploading && (
          <div className="pipeline-loading-card">
            <div className="pipeline-header">
              <div className="spinner large"></div>
              <h3>Analyzing Network Traffic...</h3>
              <p className="pipeline-status-text">{steps[currentStep]}</p>
            </div>

            <div className="pipeline-steps-list">
              {steps.map((s, idx) => {
                const isCompleted = currentStep > idx;
                const isCurrent = currentStep === idx;
                return (
                  <div
                    key={idx}
                    className={`pipeline-step-item ${isCompleted ? "completed" : ""} ${isCurrent ? "current" : ""}`}
                  >
                    <span className="step-indicator">
                      {isCompleted ? "✓" : isCurrent ? "●" : "○"}
                    </span>
                    <span className="step-text">{s}</span>
                  </div>
                );
              })}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
