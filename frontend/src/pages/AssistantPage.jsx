import React from "react";
import ChatbotAssistant from "../components/ChatbotAssistant";

export default function AssistantPage({ activeResult }) {
  return (
    <div className="assistant-page">
      <div className="page-header">
        <div className="header-badge">INTELLIGENT SOC COPILOT</div>
        <h1 className="page-title">ThreatXAI AI Security Assistant</h1>
        <p className="page-subtitle">
          Interactive context-aware assistant capable of explaining model decisions, breaking down SHAP feature attributions,
          reporting real-time telemetry, and answering cybersecurity questions.
        </p>
      </div>

      <div className="assistant-layout">
        <div className="assistant-main-col">
          <ChatbotAssistant currentResult={activeResult} isFloating={false} />
        </div>

        <div className="assistant-sidebar-col">
          <div className="assistant-guide-card">
            <h4>💡 Recommended Query Topics</h4>
            <ul className="guide-list">
              <li><strong>Prediction Reasoning:</strong> "Why was this flow flagged as malicious?"</li>
              <li><strong>SHAP Attributions:</strong> "Which features contributed most to the DDoS verdict?"</li>
              <li><strong>Model Metrics:</strong> "What is the LightGBM accuracy and macro F1 score?"</li>
              <li><strong>Attack Knowledge:</strong> "Explain how DoS Hulk differs from standard HTTP traffic."</li>
              <li><strong>Live Telemetry:</strong> "How many threats have been detected in this monitoring session?"</li>
            </ul>
          </div>

          <div className="assistant-guide-card">
            <h4>🛡️ Model Governance</h4>
            <p className="guide-text">
              The assistant communicates directly with the FastAPI backend to query real-time status and metric artifacts.
              Answers are grounded strictly in the CIC-IDS2017 feature schema and SHAP explanation math.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}
