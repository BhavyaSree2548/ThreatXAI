import React, { useState, useEffect, useRef } from "react";
import { fetchModelMetrics, fetchMonitorStatus, fetchMonitorEvents } from "../services/api";

export default function ChatbotAssistant({ currentResult = null, isFloating = false, onClose = null }) {
  const [messages, setMessages] = useState([
    {
      sender: "assistant",
      text: "Hello! I am the **ThreatXAI Security Assistant**. I can explain active predictions, analyze SHAP feature attributions, provide real-time monitoring telemetry, and answer questions about the CIC-IDS2017 LightGBM model.",
      time: new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }),
    },
  ]);
  const [input, setInput] = useState("");
  const [loading, setLoading] = useState(false);
  const [metrics, setMetrics] = useState(null);
  const [monitorData, setMonitorData] = useState(null);
  const messagesEndRef = useRef(null);

  useEffect(() => {
    fetchModelMetrics().then(setMetrics).catch(() => {});
    fetchMonitorStatus().then(setMonitorData).catch(() => {});
  }, []);

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages]);

  const quickPrompts = [
    currentResult ? "Why was this flow predicted as " + currentResult.prediction + "?" : "What dataset and model are used?",
    "What is the model accuracy and F1 score?",
    "What is the difference between DoS and DDoS?",
    "How does SHAP explainability work?",
    "What is the current live threat rate?",
  ];

  const handleSend = async (userText = input) => {
    const text = (userText || "").trim();
    if (!text) return;

    const time = new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
    setMessages((prev) => [...prev, { sender: "user", text, time }]);
    setInput("");
    setLoading(true);

    try {
      const reply = await generateAssistantResponse(text, currentResult, metrics);
      setMessages((prev) => [...prev, { sender: "assistant", text: reply, time: new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }) }]);
    } catch {
      setMessages((prev) => [
        ...prev,
        {
          sender: "assistant",
          text: "I encountered an error retrieving the requested telemetry. Please ensure the ThreatXAI backend is online.",
          time: new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }),
        },
      ]);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className={`chatbot-container ${isFloating ? "floating-chat-window" : "embedded-chat-window"}`}>
      <div className="chat-header">
        <div className="chat-header-info">
          <span className="bot-avatar">🤖</span>
          <div>
            <h4 className="chat-title">ThreatXAI SOC Assistant</h4>
            <span className="chat-status">
              <span className="online-pulse"></span> Context-Aware XAI Engine
            </span>
          </div>
        </div>
        {isFloating && onClose && (
          <button className="chat-close-btn" onClick={onClose} aria-label="Close Chat">
            ✕
          </button>
        )}
      </div>

      {/* Active Context Banner if Result Loaded */}
      {currentResult && (
        <div className="chat-context-pill">
          <span className="pill-dot"></span>
          Active Context: <strong>{currentResult.prediction}</strong> ({(currentResult.confidence * 100).toFixed(1)}% Conf)
        </div>
      )}

      {/* Messages Feed */}
      <div className="chat-messages-area">
        {messages.map((msg, i) => (
          <div key={i} className={`chat-bubble-wrap ${msg.sender === "user" ? "user-wrap" : "bot-wrap"}`}>
            <div className={`chat-bubble ${msg.sender === "user" ? "user-bubble" : "bot-bubble"}`}>
              <div className="bubble-content" dangerouslySetInnerHTML={{ __html: formatMarkdown(msg.text) }} />
              <span className="bubble-time">{msg.time}</span>
            </div>
          </div>
        ))}
        {loading && (
          <div className="chat-bubble-wrap bot-wrap">
            <div className="chat-bubble bot-bubble typing-bubble">
              <span className="typing-dot"></span>
              <span className="typing-dot"></span>
              <span className="typing-dot"></span>
            </div>
          </div>
        )}
        <div ref={messagesEndRef} />
      </div>

      {/* Quick Prompts */}
      <div className="quick-prompts-bar">
        {quickPrompts.slice(0, 3).map((p, idx) => (
          <button key={idx} className="quick-prompt-chip" onClick={() => handleSend(p)}>
            {p}
          </button>
        ))}
      </div>

      {/* Input Form */}
      <form
        className="chat-input-form"
        onSubmit={(e) => {
          e.preventDefault();
          handleSend();
        }}
      >
        <input
          type="text"
          className="chat-input"
          placeholder="Ask about threats, SHAP factors, metrics, or live monitoring..."
          value={input}
          onChange={(e) => setInput(e.target.value)}
        />
        <button type="submit" className="chat-send-btn" disabled={loading || !input.trim()}>
          ➤
        </button>
      </form>
    </div>
  );
}

// Response generator incorporating authentic project metrics and live telemetry
async function generateAssistantResponse(query, currentResult, metrics) {
  const q = query.toLowerCase();

  // 1. Current Prediction / Active Result Questions
  if (currentResult && (q.includes("why") || q.includes("explain") || q.includes("classify") || q.includes("prediction") || q.includes("predicted"))) {
    const topSupporting = (currentResult.supporting_features || []).slice(0, 3).map((f) => `**${f.feature.trim()}** (SHAP: +${f.shap_value.toFixed(4)}, Val: ${f.value})`).join(", ");
    const topOpposing = (currentResult.opposing_features || []).slice(0, 2).map((f) => `**${f.feature.trim()}** (SHAP: ${f.shap_value.toFixed(4)})`).join(", ");

    return (
      `**Model Decision Analysis:**\n\n` +
      `This network flow was classified as **${currentResult.prediction}** with **${(currentResult.confidence * 100).toFixed(2)}% confidence** by the trained LightGBM model.\n\n` +
      `**Key Contributing SHAP Factors:**\n` +
      `• **Top Supporting Features:** ${topSupporting || "None"}\n` +
      `• **Opposing Features:** ${topOpposing || "None"}\n\n` +
      `**Summary:** ${currentResult.summary || "Flow characteristics align with standard baseline behavior."}`
    );
  }

  // 2. Metrics & Model Performance Questions
  if (q.includes("accuracy") || q.includes("precision") || q.includes("recall") || q.includes("f1") || q.includes("metric") || q.includes("performance")) {
    if (metrics?.test_metrics) {
      const tm = metrics.test_metrics;
      return (
        `**Trained LightGBM Model Evaluation (CIC-IDS2017 Test Set):**\n\n` +
        `• **Test Accuracy:** ${(tm.accuracy * 100).toFixed(2)}%\n` +
        `• **Macro Precision:** ${(tm.macro_precision * 100).toFixed(2)}%\n` +
        `• **Macro Recall:** ${(tm.macro_recall * 100).toFixed(2)}%\n` +
        `• **Macro F1-Score:** ${(tm.macro_f1 * 100).toFixed(2)}%\n` +
        `• **Weighted F1-Score:** ${(tm.weighted_f1 * 100).toFixed(2)}%\n\n` +
        `Evaluated across all 15 classes from the Canadian Institute for Cybersecurity dataset.`
      );
    }
    return "Model evaluation metrics are currently unavailable from the backend service.";
  }

  // 3. Project Architecture Questions
  if (q.includes("dataset") || q.includes("features") || q.includes("model") || q.includes("lightgbm") || q.includes("classes")) {
    return (
      `**ThreatXAI System Specifications:**\n\n` +
      `• **Dataset:** CIC-IDS2017 (Canadian Institute for Cybersecurity)\n` +
      `• **Model:** LightGBM Gradient Boosted Decision Trees (15 multiclass output nodes)\n` +
      `• **Features:** Exact 78 statistical network flow metrics (inter-arrival times, packet lengths, TCP flags, subflows, active/idle rates)\n` +
      `• **Explainability:** SHAP (SHapley Additive exPlanations) TreeExplainer computing exact per-feature attributions\n` +
      `• **Packet Capture:** Npcap + Scapy Layer 3/4 flow aggregator with real-time 5-tuple tracking.`
    );
  }

  // 4. Live Monitoring Telemetry Questions
  if (q.includes("live") || q.includes("monitoring") || q.includes("threat rate") || q.includes("active flows") || q.includes("attacks detected")) {
    try {
      const st = await fetchMonitorStatus();
      const events = await fetchMonitorEvents(20);
      const threatCount = events.filter((e) => e.status === "MALICIOUS").length;
      return (
        `**Live Monitoring Status:**\n\n` +
        `• **Engine State:** ${st.status}\n` +
        `• **Active Interface:** ${st.interface || "None selected"}\n` +
        `• **Active In-Flight Flows:** ${st.active_flows}\n` +
        `• **Total Processed Flows:** ${st.processed_flows}\n` +
        `• **Normal Benign Flows:** ${st.normal_flows}\n` +
        `• **Threats Detected:** ${st.threats_detected}\n` +
        `• **Current Threat Rate:** ${st.processed_flows > 0 ? ((st.threats_detected / st.processed_flows) * 100).toFixed(1) : "0.0"}%`
      );
    } catch {
      return `Real-time monitoring is currently configured for Windows Npcap kernel packet capture across 37 network adapters.`;
    }
  }

  // 5. Cybersecurity Knowledge Base
  if (q.includes("ddos") || q.includes("dos")) {
    return (
      `**Denial of Service (DoS vs DDoS):**\n\n` +
      `• **DoS:** A single host attempts to exhaust target server resources (CPU, RAM, socket queues) via packet floods or resource-heavy requests (e.g. DoS Hulk, DoS Slowhttptest).\n` +
      `• **DDoS:** A distributed network of compromised machines (botnet) simultaneously floods the target, causing massive bandwidth exhaustion.\n\n` +
      `ThreatXAI detects DDoS via anomalous flow duration, forward packet inter-arrival times, and subflow packet counts.`
    );
  }

  if (q.includes("portscan") || q.includes("port scan")) {
    return (
      `**PortScan Reconnaissance:**\n\n` +
      `An adversary sends TCP SYN packets across multiple destination ports to determine open services and potential vulnerabilities.\n\n` +
      `ThreatXAI identifies PortScans by detecting rapid, short-lived flows with minimal backward packet responses and low flow durations.`
    );
  }

  if (q.includes("brute force") || q.includes("ssh-patator") || q.includes("patator")) {
    return (
      `**Brute Force Attacks (SSH / FTP Patator):**\n\n` +
      `Automated tools attempting rapid dictionary-based password guessing against SSH (port 22) or FTP (port 21).\n\n` +
      `ThreatXAI identifies these attacks through sustained burst connection patterns and characteristic packet length signatures.`
    );
  }

  if (q.includes("sql") || q.includes("xss") || q.includes("web attack")) {
    return (
      `**Web Application Attacks:**\n\n` +
      `• **SQL Injection:** Malicious SQL code injected into input fields to bypass authentication or extract database records.\n` +
      `• **XSS (Cross-Site Scripting):** Malicious client-side JavaScript injected to execute in other users' browsers.\n\n` +
      `ThreatXAI monitors HTTP payload features, packet sizes, and header lengths to identify web attack patterns.`
    );
  }

  if (q.includes("shap") || q.includes("xai") || q.includes("explainable")) {
    return (
      `**SHAP (SHapley Additive exPlanations):**\n\n` +
      `SHAP is a cooperative game theoretic framework that computes the exact marginal contribution of each input feature to the machine learning prediction.\n\n` +
      `In ThreatXAI, **TreeExplainer** attributes exact Shapley values to each of the 78 features, allowing security analysts to understand precisely *why* an alert was triggered.`
    );
  }

  // Default Fallback
  return (
    `I can assist you with:\n\n` +
    `• Explaining the active prediction result and its SHAP factors\n` +
    `• Reviewing model performance metrics (Accuracy, F1-score, Precision)\n` +
    `• Explaining attack types (DDoS, DoS Hulk, PortScan, SSH-Patator, Web Attacks)\n` +
    `• Live monitoring status and runtime statistics\n\n` +
    `Feel free to ask a specific question!`
  );
}

function formatMarkdown(text) {
  if (!text) return "";
  return text
    .replace(/\*\*(.*?)\*\*/g, "<strong>$1</strong>")
    .replace(/\*(.*?)\*/g, "<em>$1</em>")
    .replace(/• (.*?)(?=\n|$)/g, "<li>$1</li>")
    .replace(/\n\n/g, "<br/><br/>")
    .replace(/\n/g, "<br/>");
}
