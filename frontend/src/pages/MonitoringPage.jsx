import React, { useState, useEffect, useRef } from "react";
import {
  fetchInterfaces,
  fetchMonitorStatus,
  startMonitoring,
  stopMonitoring,
  fetchMonitorEvents,
  createMonitorWebSocket,
} from "../services/api";
import ShapVisualizer from "../components/ShapVisualizer";
import ClassProbabilitiesChart from "../components/ClassProbabilitiesChart";
import { generateSecurityReport } from "../services/pdfGenerator";

export default function MonitoringPage({ navigate, onSelectResult }) {
  const [interfaces, setInterfaces] = useState([]);
  const [selectedInterface, setSelectedInterface] = useState("");
  const [status, setStatus] = useState("STOPPED");
  const [activeFlows, setActiveFlows] = useState(0);
  const [processedFlows, setProcessedFlows] = useState(0);
  const [normalFlows, setNormalFlows] = useState(0);
  const [threatsDetected, setThreatsDetected] = useState(0);
  const [events, setEvents] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [selectedEvent, setSelectedEvent] = useState(null);
  const [recentAlert, setRecentAlert] = useState(null);
  const [sessionStartTime, setSessionStartTime] = useState(null);
  const [elapsedSeconds, setElapsedSeconds] = useState(0);

  const wsRef = useRef(null);

  // Load available interfaces and status
  useEffect(() => {
    let mounted = true;
    fetchInterfaces()
      .then((ifaces) => {
        if (mounted) {
          setInterfaces(ifaces);
          if (ifaces.length > 0 && !selectedInterface) {
            // Default to Wi-Fi or first active interface
            const wifi = ifaces.find((i) => i.name.toLowerCase().includes("wi-fi") || i.name.toLowerCase().includes("wireless"));
            setSelectedInterface(wifi ? wifi.name : ifaces[0].name);
          }
        }
      })
      .catch(() => {});

    fetchMonitorStatus()
      .then((st) => {
        if (mounted) {
          setStatus(st.status);
          setActiveFlows(st.active_flows || 0);
          setProcessedFlows(st.processed_flows || 0);
          setNormalFlows(st.normal_flows || 0);
          setThreatsDetected(st.threats_detected || 0);
          if (st.interface) setSelectedInterface(st.interface);
        }
      })
      .catch(() => {});

    fetchMonitorEvents(50)
      .then((evList) => {
        if (mounted && evList.length > 0) setEvents(evList);
      })
      .catch(() => {});

    return () => {
      mounted = false;
    };
  }, []);

  // Connect WebSocket for live telemetry streaming
  useEffect(() => {
    const ws = createMonitorWebSocket(
      (data) => {
        if (data.type === "INIT_STATE") {
          setStatus(data.status.status);
          setActiveFlows(data.status.active_flows || 0);
          setProcessedFlows(data.status.processed_flows || 0);
          setNormalFlows(data.status.normal_flows || 0);
          setThreatsDetected(data.status.threats_detected || 0);
          if (data.events) setEvents(data.events);
        } else if (data.type === "MONITOR_STATUS") {
          setStatus(data.status.status);
          setActiveFlows(data.status.active_flows || 0);
          setProcessedFlows(data.status.processed_flows || 0);
          setNormalFlows(data.status.normal_flows || 0);
          setThreatsDetected(data.status.threats_detected || 0);
        } else if (data.type === "MONITOR_EVENT") {
          setEvents((prev) => [data.event, ...prev.slice(0, 99)]);
          if (data.event.status === "MALICIOUS") {
            setRecentAlert(data.event);
          }
        }
      },
      (err) => console.log("WebSocket note:", err),
      () => console.log("WebSocket closed")
    );

    wsRef.current = ws;
    return () => {
      ws.close();
    };
  }, []);

  // Session Duration Timer
  useEffect(() => {
    let timer = null;
    if (status === "RUNNING") {
      if (!sessionStartTime) setSessionStartTime(Date.now());
      timer = setInterval(() => {
        setElapsedSeconds((prev) => prev + 1);
      }, 1000);
    } else {
      setSessionStartTime(null);
    }
    return () => {
      if (timer) clearInterval(timer);
    };
  }, [status]);

  const handleStart = async () => {
    if (!selectedInterface) {
      setError("Please select a valid network interface.");
      return;
    }
    setError("");
    setLoading(true);
    try {
      const res = await startMonitoring(selectedInterface);
      setStatus(res.status);
      setElapsedSeconds(0);
    } catch (err) {
      setError(err.message || "Failed to start real-time monitoring.");
    } finally {
      setLoading(false);
    }
  };

  const handleStop = async () => {
    setLoading(true);
    try {
      const res = await stopMonitoring();
      setStatus(res.status);
    } catch (err) {
      setError(err.message || "Failed to stop monitoring.");
    } finally {
      setLoading(false);
    }
  };

  const isRunning = status === "RUNNING";
  const threatRate = processedFlows > 0 ? ((threatsDetected / processedFlows) * 100).toFixed(1) : "0.0";

  // Attack distribution map
  const attackCounts = {};
  events.forEach((e) => {
    if (e.status === "MALICIOUS") {
      attackCounts[e.prediction] = (attackCounts[e.prediction] || 0) + 1;
    }
  });

  const formatDuration = (sec) => {
    const m = Math.floor(sec / 60);
    const s = sec % 60;
    return `${m.toString().padStart(2, "0")}:${s.toString().padStart(2, "0")}`;
  };

  return (
    <div className="monitoring-page">
      {/* Top Header & Interface Selection Bar */}
      <div className="monitoring-control-bar">
        <div className="control-left">
          <div className={`live-pulse-badge ${isRunning ? "running" : "stopped"}`}>
            <span className="pulse-circle"></span>
            <span>{isRunning ? `LIVE MONITORING (${selectedInterface || "Active"})` : "MONITORING IDLE"}</span>
          </div>
          <span className="engine-tag">Npcap Scapy Kernel Engine</span>
        </div>

        <div className="control-right">
          <div className="interface-select-wrap">
            <label className="select-label">Interface:</label>
            <select
              className="interface-dropdown"
              value={selectedInterface}
              onChange={(e) => setSelectedInterface(e.target.value)}
              disabled={isRunning}
            >
              {interfaces.map((iface) => (
                <option key={iface.id || iface.name} value={iface.name}>
                  {iface.name} ({iface.ips?.[0] || iface.description?.substring(0, 24) || "Adapter"})
                </option>
              ))}
            </select>
          </div>

          {isRunning ? (
            <button className="stop-monitor-btn" onClick={handleStop} disabled={loading}>
              ⏹ Stop Monitoring
            </button>
          ) : (
            <button className="start-monitor-btn" onClick={handleStart} disabled={loading}>
              ▶ Start Live Monitoring
            </button>
          )}
        </div>
      </div>

      {error && <div className="alert-box error">⚠️ {error}</div>}

      {/* DISMISSIBLE THREAT ALERT BANNER */}
      {recentAlert && (
        <div className="threat-alert-toast">
          <div className="alert-toast-left">
            <span className="toast-alarm-icon">🚨</span>
            <div>
              <div className="toast-title">REAL-TIME THREAT DETECTED: {recentAlert.prediction}</div>
              <div className="toast-sub">
                Source: {recentAlert.flow.source_ip}:{recentAlert.flow.source_port} ➔ Dest: {recentAlert.flow.destination_ip}:{recentAlert.flow.destination_port} | Confidence: {(recentAlert.confidence * 100).toFixed(1)}%
              </div>
            </div>
          </div>
          <div className="alert-toast-actions">
            <button
              className="inspect-alert-btn"
              onClick={() => {
                onSelectResult(recentAlert);
                navigate("/results");
              }}
            >
              Inspect SHAP →
            </button>
            <button className="dismiss-toast-btn" onClick={() => setRecentAlert(null)}>
              ✕
            </button>
          </div>
        </div>
      )}

      {/* LIVE STATISTICS CARDS */}
      <div className="monitoring-stats-grid">
        <div className="stat-card">
          <span className="stat-label">TOTAL PROCESSED FLOWS</span>
          <span className="stat-value">{processedFlows}</span>
          <span className="stat-sub">Completed 5-tuple flows</span>
        </div>

        <div className="stat-card">
          <span className="stat-label">ACTIVE IN-FLIGHT FLOWS</span>
          <span className="stat-value accent-cyan">{activeFlows}</span>
          <span className="stat-sub">Aggregating packets</span>
        </div>

        <div className="stat-card">
          <span className="stat-label">NORMAL BENIGN FLOWS</span>
          <span className="stat-value accent-green">{normalFlows}</span>
          <span className="stat-sub">Baseline traffic</span>
        </div>

        <div className="stat-card">
          <span className="stat-label">THREATS DETECTED</span>
          <span className={`stat-value ${threatsDetected > 0 ? "accent-red" : ""}`}>{threatsDetected}</span>
          <span className="stat-sub">Malicious alerts</span>
        </div>

        <div className="stat-card">
          <span className="stat-label">THREAT RATE</span>
          <span className={`stat-value ${parseFloat(threatRate) > 0 ? "accent-amber" : ""}`}>{threatRate}%</span>
          <span className="stat-sub">Malicious / Total</span>
        </div>

        <div className="stat-card">
          <span className="stat-label">MONITORING DURATION</span>
          <span className="stat-value">{formatDuration(elapsedSeconds)}</span>
          <span className="stat-sub">Active session time</span>
        </div>
      </div>

      {/* LIVE CHARTS SECTION */}
      <div className="monitoring-charts-grid">
        {/* Classification Split Bar */}
        <div className="chart-panel">
          <h4 className="chart-title">Traffic Classification Breakdown</h4>
          <div className="classification-split-bar">
            <div
              className="split-segment benign-seg"
              style={{ width: `${processedFlows > 0 ? (normalFlows / processedFlows) * 100 : 100}%` }}
              title={`Benign: ${normalFlows}`}
            ></div>
            <div
              className="split-segment threat-seg"
              style={{ width: `${processedFlows > 0 ? (threatsDetected / processedFlows) * 100 : 0}%` }}
              title={`Threats: ${threatsDetected}`}
            ></div>
          </div>
          <div className="chart-legend">
            <span className="legend-item"><span className="dot benign"></span> Benign ({normalFlows})</span>
            <span className="legend-item"><span className="dot malicious"></span> Malicious ({threatsDetected})</span>
          </div>
        </div>

        {/* Attack Distribution */}
        <div className="chart-panel">
          <h4 className="chart-title">Attack Class Distribution</h4>
          {Object.keys(attackCounts).length > 0 ? (
            <div className="attack-tags-list">
              {Object.entries(attackCounts).map(([atk, count]) => (
                <div key={atk} className="attack-dist-item">
                  <span className="atk-name">{atk}</span>
                  <span className="atk-count-badge">{count}</span>
                </div>
              ))}
            </div>
          ) : (
            <p className="no-threats-note">✓ No malicious threat signatures detected in this monitoring session.</p>
          )}
        </div>
      </div>

      {/* LIVE EVENT FEED TABLE */}
      <div className="event-feed-card">
        <div className="event-feed-header">
          <div>
            <h3 className="event-feed-title">Live Flow Event Stream</h3>
            <p className="event-feed-subtitle">Real-time evaluations by LightGBM model with instant SHAP attribution</p>
          </div>
          <div className="feed-actions">
            <span className="event-counter">{events.length} Events Captured</span>
          </div>
        </div>

        {events.length === 0 ? (
          <div className="empty-feed-state">
            <div className="radar-spinner"></div>
            <p>Waiting for completed network flows on {selectedInterface || "selected interface"}...</p>
            <span className="empty-sub">Send network traffic (e.g. browse web, DNS queries) to see real-time classifications.</span>
          </div>
        ) : (
          <div className="table-responsive">
            <table className="events-table">
              <thead>
                <tr>
                  <th>TIME</th>
                  <th>SOURCE IP : PORT</th>
                  <th>DESTINATION IP : PORT</th>
                  <th>PROTO</th>
                  <th>PREDICTION</th>
                  <th>STATUS</th>
                  <th>CONFIDENCE</th>
                  <th>ACTION</th>
                </tr>
              </thead>
              <tbody>
                {events.map((ev) => {
                  const isMal = ev.status === "MALICIOUS";
                  return (
                    <tr
                      key={ev.id}
                      className={`event-row ${isMal ? "malicious-row" : "benign-row"}`}
                      onClick={() => setSelectedEvent(ev)}
                    >
                      <td className="time-col">{ev.timestamp}</td>
                      <td className="ip-col">{ev.flow.source_ip}:{ev.flow.source_port}</td>
                      <td className="ip-col">{ev.flow.destination_ip}:{ev.flow.destination_port}</td>
                      <td className="proto-col">{ev.flow.protocol}</td>
                      <td className="pred-col">
                        <span className={`pred-pill ${isMal ? "threat" : "benign"}`}>{ev.prediction}</span>
                      </td>
                      <td className="status-col">
                        <span className={`status-badge ${isMal ? "threat" : "benign"}`}>{ev.status}</span>
                      </td>
                      <td className="conf-col">{(ev.confidence * 100).toFixed(1)}%</td>
                      <td className="action-col">
                        <button
                          className="inspect-link-btn"
                          onClick={(e) => {
                            e.stopPropagation();
                            setSelectedEvent(ev);
                          }}
                        >
                          Inspect SHAP
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* MODAL: EVENT SHAP INSPECTION MODAL */}
      {selectedEvent && (
        <div className="modal-backdrop" onClick={() => setSelectedEvent(null)}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <div className="modal-title-group">
                <span className="modal-icon">{selectedEvent.status === "MALICIOUS" ? "🚨" : "✓"}</span>
                <div>
                  <h3>Flow #{selectedEvent.id}: {selectedEvent.prediction}</h3>
                  <p>
                    {selectedEvent.flow.protocol} {selectedEvent.flow.source_ip}:{selectedEvent.flow.source_port} ➔ {selectedEvent.flow.destination_ip}:{selectedEvent.flow.destination_port}
                  </p>
                </div>
              </div>
              <button className="modal-close-btn" onClick={() => setSelectedEvent(null)}>✕</button>
            </div>

            <div className="modal-body">
              <ShapVisualizer
                explanation={selectedEvent.explanation}
                supporting={selectedEvent.supporting_features}
                opposing={selectedEvent.opposing_features}
                summary={selectedEvent.summary}
              />

              <ClassProbabilitiesChart
                probabilities={selectedEvent.class_probabilities}
                predictedClass={selectedEvent.prediction}
              />
            </div>

            <div className="modal-footer">
              <button className="pdf-download-btn" onClick={() => generateSecurityReport(selectedEvent)}>
                📑 Export PDF Report
              </button>
              <button
                className="primary-btn"
                onClick={() => {
                  onSelectResult(selectedEvent);
                  navigate("/results");
                }}
              >
                Open in Full Results Screen →
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
