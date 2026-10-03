import React, { useState, useEffect } from "react";
import { fetchMonitorEvents } from "../services/api";
import ShapVisualizer from "../components/ShapVisualizer";
import { generateSecurityReport } from "../services/pdfGenerator";

export default function HistoryPage({ navigate, onSelectResult }) {
  const [events, setEvents] = useState([]);
  const [loading, setLoading] = useState(true);
  const [searchTerm, setSearchTerm] = useState("");
  const [statusFilter, setStatusFilter] = useState("ALL");
  const [selectedEvent, setSelectedEvent] = useState(null);

  useEffect(() => {
    fetchMonitorEvents(100)
      .then((data) => {
        setEvents(data || []);
        setLoading(false);
      })
      .catch(() => {
        setLoading(false);
      });
  }, []);

  const filteredEvents = events.filter((ev) => {
    const term = searchTerm.toLowerCase();
    const matchesSearch =
      ev.id.toLowerCase().includes(term) ||
      ev.prediction.toLowerCase().includes(term) ||
      ev.flow.source_ip.includes(term) ||
      ev.flow.destination_ip.includes(term) ||
      String(ev.flow.destination_port).includes(term) ||
      String(ev.flow.source_port).includes(term);

    const matchesStatus =
      statusFilter === "ALL" ||
      (statusFilter === "MALICIOUS" && ev.status === "MALICIOUS") ||
      (statusFilter === "BENIGN" && ev.status === "BENIGN");

    return matchesSearch && matchesStatus;
  });

  const handleExportCSV = () => {
    if (filteredEvents.length === 0) return;
    const rows = [
      ["Event ID", "Timestamp", "Source IP", "Source Port", "Destination IP", "Destination Port", "Protocol", "Prediction", "Status", "Confidence"],
      ...filteredEvents.map((e) => [
        e.id,
        e.timestamp,
        e.flow.source_ip,
        e.flow.source_port,
        e.flow.destination_ip,
        e.flow.destination_port,
        e.flow.protocol,
        e.prediction,
        e.status,
        (e.confidence * 100).toFixed(2) + "%",
      ]),
    ];

    const csvContent = "data:text/csv;charset=utf-8," + rows.map((r) => r.join(",")).join("\n");
    const encodedUri = encodeURI(csvContent);
    const link = document.createElement("a");
    link.setAttribute("href", encodedUri);
    link.setAttribute("download", `ThreatXAI_History_${Date.now()}.csv`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  return (
    <div className="history-page">
      <div className="page-header">
        <div className="header-badge">AUDIT TRAIL & TELEMETRY LOGS</div>
        <h1 className="page-title">Threat History & Flow Logs</h1>
        <p className="page-subtitle">
          Search, filter, and inspect historical network flows evaluated by the LightGBM intrusion detection model.
        </p>
      </div>

      {/* Filter & Search Bar */}
      <div className="history-filter-bar">
        <div className="search-box">
          <span className="search-icon">🔍</span>
          <input
            type="text"
            className="search-input"
            placeholder="Search by IP, Port, Attack Type, or Flow ID..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
          />
          {searchTerm && (
            <button className="clear-search-btn" onClick={() => setSearchTerm("")}>✕</button>
          )}
        </div>

        <div className="filter-group">
          <button
            className={`filter-btn ${statusFilter === "ALL" ? "active" : ""}`}
            onClick={() => setStatusFilter("ALL")}
          >
            All Logs ({events.length})
          </button>
          <button
            className={`filter-btn ${statusFilter === "MALICIOUS" ? "active threat-active" : ""}`}
            onClick={() => setStatusFilter("MALICIOUS")}
          >
            🚨 Threats Only ({events.filter((e) => e.status === "MALICIOUS").length})
          </button>
          <button
            className={`filter-btn ${statusFilter === "BENIGN" ? "active benign-active" : ""}`}
            onClick={() => setStatusFilter("BENIGN")}
          >
            ✓ Benign ({events.filter((e) => e.status === "BENIGN").length})
          </button>

          <button className="export-btn" onClick={handleExportCSV} disabled={filteredEvents.length === 0}>
            ⬇️ Export CSV
          </button>
        </div>
      </div>

      {/* History Data Table */}
      {loading ? (
        <div className="loading-container">
          <div className="spinner"></div>
          <p>Loading threat logs...</p>
        </div>
      ) : filteredEvents.length === 0 ? (
        <div className="empty-history-card">
          <span className="empty-icon">📁</span>
          <h3>No matching flow records found</h3>
          <p>Start live network monitoring or analyze sample traffic to populate historical threat logs.</p>
        </div>
      ) : (
        <div className="table-responsive">
          <table className="events-table history-table">
            <thead>
              <tr>
                <th>FLOW ID</th>
                <th>TIME</th>
                <th>SOURCE</th>
                <th>DESTINATION</th>
                <th>PROTO</th>
                <th>PREDICTION</th>
                <th>STATUS</th>
                <th>CONFIDENCE</th>
                <th>ACTIONS</th>
              </tr>
            </thead>
            <tbody>
              {filteredEvents.map((ev) => {
                const isMal = ev.status === "MALICIOUS";
                return (
                  <tr
                    key={ev.id}
                    className={`event-row ${isMal ? "malicious-row" : "benign-row"}`}
                    onClick={() => setSelectedEvent(ev)}
                  >
                    <td className="id-col">#{ev.id}</td>
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

      {/* Modal for SHAP Inspection */}
      {selectedEvent && (
        <div className="modal-backdrop" onClick={() => setSelectedEvent(null)}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <div className="modal-title-group">
                <span className="modal-icon">{selectedEvent.status === "MALICIOUS" ? "🚨" : "✓"}</span>
                <div>
                  <h3>Historical Flow #{selectedEvent.id}: {selectedEvent.prediction}</h3>
                  <p>
                    {selectedEvent.flow.protocol} {selectedEvent.flow.source_ip}:{selectedEvent.flow.source_port} ➔ {selectedEvent.flow.destination_ip}:{selectedEvent.flow.destination_port} | Timestamp: {selectedEvent.timestamp}
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
            </div>

            <div className="modal-footer">
              <button className="pdf-download-btn" onClick={() => generateSecurityReport(selectedEvent)}>
                📑 Download PDF Report
              </button>
              <button
                className="primary-btn"
                onClick={() => {
                  onSelectResult(selectedEvent);
                  navigate("/results");
                }}
              >
                View Full Results Page →
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
