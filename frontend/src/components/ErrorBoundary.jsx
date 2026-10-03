import React from "react";

export default class ErrorBoundary extends React.Component {
  constructor(props) {
    super(props);
    this.state = { hasError: false, error: null };
  }

  static getDerivedStateFromError(error) {
    return { hasError: true, error };
  }

  componentDidCatch(error, errorInfo) {
    console.error("ThreatXAI ErrorBoundary caught an error:", error, errorInfo);
  }

  render() {
    if (this.state.hasError) {
      return (
        <div style={{
          minHeight: "100vh",
          display: "flex",
          flexDirection: "column",
          alignItems: "center",
          justifyContent: "center",
          background: "#0b0f19",
          color: "#f8fafc",
          fontFamily: "Inter, sans-serif",
          padding: "2rem"
        }}>
          <div style={{
            maxWidth: "600px",
            background: "rgba(30, 41, 59, 0.9)",
            border: "1px solid rgba(239, 68, 68, 0.4)",
            borderRadius: "12px",
            padding: "2rem",
            textAlign: "center",
            boxShadow: "0 8px 32px rgba(0, 0, 0, 0.5)"
          }}>
            <h2 style={{ color: "#ef4444", marginTop: 0 }}>⚠️ Application Render Notice</h2>
            <p style={{ color: "#94a3b8", fontSize: "0.95rem" }}>
              A temporary render transition occurred. Click below to continue to the dashboard.
            </p>
            {this.state.error && (
              <div style={{
                textAlign: "left",
                background: "#0f172a",
                padding: "0.75rem",
                borderRadius: "6px",
                fontFamily: "monospace",
                fontSize: "0.8rem",
                color: "#f87171",
                overflowX: "auto",
                margin: "1rem 0"
              }}>
                {this.state.error.toString()}
              </div>
            )}
            <button
              onClick={() => {
                this.setState({ hasError: false, error: null });
                window.location.href = "/dashboard";
              }}
              style={{
                background: "#0284c7",
                color: "#ffffff",
                border: "none",
                padding: "0.75rem 1.5rem",
                borderRadius: "8px",
                fontWeight: 600,
                cursor: "pointer",
                marginTop: "0.5rem"
              }}
            >
              📊 Continue to SOC Dashboard
            </button>
          </div>
        </div>
      );
    }

    return this.props.children;
  }
}
