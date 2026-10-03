import React, { useState } from "react";
import { useAuth } from "../context/AuthContext";

export default function LoginPage({ navigate }) {
  const { login, register } = useAuth();
  const [mode, setMode] = useState("login"); // "login" | "register"

  // Login form state
  const [loginUsername, setLoginUsername] = useState("");
  const [loginPassword, setLoginPassword] = useState("");
  const [showLoginPassword, setShowLoginPassword] = useState(false);

  // Register form state
  const [regFullName, setRegFullName] = useState("");
  const [regUsername, setRegUsername] = useState("");
  const [regEmail, setRegEmail] = useState("");
  const [regPassword, setRegPassword] = useState("");
  const [regConfirmPassword, setRegConfirmPassword] = useState("");
  const [showRegPassword, setShowRegPassword] = useState(false);

  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");
  const [loading, setLoading] = useState(false);

  const handleLoginSubmit = async (e) => {
    e.preventDefault();
    setError("");
    setSuccess("");

    if (!loginUsername.trim() || !loginPassword) {
      setError("Please enter both username/email and password.");
      return;
    }

    setLoading(true);
    try {
      await login(loginUsername.trim(), loginPassword);
      navigate("/dashboard");
    } catch (err) {
      setError(err.message || "Authentication failed.");
      setLoading(false);
    }
  };

  const handleRegisterSubmit = async (e) => {
    e.preventDefault();
    setError("");
    setSuccess("");

    const fn = regFullName.trim();
    const u = regUsername.trim();
    const em = regEmail.trim();

    if (!fn) {
      setError("Please enter your full name.");
      return;
    }
    if (!u) {
      setError("Please enter a username.");
      return;
    }
    if (!em || !em.includes("@") || !em.includes(".")) {
      setError("Please enter a valid email address.");
      return;
    }
    if (!regPassword) {
      setError("Please enter a password.");
      return;
    }
    if (regPassword.length < 6) {
      setError("Password must be at least 6 characters long.");
      return;
    }
    if (regPassword !== regConfirmPassword) {
      setError("Passwords do not match. Please verify your confirmation password.");
      return;
    }

    setLoading(true);
    try {
      await register({
        fullName: fn,
        username: u,
        email: em,
        password: regPassword,
      });
      navigate("/dashboard");
    } catch (err) {
      setError(err.message || "Registration failed.");
      setLoading(false);
    }
  };

  const handleDemoLogin = async () => {
    setError("");
    setSuccess("");
    setLoading(true);
    try {
      setLoginUsername("analyst_soc");
      setLoginPassword("ThreatXAI#2026");
      await login("analyst_soc", "ThreatXAI#2026");
      navigate("/dashboard");
    } catch (err) {
      setError(err.message || "Demo login failed.");
      setLoading(false);
    }
  };

  return (
    <div className="login-page">
      <div className="login-matrix-bg"></div>

      <div className="login-card">
        {/* Brand Header */}
        <div className="login-header">
          <div className="login-badge-icon">⚡</div>
          <h1 className="login-title">THREAT<span className="brand-accent">XAI</span></h1>
          <p className="login-subtitle">Real-Time Explainable Network Threat Intelligence</p>
          <span className="login-version-pill">H2 Database Persistent Auth • LightGBM + SHAP</span>
        </div>

        {/* Mode Selector Tabs */}
        <div className="auth-tab-group" style={{ display: "flex", gap: "0.5rem", marginBottom: "1.5rem", background: "rgba(15, 23, 42, 0.6)", padding: "0.25rem", borderRadius: "8px", border: "1px solid rgba(56, 189, 248, 0.15)" }}>
          <button
            type="button"
            className={`tab-btn ${mode === "login" ? "active" : ""}`}
            onClick={() => { setMode("login"); setError(""); setSuccess(""); }}
            style={{
              flex: 1,
              padding: "0.6rem 1rem",
              borderRadius: "6px",
              border: "none",
              background: mode === "login" ? "rgba(56, 189, 248, 0.2)" : "transparent",
              color: mode === "login" ? "#38bdf8" : "#94a3b8",
              fontWeight: 600,
              cursor: "pointer",
              transition: "all 0.2s ease"
            }}
          >
            🔐 Sign In
          </button>
          <button
            type="button"
            className={`tab-btn ${mode === "register" ? "active" : ""}`}
            onClick={() => { setMode("register"); setError(""); setSuccess(""); }}
            style={{
              flex: 1,
              padding: "0.6rem 1rem",
              borderRadius: "6px",
              border: "none",
              background: mode === "register" ? "rgba(56, 189, 248, 0.2)" : "transparent",
              color: mode === "register" ? "#38bdf8" : "#94a3b8",
              fontWeight: 600,
              cursor: "pointer",
              transition: "all 0.2s ease"
            }}
          >
            📝 Register
          </button>
        </div>

        {error && <div className="login-error-box">⚠️ {error}</div>}
        {success && <div className="login-success-box" style={{ background: "rgba(16, 185, 129, 0.15)", border: "1px solid rgba(16, 185, 129, 0.4)", color: "#34d399", padding: "0.75rem", borderRadius: "8px", marginBottom: "1.2rem", fontSize: "0.88rem" }}>✓ {success}</div>}

        {/* 1. LOGIN MODE */}
        {mode === "login" && (
          <form onSubmit={handleLoginSubmit} className="login-form">
            <div className="form-group">
              <label className="form-label">Email or Username</label>
              <div className="input-wrap">
                <span className="input-icon">👤</span>
                <input
                  type="text"
                  className="form-input"
                  placeholder="analyst_soc or user@threatxai.soc"
                  value={loginUsername}
                  onChange={(e) => setLoginUsername(e.target.value)}
                  required
                />
              </div>
            </div>

            <div className="form-group">
              <label className="form-label">Password</label>
              <div className="input-wrap">
                <span className="input-icon">🔒</span>
                <input
                  type={showLoginPassword ? "text" : "password"}
                  className="form-input"
                  placeholder="Enter password"
                  value={loginPassword}
                  onChange={(e) => setLoginPassword(e.target.value)}
                  required
                />
                <button
                  type="button"
                  className="password-toggle-btn"
                  onClick={() => setShowLoginPassword(!showLoginPassword)}
                  title={showLoginPassword ? "Hide password" : "Show password"}
                >
                  {showLoginPassword ? "🙈" : "👁️"}
                </button>
              </div>
            </div>

            <button type="submit" className="login-submit-btn" disabled={loading}>
              {loading ? "AUTHENTICATING..." : "ACCESS SOC PLATFORM →"}
            </button>

            {/* Demo Fast Login Shortcut */}
            <div className="demo-credentials-section" style={{ marginTop: "1.2rem" }}>
              <div className="demo-divider"><span>OR QUICK DEMO ACCESS</span></div>
              <button type="button" className="demo-login-btn" onClick={handleDemoLogin} disabled={loading}>
                ⚡ One-Click Analyst Demo Sign-In
              </button>
            </div>
          </form>
        )}

        {/* 2. REGISTER MODE */}
        {mode === "register" && (
          <form onSubmit={handleRegisterSubmit} className="login-form">
            <div className="form-group">
              <label className="form-label">Full Name</label>
              <div className="input-wrap">
                <span className="input-icon">🏷️</span>
                <input
                  type="text"
                  className="form-input"
                  placeholder="e.g. Alex Rivera"
                  value={regFullName}
                  onChange={(e) => setRegFullName(e.target.value)}
                  required
                />
              </div>
            </div>

            <div className="form-group">
              <label className="form-label">Username</label>
              <div className="input-wrap">
                <span className="input-icon">👤</span>
                <input
                  type="text"
                  className="form-input"
                  placeholder="e.g. arivera_sec"
                  value={regUsername}
                  onChange={(e) => setRegUsername(e.target.value)}
                  required
                />
              </div>
            </div>

            <div className="form-group">
              <label className="form-label">Email Address</label>
              <div className="input-wrap">
                <span className="input-icon">✉️</span>
                <input
                  type="email"
                  className="form-input"
                  placeholder="alex.rivera@threatxai.soc"
                  value={regEmail}
                  onChange={(e) => setRegEmail(e.target.value)}
                  required
                />
              </div>
            </div>

            <div className="form-group">
              <label className="form-label">Password (min 6 characters)</label>
              <div className="input-wrap">
                <span className="input-icon">🔒</span>
                <input
                  type={showRegPassword ? "text" : "password"}
                  className="form-input"
                  placeholder="Create secure password"
                  value={regPassword}
                  onChange={(e) => setRegPassword(e.target.value)}
                  required
                />
                <button
                  type="button"
                  className="password-toggle-btn"
                  onClick={() => setShowRegPassword(!showRegPassword)}
                  title={showRegPassword ? "Hide password" : "Show password"}
                >
                  {showRegPassword ? "🙈" : "👁️"}
                </button>
              </div>
            </div>

            <div className="form-group">
              <label className="form-label">Confirm Password</label>
              <div className="input-wrap">
                <span className="input-icon">🔒</span>
                <input
                  type={showRegPassword ? "text" : "password"}
                  className="form-input"
                  placeholder="Re-enter password"
                  value={regConfirmPassword}
                  onChange={(e) => setRegConfirmPassword(e.target.value)}
                  required
                />
              </div>
            </div>

            <button type="submit" className="login-submit-btn" disabled={loading}>
              {loading ? "REGISTERING IN H2..." : "REGISTER SOC ACCOUNT →"}
            </button>
          </form>
        )}

        {/* Footer Feature Badges */}
        <div className="login-features-footer" style={{ marginTop: "1.5rem" }}>
          <div className="feat-item">78 Network Features</div>
          <div className="feat-item">💡 TreeExplainer SHAP</div>
          <div className="feat-item">📡 Real-Time Npcap</div>
        </div>
      </div>
    </div>
  );
}

