import React, { useState, useEffect } from "react";
import { useAuth } from "../context/AuthContext";
import { fetchHealth } from "../services/api";

export default function Navbar({ currentRoute, navigate }) {
  const { user, logout } = useAuth();
  const [healthOk, setHealthOk] = useState(null);
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);

  useEffect(() => {
    let mounted = true;
    const check = async () => {
      try {
        const res = await fetchHealth();
        if (mounted) setHealthOk(res.status === "ok" && res.model_loaded);
      } catch {
        if (mounted) setHealthOk(false);
      }
    };
    check();
    const interval = setInterval(check, 10000);
    return () => {
      mounted = false;
      clearInterval(interval);
    };
  }, []);

  const navItems = [
    { path: "/dashboard", label: "Dashboard", icon: "📊" },
    { path: "/monitoring", label: "Live Monitor", icon: "⚡" },
    { path: "/test-samples", label: "Test Samples", icon: "🧪" },
    { path: "/upload", label: "Upload Traffic", icon: "📂" },
    { path: "/history", label: "Threat Logs", icon: "🕒" },
    { path: "/reports", label: "Reports", icon: "📑" },
    { path: "/assistant", label: "AI Assistant", icon: "🤖" },
    { path: "/system-health", label: "Health", icon: "🛡️" },
  ];

  return (
    <header className="navbar">
      <div className="navbar-container">
        {/* Brand */}
        <div className="navbar-brand" onClick={() => navigate("/dashboard")}>
          <div className="brand-logo">
            <span className="brand-icon">⚡</span>
            <div className="brand-glow"></div>
          </div>
          <div className="brand-text">
            <span className="brand-name">THREAT<span className="brand-accent">XAI</span></span>
            <span className="brand-tagline">Real-Time Explainable SOC</span>
          </div>
        </div>

        {/* Desktop Navigation Links */}
        <nav className="navbar-links">
          {navItems.map((item) => {
            const isActive = currentRoute === item.path;
            return (
              <button
                key={item.path}
                onClick={() => {
                  navigate(item.path);
                  setMobileMenuOpen(false);
                }}
                className={`nav-btn ${isActive ? "active" : ""}`}
              >
                <span className="nav-icon">{item.icon}</span>
                <span>{item.label}</span>
              </button>
            );
          })}
        </nav>

        {/* Right Section: Health Pulse & User/Logout */}
        <div className="navbar-right">
          {/* Health Pill */}
          <div
            className={`health-badge ${healthOk === true ? "online" : healthOk === false ? "offline" : "checking"}`}
            title={healthOk ? "FastAPI & LightGBM Active" : "Backend Disconnected"}
            onClick={() => navigate("/system-health")}
          >
            <span className="pulse-dot"></span>
            <span className="health-label">{healthOk ? "API ACTIVE" : "OFFLINE"}</span>
          </div>

          {/* User Profile / Logout */}
          {user && (
            <div className="user-profile">
              <span className="user-avatar">
                {((user.username || user.full_name || "AU").substring(0, 2)).toUpperCase()}
              </span>
              <span className="user-name">{user.username || user.full_name || "Analyst"}</span>
              <button className="logout-btn" onClick={logout} title="Sign Out">
                Logout
              </button>
            </div>
          )}

          {/* Mobile Hamburger Toggle */}
          <button
            className="mobile-toggle-btn"
            onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
            aria-label="Toggle Navigation Menu"
          >
            {mobileMenuOpen ? "✕" : "☰"}
          </button>
        </div>
      </div>

      {/* Mobile Menu Dropdown */}
      {mobileMenuOpen && (
        <div className="mobile-menu">
          {navItems.map((item) => (
            <button
              key={item.path}
              onClick={() => {
                navigate(item.path);
                setMobileMenuOpen(false);
              }}
              className={`mobile-nav-btn ${currentRoute === item.path ? "active" : ""}`}
            >
              <span className="nav-icon">{item.icon}</span>
              <span>{item.label}</span>
            </button>
          ))}
          {user && (
            <button className="mobile-logout-btn" onClick={logout}>
              Sign Out ({user.username})
            </button>
          )}
        </div>
      )}
    </header>
  );
}
