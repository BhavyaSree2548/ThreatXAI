import React, { useState, useEffect } from "react";
import { AuthProvider, useAuth } from "./context/AuthContext";
import ErrorBoundary from "./components/ErrorBoundary";
import Navbar from "./components/Navbar";
import ChatbotAssistant from "./components/ChatbotAssistant";
import LoginPage from "./pages/LoginPage";
import DashboardHome from "./pages/DashboardHome";
import TestSamplesPage from "./pages/TestSamplesPage";
import UploadPage from "./pages/UploadPage";
import ResultsPage from "./pages/ResultsPage";
import MonitoringPage from "./pages/MonitoringPage";
import HistoryPage from "./pages/HistoryPage";
import ReportsPage from "./pages/ReportsPage";
import AssistantPage from "./pages/AssistantPage";
import SystemHealthPage from "./pages/SystemHealthPage";

function MainApp() {
  const { isAuthenticated, authLoading } = useAuth();
  const [currentRoute, setCurrentRoute] = useState(() => {
    const path = window.location.pathname;
    return path && path !== "/" && path !== "/login" ? path : "/dashboard";
  });
  const [activeResult, setActiveResult] = useState(null);
  const [isChatbotOpen, setIsChatbotOpen] = useState(false);

  // Sync state with browser URL navigation
  useEffect(() => {
    const handlePopState = () => {
      const path = window.location.pathname;
      setCurrentRoute(path && path !== "/" && path !== "/login" ? path : "/dashboard");
    };
    window.addEventListener("popstate", handlePopState);
    return () => window.removeEventListener("popstate", handlePopState);
  }, []);

  const navigate = (path) => {
    const target = path === "/" || path === "/login" ? "/dashboard" : path;
    setCurrentRoute(target);
    window.history.pushState({}, "", target);
    window.scrollTo({ top: 0, behavior: "smooth" });
  };

  // 1. Initial Authentication Loading State
  if (authLoading) {
    return (
      <div
        className="auth-loading-screen"
        style={{
          display: "flex",
          flexDirection: "column",
          alignItems: "center",
          justifyContent: "center",
          minHeight: "100vh",
          background: "#0b0f19",
          color: "#38bdf8",
          fontFamily: "Inter, sans-serif",
        }}
      >
        <div
          className="spinner"
          style={{
            width: "48px",
            height: "48px",
            border: "4px solid rgba(56, 189, 248, 0.2)",
            borderTop: "4px solid #38bdf8",
            borderRadius: "50%",
            animation: "spin 0.8s linear infinite",
            marginBottom: "1rem",
          }}
        ></div>
        <p style={{ fontSize: "1rem", fontWeight: 500, color: "#94a3b8" }}>
          Initializing ThreatXAI SOC Platform...
        </p>
      </div>
    );
  }

  // 2. Unauthenticated State -> Render Login / Register Page
  if (!isAuthenticated) {
    return <LoginPage navigate={navigate} />;
  }

  // 3. Authenticated State -> Render Protected Routes
  const renderCurrentPage = () => {
    switch (currentRoute) {
      case "/":
      case "/login":
      case "/dashboard":
        return <DashboardHome navigate={navigate} />;
      case "/test-samples":
        return <TestSamplesPage navigate={navigate} onSelectResult={setActiveResult} />;
      case "/upload":
        return <UploadPage navigate={navigate} onSelectResult={setActiveResult} />;
      case "/results":
        return (
          <ResultsPage
            result={activeResult}
            navigate={navigate}
            onOpenChatbot={(res) => {
              setActiveResult(res);
              setIsChatbotOpen(true);
            }}
          />
        );
      case "/monitoring":
        return <MonitoringPage navigate={navigate} onSelectResult={setActiveResult} />;
      case "/history":
        return <HistoryPage navigate={navigate} onSelectResult={setActiveResult} />;
      case "/reports":
        return <ReportsPage navigate={navigate} activeResult={activeResult} />;
      case "/assistant":
        return <AssistantPage activeResult={activeResult} />;
      case "/system-health":
        return <SystemHealthPage navigate={navigate} />;
      default:
        return <DashboardHome navigate={navigate} />;
    }
  };

  return (
    <div className="threatxai-app-shell">
      {/* Top SOC Navbar */}
      <Navbar currentRoute={currentRoute} navigate={navigate} />

      {/* Main Page Content */}
      <main className="main-content-container">{renderCurrentPage()}</main>

      {/* Floating SOC Assistant Button */}
      {currentRoute !== "/assistant" && (
        <button
          className={`floating-assistant-toggle ${isChatbotOpen ? "active" : ""}`}
          onClick={() => setIsChatbotOpen(!isChatbotOpen)}
          title="Open ThreatXAI SOC Assistant"
        >
          <span className="bot-icon">🤖</span>
          <span className="bot-text">AI Assistant</span>
        </button>
      )}

      {/* Floating SOC Assistant Window */}
      {isChatbotOpen && currentRoute !== "/assistant" && (
        <div className="floating-chat-backdrop">
          <ChatbotAssistant
            currentResult={activeResult}
            isFloating={true}
            onClose={() => setIsChatbotOpen(false)}
          />
        </div>
      )}

      {/* SOC Global Footer */}
      <footer className="global-footer">
        <div className="footer-content">
          <span>THREAT<span className="brand-accent">XAI</span> • Real-Time Explainable AI Intrusion Detection System</span>
          <span className="footer-model-badge">LightGBM • CIC-IDS2017 • SHAP TreeExplainer</span>
        </div>
      </footer>
    </div>
  );
}

export default function App() {
  return (
    <ErrorBoundary>
      <AuthProvider>
        <MainApp />
      </AuthProvider>
    </ErrorBoundary>
  );
}
