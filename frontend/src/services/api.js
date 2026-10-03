/**
 * ThreatXAI API Client Service
 * Connects frontend to the FastAPI ML backend on http://127.0.0.1:8000
 */

const rawBase = import.meta.env.VITE_API_URL || "http://127.0.0.1:8000";
export const API_BASE = rawBase.replace(/\/+$/, "");

export function getApiBaseUrl() {
  return API_BASE;
}

export async function fetchHealth() {
  const res = await fetch(`${API_BASE}/health`);
  if (!res.ok) throw new Error(`Health check failed (${res.status})`);
  return res.json();
}

export async function fetchModelMetrics() {
  const res = await fetch(`${API_BASE}/model/metrics`);
  if (!res.ok) throw new Error(`Failed to fetch model metrics (${res.status})`);
  return res.json();
}

export async function fetchSamplesCatalog() {
  const res = await fetch(`${API_BASE}/samples/catalog`);
  if (!res.ok) throw new Error(`Failed to fetch samples catalog (${res.status})`);
  return res.json();
}

export async function predictFlow(features) {
  const res = await fetch(`${API_BASE}/predict`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ features }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: "Prediction error" }));
    throw new Error(typeof err.detail === "string" ? err.detail : JSON.stringify(err.detail));
  }
  return res.json();
}

export async function explainFlow(features) {
  const res = await fetch(`${API_BASE}/explain`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ features }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: "Explainability error" }));
    throw new Error(typeof err.detail === "string" ? err.detail : JSON.stringify(err.detail));
  }
  return res.json();
}

export async function uploadTrafficFile(file) {
  const formData = new FormData();
  formData.append("file", file);

  const res = await fetch(`${API_BASE}/upload/traffic`, {
    method: "POST",
    body: formData,
  });

  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: `Upload request failed (HTTP ${res.status})` }));
    let msg = `Upload failed (${res.status})`;
    if (typeof err.detail === "string") {
      msg = `Upload failed: ${err.detail}`;
    } else if (err.detail && typeof err.detail === "object") {
      if (err.detail.message) {
        msg = `Upload failed: ${err.detail.message}`;
        if (err.detail.missing_features && err.detail.missing_features.length > 0) {
          msg += ` (Missing: ${err.detail.missing_features.slice(0, 3).join(", ")})`;
        }
      } else {
        msg = `Upload failed: ${JSON.stringify(err.detail)}`;
      }
    }
    throw new Error(msg);
  }
  return res.json();
}


export async function fetchInterfaces() {
  const res = await fetch(`${API_BASE}/monitor/interfaces`);
  if (!res.ok) throw new Error(`Failed to fetch network interfaces (${res.status})`);
  return res.json();
}

export async function fetchMonitorStatus() {
  const res = await fetch(`${API_BASE}/monitor/status`);
  if (!res.ok) throw new Error(`Failed to fetch monitor status (${res.status})`);
  return res.json();
}

export async function startMonitoring(interfaceName) {
  const res = await fetch(`${API_BASE}/monitor/start`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ interface: interfaceName }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: "Failed to start monitoring" }));
    throw new Error(typeof err.detail === "string" ? err.detail : JSON.stringify(err.detail));
  }
  return res.json();
}

export async function stopMonitoring() {
  const res = await fetch(`${API_BASE}/monitor/stop`, {
    method: "POST",
  });
  if (!res.ok) throw new Error(`Failed to stop monitoring (${res.status})`);
  return res.json();
}

export async function fetchMonitorEvents(limit = 50) {
  const res = await fetch(`${API_BASE}/monitor/events?limit=${limit}`);
  if (!res.ok) throw new Error(`Failed to fetch monitor events (${res.status})`);
  return res.json();
}

export function createMonitorWebSocket(onMessage, onError, onClose) {
  const wsBase = API_BASE.startsWith("https:")
    ? API_BASE.replace(/^https:/, "wss:")
    : API_BASE.replace(/^http:/, "ws:");
  const wsUrl = `${wsBase}/ws/monitor`;
  const ws = new WebSocket(wsUrl);

  ws.onmessage = (event) => {
    try {
      const data = JSON.parse(event.data);
      onMessage(data);
    } catch (e) {
      console.error("WS parse error:", e);
    }
  };

  ws.onerror = (err) => {
    if (onError) onError(err);
  };

  ws.onclose = () => {
    if (onClose) onClose();
  };

  return ws;
}

export async function loginUser(username, password) {
  const res = await fetch(`${API_BASE}/auth/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username, password }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: "Login failed" }));
    throw new Error(typeof err.detail === "string" ? err.detail : JSON.stringify(err.detail));
  }
  return res.json();
}

export async function registerUser({ fullName, username, email, password }) {
  const res = await fetch(`${API_BASE}/auth/register`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      full_name: fullName,
      username,
      email,
      password,
    }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: "Registration failed" }));
    throw new Error(typeof err.detail === "string" ? err.detail : JSON.stringify(err.detail));
  }
  return res.json();
}

export async function fetchRegisteredUsers() {
  const res = await fetch(`${API_BASE}/auth/users`);
  if (!res.ok) throw new Error("Failed to fetch registered users");
  return res.json();
}

