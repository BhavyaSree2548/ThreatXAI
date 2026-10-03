import React, { createContext, useContext, useState, useEffect } from "react";
import { loginUser, registerUser } from "../services/api";

const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null);
  const [authLoading, setAuthLoading] = useState(true);

  // Initialize authentication from storage safely
  useEffect(() => {
    try {
      const saved = localStorage.getItem("threatxai_user");
      if (saved) {
        const parsed = JSON.parse(saved);
        if (parsed && typeof parsed === "object" && (parsed.username || parsed.email)) {
          setUser(parsed);
        } else {
          localStorage.removeItem("threatxai_user");
        }
      }
    } catch (e) {
      console.error("Failed to parse stored auth user:", e);
      localStorage.removeItem("threatxai_user");
    } finally {
      setAuthLoading(false);
    }
  }, []);

  const login = async (username, password) => {
    if (!username || !password) {
      throw new Error("Please enter both username/email and password.");
    }

    const res = await loginUser(username.trim(), password);
    if (!res || !res.user) {
      throw new Error("Authentication failed: invalid server response.");
    }

    const authUser = {
      ...res.user,
      token: res.token,
      loginTime: new Date().toISOString(),
    };

    localStorage.setItem("threatxai_user", JSON.stringify(authUser));
    setUser(authUser);
    return authUser;
  };

  const register = async ({ fullName, username, email, password }) => {
    if (!fullName || !username || !email || !password) {
      throw new Error("All fields are required.");
    }

    const res = await registerUser({
      fullName: fullName.trim(),
      username: username.trim(),
      email: email.trim(),
      password,
    });

    if (!res || !res.user) {
      throw new Error("Registration failed: invalid server response.");
    }

    const authUser = {
      ...res.user,
      token: res.token,
      loginTime: new Date().toISOString(),
    };

    localStorage.setItem("threatxai_user", JSON.stringify(authUser));
    setUser(authUser);
    return authUser;
  };

  const logout = () => {
    setUser(null);
    try {
      localStorage.removeItem("threatxai_user");
    } catch {}
  };

  return (
    <AuthContext.Provider
      value={{
        user,
        isAuthenticated: !!user,
        authLoading,
        login,
        register,
        logout,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error("useAuth must be used within an AuthProvider");
  }
  return context;
}
