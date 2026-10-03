"""
ThreatXAI Database Manager for User Registration and Authentication.
Provides persistent H2 / SQLite database storage for user accounts, using scrypt password hashing.
"""

from __future__ import annotations

import json
import shutil
import sqlite3
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional
from werkzeug.security import check_password_hash, generate_password_hash


class H2Database:
    """Manages persistent user authentication in H2 Database (with SQLite cloud resilience fallback)."""

    def __init__(self, db_dir: Optional[Path] = None) -> None:
        if db_dir is None:
            db_dir = Path(__file__).parent.resolve()
        self.db_dir = db_dir
        self.db_dir.mkdir(parents=True, exist_ok=True)
        self.jar_path = (self.db_dir / "h2.jar").resolve()
        self.db_path = (self.db_dir / "threatxai").resolve()
        self.db_url = f"jdbc:h2:{self.db_path.as_posix()};AUTO_SERVER=TRUE;DB_CLOSE_DELAY=-1"
        self.sqlite_path = (self.db_dir / "threatxai.db").resolve()
        self.use_h2 = bool(shutil.which("java") and self.jar_path.exists())

    def _get_sqlite_conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.sqlite_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _run_sql(self, sql: str) -> str:
        if not self.jar_path.exists():
            raise FileNotFoundError(f"H2 jar not found at: {self.jar_path}")

        cmd = [
            "java",
            "-cp",
            str(self.jar_path),
            "org.h2.tools.Shell",
            "-url",
            self.db_url,
            "-user",
            "sa",
            "-password",
            "",
            "-sql",
            sql,
        ]
        res = subprocess.run(cmd, capture_output=True, text=True)
        if res.returncode != 0:
            raise RuntimeError(f"H2 Database Error (exit {res.returncode}): {res.stderr or res.stdout}")
        return res.stdout

    def init_db(self) -> None:
        """Initialize database tables and ensure default SOC analyst account exists."""
        if self.use_h2:
            create_sql = """
            CREATE TABLE IF NOT EXISTS users (
                id INT AUTO_INCREMENT PRIMARY KEY,
                username VARCHAR(255) NOT NULL UNIQUE,
                email VARCHAR(255) NOT NULL UNIQUE,
                full_name VARCHAR(255) NOT NULL,
                password_hash VARCHAR(500) NOT NULL,
                role VARCHAR(50) DEFAULT 'Security Analyst',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            """
            self._run_sql(create_sql)
        else:
            with self._get_sqlite_conn() as conn:
                conn.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL UNIQUE,
                    email TEXT NOT NULL UNIQUE,
                    full_name TEXT NOT NULL,
                    password_hash TEXT NOT NULL,
                    role TEXT DEFAULT 'Security Analyst',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
                """)
                conn.commit()

        # Seed default demo analyst account if not already present
        demo_user = self.get_user("analyst_soc")
        if not demo_user:
            self.create_user(
                full_name="SOC Senior Analyst",
                username="analyst_soc",
                email="analyst@threatxai.soc",
                password="ThreatXAI#2026",
                role="Security Analyst",
            )

    def _escape_sql(self, val: str) -> str:
        return val.replace("'", "''")

    def get_user(self, identifier: str) -> Optional[Dict[str, Any]]:
        """Retrieve user record by username or email."""
        clean_id = identifier.strip().lower()

        if self.use_h2:
            escaped_id = self._escape_sql(clean_id)
            sql = f"""
            SELECT JSON_OBJECT(
                'id': id,
                'username': username,
                'email': email,
                'full_name': full_name,
                'password_hash': password_hash,
                'role': role
            ) AS user_json
            FROM users
            WHERE LOWER(username) = '{escaped_id}' OR LOWER(email) = '{escaped_id}';
            """
            output = self._run_sql(sql)
            for line in output.splitlines():
                line = line.strip()
                if line.startswith("{") and line.endswith("}"):
                    try:
                        return json.loads(line)
                    except Exception:
                        continue
            return None
        else:
            with self._get_sqlite_conn() as conn:
                cur = conn.cursor()
                cur.execute(
                    "SELECT id, username, email, full_name, password_hash, role FROM users WHERE LOWER(username) = ? OR LOWER(email) = ?",
                    (clean_id, clean_id),
                )
                row = cur.fetchone()
                if row:
                    return dict(row)
            return None

    def create_user(
        self,
        full_name: str,
        username: str,
        email: str,
        password: str,
        role: str = "Security Analyst",
    ) -> Dict[str, Any]:
        """Create a new user in database with hashed password."""
        u_clean = username.strip()
        e_clean = email.strip()
        fn_clean = full_name.strip()

        if not u_clean or not e_clean or not fn_clean or not password:
            raise ValueError("All fields are required.")

        # Hash password securely with scrypt
        pwd_hash = generate_password_hash(password, method="scrypt")

        if self.use_h2:
            escaped_u = self._escape_sql(u_clean)
            escaped_e = self._escape_sql(e_clean)

            # Single combined existence check
            check_sql = f"""
            SELECT JSON_OBJECT('username': username, 'email': email) AS json_out
            FROM users
            WHERE LOWER(username) = '{escaped_u.lower()}' OR LOWER(email) = '{escaped_e.lower()}';
            """
            out = self._run_sql(check_sql)
            for line in out.splitlines():
                line = line.strip()
                if line.startswith("{") and line.endswith("}"):
                    try:
                        matched = json.loads(line)
                        if matched.get("username", "").lower() == u_clean.lower():
                            raise ValueError(f"Username '{u_clean}' is already registered.")
                        if matched.get("email", "").lower() == e_clean.lower():
                            raise ValueError(f"Email '{e_clean}' is already registered.")
                    except json.JSONDecodeError:
                        pass

            escaped_hash = self._escape_sql(pwd_hash)
            escaped_fn = self._escape_sql(fn_clean)
            escaped_role = self._escape_sql(role)

            insert_sql = f"""
            INSERT INTO users (username, email, full_name, password_hash, role)
            VALUES ('{escaped_u}', '{escaped_e}', '{escaped_fn}', '{escaped_hash}', '{escaped_role}');
            """
            self._run_sql(insert_sql)
        else:
            with self._get_sqlite_conn() as conn:
                cur = conn.cursor()
                cur.execute(
                    "SELECT username, email FROM users WHERE LOWER(username) = ? OR LOWER(email) = ?",
                    (u_clean.lower(), e_clean.lower()),
                )
                existing = cur.fetchone()
                if existing:
                    if existing["username"].lower() == u_clean.lower():
                        raise ValueError(f"Username '{u_clean}' is already registered.")
                    if existing["email"].lower() == e_clean.lower():
                        raise ValueError(f"Email '{e_clean}' is already registered.")

                cur.execute(
                    "INSERT INTO users (username, email, full_name, password_hash, role) VALUES (?, ?, ?, ?, ?)",
                    (u_clean, e_clean, fn_clean, pwd_hash, role),
                )
                conn.commit()

        user = self.get_user(u_clean)
        if not user:
            raise RuntimeError("Failed to retrieve newly registered user from database.")

        return {
            "id": user["id"],
            "username": user["username"],
            "email": user["email"],
            "full_name": user["full_name"],
            "role": user["role"],
        }

    def authenticate(self, identifier: str, password: str) -> Optional[Dict[str, Any]]:
        """Authenticate user against password hash. Returns safe user dictionary or None."""
        user = self.get_user(identifier)
        if not user:
            return None
        if not check_password_hash(user["password_hash"], password):
            return None

        return {
            "id": user["id"],
            "username": user["username"],
            "email": user["email"],
            "full_name": user["full_name"],
            "role": user["role"],
        }

    def list_users(self) -> List[Dict[str, Any]]:
        """List all users (safe fields only)."""
        if self.use_h2:
            sql = """
            SELECT JSON_OBJECT(
                'id': id,
                'username': username,
                'email': email,
                'full_name': full_name,
                'role': role
            ) AS user_json FROM users ORDER BY id ASC;
            """
            output = self._run_sql(sql)
            users = []
            for line in output.splitlines():
                line = line.strip()
                if line.startswith("{") and line.endswith("}"):
                    try:
                        users.append(json.loads(line))
                    except Exception:
                        continue
            return users
        else:
            with self._get_sqlite_conn() as conn:
                cur = conn.cursor()
                cur.execute("SELECT id, username, email, full_name, role FROM users ORDER BY id ASC")
                return [dict(row) for row in cur.fetchall()]
