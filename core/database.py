"""
database.py — Full SQLite memory for pentest agent
All scan data, findings, sessions, AI decisions stored here
"""
import sqlite3
import json
import os
from datetime import datetime
from pathlib import Path
from typing import Optional, List, Dict, Any


def get_timestamp():
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def get_time():
    return datetime.now().strftime("%H:%M:%S")


class Database:
    def __init__(self, db_path: str):
        self.db_path = db_path
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        # WAL mode for concurrent access safety
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA synchronous=NORMAL")
        self._create_schema()

    def _create_schema(self):
        c = self.conn.cursor()

        c.executescript("""
        CREATE TABLE IF NOT EXISTS nodes (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            url         TEXT UNIQUE,
            method      TEXT DEFAULT '["GET"]',
            params      TEXT DEFAULT '[]',
            node_type   TEXT DEFAULT 'NORMAL',
            auth_req    BOOLEAN DEFAULT 0,
            role_req    TEXT DEFAULT 'none',
            tech        TEXT DEFAULT '',
            sensitive   BOOLEAN DEFAULT 0,
            tested      BOOLEAN DEFAULT 0,
            priority    INTEGER DEFAULT 5,
            created_at  TEXT
        );

        CREATE TABLE IF NOT EXISTS edges (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            from_node   INTEGER,
            to_node     INTEGER,
            edge_type   TEXT,
            action_desc TEXT
        );

        CREATE TABLE IF NOT EXISTS sessions (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            role        TEXT,
            token       TEXT,
            cookies     TEXT DEFAULT '{}',
            user_id     TEXT,
            status      TEXT DEFAULT 'active',
            expires_at  TEXT,
            created_at  TEXT
        );

        CREATE TABLE IF NOT EXISTS requests (
            id                  INTEGER PRIMARY KEY AUTOINCREMENT,
            url                 TEXT,
            method              TEXT,
            headers             TEXT,
            body                TEXT,
            response_status     INTEGER,
            response_headers    TEXT,
            response_body       TEXT,
            response_time_ms    INTEGER,
            session_role        TEXT,
            source_page         TEXT,
            captured_at         TEXT
        );

        CREATE TABLE IF NOT EXISTS baselines (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            node_id         INTEGER,
            url             TEXT,
            status_code     INTEGER,
            body_size       INTEGER,
            response_time   INTEGER,
            structure_hash  TEXT,
            session_role    TEXT DEFAULT 'unauth',
            created_at      TEXT
        );

        CREATE TABLE IF NOT EXISTS findings (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            vuln_type       TEXT,
            severity        TEXT,
            endpoint        TEXT,
            param           TEXT,
            method          TEXT,
            proof_request   TEXT,
            proof_response  TEXT,
            description     TEXT,
            confidence      INTEGER DEFAULT 50,
            status          TEXT DEFAULT 'unverified',
            poc_file        TEXT,
            remediation     TEXT,
            found_at        TEXT,
            verified_at     TEXT
        );

        CREATE TABLE IF NOT EXISTS chains (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            chain_id    TEXT,
            name        TEXT,
            severity    TEXT,
            finding_ids TEXT DEFAULT '[]',
            steps       TEXT DEFAULT '[]',
            poc_steps   TEXT DEFAULT '[]',
            confidence  INTEGER DEFAULT 50,
            created_at  TEXT
        );

        CREATE TABLE IF NOT EXISTS ai_actions (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            action      TEXT,
            engine      TEXT,
            params      TEXT DEFAULT '{}',
            reason      TEXT,
            ai_model    TEXT DEFAULT 'rule-based',
            confidence  INTEGER DEFAULT 70,
            result      TEXT DEFAULT '{}',
            finding_ids TEXT DEFAULT '[]',
            duration_ms INTEGER DEFAULT 0,
            timestamp   TEXT
        );

        CREATE TABLE IF NOT EXISTS waf_info (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            target      TEXT,
            waf_type    TEXT,
            detected_at TEXT,
            bypass_method TEXT
        );

        CREATE TABLE IF NOT EXISTS js_secrets (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            url         TEXT,
            secret_type TEXT,
            value       TEXT,
            found_at    TEXT
        );
        """)
        self.conn.commit()

    # ── Node operations ──────────────────────────────────────
    def add_node(self, url: str, node_type: str = "NORMAL", method: list = None,
                 params: list = None, auth_req: bool = False, sensitive: bool = False,
                 priority: int = 5) -> int:
        method = method or ["GET"]
        params = params or []
        try:
            c = self.conn.cursor()
            c.execute("""INSERT OR IGNORE INTO nodes 
                        (url, method, params, node_type, auth_req, sensitive, priority, created_at)
                        VALUES (?,?,?,?,?,?,?,?)""",
                     (url, json.dumps(method), json.dumps(params),
                      node_type, auth_req, sensitive, priority, get_time()))
            self.conn.commit()
            c.execute("SELECT id FROM nodes WHERE url=?", (url,))
            row = c.fetchone()
            return row["id"] if row else -1
        except Exception as e:
            return -1

    def get_untested_nodes(self, limit: int = 20, min_priority: int = 1) -> List[Dict]:
        c = self.conn.cursor()
        c.execute("""SELECT * FROM nodes WHERE tested=0 AND priority >= ?
                    ORDER BY priority DESC, sensitive DESC LIMIT ?""",
                 (min_priority, limit))
        return [dict(r) for r in c.fetchall()]

    def mark_node_tested(self, node_id: int):
        self.conn.execute("UPDATE nodes SET tested=1 WHERE id=?", (node_id,))
        self.conn.commit()

    def get_all_nodes(self) -> List[Dict]:
        c = self.conn.cursor()
        c.execute("SELECT * FROM nodes ORDER BY priority DESC")
        return [dict(r) for r in c.fetchall()]

    # ── Session operations ────────────────────────────────────
    def add_session(self, role: str, token: str = None, cookies: dict = None,
                    user_id: str = None) -> int:
        c = self.conn.cursor()
        c.execute("""INSERT INTO sessions (role, token, cookies, user_id, created_at)
                    VALUES (?,?,?,?,?)""",
                 (role, token, json.dumps(cookies or {}), user_id, get_time()))
        self.conn.commit()
        return c.lastrowid

    def get_session(self, role: str) -> Optional[Dict]:
        c = self.conn.cursor()
        c.execute("SELECT * FROM sessions WHERE role=? AND status='active' ORDER BY id DESC LIMIT 1", (role,))
        row = c.fetchone()
        return dict(row) if row else None

    def get_all_sessions(self) -> List[Dict]:
        c = self.conn.cursor()
        c.execute("SELECT * FROM sessions WHERE status='active'")
        return [dict(r) for r in c.fetchall()]

    # ── Finding operations ────────────────────────────────────
    def add_finding(self, vuln_type: str, severity: str, endpoint: str,
                    description: str, param: str = None, method: str = "GET",
                    proof_req: str = None, proof_resp: str = None,
                    confidence: int = 70, remediation: str = None) -> int:
        c = self.conn.cursor()
        c.execute("""INSERT INTO findings 
                    (vuln_type, severity, endpoint, param, method, proof_request, 
                     proof_response, description, confidence, remediation, found_at)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                 (vuln_type, severity, endpoint, param, method,
                  proof_req, proof_resp, description, confidence, remediation, get_time()))
        self.conn.commit()
        return c.lastrowid

    def get_findings(self, status: str = None) -> List[Dict]:
        c = self.conn.cursor()
        if status:
            c.execute("SELECT * FROM findings WHERE status=? ORDER BY confidence DESC", (status,))
        else:
            c.execute("SELECT * FROM findings ORDER BY confidence DESC")
        return [dict(r) for r in c.fetchall()]

    def verify_finding(self, finding_id: int, confidence: int):
        status = "verified" if confidence >= 60 else "false_positive"
        self.conn.execute("""UPDATE findings SET status=?, confidence=?, verified_at=? 
                            WHERE id=?""", (status, confidence, get_time(), finding_id))
        self.conn.commit()

    # ── AI action log ─────────────────────────────────────────
    def log_action(self, action: str, engine: str = None, params: dict = None,
                   reason: str = None, ai_model: str = "rule-based",
                   confidence: int = 70, result: dict = None,
                   finding_ids: list = None, duration_ms: int = 0):
        self.conn.execute("""INSERT INTO ai_actions 
                            (action, engine, params, reason, ai_model, confidence,
                             result, finding_ids, duration_ms, timestamp)
                            VALUES (?,?,?,?,?,?,?,?,?,?)""",
                         (action, engine, json.dumps(params or {}), reason,
                          ai_model, confidence, json.dumps(result or {}),
                          json.dumps(finding_ids or []), duration_ms, get_time()))
        self.conn.commit()

    def get_recent_actions(self, limit: int = 10) -> List[Dict]:
        c = self.conn.cursor()
        c.execute("SELECT * FROM ai_actions ORDER BY id DESC LIMIT ?", (limit,))
        return [dict(r) for r in c.fetchall()]

    def action_exists(self, action: str, engine: str, params: dict) -> bool:
        """Check if exact same action was already performed"""
        c = self.conn.cursor()
        params_str = json.dumps(params, sort_keys=True)
        c.execute("""SELECT id FROM ai_actions WHERE action=? AND engine=? AND params=?
                    LIMIT 1""", (action, engine, params_str))
        return c.fetchone() is not None

    # ── Baseline ──────────────────────────────────────────────
    def save_baseline(self, url: str, status: int, size: int,
                      response_time: int, structure_hash: str,
                      session_role: str = "unauth"):
        self.conn.execute("""INSERT OR REPLACE INTO baselines
                            (url, status_code, body_size, response_time, structure_hash, session_role, created_at)
                            VALUES (?,?,?,?,?,?,?)""",
                         (url, status, size, response_time, structure_hash, session_role, get_time()))
        self.conn.commit()

    def get_baseline(self, url: str) -> Optional[Dict]:
        c = self.conn.cursor()
        c.execute("SELECT * FROM baselines WHERE url=? ORDER BY id DESC LIMIT 1", (url,))
        row = c.fetchone()
        return dict(row) if row else None

    # ── WAF ───────────────────────────────────────────────────
    def save_waf(self, target: str, waf_type: str, bypass_method: str = None):
        self.conn.execute("""INSERT OR REPLACE INTO waf_info 
                            (target, waf_type, detected_at, bypass_method)
                            VALUES (?,?,?,?)""",
                         (target, waf_type, get_time(), bypass_method))
        self.conn.commit()

    def get_waf(self, target: str) -> Optional[Dict]:
        c = self.conn.cursor()
        c.execute("SELECT * FROM waf_info WHERE target=? ORDER BY id DESC LIMIT 1", (target,))
        row = c.fetchone()
        return dict(row) if row else None

    # ── Stats ─────────────────────────────────────────────────
    def get_stats(self) -> Dict:
        c = self.conn.cursor()
        stats = {}
        c.execute("SELECT COUNT(*) as n FROM nodes"); stats["total_nodes"] = c.fetchone()["n"]
        c.execute("SELECT COUNT(*) as n FROM nodes WHERE tested=1"); stats["tested_nodes"] = c.fetchone()["n"]
        c.execute("SELECT COUNT(*) as n FROM findings"); stats["total_findings"] = c.fetchone()["n"]
        c.execute("SELECT COUNT(*) as n FROM findings WHERE status='verified'"); stats["verified_findings"] = c.fetchone()["n"]
        c.execute("SELECT COUNT(*) as n FROM findings WHERE severity='CRITICAL'"); stats["critical"] = c.fetchone()["n"]
        c.execute("SELECT COUNT(*) as n FROM findings WHERE severity='HIGH'"); stats["high"] = c.fetchone()["n"]
        c.execute("SELECT COUNT(*) as n FROM findings WHERE severity='MEDIUM'"); stats["medium"] = c.fetchone()["n"]
        c.execute("SELECT COUNT(*) as n FROM chains"); stats["chains"] = c.fetchone()["n"]
        c.execute("SELECT COUNT(*) as n FROM ai_actions"); stats["ai_actions"] = c.fetchone()["n"]
        return stats

    def checkpoint(self):
        """WAL checkpoint for safety"""
        try:
            self.conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        except:
            pass

    def close(self):
        self.checkpoint()
        self.conn.close()
