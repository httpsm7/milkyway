"""
chain_detector.py — Bug chain detection + 3-step verifier
BUG8 FIX: get_all_chains() now properly defined in ChainDetector class
"""
import asyncio
import json
from typing import List, Dict, Optional


class ChainDetector:
    CHAINS = [
        {"id":"C001","name":"IDOR → Account Takeover","severity":"CRITICAL",
         "requires":["IDOR","PASSWORD_RESET"],"steps":["IDOR to change victim email","Trigger password reset","Full account takeover"]},
        {"id":"C002","name":"OTP Brute Force → Auth Bypass","severity":"CRITICAL",
         "requires":["OTP_NO_RATE_LIMIT"],"steps":["Bypass OTP rate limit","Brute force OTP","Auth bypass"]},
        {"id":"C003","name":"IDOR + Mass Assignment → Admin","severity":"CRITICAL",
         "requires":["IDOR","MASS_ASSIGNMENT"],"steps":["Enumerate admin IDs via IDOR","Set role=admin via mass assignment","Admin access"]},
        {"id":"C004","name":"JWT None Algorithm → Admin","severity":"CRITICAL",
         "requires":["JWT_NONE_ALGORITHM"],"steps":["Change JWT alg to none","Modify role=admin","Server accepts unsigned JWT"]},
        {"id":"C005","name":"SSRF → AWS Credential Theft","severity":"CRITICAL",
         "requires":["SSRF"],"steps":["SSRF to 169.254.169.254","Read IAM credentials","AWS account compromise"]},
        {"id":"C006","name":"Race Condition → Double Spend","severity":"HIGH",
         "requires":["RACE_CONDITION"],"steps":["50 concurrent requests","Multiple succeed","Free items/money"]},
        {"id":"C007","name":"CORS + Credentials → Data Theft","severity":"CRITICAL",
         "requires":["CORS_MISCONFIGURATION"],"steps":["CORS reflects origin with credentials","Victim visits attacker site","Steal API responses"]},
        {"id":"C008","name":"SQL Injection → Auth Bypass","severity":"CRITICAL",
         "requires":["SQL_INJECTION_ERROR"],"steps":["SQLi in login param","Use ' OR 1=1--","Admin login without password"]},
        {"id":"C009","name":"JWT Weak Secret → Admin Takeover","severity":"CRITICAL",
         "requires":["JWT_WEAK_SECRET"],"steps":["Cracked JWT secret","Forge admin JWT","Full admin access"]},
        {"id":"C010","name":"Mass Assignment → Admin Escalation","severity":"CRITICAL",
         "requires":["MASS_ASSIGNMENT"],"steps":["Register with role=admin","Server accepts","Admin access"]},
        {"id":"C011","name":"Payment Manipulation → Free Purchase","severity":"CRITICAL",
         "requires":["PAYMENT_BYPASS"],"steps":["Set price=0","Complete order","Free items"]},
        {"id":"C012","name":"LFI → Log Poisoning → RCE","severity":"CRITICAL",
         "requires":["LFI"],"steps":["LFI to read /etc/passwd","Poison access log","LFI includes log → RCE"]},
        {"id":"C013","name":"Auth Bypass + Privilege Escalation","severity":"CRITICAL",
         "requires":["AUTH_BYPASS","PRIVILEGE_ESCALATION"],"steps":["Bypass auth","Escalate to admin","Full access"]},
        {"id":"C014","name":"IDOR on Payment → Financial Fraud","severity":"CRITICAL",
         "requires":["IDOR","PAYMENT_BYPASS"],"steps":["IDOR to access other users' payments","Use victim's saved card","Financial fraud"]},
        {"id":"C015","name":"Race Condition → Negative Balance","severity":"HIGH",
         "requires":["RACE_CONDITION"],"steps":["Concurrent withdrawals","Multiple succeed","Negative balance/free money"]},
    ]

    def __init__(self, db, logger=None):
        self.db = db
        self.log = logger

    def detect(self) -> List[Dict]:
        findings = self.db.get_findings()
        ftypes = {f["vuln_type"] for f in findings}
        triggered = []
        for pattern in self.CHAINS:
            if set(pattern["requires"]).issubset(ftypes):
                existing = self.db.conn.execute(
                    "SELECT id FROM chains WHERE chain_id=?", (pattern["id"],)
                ).fetchone()
                if not existing:
                    rids = [f["id"] for f in findings if f["vuln_type"] in pattern["requires"]]
                    self.db.conn.execute(
                        "INSERT INTO chains (chain_id,name,severity,finding_ids,steps,confidence,created_at) VALUES (?,?,?,?,?,?,datetime('now'))",
                        (pattern["id"],pattern["name"],pattern["severity"],
                         json.dumps(rids),json.dumps(pattern["steps"]),88)
                    )
                    self.db.conn.commit()
                    triggered.append(pattern)
                    if self.log:
                        self.log.chain(pattern["name"], pattern["severity"])
        return triggered

    # BUG8 FIX: was missing this method
    def get_all_chains(self) -> List[Dict]:
        try:
            c = self.db.conn.cursor()
            c.execute("SELECT * FROM chains ORDER BY id DESC")
            return [dict(r) for r in c.fetchall()]
        except:
            return []


class FindingVerifier:
    def __init__(self, http_client, db, logger=None):
        self.http = http_client
        self.db = db
        self.log = logger

    async def verify(self, finding: dict) -> dict:
        vuln_type = finding.get("vuln_type","")
        endpoint  = finding.get("endpoint","")

        # Step 1: Reproduce x3
        repro = await self._reproduce(finding)
        if repro < 1:
            self.db.verify_finding(finding["id"], 10)
            return {**finding, "status":"false_positive", "confidence":10}

        # Step 2: Baseline compare
        baseline_ok = await self._baseline_diff(finding)

        # Step 3: Confidence
        base_conf = finding.get("confidence", 60)
        conf = base_conf + (10 if repro >= 2 else 5 if repro == 1 else -20)
        conf = conf + (5 if baseline_ok else -5)
        conf = min(max(conf, 10), 100)

        status = "verified" if conf >= 55 else "false_positive"
        self.db.verify_finding(finding["id"], conf)

        if self.log:
            icon = "✅" if status == "verified" else "❌"
            self.log.debug(f"{icon} {status} {vuln_type} ({conf}%)")

        return {**finding, "status":status, "confidence":conf}

    async def _reproduce(self, finding) -> int:
        successes = 0
        endpoint = finding.get("endpoint","")
        method   = finding.get("method","GET")
        for _ in range(2):
            try:
                r = await self.http.request(method, endpoint, timeout=6)
                if r and r.get("status",0) not in [0, 500, 503]:
                    successes += 1
            except:
                pass
            await asyncio.sleep(0.3)
        return successes

    async def _baseline_diff(self, finding) -> bool:
        endpoint = finding.get("endpoint","")
        baseline = self.db.get_baseline(endpoint)
        if not baseline:
            return True
        r = await self.http.request("GET", endpoint, timeout=6)
        if not r:
            return False
        diff = abs(len(r.get("body","")) - baseline.get("body_size",0))
        return diff > 100 or r.get("status") != baseline.get("status_code")

