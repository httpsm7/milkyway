"""
chain_detector.py — Detects multi-bug attack chains from findings
verifier.py — 3-step finding verification system
"""
import asyncio
import json
from typing import List, Dict, Optional


# ═══════════════════════════════════════════════════════════
# CHAIN DETECTOR
# ═══════════════════════════════════════════════════════════

class ChainDetector:
    """Detects exploitable bug chains from findings list"""

    CHAIN_PATTERNS = [
        {
            "id": "C001", "name": "IDOR → Account Takeover", "severity": "CRITICAL",
            "requires": ["IDOR", "PASSWORD_RESET"],
            "steps": ["Use IDOR to change victim email", "Trigger password reset", "Full account takeover"]
        },
        {
            "id": "C002", "name": "OTP Brute Force → Auth Bypass", "severity": "CRITICAL",
            "requires": ["OTP_NO_RATE_LIMIT"],
            "steps": ["Bypass rate limit via IP header rotation", "Brute force OTP", "Auth bypass"]
        },
        {
            "id": "C003", "name": "IDOR + Mass Assignment → Admin", "severity": "CRITICAL",
            "requires": ["IDOR", "MASS_ASSIGNMENT"],
            "steps": ["IDOR to enumerate admin IDs", "Mass assignment role=admin", "Admin access"]
        },
        {
            "id": "C004", "name": "JWT None Alg → Admin Takeover", "severity": "CRITICAL",
            "requires": ["JWT_NONE_ALGORITHM"],
            "steps": ["Change JWT alg to none", "Modify role=admin", "Server accepts unsigned JWT"]
        },
        {
            "id": "C005", "name": "SSRF → AWS Credential Theft", "severity": "CRITICAL",
            "requires": ["SSRF"],
            "steps": ["SSRF to 169.254.169.254", "Read IAM credentials", "AWS compromise"]
        },
        {
            "id": "C006", "name": "Race Condition → Double Purchase", "severity": "HIGH",
            "requires": ["RACE_CONDITION"],
            "steps": ["50 concurrent purchase requests", "Multiple succeed", "Free items"]
        },
        {
            "id": "C007", "name": "Stored XSS + CSRF → Account Takeover", "severity": "HIGH",
            "requires": ["XSS_STORED", "CSRF"],
            "steps": ["Inject stored XSS", "CSRF request via XSS", "Email change → takeover"]
        },
        {
            "id": "C008", "name": "CORS + Credentials → Data Theft", "severity": "CRITICAL",
            "requires": ["CORS_MISCONFIGURATION"],
            "steps": ["CORS reflects origin with credentials=true", "Victim visits attacker site", "Data theft"]
        },
        {
            "id": "C010", "name": "SSTI → RCE", "severity": "CRITICAL",
            "requires": ["SSTI"],
            "steps": ["Confirm SSTI", "Escalate to RCE", "Server compromise"]
        },
        {
            "id": "C012", "name": "SQLi → Auth Bypass", "severity": "CRITICAL",
            "requires": ["SQL_INJECTION_ERROR"],
            "steps": ["SQL injection in login", "' OR 1=1--", "Admin access"]
        },
        {
            "id": "C019", "name": "JWT Weak Secret → Admin Takeover", "severity": "CRITICAL",
            "requires": ["JWT_WEAK_SECRET"],
            "steps": ["Cracked JWT secret", "Forge admin token", "Full admin access"]
        },
        {
            "id": "C023", "name": "Mass Assignment → Role Escalation", "severity": "CRITICAL",
            "requires": ["MASS_ASSIGNMENT"],
            "steps": ["Register/update with role=admin", "Server accepts", "Admin access"]
        },
        {
            "id": "C018", "name": "Payment Manipulation → Free Purchase", "severity": "CRITICAL",
            "requires": ["PAYMENT_MANIPULATION"],
            "steps": ["Set price=0 or price=-1", "Complete order", "Free items"]
        },
        {
            "id": "C027", "name": "IDOR on Payment → Financial Fraud", "severity": "CRITICAL",
            "requires": ["IDOR", "PAYMENT_MANIPULATION"],
            "steps": ["IDOR to access other users' payment methods", "Use victim's card", "Financial fraud"]
        },
        {
            "id": "C030", "name": "Race Condition → Negative Balance", "severity": "HIGH",
            "requires": ["RACE_CONDITION"],
            "steps": ["Concurrent withdrawal requests", "Multiple succeed before check", "Negative balance"]
        },
    ]

    def __init__(self, db, logger=None):
        self.db = db
        self.log = logger

    def detect(self) -> List[Dict]:
        """Run chain detection on all current findings"""
        findings = self.db.get_findings(status="verified")
        finding_types = set(f["vuln_type"] for f in findings)

        triggered = []

        for pattern in self.CHAIN_PATTERNS:
            required = set(pattern["requires"])
            # Check if all required bug types are present
            if required.issubset(finding_types):
                # Already detected this chain?
                existing = self.db.conn.execute(
                    "SELECT id FROM chains WHERE chain_id=?", (pattern["id"],)
                ).fetchone()

                if not existing:
                    # Get relevant finding IDs
                    related_ids = [
                        f["id"] for f in findings
                        if f["vuln_type"] in required
                    ]

                    # Save chain
                    self.db.conn.execute("""
                        INSERT INTO chains (chain_id, name, severity, finding_ids, steps, confidence, created_at)
                        VALUES (?,?,?,?,?,?,datetime('now'))
                    """, (
                        pattern["id"], pattern["name"], pattern["severity"],
                        json.dumps(related_ids), json.dumps(pattern["steps"]),
                        88
                    ))
                    self.db.conn.commit()

                    triggered.append(pattern)

                    if self.log:
                        self.log.chain(pattern["name"], pattern["severity"])

        return triggered

    def get_all_chains(self) -> List[Dict]:
        c = self.db.conn.cursor()
        c.execute("SELECT * FROM chains ORDER BY id DESC")
        return [dict(r) for r in c.fetchall()]


# ═══════════════════════════════════════════════════════════
# VERIFIER — 3-Step Finding Verification
# ═══════════════════════════════════════════════════════════

class FindingVerifier:
    """
    3-step verification before any finding is reported:
    1. Reproduce (2/3 attempts must succeed)
    2. Baseline compare (is difference meaningful?)
    3. Confidence score (>= 60 to report)
    """

    def __init__(self, http_client, db, logger=None):
        self.http = http_client
        self.db = db
        self.log = logger

    async def verify(self, finding: dict) -> Dict:
        """Full 3-step verification. Returns updated finding dict."""

        vuln_type = finding.get("vuln_type", "UNKNOWN")
        endpoint = finding.get("endpoint", "")
        method = finding.get("method", "GET")
        proof_req = finding.get("proof_req", "")

        if self.log:
            self.log.info(f"Verifying: {vuln_type} on {endpoint}")

        # Step 1: Reproduce
        reproduce_score = await self._step1_reproduce(finding)

        if reproduce_score < 2:
            if self.log:
                self.log.warn(f"  Verification FAILED (reproduce: {reproduce_score}/3)")
            self.db.verify_finding(finding["id"], 0)
            return {**finding, "status": "false_positive", "confidence": 10}

        # Step 2: Baseline compare
        baseline_meaningful = await self._step2_baseline(finding)

        if not baseline_meaningful:
            if self.log:
                self.log.warn(f"  Verification: baseline difference not meaningful")
            confidence = max(finding.get("confidence", 50) - 20, 30)
        else:
            confidence = finding.get("confidence", 70)

        # Step 3: Confidence score
        final_confidence = self._step3_confidence(finding, reproduce_score, baseline_meaningful)

        status = "verified" if final_confidence >= 60 else "false_positive"
        self.db.verify_finding(finding["id"], final_confidence)

        if self.log:
            emoji = "✅" if status == "verified" else "❌"
            self.log.info(f"  {emoji} {status} (confidence: {final_confidence}%)")

        return {**finding, "status": status, "confidence": final_confidence}

    async def _step1_reproduce(self, finding: dict) -> int:
        """Try to reproduce finding 3 times. Returns number of successes."""
        successes = 0
        endpoint = finding.get("endpoint", "")
        method = finding.get("method", "GET")

        for i in range(3):
            try:
                resp = await self.http.request(method, endpoint, timeout=8)
                if resp and resp.get("status") not in [0, 500, 503]:
                    # For auth bypass — 200 is success
                    if finding.get("vuln_type") in ["AUTH_BYPASS", "BAC_PATH_BYPASS"]:
                        if resp.get("status") == 200:
                            successes += 1
                    # For SQLi — error indicators
                    elif "SQL" in finding.get("vuln_type", ""):
                        body = resp.get("body", "").lower()
                        if any(e in body for e in ["sql", "syntax", "mysql", "ora-"]):
                            successes += 1
                    else:
                        # Generic: non-error response
                        if resp.get("status") in [200, 201]:
                            successes += 1
            except:
                pass
            await asyncio.sleep(0.5)

        return successes

    async def _step2_baseline(self, finding: dict) -> bool:
        """Check if anomaly is meaningful compared to baseline"""
        endpoint = finding.get("endpoint", "")
        baseline = self.db.get_baseline(endpoint)

        if not baseline:
            return True  # No baseline = assume meaningful

        resp = await self.http.request("GET", endpoint, timeout=8)
        if not resp:
            return False

        current_size = len(resp.get("body", ""))
        baseline_size = baseline.get("body_size", 0)
        size_diff = abs(current_size - baseline_size)

        # Meaningful if: size changed significantly OR status changed
        if size_diff > 200:
            return True
        if resp.get("status") != baseline.get("status_code"):
            return True

        return False

    def _step3_confidence(self, finding: dict, reproduce_score: int,
                          baseline_meaningful: bool) -> int:
        """Calculate final confidence score"""
        base = finding.get("confidence", 50)

        # Reproduce bonus
        if reproduce_score == 3:
            base = min(base + 10, 100)
        elif reproduce_score == 2:
            base = min(base + 5, 100)
        else:
            base = max(base - 20, 10)

        # Baseline bonus
        if baseline_meaningful:
            base = min(base + 5, 100)
        else:
            base = max(base - 10, 10)

        # Severity weight
        severity = finding.get("severity", "MEDIUM")
        if severity == "CRITICAL":
            base = min(base + 5, 100)

        return base
