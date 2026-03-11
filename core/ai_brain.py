
"""
ai_brain.py — AI decision engine (Ollama primary, Groq fallback, Rule-based fallback)
Solves context window problem with smart context trimming
"""
import json
import time
import asyncio
from typing import Optional, Dict, Any, List
from datetime import datetime

try:
    import httpx
    HAS_HTTPX = True
except ImportError:
    import urllib.request
    HAS_HTTPX = False

try:
    from groq import Groq as GroqClient
    HAS_GROQ = True
except ImportError:
    HAS_GROQ = False


class ContextBuilder:
    """
    Smart context builder — solves LLM context window overflow.
    Instead of dumping all 5000 endpoints, we send ONLY:
    - Top 10 untested HIGH priority endpoints
    - Last 5 actions + results
    - Current findings summary (not full body)
    - Relevant YAML rules for current focus
    """

    MAX_NODES_IN_CONTEXT = 15  # Never send more than 15 nodes at once
    MAX_FINDINGS_IN_CONTEXT = 10
    MAX_ACTIONS_IN_CONTEXT = 5

    @staticmethod
    def build(db, rules: dict, focus: str = None) -> str:
        """Build trimmed, relevant context for AI decision"""
        context = {}

        # 1. High-priority untested nodes only
        untested = db.get_untested_nodes(limit=ContextBuilder.MAX_NODES_IN_CONTEXT, min_priority=3)
        context["untested_endpoints"] = [
            {
                "url": n["url"],
                "type": n["node_type"],
                "methods": json.loads(n["method"]) if isinstance(n["method"], str) else n["method"],
                "params": json.loads(n["params"])[:5] if n["params"] else [],  # max 5 params
                "sensitive": bool(n["sensitive"]),
                "priority": n["priority"]
            }
            for n in untested[:ContextBuilder.MAX_NODES_IN_CONTEXT]
        ]

        # 2. Recent findings (summary only, not full HTTP bodies)
        findings = db.get_findings()
        context["findings_summary"] = [
            {
                "id": f["id"],
                "type": f["vuln_type"],
                "severity": f["severity"],
                "endpoint": f["endpoint"],
                "confidence": f["confidence"],
                "status": f["status"]
            }
            for f in findings[:ContextBuilder.MAX_FINDINGS_IN_CONTEXT]
        ]

        # 3. Last 5 AI actions (what was done, avoid repeating)
        recent = db.get_recent_actions(limit=ContextBuilder.MAX_ACTIONS_IN_CONTEXT)
        context["recent_actions"] = [
            {
                "action": a["action"],
                "engine": a["engine"],
                "result_summary": "success" if json.loads(a["result"] or "{}").get("success") else "no_finding"
            }
            for a in recent
        ]

        # 4. Stats
        stats = db.get_stats()
        context["stats"] = stats

        # 5. Relevant rules (only attack_patterns keys, not full payloads)
        if rules.get("patterns"):
            context["available_attack_types"] = list(rules["patterns"].keys())[:20]

        # 6. Focus hint
        if focus:
            context["current_focus"] = focus

        return json.dumps(context, indent=2)


class AIBrain:
    def __init__(self, config: dict, logger=None):
        self.config = config
        self.log = logger
        self.ollama_url = config.get("ollama_url", "http://localhost:11434")
        self.ollama_model = config.get("ollama_model", "llama3:8b")
        self.groq_key = config.get("groq_key")
        self.use_ai = config.get("use_ai", True)
        self.groq_client = None

        if HAS_GROQ and self.groq_key:
            try:
                self.groq_client = GroqClient(api_key=self.groq_key)
            except Exception:
                pass

    def _ollama_available(self) -> bool:
        """Quick check if Ollama is running"""
        try:
            if HAS_HTTPX:
                r = httpx.get(f"{self.ollama_url}/api/tags", timeout=3)
                return r.status_code == 200
            else:
                req = urllib.request.urlopen(f"{self.ollama_url}/api/tags", timeout=3)
                return req.status == 200
        except:
            return False

    def _call_ollama(self, system_prompt: str, user_prompt: str, timeout: int = 15) -> Optional[str]:
        """Call Ollama API"""
        payload = {
            "model": self.ollama_model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ],
            "stream": False,
            "format": "json",
            "options": {"temperature": 0.1, "num_predict": 500}
        }
        try:
            if HAS_HTTPX:
                r = httpx.post(
                    f"{self.ollama_url}/api/chat",
                    json=payload, timeout=timeout
                )
                data = r.json()
                return data["message"]["content"]
            else:
                import urllib.request
                import urllib.parse
                req = urllib.request.Request(
                    f"{self.ollama_url}/api/chat",
                    data=json.dumps(payload).encode(),
                    headers={"Content-Type": "application/json"}
                )
                with urllib.request.urlopen(req, timeout=timeout) as resp:
                    data = json.loads(resp.read())
                    return data["message"]["content"]
        except Exception as e:
            if self.log:
                self.log.debug(f"Ollama error: {e}")
            return None

    def _call_groq(self, system_prompt: str, user_prompt: str) -> Optional[str]:
        """Call Groq API as fallback"""
        if not self.groq_client:
            return None
        try:
            resp = self.groq_client.chat.completions.create(
                model="llama-3.1-70b-versatile",
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt}
                ],
                temperature=0.1,
                max_tokens=500,
                response_format={"type": "json_object"}
            )
            return resp.choices[0].message.content
        except Exception as e:
            if self.log:
                self.log.debug(f"Groq error: {e}")
            return None

    def _parse_json(self, text: str) -> Optional[dict]:
        """Safe JSON parser with cleanup"""
        if not text:
            return None
        try:
            # Clean markdown code blocks
            text = text.strip()
            if "```json" in text:
                text = text.split("```json")[1].split("```")[0]
            elif "```" in text:
                text = text.split("```")[1].split("```")[0]
            return json.loads(text.strip())
        except:
            try:
                # Try finding JSON object in text
                start = text.find("{")
                end = text.rfind("}") + 1
                if start >= 0 and end > start:
                    return json.loads(text[start:end])
            except:
                return None

    def decide(self, context_str: str, system_prompt: str) -> Dict:
        """
        Core AI decision — tries Ollama → Groq → rule-based fallback
        Returns action dict
        """
        if not self.use_ai:
            return self._rule_based_decision(context_str)

        # Try Ollama first
        model_used = "rule-based"
        response_text = None

        if self._ollama_available():
            t0 = time.time()
            response_text = self._call_ollama(system_prompt, context_str, timeout=12)
            elapsed = time.time() - t0
            if response_text:
                model_used = f"ollama:{self.ollama_model}"
                if self.log:
                    self.log.debug(f"Ollama responded in {elapsed:.1f}s")
            else:
                if self.log:
                    self.log.warn("Ollama timeout/error, trying Groq...")

        # Fallback to Groq
        if not response_text and self.groq_client:
            response_text = self._call_groq(system_prompt, context_str)
            if response_text:
                model_used = "groq:llama-3.1-70b"
                if self.log:
                    self.log.debug("Using Groq response")

        # Parse AI response
        if response_text:
            parsed = self._parse_json(response_text)
            if parsed and "action" in parsed:
                parsed["_model"] = model_used
                return parsed

        # Final fallback — rule-based
        if self.log:
            self.log.warn("AI unavailable, using rule-based decisions")
        result = self._rule_based_decision(context_str)
        result["_model"] = "rule-based"
        return result

    def _rule_based_decision(self, context_str: str) -> Dict:
        """
        Rule-based fallback when AI is unavailable.
        Priority: AUTH > PAYMENT > ADMIN > IDOR candidates > others
        """
        try:
            ctx = json.loads(context_str)
        except:
            return {"action": "done", "reason": "context parse error", "confidence": 50}

        endpoints = ctx.get("untested_endpoints", [])
        if not endpoints:
            return {"action": "done", "reason": "all endpoints tested", "confidence": 90}

        # Priority mapping
        priority_map = {
            "AUTH": ("e08_auth_bypass", 9),
            "PAYMENT": ("e17_payment_engine", 9),
            "ADMIN": ("e13_priv_esc_engine", 8),
            "PROFILE": ("e12_idor_engine", 7),
            "API": ("e12_idor_engine", 6),
            "FILE": ("e32_lfi_engine", 6),
            "GRAPHQL": ("e25_graphql_engine", 7),
            "WEBSOCKET": ("e26_websocket_engine", 6),
            "NORMAL": ("e14_bac_engine", 4),
        }

        # Sort by type priority
        sorted_endpoints = sorted(
            endpoints,
            key=lambda e: priority_map.get(e.get("type", "NORMAL"), ("", 3))[1],
            reverse=True
        )

        if sorted_endpoints:
            ep = sorted_endpoints[0]
            ep_type = ep.get("type", "NORMAL")
            engine, _ = priority_map.get(ep_type, ("e14_bac_engine", 4))
            return {
                "action": "run_engine",
                "engine": engine,
                "params": {
                    "endpoint": ep["url"],
                    "method": ep["methods"][0] if ep.get("methods") else "GET",
                    "params": ep.get("params", [])
                },
                "reason": f"Rule-based: testing {ep_type} endpoint",
                "priority": "HIGH" if ep_type in ["AUTH","PAYMENT","ADMIN"] else "MEDIUM",
                "confidence": 65
            }

        return {"action": "done", "reason": "no more endpoints", "confidence": 80}

    def analyze_response(self, request_info: dict, response_info: dict,
                         baseline: dict = None, vuln_type: str = None) -> Dict:
        """AI analyzes HTTP response for vulnerability indicators"""
        # Simple heuristic analysis (works without AI)
        result = {
            "is_vulnerability": False,
            "confidence": 0,
            "vuln_type": vuln_type or "UNKNOWN",
            "reason": ""
        }

        resp_body = response_info.get("body", "")
        resp_status = response_info.get("status", 200)
        resp_size = len(resp_body)

        # Compare with baseline
        if baseline:
            baseline_size = baseline.get("body_size", 0)
            baseline_status = baseline.get("status_code", 200)

            size_diff = abs(resp_size - baseline_size)
            status_changed = resp_status != baseline_status

            if status_changed and resp_status == 200 and baseline_status in [401, 403]:
                result["is_vulnerability"] = True
                result["confidence"] = 85
                result["reason"] = "Status changed from auth-required to 200"
                return result

            if size_diff > 500 and vuln_type == "IDOR":
                result["is_vulnerability"] = True
                result["confidence"] = 75
                result["reason"] = f"Response size increased by {size_diff} bytes"
                return result

        # Keyword-based detection
        error_indicators = ["sql syntax", "mysql error", "ora-", "pg_query",
                           "unclosed quotation", "invalid input syntax"]
        for indicator in error_indicators:
            if indicator.lower() in resp_body.lower():
                result["is_vulnerability"] = True
                result["confidence"] = 80
                result["vuln_type"] = "SQL_INJECTION"
                result["reason"] = f"SQL error indicator: {indicator}"
                return result

        sensitive_data = ["password", "secret", "api_key", "access_token", "private_key"]
        for keyword in sensitive_data:
            if keyword in resp_body.lower() and resp_status == 200:
                result["is_vulnerability"] = True
                result["confidence"] = 70
                result["vuln_type"] = "SENSITIVE_DATA_EXPOSURE"
                result["reason"] = f"Sensitive keyword in response: {keyword}"
                return result

        return result

    def score_finding(self, finding: dict) -> int:
        """Score finding confidence 0-100"""
        score = finding.get("confidence", 50)

        # Boost for critical vuln types
        critical_types = ["IDOR", "AUTH_BYPASS", "JWT_BYPASS", "SQL_INJECTION", "SSRF"]
        if finding.get("vuln_type") in critical_types:
            score = min(score + 10, 100)

        # Reduce for common FPs
        if finding.get("severity") == "INFO":
            score = max(score - 20, 10)

        return score

    def generate_poc(self, finding: dict) -> str:
        """Generate proof-of-concept Python code for a finding"""
        vuln_type = finding.get("vuln_type", "UNKNOWN")
        endpoint = finding.get("endpoint", "/")
        method = finding.get("method", "GET")
        param = finding.get("param", "id")

        poc_templates = {
            "IDOR": f'''#!/usr/bin/env python3
"""PoC: IDOR on {endpoint}"""
import requests

TARGET = "{endpoint}"
# Session tokens
USER_A_TOKEN = "USER_A_TOKEN_HERE"
USER_B_TOKEN = "USER_B_TOKEN_HERE"

# Get User A's own data first
r1 = requests.get(TARGET, headers={{"Authorization": f"Bearer {{USER_A_TOKEN}}"}})
user_a_data = r1.json()
print("[*] User A data:", user_a_data)

# Try to access User B's data with User A's token
user_b_id = "USER_B_ID_HERE"
r2 = requests.get(TARGET.replace("USER_A_ID", user_b_id),
                  headers={{"Authorization": f"Bearer {{USER_A_TOKEN}}"}})
print("[*] IDOR attempt status:", r2.status_code)
if r2.status_code == 200:
    print("[+] VULNERABLE: User A can access User B's data!")
    print(r2.json())
''',
            "AUTH_BYPASS": f'''#!/usr/bin/env python3
"""PoC: Auth Bypass on {endpoint}"""
import requests

TARGET = "{endpoint}"

# Test without authentication
r = requests.{method.lower()}(TARGET)
print(f"[*] No-auth status: {{r.status_code}}")
if r.status_code == 200:
    print("[+] VULNERABLE: Endpoint accessible without authentication!")
    print(r.text[:500])
''',
            "SQL_INJECTION": f'''#!/usr/bin/env python3
"""PoC: SQL Injection on {endpoint} param: {param}"""
import requests

TARGET = "{endpoint}"
PAYLOADS = ["'", "' OR '1'='1", "' OR 1=1--", "1' AND SLEEP(5)--"]

for payload in PAYLOADS:
    r = requests.{method.lower()}(TARGET, params={{"{param}": payload}})
    print(f"[*] Payload: {{payload}} → Status: {{r.status_code}} Size: {{len(r.text)}}")
    if any(e in r.text.lower() for e in ["sql", "mysql", "syntax error", "ora-"]):
        print(f"[+] VULNERABLE with payload: {{payload}}")
        break
''',
        }

        template = poc_templates.get(vuln_type, f'''#!/usr/bin/env python3
"""PoC: {vuln_type} on {endpoint}"""
import requests

TARGET = "{endpoint}"
# Add your specific exploit here
r = requests.{method.lower()}(TARGET)
print(f"Status: {{r.status_code}}")
print(r.text[:1000])
''')
        return template

    def write_executive_summary(self, stats: dict, findings: list) -> str:
        """Generate executive summary text"""
        critical = sum(1 for f in findings if f.get("severity") == "CRITICAL")
        high = sum(1 for f in findings if f.get("severity") == "HIGH")
        medium = sum(1 for f in findings if f.get("severity") == "MEDIUM")

        severity = "CRITICAL" if critical > 0 else "HIGH" if high > 0 else "MEDIUM" if medium > 0 else "LOW"

        summary = f"""
Security Assessment Executive Summary
=====================================
Overall Risk Level: {severity}

{critical} Critical, {high} High, and {medium} Medium severity vulnerabilities were identified.

{'CRITICAL FINDINGS REQUIRE IMMEDIATE REMEDIATION.' if critical > 0 else ''}
{'HIGH severity findings should be addressed within 30 days.' if high > 0 else ''}

Total endpoints discovered: {stats.get('total_nodes', 0)}
Endpoints tested: {stats.get('tested_nodes', 0)}
Total findings: {stats.get('total_findings', 0)}
Verified findings: {stats.get('verified_findings', 0)}
Attack chains identified: {stats.get('chains', 0)}
        """
        return summary.strip()
