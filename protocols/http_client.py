"""
http_client.py — Async HTTP engine with WAF detection, rate bypass, Tor support
"""
import asyncio
import hashlib
import json
import random
import socket
import time
from typing import Dict, Optional, Tuple, List
from urllib.parse import urljoin, urlparse

try:
    import httpx
    HAS_HTTPX = True
except ImportError:
    import urllib.request
    import urllib.parse
    HAS_HTTPX = False

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/605.1.15",
]

WAF_SIGNATURES = {
    "Cloudflare":     ["cf-ray", "cloudflare", "__cfduid", "cf_clearance"],
    "Akamai":         ["akamai", "ak_bmsc", "bm_sz"],
    "AWS_WAF":        ["awswaf", "x-amzn-requestid", "x-amz-cf-id"],
    "Imperva":        ["x-iinfo", "visid_incap", "incap_ses"],
    "F5_BIG_IP":      ["bigipserver", "ts0", "ts01"],
    "Sucuri":         ["x-sucuri-id", "sucuri"],
    "ModSecurity":    ["mod_security", "modsecurity"],
    "Barracuda":      ["barra_counter_session"],
}

WAF_STATUS_CODES = [403, 406, 429, 503]


class HTTPClient:
    def __init__(self, config: dict = None, logger=None, use_tor: bool = False):
        self.config = config or {}
        self.log = logger
        self.use_tor = use_tor
        self.rate_limit = config.get("rate_limit", 10)  # req/sec
        self.request_delay = 1.0 / self.rate_limit
        self.waf_detected = None
        self.waf_bypass_method = None
        self.consecutive_blocks = 0
        self.adaptive_delay = self.request_delay
        self._session = None
        self._last_request_time = 0

        # Tor proxy
        self.tor_proxy = {
            "http://": "socks5://127.0.0.1:9050",
            "https://": "socks5://127.0.0.1:9050"
        } if use_tor else None

    def _get_headers(self, extra: dict = None, rotate_ua: bool = True) -> Dict:
        headers = {
            "User-Agent": random.choice(USER_AGENTS) if rotate_ua else USER_AGENTS[0],
            "Accept": "application/json, text/html, */*",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "keep-alive",
        }
        if extra:
            headers.update(extra)
        return headers

    def _detect_waf(self, response) -> Optional[str]:
        """Detect WAF from response headers"""
        headers_str = ""
        if hasattr(response, 'headers'):
            headers_str = str(dict(response.headers)).lower()
        body_str = ""
        try:
            if hasattr(response, 'text'):
                body_str = response.text[:500].lower()
        except:
            pass

        combined = headers_str + body_str

        for waf_name, signatures in WAF_SIGNATURES.items():
            for sig in signatures:
                if sig.lower() in combined:
                    return waf_name

        # Check for WAF-like status codes with minimal body
        try:
            status = response.status_code
            if status in WAF_STATUS_CODES:
                body_len = len(body_str)
                if body_len < 100:
                    return "UNKNOWN_WAF"
        except:
            pass

        return None

    def _get_waf_bypass_headers(self, method_num: int = 0) -> Dict:
        """Return different bypass header sets"""
        methods = [
            # Method 0: IP spoofing headers
            {
                "X-Forwarded-For": f"{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}",
                "X-Real-IP": f"{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}",
                "X-Originating-IP": "127.0.0.1",
                "X-Remote-IP": "127.0.0.1",
                "X-Client-IP": "127.0.0.1",
            },
            # Method 1: Custom User-Agent
            {"User-Agent": "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"},
            # Method 2: Referer tricks
            {"Referer": "https://www.google.com/", "X-Forwarded-Host": "www.google.com"},
            # Method 3: Minimal headers
            {"User-Agent": USER_AGENTS[0]},
            # Method 4: Accept variations
            {"Accept": "*/*", "User-Agent": USER_AGENTS[2], "X-Forwarded-For": "127.0.0.1"},
        ]
        return methods[method_num % len(methods)]

    async def _adaptive_delay(self):
        """Adaptive rate limiting based on WAF detection"""
        now = time.time()
        elapsed = now - self._last_request_time
        if elapsed < self.adaptive_delay:
            await asyncio.sleep(self.adaptive_delay - elapsed)
        self._last_request_time = time.time()

    async def request(self, method: str, url: str, headers: dict = None,
                      params: dict = None, data: dict = None, json_body: dict = None,
                      session_token: str = None, cookies: dict = None,
                      timeout: int = 10, retry_on_waf: bool = True) -> Optional[Dict]:
        """
        Make HTTP request with automatic WAF detection and bypass
        Returns: dict with status, headers, body, response_time
        """
        await self._adaptive_delay()

        req_headers = self._get_headers(headers)

        # Add session auth
        if session_token:
            req_headers["Authorization"] = f"Bearer {session_token}"

        # Add WAF bypass if we've already detected one
        if self.waf_detected and self.waf_bypass_method is not None:
            bypass_headers = self._get_waf_bypass_headers(self.waf_bypass_method)
            req_headers.update(bypass_headers)

        t0 = time.time()
        result = None

        try:
            if HAS_HTTPX:
                result = await self._httpx_request(
                    method, url, req_headers, params, data, json_body, cookies, timeout
                )
            elif HAS_REQUESTS:
                result = self._requests_request(
                    method, url, req_headers, params, data, json_body, cookies, timeout
                )
            else:
                result = self._urllib_request(method, url, req_headers, params, timeout)

        except Exception as e:
            if self.log:
                self.log.debug(f"Request error {url}: {e}")
            return {"status": 0, "body": "", "headers": {}, "response_time": 0, "error": str(e)}

        if result:
            elapsed_ms = int((time.time() - t0) * 1000)
            result["response_time"] = elapsed_ms

            # WAF detection
            if not self.waf_detected:
                status = result.get("status", 0)
                if status in WAF_STATUS_CODES or self._detect_waf_from_dict(result):
                    self.waf_detected = self._detect_waf_from_dict(result) or "UNKNOWN_WAF"
                    self.consecutive_blocks += 1
                    if self.log:
                        self.log.warn(f"WAF detected: {self.waf_detected}")

            # Adaptive delay on blocks
            if result.get("status") == 429:
                self.adaptive_delay = min(self.adaptive_delay * 2, 5.0)
                self.consecutive_blocks += 1
                if self.log:
                    self.log.warn(f"Rate limited, increasing delay to {self.adaptive_delay:.1f}s")

                # Try WAF bypass
                if retry_on_waf and self.waf_bypass_method is None:
                    self.waf_bypass_method = 0
                    return await self.request(method, url, headers, params, data,
                                              json_body, session_token, cookies,
                                              timeout, retry_on_waf=False)
            else:
                # Reset consecutive blocks on success
                if self.consecutive_blocks > 0:
                    self.consecutive_blocks = max(0, self.consecutive_blocks - 1)
                if self.adaptive_delay > self.request_delay:
                    self.adaptive_delay = max(self.adaptive_delay * 0.9, self.request_delay)

        return result

    def _detect_waf_from_dict(self, result: dict) -> Optional[str]:
        """Detect WAF from response dict"""
        headers_str = str(result.get("headers", {})).lower()
        body_str = result.get("body", "")[:200].lower()
        combined = headers_str + body_str

        for waf_name, sigs in WAF_SIGNATURES.items():
            for sig in sigs:
                if sig.lower() in combined:
                    return waf_name
        return None

    async def _httpx_request(self, method, url, headers, params, data,
                              json_body, cookies, timeout) -> Dict:
        """httpx-based async request"""
        proxies = self.tor_proxy

        async with httpx.AsyncClient(
            headers=headers,
            verify=False,
            timeout=timeout,
            follow_redirects=True,
            proxies=proxies
        ) as client:
            resp = await client.request(
                method=method.upper(),
                url=url,
                params=params,
                data=data,
                json=json_body,
                cookies=cookies
            )
            return {
                "status": resp.status_code,
                "headers": dict(resp.headers),
                "body": resp.text[:50000],  # Cap at 50KB
                "url": str(resp.url),
                "redirect_chain": [str(r.url) for r in resp.history]
            }

    def _requests_request(self, method, url, headers, params, data,
                           json_body, cookies, timeout) -> Dict:
        """requests-based sync request"""
        import requests as req_lib
        import warnings
        warnings.filterwarnings('ignore')

        proxies = None
        if self.use_tor:
            proxies = {"http": "socks5://127.0.0.1:9050",
                       "https": "socks5://127.0.0.1:9050"}

        resp = req_lib.request(
            method=method.upper(),
            url=url,
            headers=headers,
            params=params,
            data=data,
            json=json_body,
            cookies=cookies,
            timeout=timeout,
            verify=False,
            allow_redirects=True,
            proxies=proxies
        )
        return {
            "status": resp.status_code,
            "headers": dict(resp.headers),
            "body": resp.text[:50000],
            "url": resp.url,
            "redirect_chain": [r.url for r in resp.history]
        }

    def _urllib_request(self, method, url, headers, params, timeout) -> Dict:
        """urllib fallback"""
        import urllib.request as urllib_req
        import ssl
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        req = urllib_req.Request(url, headers=headers, method=method.upper())
        try:
            with urllib_req.urlopen(req, timeout=timeout, context=ctx) as resp:
                return {
                    "status": resp.status,
                    "headers": dict(resp.headers),
                    "body": resp.read(50000).decode("utf-8", errors="replace"),
                    "url": resp.url
                }
        except urllib.error.HTTPError as e:
            return {
                "status": e.code,
                "headers": dict(e.headers) if e.headers else {},
                "body": e.read(1000).decode("utf-8", errors="replace") if e.fp else "",
                "url": url
            }

    def body_hash(self, body: str) -> str:
        """Hash response body structure for baseline comparison"""
        # Remove dynamic values (timestamps, UUIDs) before hashing
        import re
        normalized = re.sub(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}', 'TIMESTAMP', body)
        normalized = re.sub(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
                           'UUID', normalized)
        normalized = re.sub(r'\d{10,13}', 'TIMESTAMP', normalized)
        return hashlib.md5(normalized[:1000].encode()).hexdigest()

    def rotate_tor(self) -> bool:
        """Request new Tor circuit"""
        try:
            s = socket.socket()
            s.connect(("127.0.0.1", 9051))
            s.sendall(b'AUTHENTICATE ""\r\nSIGNAL NEWNYM\r\n')
            time.sleep(2)
            s.close()
            if self.log:
                self.log.info("Tor circuit rotated")
            return True
        except Exception as e:
            if self.log:
                self.log.debug(f"Tor rotation failed: {e}")
            return False
