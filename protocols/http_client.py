"""
http_client.py — Async HTTP engine
FIXES:
- BUG7: sync requests no longer called from async context (uses run_in_executor)
- BUG5: DNS errors logged at debug level only
- Proper async throughout
"""
import asyncio
import hashlib
import json
import random
import re
import socket
import time
from typing import Dict, Optional

try:
    import httpx
    HAS_HTTPX = True
except ImportError:
    HAS_HTTPX = False

try:
    import requests as _requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/119.0.0.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
]

WAF_SIGNATURES = {
    "Cloudflare":  ["cf-ray","cloudflare","__cfduid","cf_clearance"],
    "Akamai":      ["akamai","ak_bmsc","bm_sz"],
    "AWS_WAF":     ["awswaf","x-amzn-requestid"],
    "Imperva":     ["x-iinfo","visid_incap","incap_ses"],
    "F5":          ["bigipserver","ts0"],
    "Sucuri":      ["x-sucuri-id","sucuri"],
    "ModSecurity": ["mod_security","modsecurity"],
}


class HTTPClient:
    def __init__(self, config=None, logger=None, use_tor=False):
        self.config = config or {}
        self.log = logger
        self.use_tor = use_tor
        self.rate_limit = self.config.get("rate_limit", 5)
        self.base_delay = 1.0 / max(self.rate_limit, 1)
        self.adaptive_delay = self.base_delay
        self.waf_detected = None
        self.consecutive_blocks = 0
        self._last_req = 0
        self._lock = asyncio.Lock()

    def _headers(self, extra=None):
        h = {
            "User-Agent": random.choice(USER_AGENTS),
            "Accept": "application/json, text/html, */*",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "keep-alive",
        }
        if extra:
            h.update(extra)
        return h

    def _bypass_headers(self, n=0):
        methods = [
            {"X-Forwarded-For": f"{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}.1",
             "X-Real-IP": "127.0.0.1", "X-Client-IP": "127.0.0.1"},
            {"User-Agent": "Mozilla/5.0 (compatible; Googlebot/2.1)"},
            {"Referer": "https://www.google.com/", "User-Agent": USER_AGENTS[0]},
        ]
        return methods[n % len(methods)]

    async def _throttle(self):
        async with self._lock:
            now = time.time()
            wait = self.adaptive_delay - (now - self._last_req)
            if wait > 0:
                await asyncio.sleep(wait)
            self._last_req = time.time()

    async def request(self, method, url, headers=None, params=None,
                      data=None, json_body=None, session_token=None,
                      cookies=None, timeout=10, retry_on_block=True) -> Optional[Dict]:
        await self._throttle()

        req_headers = self._headers(headers)
        if session_token:
            req_headers["Authorization"] = f"Bearer {session_token}"
        if self.waf_detected and self.consecutive_blocks > 0:
            req_headers.update(self._bypass_headers(self.consecutive_blocks))

        try:
            result = await self._do_request(method, url, req_headers,
                                             params, data, json_body, cookies, timeout)
        except Exception as e:
            # BUG5 fix: DNS errors at debug level only
            if self.log:
                self.log.debug(f"Request error {url}: {type(e).__name__}")
            return {"status": 0, "body": "", "headers": {}, "response_time": 0, "error": str(e)}

        if result:
            status = result.get("status", 0)
            # Detect WAF
            if not self.waf_detected:
                detected = self._detect_waf(result)
                if detected:
                    self.waf_detected = detected
                    if self.log:
                        self.log.warn(f"WAF detected: {detected}")
            # Rate limit handling
            if status == 429:
                self.consecutive_blocks += 1
                self.adaptive_delay = min(self.adaptive_delay * 2, 8.0)
                if self.log:
                    self.log.warn(f"Rate limited — delay: {self.adaptive_delay:.1f}s")
                if retry_on_block and self.consecutive_blocks < 3:
                    await asyncio.sleep(self.adaptive_delay)
                    return await self.request(method, url, headers, params, data,
                                              json_body, session_token, cookies,
                                              timeout, retry_on_block=False)
            elif status > 0:
                self.consecutive_blocks = max(0, self.consecutive_blocks - 1)
                if self.adaptive_delay > self.base_delay:
                    self.adaptive_delay = max(self.adaptive_delay * 0.85, self.base_delay)

        return result

    async def _do_request(self, method, url, headers, params,
                           data, json_body, cookies, timeout) -> Dict:
        if HAS_HTTPX:
            return await self._httpx(method, url, headers, params, data, json_body, cookies, timeout)
        elif HAS_REQUESTS:
            # BUG7 fix: run sync requests in executor, not directly in async
            loop = asyncio.get_event_loop()
            return await loop.run_in_executor(
                None,
                lambda: self._requests_sync(method, url, headers, params, data, json_body, cookies, timeout)
            )
        else:
            loop = asyncio.get_event_loop()
            return await loop.run_in_executor(
                None, lambda: self._urllib_sync(method, url, headers, timeout)
            )

    async def _httpx(self, method, url, headers, params, data, json_body, cookies, timeout) -> Dict:
        proxies = {"http://": "socks5://127.0.0.1:9050",
                   "https://": "socks5://127.0.0.1:9050"} if self.use_tor else None
        import ssl
        async with httpx.AsyncClient(
            headers=headers, verify=False, timeout=timeout,
            follow_redirects=True, proxies=proxies
        ) as client:
            resp = await client.request(
                method=method.upper(), url=url,
                params=params, data=data, json=json_body, cookies=cookies
            )
            return {
                "status": resp.status_code,
                "headers": dict(resp.headers),
                "body": resp.text[:40000],
                "url": str(resp.url),
            }

    def _requests_sync(self, method, url, headers, params, data, json_body, cookies, timeout) -> Dict:
        import warnings, urllib3
        warnings.filterwarnings("ignore")
        urllib3.disable_warnings()
        proxies = None
        if self.use_tor:
            proxies = {"http": "socks5://127.0.0.1:9050",
                       "https": "socks5://127.0.0.1:9050"}
        resp = _requests.request(
            method=method.upper(), url=url, headers=headers,
            params=params, data=data, json=json_body, cookies=cookies,
            timeout=timeout, verify=False, allow_redirects=True, proxies=proxies
        )
        return {
            "status": resp.status_code,
            "headers": dict(resp.headers),
            "body": resp.text[:40000],
            "url": str(resp.url),
        }

    def _urllib_sync(self, method, url, headers, timeout) -> Dict:
        import urllib.request as ur, ssl
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        req = ur.Request(url, headers=headers, method=method.upper())
        try:
            with ur.urlopen(req, timeout=timeout, context=ctx) as r:
                return {"status": r.status, "headers": dict(r.headers),
                        "body": r.read(40000).decode("utf-8","replace"), "url": r.url}
        except Exception as e:
            code = getattr(e, "code", 0)
            return {"status": code, "headers": {}, "body": "", "url": url}

    def _detect_waf(self, result) -> Optional[str]:
        combined = (str(result.get("headers",{})) + result.get("body","")[:300]).lower()
        for name, sigs in WAF_SIGNATURES.items():
            if any(s in combined for s in sigs):
                return name
        return None

    def body_hash(self, body: str) -> str:
        normalized = re.sub(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}', 'TS', body)
        normalized = re.sub(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', 'UUID', normalized)
        normalized = re.sub(r'\d{10,13}', 'TS', normalized)
        return hashlib.md5(normalized[:800].encode()).hexdigest()

    def rotate_tor(self) -> bool:
        try:
            s = socket.socket()
            s.connect(("127.0.0.1", 9051))
            s.sendall(b'AUTHENTICATE ""\r\nSIGNAL NEWNYM\r\n')
            time.sleep(2)
            s.close()
            if self.log: self.log.info("Tor circuit rotated")
            return True
        except:
            return False
