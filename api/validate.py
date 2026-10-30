"""
QR-Shield — Vercel Serverless Validation Endpoint
===================================================
Mirrors the AWS Lambda validation logic using Python 3.11 stdlib.

Endpoint : POST /api/validate
Payload  : { "url": "https://example.com" }
Response : JSON with verdict, Risk_Score, Redirect_Chain, Threat_Flags, etc.

Architecture:
  • Multi-Hop Redirect Tracer (urllib stdlib, max 5 hops, 2.5s timeout per hop)
  • Heuristic Phishing Engine (8 deterministic rules R-01 through R-08)
  • URLhaus Threat Intelligence API (abuse.ch keyless endpoint)
  • In-Memory TTL Cache (for warm execution context)
  • CORS-enabled for browser scanners
"""

from http.server import BaseHTTPRequestHandler
import hashlib
import json
import logging
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

# Configure logging
logger = logging.getLogger("qr_shield_vercel")
logger.setLevel(logging.INFO)

# In-memory L1 cache for serverless execution context: {url_hash: {"payload": dict, "ttl": float}}
_WARM_CACHE: dict[str, dict[str, Any]] = {}
CACHE_TTL = 86_400  # 24 hours

# Heuristic constants matching PRD Section 7
SUSPICIOUS_TLDS: set[str] = {".xyz", ".top", ".zip", ".click", ".tk", ".gq", ".work"}
PHISHING_KEYWORDS: list[str] = ["kyc", "verify", "reward", "claim", "login", "update-pan"]
URL_SHORTENER_DOMAINS: set[str] = {
    "bit.ly", "t.co", "tinyurl.com", "goo.gl", "is.gd", "ow.ly",
    "buff.ly", "shorturl.at", "rb.gy", "cutt.ly",
}
IPV4_RE = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")

MAX_HOPS: int = 5
HOP_TIMEOUT: float = 2.5
URLHAUS_TIMEOUT: float = 2.0
URLHAUS_API: str = "https://urlhaus-api.abuse.ch/v1/url/"

CORS_HEADERS = {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
}


def _trace_redirects(url: str) -> tuple[str, int, list[str]]:
    """Follow HTTP redirects manually using HEAD then GET fallback.

    Args:
        url: Initial scanned QR URL.

    Returns:
        tuple of (final_url, hop_count, redirect_chain_urls).
    """
    redirect_codes = {301, 302, 303, 307, 308}
    chain: list[str] = [url]
    current = url
    hops = 0

    for _ in range(MAX_HOPS):
        location = None
        status = None

        # 1. Attempt HEAD
        try:
            req = urllib.request.Request(current, method="HEAD")
            req.add_header("User-Agent", "QR-Shield/1.0")
            resp = urllib.request.urlopen(req, timeout=HOP_TIMEOUT)
            status = resp.status
            location = resp.headers.get("Location")
            resp.close()
        except urllib.error.HTTPError as exc:
            status = exc.code
            location = exc.headers.get("Location") if exc.headers else None
            # Fallback to GET on 405 Method Not Allowed
            if status == 405:
                try:
                    req = urllib.request.Request(current, method="GET")
                    req.add_header("User-Agent", "QR-Shield/1.0")
                    resp = urllib.request.urlopen(req, timeout=HOP_TIMEOUT)
                    status = resp.status
                    location = resp.headers.get("Location")
                    resp.close()
                except urllib.error.HTTPError as get_exc:
                    status = get_exc.code
                    location = get_exc.headers.get("Location") if get_exc.headers else None
                except Exception:
                    break
        except Exception:
            break

        if status in redirect_codes and location:
            location = urllib.parse.urljoin(current, location)
            hops += 1
            chain.append(location)
            current = location
        else:
            break

    return current, hops, chain


def _heuristic_scan(final_url: str, hops: int, chain: list[str]) -> tuple[int, list[dict[str, Any]]]:
    """Inspect resolved URL against the 8-rule threat matrix.

    Returns:
        tuple of (raw_score, list_of_flag_dicts).
    """
    parsed = urllib.parse.urlparse(final_url)
    hostname: str = parsed.hostname or ""
    netloc: str = parsed.netloc or ""
    scheme: str = parsed.scheme or ""
    url_lower: str = final_url.lower()
    tld: str = "." + hostname.rsplit(".", 1)[-1] if "." in hostname else ""

    score = 0
    flags: list[dict[str, Any]] = []

    # R-02: Raw IPv4 hostname (+50)
    if IPV4_RE.match(hostname):
        score += 50
        flags.append({
            "rule": "R-02",
            "weight": 50,
            "description": "Destination uses a raw IP address instead of a verified domain",
        })

    # R-03: '@' Credential Harvesting in Netloc (+45)
    if "@" in netloc:
        score += 45
        flags.append({
            "rule": "R-03",
            "weight": 45,
            "description": "Credential harvesting '@' syntax detected in URL authority",
        })

    # R-04: Punycode / Homograph Domain (+40)
    if "xn--" in hostname:
        score += 40
        flags.append({
            "rule": "R-04",
            "weight": 40,
            "description": "Punycode (xn--) internationalized domain detected (possible homograph spoofing)",
        })

    # R-05: Suspicious Top-Level Domain (+25)
    if tld in SUSPICIOUS_TLDS:
        score += 25
        flags.append({
            "rule": "R-05",
            "weight": 25,
            "description": f"Domain registered with suspicious high-risk TLD '{tld}'",
        })

    # R-06: Phishing Lure Keywords (+20 per keyword)
    matched_kws = [kw for kw in PHISHING_KEYWORDS if kw in url_lower]
    for kw in matched_kws:
        score += 20
        flags.append({
            "rule": "R-06",
            "weight": 20,
            "description": f"Contains high-risk phishing lure keyword: '{kw}'",
        })

    # R-07: Unencrypted HTTP Scheme (+20)
    if scheme == "http":
        score += 20
        flags.append({
            "rule": "R-07",
            "weight": 20,
            "description": "Unencrypted HTTP protocol used instead of HTTPS",
        })

    # R-08: URL Shortener or Multi-Hop Chain >= 2 hops (+15)
    first_host = urllib.parse.urlparse(chain[0]).hostname or ""
    if first_host in URL_SHORTENER_DOMAINS or hops >= 2:
        score += 15
        desc = (
            f"Known URL shortener service '{first_host}' masks destination"
            if first_host in URL_SHORTENER_DOMAINS
            else f"Obfuscated behind {hops} redirect hop(s)"
        )
        flags.append({
            "rule": "R-08",
            "weight": 15,
            "description": desc,
        })

    return score, flags


def _urlhaus_lookup(final_url: str) -> tuple[int, dict[str, Any] | None]:
    """Query the URLhaus public API for threat intelligence.

    Returns:
        tuple of (score_delta, flag_dict_or_None).
    """
    try:
        data = urllib.parse.urlencode({"url": final_url}).encode("utf-8")
        req = urllib.request.Request(URLHAUS_API, data=data, method="POST")
        req.add_header("User-Agent", "QR-Shield/1.0")
        resp = urllib.request.urlopen(req, timeout=URLHAUS_TIMEOUT)
        body = json.loads(resp.read().decode("utf-8"))
        resp.close()

        if body.get("query_status") == "listed":
            return 100, {
                "rule": "R-01",
                "weight": 100,
                "description": "Listed in abuse.ch URLhaus Threat Feed (active malware/phishing distribution)",
            }
    except Exception as exc:
        logger.warning("URLhaus lookup error (graceful degradation): %s", exc)

    return 0, None


def _compute_verdict(score: int) -> str:
    """Map risk score to SAFE, SUSPICIOUS, or MALICIOUS."""
    if score <= 24:
        return "SAFE"
    if score <= 59:
        return "SUSPICIOUS"
    return "MALICIOUS"


def validate_url(url: str) -> dict[str, Any]:
    """Execute the full QR-Shield validation pipeline."""
    start_time = time.time()
    url_hash = hashlib.sha256(url.encode("utf-8")).hexdigest()

    # Cache lookup
    now = time.time()
    if url_hash in _WARM_CACHE:
        cached = _WARM_CACHE[url_hash]
        if cached.get("ttl", 0) > now:
            result = dict(cached["payload"])
            result["cache_hit"] = True
            result["execution_ms"] = round((time.time() - start_time) * 1000, 2)
            return result
        else:
            del _WARM_CACHE[url_hash]

    # Trace redirects
    final_url, hops, chain = _trace_redirects(url)

    # Heuristic scoring
    heuristic_score, flags = _heuristic_scan(final_url, hops, chain)

    # Threat feed
    urlhaus_score, urlhaus_flag = _urlhaus_lookup(final_url)
    if urlhaus_flag:
        flags.insert(0, urlhaus_flag)

    # Aggregated score & verdict
    total_score = min(100, heuristic_score + urlhaus_score)
    verdict = _compute_verdict(total_score)

    result_payload: dict[str, Any] = {
        "Input_QR_URL": url,
        "Final_Resolved_URL": final_url,
        "Redirect_Hops": hops,
        "Redirect_Chain": chain,
        "Risk_Score": total_score,
        "Verdict": verdict,
        "Threat_Flags": [f["description"] for f in flags],
        "threat_details": flags,
        "cache_hit": False,
        "execution_ms": round((time.time() - start_time) * 1000, 2),
        "aws_request_id": f"vercel-{int(start_time*1000)}",
    }

    # Cache write
    _WARM_CACHE[url_hash] = {
        "payload": result_payload,
        "ttl": now + CACHE_TTL,
    }

    return result_payload


class handler(BaseHTTPRequestHandler):
    """Vercel Python serverless HTTP request handler."""

    def _send_cors(self, status: int = 200, body: dict | None = None) -> None:
        self.send_response(status)
        for k, v in CORS_HEADERS.items():
            self.send_header(k, v)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        if body is not None:
            self.wfile.write(json.dumps(body).encode("utf-8"))

    def do_OPTIONS(self) -> None:
        """Handle CORS preflight requests."""
        self._send_cors(200, {"message": "CORS preflight OK"})

    def do_POST(self) -> None:
        """Handle validation requests."""
        content_length = int(self.headers.get("Content-Length", 0))
        if content_length <= 0:
            self._send_cors(400, {"error": "Invalid payload. Provide a valid 'url' starting with http:// or https://"})
            return

        try:
            raw_body = self.rfile.read(content_length).decode("utf-8")
            data = json.loads(raw_body)
        except Exception:
            self._send_cors(400, {"error": "Invalid JSON in request body."})
            return

        url = data.get("url") if isinstance(data, dict) else None
        if not url or not isinstance(url, str) or not (url.startswith("http://") or url.startswith("https://")):
            self._send_cors(400, {"error": "Invalid payload. Provide a valid 'url' starting with http:// or https://"})
            return

        result = validate_url(url)
        self._send_cors(200, result)
