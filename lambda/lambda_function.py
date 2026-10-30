"""
QR-Shield Lambda Function – Dynamic QR Code Threat Validator
=============================================================

This Lambda function implements the core QR-Shield pipeline:
  1. Input Parsing & Validation       (FR-01, FR-02)
  2. SHA-256 Cache Lookup              (FR-03)
  3. Multi-Hop Redirect Tracer         (FR-04)
  4. Heuristic Phishing Engine         (FR-05)
  5. URLhaus Threat Feed Integration   (FR-06)
  6. Risk Scoring & Verdict            (FR-07)
  7. Cache Write & Response Generation

Runtime  : Python 3.11 (standard library + boto3 only)
Memory   : 128 MB
Timeout  : 6 seconds
"""

import hashlib
import json
import logging
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

import boto3
from botocore.exceptions import ClientError

# ---------------------------------------------------------------------------
# Logging Configuration
# ---------------------------------------------------------------------------
logger = logging.getLogger("qr_shield")
logger.setLevel(logging.INFO)

# ---------------------------------------------------------------------------
# Module-level AWS resources (reused across warm invocations)
# ---------------------------------------------------------------------------
DYNAMODB_ENDPOINT: str | None = os.environ.get("DYNAMODB_ENDPOINT")
TABLE_NAME: str = os.environ.get("DYNAMODB_TABLE", "QRThreatCache")

_dynamodb_kwargs: dict[str, Any] = {"region_name": os.environ.get("AWS_DEFAULT_REGION", "us-east-1")}
if DYNAMODB_ENDPOINT:
    _dynamodb_kwargs["endpoint_url"] = DYNAMODB_ENDPOINT

try:
    dynamodb = boto3.resource("dynamodb", **_dynamodb_kwargs)
    table = dynamodb.Table(TABLE_NAME)
except Exception as e:
    logger.warning("Could not initialize DynamoDB resource at module load: %s", e)
    dynamodb = None
    table = None

# ---------------------------------------------------------------------------
# L1 warm-container memory cache  {url_hash: {"payload": dict, "ttl": int}}
# ---------------------------------------------------------------------------
_warm_cache: dict[str, dict[str, Any]] = {}

# ---------------------------------------------------------------------------
# CORS headers applied to every response
# ---------------------------------------------------------------------------
CORS_HEADERS: dict[str, str] = {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Headers": "Content-Type",
    "Access-Control-Allow-Methods": "POST, OPTIONS",
}

# ---------------------------------------------------------------------------
# Heuristic-engine constants (PRD Section 7)
# ---------------------------------------------------------------------------
SUSPICIOUS_TLDS: set[str] = {".xyz", ".top", ".zip", ".click", ".tk", ".gq", ".work"}
PHISHING_KEYWORDS: list[str] = ["kyc", "verify", "reward", "claim", "login", "update-pan"]
URL_SHORTENER_DOMAINS: set[str] = {
    "bit.ly", "t.co", "tinyurl.com", "goo.gl", "is.gd", "ow.ly",
    "buff.ly", "shorturl.at", "rb.gy", "cutt.ly",
}
IPV4_RE = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")

# Network & Timeout Bounds (NFR Section 5)
MAX_HOPS: int = 5
HOP_TIMEOUT: float = 2.5
URLHAUS_TIMEOUT: float = 2.0
URLHAUS_API: str = "https://urlhaus-api.abuse.ch/v1/url/"
CACHE_TTL: int = 86_400  # 24 hours


# ===================================================================
# Helper: build API-Gateway-compatible JSON response
# ===================================================================
def _api_response(status_code: int, body: dict) -> dict:
    """Return a properly formatted API Gateway proxy response."""
    return {
        "statusCode": status_code,
        "headers": {**CORS_HEADERS, "Content-Type": "application/json"},
        "body": json.dumps(body),
    }


# ===================================================================
# Step 1 – Input Parsing & Validation (FR-01, FR-02)
# ===================================================================
def _parse_and_validate(event: dict) -> tuple[str | None, dict | None]:
    """Extract and validate the ``url`` field from the incoming event."""
    body: Any = event
    if "body" in event:
        raw_body = event["body"]
        if isinstance(raw_body, str):
            try:
                body = json.loads(raw_body)
            except (json.JSONDecodeError, TypeError):
                return None, _api_response(
                    400,
                    {"error": "Invalid payload. Provide a valid 'url' starting with http:// or https://"},
                )
        elif isinstance(raw_body, dict):
            body = raw_body
        else:
            return None, _api_response(
                400,
                {"error": "Invalid payload. Provide a valid 'url' starting with http:// or https://"},
            )

    url: str | None = body.get("url") if isinstance(body, dict) else None
    if not url or not isinstance(url, str) or not (url.startswith("http://") or url.startswith("https://")):
        return None, _api_response(
            400,
            {"error": "Invalid payload. Provide a valid 'url' starting with http:// or https://"},
        )

    return url, None


# ===================================================================
# Step 2 – SHA-256 Cache Lookup (FR-03)
# ===================================================================
def _cache_lookup(url_hash: str) -> dict | None:
    """Check L1 warm memory cache, then DynamoDB table for cached analysis."""
    now = int(time.time())

    # --- L1: warm-container memory ---
    if url_hash in _warm_cache:
        cached = _warm_cache[url_hash]
        if cached.get("ttl", 0) > now:
            logger.info("L1 warm cache hit for %s", url_hash[:12])
            cached_body = dict(cached.get("payload", {}))
            cached_body["cache_hit"] = True
            return cached_body
        else:
            del _warm_cache[url_hash]

    # --- L2: DynamoDB ---
    if table is not None:
        try:
            response = table.get_item(Key={"url_hash": url_hash})
            item = response.get("Item")
            if item and int(item.get("ttl", 0)) > now:
                logger.info("DynamoDB cache hit for %s", url_hash[:12])
                payload = json.loads(item["payload"]) if isinstance(item["payload"], str) else item["payload"]
                payload["cache_hit"] = True
                _warm_cache[url_hash] = {"payload": payload, "ttl": int(item["ttl"])}
                return payload
        except Exception as exc:
            logger.warning("DynamoDB GetItem error: %s", exc)

    return None


# ===================================================================
# Step 3 – Multi-Hop Redirect Tracer (FR-04)
# ===================================================================
def _trace_redirects(url: str) -> tuple[str, int, list[str]]:
    """Follow HTTP redirects manually to trace the full landing chain."""
    redirect_codes = {301, 302, 303, 307, 308}
    chain: list[str] = [url]
    current = url
    hops = 0

    for _ in range(MAX_HOPS):
        location = None
        status = None

        # Try HEAD first
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
            if status == 405:  # Method Not Allowed -> fallback to GET
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


# ===================================================================
# Step 4 – Heuristic Phishing Engine (FR-05)
# ===================================================================
def _heuristic_scan(
    final_url: str,
    hops: int,
    chain: list[str],
) -> tuple[int, list[dict[str, Any]]]:
    """Evaluate resolved destination against the deterministic threat matrix."""
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

    # R-04: Punycode 'xn--' in hostname (+40)
    if "xn--" in hostname:
        score += 40
        flags.append({
            "rule": "R-04",
            "weight": 40,
            "description": "Punycode (xn--) internationalized domain detected (possible homograph spoofing)",
        })

    # R-05: Suspicious TLDs (+25)
    if tld in SUSPICIOUS_TLDS:
        score += 25
        flags.append({
            "rule": "R-05",
            "weight": 25,
            "description": f"Domain registered with suspicious high-risk TLD '{tld}'",
        })

    # R-06: Phishing keywords (+20 per keyword)
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

    # R-08: URL shortener domain or >= 2 redirect hops (+15)
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


# ===================================================================
# Step 5 – URLhaus Threat Feed (FR-06)
# ===================================================================
def _urlhaus_lookup(final_url: str) -> tuple[int, dict[str, Any] | None]:
    """Query abuse.ch URLhaus threat intelligence API."""
    try:
        data = urllib.parse.urlencode({"url": final_url}).encode("utf-8")
        req = urllib.request.Request(URLHAUS_API, data=data, method="POST")
        req.add_header("User-Agent", "QR-Shield/1.0")
        resp = urllib.request.urlopen(req, timeout=URLHAUS_TIMEOUT)
        result = json.loads(resp.read().decode("utf-8"))
        resp.close()

        if result.get("query_status") == "listed":
            return 100, {
                "rule": "R-01",
                "weight": 100,
                "description": "Listed in abuse.ch URLhaus Threat Feed (active malware/phishing distribution)",
            }
    except Exception as exc:
        logger.warning("URLhaus lookup error (graceful degradation): %s", exc)

    return 0, None


# ===================================================================
# Step 6 – Risk Scoring & Verdict (FR-07)
# ===================================================================
def _compute_verdict(score: int) -> str:
    """Map numeric risk score to strict safety verdict."""
    if score <= 24:
        return "SAFE"
    if score <= 59:
        return "SUSPICIOUS"
    return "MALICIOUS"


# ===================================================================
# Step 7 – Cache Write
# ===================================================================
def _cache_write(url_hash: str, payload: dict, ttl: int) -> None:
    """Store scan verdict in L1 memory and L2 DynamoDB."""
    _warm_cache[url_hash] = {"payload": payload, "ttl": ttl}

    if table is not None:
        try:
            table.put_item(
                Item={
                    "url_hash": url_hash,
                    "payload": json.dumps(payload),
                    "ttl": ttl,
                }
            )
        except Exception as exc:
            logger.warning("DynamoDB PutItem error: %s", exc)


# ===================================================================
# Lambda Handler
# ===================================================================
def lambda_handler(event: dict, context: Any) -> dict:
    """AWS Lambda entry-point for QR-Shield URL validation."""
    start_ms = time.time() * 1000

    # CORS preflight handling
    http_method = event.get("httpMethod") or event.get("requestContext", {}).get("http", {}).get("method", "")
    if http_method == "OPTIONS":
        return _api_response(200, {"message": "CORS preflight OK"})

    # 1. Parse & validate
    url, error_resp = _parse_and_validate(event)
    if error_resp:
        return error_resp

    # 2. Cache lookup
    url_hash = hashlib.sha256(url.encode("utf-8")).hexdigest()
    cached = _cache_lookup(url_hash)
    if cached:
        cached["execution_ms"] = round(time.time() * 1000 - start_ms, 2)
        cached["aws_request_id"] = getattr(context, "aws_request_id", "cached-execution")
        return _api_response(200, cached)

    # 3. Trace redirects
    final_url, hops, chain = _trace_redirects(url)

    # 4. Heuristic phishing scan
    heuristic_score, flags = _heuristic_scan(final_url, hops, chain)

    # 5. URLhaus threat feed
    urlhaus_score, urlhaus_flag = _urlhaus_lookup(final_url)
    if urlhaus_flag:
        flags.insert(0, urlhaus_flag)

    # 6. Risk score & verdict
    raw_score = heuristic_score + urlhaus_score
    risk_score = min(100, raw_score)
    verdict = _compute_verdict(risk_score)

    # 7. Construct standard response payload
    result_body: dict[str, Any] = {
        "Input_QR_URL": url,
        "Final_Resolved_URL": final_url,
        "Redirect_Hops": hops,
        "Redirect_Chain": chain,
        "Risk_Score": risk_score,
        "Verdict": verdict,
        "Threat_Flags": [f["description"] for f in flags],
        "threat_details": flags,
        "cache_hit": False,
        "execution_ms": round(time.time() * 1000 - start_ms, 2),
        "aws_request_id": getattr(context, "aws_request_id", "local-request-id"),
    }

    # 8. Cache write (24h TTL)
    ttl = int(time.time()) + CACHE_TTL
    _cache_write(url_hash, result_body, ttl)

    return _api_response(200, result_body)
