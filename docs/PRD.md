# Product Requirements Document (PRD): QR-Shield

* **Project Title:** QR-Shield — Dynamic QR Code Shield & Phishing Link Validator
* **Course Alignment:** Serverless Computing (Professional Elective – 6)
* **Deployment Target:** LocalStack (AWS Lambda, API Gateway, DynamoDB, IAM Emulator) & Vercel Serverless (Zero-Cost Live Edge)
* **Runtime & Stack:** Python 3.11 Standard Library, AWS Boto3, HTML5/JS (Client Scanner)

---

## 1. Problem Statement & Objective

### 1.1 Problem Statement

QR codes ("Quishing" — QR Phishing) inherently mask destination URLs behind visual matrices and URL shorteners (`bit.ly`, `tinyurl.com`, `rb.gy`). Users scanning payment standees, event posters, or restaurant menus cannot inspect the underlying link before their mobile browser triggers redirect chains, exposing them to credential harvesting, fake UPI/payment portals, and malware downloads. Running a 24/7 dedicated backend server to validate intermittent QR scans is cost-inefficient and wastes idle compute resources.

### 1.2 Objective

Build a 100% serverless, event-driven API and web client that intercepts a scanned QR URL, unrolls multi-hop HTTP redirects in an isolated FaaS execution environment, evaluates the final landing page against zero-day heuristic rules and open-source threat intelligence (abuse.ch URLhaus), caches results with automatic Time-To-Live (TTL), and returns a real-time safety verdict (`SAFE`, `SUSPICIOUS`, or `MALICIOUS`) within milliseconds.

---

## 2. Syllabus & Course Outcome (CO) Traceability

| Course Outcome | Syllabus Unit | Implementation in QR-Shield |
| --- | --- | --- |
| **CO1 & CO2** | **Unit I & II:** Evolution of Compute, FaaS States, #NoOps, FaaS vs. PaaS/Containers | Replaces always-on container/PaaS servers with ephemeral, stateless FaaS execution that scales to zero when idle and reuses warm container memory for low-latency caching. |
| **CO3** | **Unit III:** Event-Driven Applications & Serverless Automation | Synchronous HTTP scan events automatically trigger a multi-stage pipeline: cache lookup $\rightarrow$ redirect unrolling $\rightarrow$ heuristic scoring $\rightarrow$ threat feed verification $\rightarrow$ TTL persistence. |
| **CO4** | **Unit IV:** AWS Lambda Execution Environment, Configuration & IAM Security | Configures Lambda with strict memory (`128 MB`), timeout (`6s`), environment variables, and Least-Privilege IAM roles (`trust-policy.json` & `execution-policy.json`). |
| **CO5** | **Unit V:** Foundations of a Function, Programming Model & Amazon API Gateway | Implements the standard `lambda_handler(event, context)` model exposed via an Amazon API Gateway REST endpoint (`POST /api/validate`) with CORS and payload validation. |

---

## 3. Target Users & Use Cases

* **UC-01: Shortened URL Unmasking:** A user scans a QR code containing `[https://bit.ly/3xYz99](https://bit.ly/3xYz99)`. The system unrolls 3 intermediate HTTP `301/302` hops, reveals the true destination (`[http://secure-kyc-update.xyz/login](http://secure-kyc-update.xyz/login)`), and flags it as `MALICIOUS`.
* **UC-02: Known Malware Host Detection:** A user submits a URL linked to an active botnet or phishing drop site. The system queries the URLhaus public API, matches the indicator, and returns a risk score of `100`.
* **UC-03: Repeat Scan Warm Cache Hit:** Multiple students scan the same campus event poster QR code. The first scan computes the verdict in ~450 ms and writes to DynamoDB; subsequent scans return in under 30 ms via cache hit.

---

## 4. Functional Requirements (FR)

| ID | Feature Module | Requirement Specification | Priority |
| --- | --- | --- | --- |
| **FR-01** | **API Gateway Ingestion** | Expose a `POST /api/validate` REST endpoint accepting JSON `{"url": "<string>"}` and an `OPTIONS` method for browser CORS preflight checks. | P0 |
| **FR-02** | **Input Sanitization** | Validate that the extracted QR payload is a syntactically valid `http://` or `https://` URI; reject malformed strings or non-URI text with HTTP `400 Bad Request`. | P0 |
| **FR-03** | **Serverless Cache Lookup** | Compute a `SHA-256` hash of the normalized input URL and query DynamoDB (`QRThreatCache`) or warm container memory before initiating external network calls. | P0 |
| **FR-04** | **Multi-Hop Redirect Tracer** | Trace HTTP `301`, `302`, `303`, `307`, and `308` `Location` headers up to a maximum of `5 hops` using `HEAD`/`GET` requests without executing client-side scripts. | P0 |
| **FR-05** | **Heuristic Phishing Engine** | Inspect the final resolved URL for: (a) unencrypted HTTP, (b) raw IPv4 hostnames, (c) `@` credential-harvesting syntax, (d) Punycode (`xn--`), (e) high-risk TLDs (`.xyz`, `.top`, `.zip`, `.tk`, `.click`), and (f) phishing keywords (`kyc`, `verify`, `reward`, `login`, `claim`). | P0 |
| **FR-06** | **Threat Feed Integration** | Query the keyless `[https://urlhaus-api.abuse.ch/v1/url/](https://urlhaus-api.abuse.ch/v1/url/)` endpoint with the final resolved URL and gracefully degrade to heuristic-only scoring if the external feed times out. | P1 |
| **FR-07** | **Deterministic Risk Scoring** | Aggregate heuristic weights and threat feed hits into a normalized score (`0–100`) mapped to three strict verdicts: `SAFE` (0–24), `SUSPICIOUS` (25–59), and `MALICIOUS` (60–100). | P0 |
| **FR-08** | **Client Scanner UI** | Provide a lightweight single-page HTML5 frontend capable of decoding QR images via device camera/file upload (`html5-qrcode`) or manual URL entry and rendering the JSON verdict. | P1 |

---

## 5. Non-Functional Requirements (NFR) & Lambda Constraints

| Category | Parameter | Target / Constraint | Syllabus Justification |
| --- | --- | --- | --- |
| **Compute Limits** | Memory / Timeout | `128 MB` RAM / `6.0 seconds` hard timeout | Prevents runaway billing/hanging on unresponsive redirect servers (Unit IV). |
| **Network Bounds** | Per-Hop Socket Timeout | `2.5 seconds` max per HTTP hop | Ensures 2 slow hops + threat check never breach the 6s Lambda timeout. |
| **Package Size** | Deployment Artifact | Less than `25 KB` zipped (Zero 3rd-party pip wheels) | Eliminates cold-start bloat (`Init Duration` under 150 ms) by using Python `stdlib`. |
| **State Management** | Statelessness | Zero local disk persistence | Adheres strictly to FaaS stateless architecture; all state lives in DynamoDB (Unit II). |
| **Security & IAM** | Execution Role | `dynamodb:GetItem`, `dynamodb:PutItem`, `logs:*` | Enforces Least-Privilege IAM access scoped strictly to `QRThreatCache` ARN (Unit IV). |
| **Cost Ceiling** | Infrastructure Spend | `$0.00` (100% Free / No Credit Card) | Runs on LocalStack Community Docker locally and Vercel Free Tier for live demo. |

---

## 6. Technical Architecture & Data Specifications

### 6.1 Component Architecture

```text
[Client UI / QR Scanner]
        │
        ▼  HTTPS POST /api/validate
[Amazon API Gateway]  (CORS + Payload Routing)
        │
        ▼  APIGatewayProxyEvent
[AWS Lambda: qr_validator_lambda]  (IAM Role: QRShieldLambdaRole)
        ├──► 1. [Amazon DynamoDB: QRThreatCache] (Check SHA-256 Partition Key)
        ├──► 2. [Redirect Tracer] (Unrolls up to 5 HTTP 3xx hops)
        ├──► 3. [Heuristic & URLhaus Engine] (Scores 0-100)
        └──► 4. [Amazon DynamoDB: QRThreatCache] (Write result with 24h TTL)

```

### 6.2 API Contract (`POST /api/validate`)

**Request Payload:**

```json
{
  "url": "https://bit.ly/3xYz99"
}

```

**Success Response (`200 OK`):**

```json
{
  "Input_QR_URL": "https://bit.ly/3xYz99",
  "Final_Resolved_URL": "http://192.168.42.10/kyc-verify/login.php",
  "Redirect_Hops": 2,
  "Redirect_Chain": [
    "https://bit.ly/3xYz99",
    "https://t.co/short123",
    "http://192.168.42.10/kyc-verify/login.php"
  ],
  "Risk_Score": 100,
  "Verdict": "MALICIOUS",
  "Threat_Flags": [
    "Unencrypted HTTP protocol used instead of HTTPS",
    "Destination uses a raw IP address instead of a verified domain",
    "Obfuscated behind 2 redirect hop(s)",
    "Contains high-risk phishing lure keywords: kyc, verify, login"
  ],
  "cache_hit": false,
  "execution_ms": 384.15,
  "aws_request_id": "52fdfc07-2182-454f-b63f-5f0f9a621d72"
}

```

**Error Response (`400 Bad Request`):**

```json
{
  "error": "Invalid payload. Provide a valid 'url' starting with http:// or https://"
}

```

### 6.3 DynamoDB Table Schema (`QRThreatCache`)

* **Table Name:** `QRThreatCache`
* **Billing Mode:** `PAY_PER_REQUEST` (Serverless On-Demand)
* **Partition Key (`PK`):** `url_hash` (`String` — SHA-256 hex digest of input URL)
* **Attributes:**
* `payload` (`String` — serialized JSON response dict)
* `ttl` (`Number` — Unix epoch timestamp set to `current_time + 86400` seconds)



---

## 7.Deterministic Risk Scoring Matrix

The Threat Engine calculates `Risk_Score = min(100, sum(triggered_weights))`:

| Rule ID | Detection Condition | Weight | Example Trigger |
| --- | --- | --- | --- |
| **R-01** | Listed in `abuse.ch` URLhaus Threat Feed | `+100` | Known malware/phishing distribution URL |
| **R-02** | Raw IPv4 Address Hostname | `+50` | `[http://103.45.12.9/paytm-cashback](http://103.45.12.9/paytm-cashback)` |
| **R-03** | `@` Credential Harvesting in Netloc | `+45` | `[https://google.com@evil-phish.xyz/auth](https://google.com@evil-phish.xyz/auth)` |
| **R-04** | Punycode / Homograph Domain (`xn--`) | `+40` | `[https://xn--pple-43d.com](https://xn--pple-43d.com)` (spoofed `apple.com`) |
| **R-05** | Suspicious Top-Level Domain (TLD) | `+25` | `.xyz`, `.top`, `.zip`, `.click`, `.tk`, `.gq`, `.work` |
| **R-06** | Phishing Lure Keyword Match (per keyword) | `+20` | `kyc`, `verify`, `reward`, `claim`, `login`, `update-pan` |
| **R-07** | Unencrypted Scheme (`http://`) | `+20` | Missing TLS certificate on destination |
| **R-08** | URL Shortener or Multi-Hop Chain ($\ge 2$ hops) | `+15` | `bit.ly`, `tinyurl.com`, `rb.gy`, `is.gd`, `cutt.ly` |

---

## 8. Acceptance Criteria & Test Cases (For Lab Evaluation)

| Test ID | Scenario | Input URL | Expected Verdict | Expected Score |
| --- | --- | --- | --- | --- |
| **TC-01** | Clean HTTPS Official Domain | `[https://www.cbit.ac.in](https://www.cbit.ac.in)` | `SAFE` | `0` |
| **TC-02** | Unencrypted Legacy Link | `[http://neverssl.com](http://neverssl.com)` | `SAFE` | `20` |
| **TC-03** | Shortened Link + Suspicious TLD | `[https://bit.ly/](https://bit.ly/)...` $\rightarrow$ `[https://promo-event.xyz](https://promo-event.xyz)` | `SUSPICIOUS` | `40` |
| **TC-04** | Raw IP + Phishing Keywords | `[http://45.33.32.156/kyc-verify/login](http://45.33.32.156/kyc-verify/login)` | `MALICIOUS` | `100` |
| **TC-05** | `@` Authority Obfuscation | `[https://sbi.co.in@secure-claim.top/reward](https://sbi.co.in@secure-claim.top/reward)` | `MALICIOUS` | `100` |
| **TC-06** | Warm Cache Validation | Re-submit **TC-04** immediately | `MALICIOUS` (`cache_hit: true`) | `100` (Latency $< 30\text{ ms}$) |
| **TC-07** | Invalid Payload Rejection | `{"url": "javascript:alert(1)"}` | HTTP `400 Bad Request` | N/A |

---

## 9. Scope Boundaries (Out of Scope)

* **Full Headless Browser Rendering:** The Lambda function inspects HTTP headers and URL structures without spinning up headless Chromium/Playwright to stay under the `128 MB` memory limit and `25 KB` package size constraint.
* **User Authentication:** The verification endpoint is intentionally public so anyone can validate a QR link without creating an account.