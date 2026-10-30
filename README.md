# QR-Shield: Dynamic QR Code Shield and Phishing Link Validator

QR-Shield is a serverless security tool that inspects links hidden behind QR codes before users open them on their devices. When someone scans a QR code, the system traces any intermediate redirect hops, checks the destination against heuristic phishing rules and the URLhaus threat feed, caches the verdict, and returns a clear assessment: Safe, Suspicious, or Malicious.

The backend is built around AWS Lambda, Amazon API Gateway, and DynamoDB, with full local support via LocalStack and live edge deployment through Vercel.

---

## Table of Contents

- [The Problem](#the-problem)
- [How It Works](#how-it-works)
- [Architecture](#architecture)
- [Detection Rules and Scoring](#detection-rules-and-scoring)
- [Repository Structure](#repository-structure)
- [Getting Started](#getting-started)
  - [Local Development with LocalStack](#local-development-with-localstack)
  - [Live Edge Deployment on Vercel](#live-edge-deployment-on-vercel)
- [API Reference](#api-reference)
- [Test Suite](#test-suite)
- [Course Outcome Alignment](#course-outcome-alignment)
- [Security Considerations](#security-considerations)

---

## The Problem

QR code phishing, often referred to as "quishing," takes advantage of the fact that people cannot read QR matrices directly. Attackers routinely disguise malicious landing pages behind shortened links (such as bit.ly, tinyurl.com, or rb.gy) and place them on payment stands, event posters, or dining tables. 

When a smartphone scans one of these codes, the default mobile browser automatically follows the redirect chain. By the time the user realizes the page is fake, their browser has already loaded credential harvesting forms or suspicious downloads.

Traditional backends for this kind of check run around the clock on dedicated virtual machines or container clusters. Because scans arrive intermittently, those servers spend most of their time idle while still incurring hosting costs. QR-Shield uses an event-driven serverless model: compute runs only during a scan, scales down to zero between requests, and reuses warm container memory for repeat lookups.

---

## How It Works

1. **Intake and Validation:** The client scanner submits the URL extracted from the QR code. The API Gateway validates that the scheme is `http://` or `https://` and rejects non-web URIs or malformed strings.
2. **Cache Check:** The system computes the SHA-256 hash of the input URL and checks an in-memory dictionary (L1) and DynamoDB (L2). If the URL was analyzed recently and its TTL has not expired, the cached verdict returns immediately.
3. **Redirect Tracing:** For new URLs, the backend follows HTTP 301, 302, 303, 307, and 308 redirect headers up to 5 hops using lightweight standard library calls. It attempts `HEAD` requests first to avoid downloading body content, falling back to `GET` only when servers return `405 Method Not Allowed`.
4. **Heuristic Analysis:** The resolved landing page is evaluated against 8 structural indicators, such as raw IP addresses, credential-harvesting `@` signs, Punycode spoofing, suspicious TLDs, and common phishing terms.
5. **Threat Intelligence Query:** The destination is checked against abuse.ch URLhaus. If the feed is unreachable or slow, the system degrades gracefully to the heuristic score alone without failing the request.
6. **Verdict and Caching:** Triggered weights are summed and clamped between 0 and 100. The result is saved to DynamoDB with a 24-hour TTL and returned to the user alongside the full redirect chain and specific flags triggered.

---

## Architecture

```text
[ Browser Scanner / Mobile UI ]
               │
               ▼  HTTPS POST /api/validate
[ Amazon API Gateway ]  (Routes request and handles CORS preflight)
               │
               ▼  APIGatewayProxyEvent
[ AWS Lambda: qr_validator_lambda ]  (128 MB RAM, 6s timeout)
        │
        ├── 1. SHA-256 Cache Check (Warm container memory -> DynamoDB)
        ├── 2. Redirect Tracer (Follows up to 5 hops with 2.5s socket timeout)
        ├── 3. Heuristic Engine + URLhaus API Lookup
        └── 4. Cache Write (Stores verdict in DynamoDB with 24-hour TTL)
```

### Deployment Targets

- **LocalStack (Docker):** Emulates API Gateway, Lambda, DynamoDB, IAM, and CloudWatch locally for testing and lab evaluation without cloud expenses.
- **Vercel (Edge Functions):** Provides an internet-accessible demo running on serverless Python functions alongside the static frontend.

---

## Detection Rules and Scoring

The engine calculates risk using a deterministic additive model:

$$\text{Risk Score} = \min\left(100, \sum \text{triggered weights}\right)$$

| Rule ID | Condition Checked | Weight | Example Scenario |
| :--- | :--- | :---: | :--- |
| **R-01** | Listed in abuse.ch URLhaus feed | +100 | Active malware distribution or phishing host |
| **R-02** | Raw IPv4 address hostname | +50 | `http://103.45.12.9/paytm-cashback` |
| **R-03** | `@` symbol in URL authority | +45 | `https://bank.com@evil-site.top/login` |
| **R-04** | Punycode / IDN homograph domain | +40 | `https://xn--pple-43d.com` (spoofed apple.com) |
| **R-05** | Suspicious Top-Level Domain | +25 | `.xyz`, `.top`, `.zip`, `.click`, `.tk`, `.gq`, `.work` |
| **R-06** | Phishing lure keywords in URL | +20 each | `kyc`, `verify`, `reward`, `claim`, `login`, `update-pan` |
| **R-07** | Insecure HTTP scheme | +20 | Plaintext connection without TLS |
| **R-08** | Shortener domain or 2 or more redirect hops | +15 | `bit.ly`, `tinyurl.com`, or multiple link jumps |

### Verdict Categories

| Score Range | Verdict | Interpretation |
| :--- | :--- | :--- |
| **0 to 24** | SAFE | Standard verified link or benign destination with minimal risk markers. |
| **25 to 59** | SUSPICIOUS | Contains indicators such as a suspicious TLD or shortener hops; caution advised. |
| **60 to 100** | MALICIOUS | Strong evidence of phishing, raw IP routing, credential harvesting, or known malware. |

---

## Repository Structure

```text
Dynamic QR Code Sheild/
├── lambda/
│   └── lambda_function.py          # AWS Lambda handler (stdlib + boto3)
├── api/
│   └── validate.py                 # Vercel serverless function (Python HTTP handler)
├── frontend/
│   └── index.html                  # Single-page scanner UI (camera, file, manual URL)
├── iam/
│   ├── trust-policy.json           # Lambda assume-role trust policy
│   └── execution-policy.json       # Least-privilege IAM permissions
├── scripts/
│   ├── deploy_localstack.sh        # Bash deployment script for Linux/macOS
│   └── deploy_localstack.ps1       # PowerShell deployment script for Windows
├── tests/
│   └── test_lambda.py              # Test cases covering TC-01 through TC-12
├── docs/
│   ├── PRD.md                      # Product Requirements Document
│   ├── ARCHITECTURE.md             # Detailed architecture design and FaaS lifecycle
│   └── DEPLOYMENT.md               # Step-by-step local and cloud deployment guide
├── docker-compose.yml              # LocalStack Docker service configuration
├── vercel.json                     # Vercel routing and function configuration
├── .env.example                    # Sample environment variables
└── README.md                       # Main project documentation
```

---

## Getting Started

### Prerequisites

- Python 3.11 or higher
- Docker and Docker Compose (if running LocalStack)
- AWS CLI v2
- Node.js and npm (optional, only for the Vercel CLI)

### Local Development with LocalStack

1. **Start the LocalStack container:**
   ```bash
   docker-compose up -d
   ```

2. **Deploy the serverless resources:**
   - On Windows (PowerShell):
     ```powershell
     .\scripts\deploy_localstack.ps1
     ```
   - On Linux / macOS:
     ```bash
     chmod +x scripts/deploy_localstack.sh
     ./scripts/deploy_localstack.sh
     ```

3. **Verify the deployment output:**
   The script outputs the active REST API URL. Test it directly using curl:
   ```bash
   curl -X POST "http://localhost:4566/restapis/<API_ID>/prod/_user_request_/api/validate" \
     -H "Content-Type: application/json" \
     -d '{"url": "https://www.cbit.ac.in"}'
   ```

4. **Launch the web interface:**
   Open `frontend/index.html` in your browser. To point it at your local LocalStack deployment, update `API_ENDPOINT` near line 765 in `frontend/index.html`.

### Live Edge Deployment on Vercel

1. **Install the Vercel CLI:**
   ```bash
   npm install -g vercel
   ```

2. **Deploy from the project root:**
   ```bash
   vercel --prod
   ```
   Vercel reads `vercel.json`, compiles `api/validate.py` under the Python runtime, and serves the static files from `frontend/index.html`.

---

## API Reference

### Validation Endpoint

- **Path:** `/api/validate`
- **Method:** `POST`
- **Headers:** `Content-Type: application/json`

#### Request Body

```json
{
  "url": "https://bit.ly/3xYz99"
}
```

#### Success Response (200 OK)

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
    "Destination uses a raw IP address instead of a verified domain",
    "Contains high-risk phishing lure keyword: 'kyc'",
    "Contains high-risk phishing lure keyword: 'verify'",
    "Contains high-risk phishing lure keyword: 'login'",
    "Unencrypted HTTP protocol used instead of HTTPS",
    "Obfuscated behind 2 redirect hop(s)"
  ],
  "cache_hit": false,
  "execution_ms": 384.15,
  "aws_request_id": "52fdfc07-2182-454f-b63f-5f0f9a621d72"
}
```

#### Error Response (400 Bad Request)

```json
{
  "error": "Invalid payload. Provide a valid 'url' starting with http:// or https://"
}
```

#### CORS Preflight (`OPTIONS /api/validate`)

Returns status `200` with the following headers:
- `Access-Control-Allow-Origin: *`
- `Access-Control-Allow-Methods: POST, OPTIONS`
- `Access-Control-Allow-Headers: Content-Type`

---

## Test Suite

The test suite in `tests/test_lambda.py` validates all functional scenarios from the PRD specification:

| Test ID | Scenario | Input URL | Expected Verdict | Expected Score |
| :--- | :--- | :--- | :---: | :---: |
| **TC-01** | Clean HTTPS Domain | `https://www.cbit.ac.in` | SAFE | 0 |
| **TC-02** | Unencrypted Legacy Link | `http://neverssl.com` | SAFE | 20 |
| **TC-03** | Shortened Link with Suspicious TLD | `https://bit.ly/...` -> `.xyz` | SUSPICIOUS | 40 |
| **TC-04** | Raw IP with Phishing Keywords | `http://45.33.32.156/kyc-verify/login` | MALICIOUS | 100 |
| **TC-05** | Authority Obfuscation (`@`) | `https://sbi.co.in@secure-claim.top/reward` | MALICIOUS | 100 |
| **TC-06** | Warm Cache Verification | Repeat TC-04 immediately | MALICIOUS (`cache_hit: true`) | 100 (< 30 ms) |
| **TC-07** | Non-HTTP Scheme Rejection | `javascript:alert(1)` | 400 Bad Request | N/A |

Run the test suite:
```bash
python -m unittest tests/test_lambda.py -v
```

---

## Course Outcome Alignment

This project is built for the **Serverless Computing** course and demonstrates key syllabus concepts:

- **Unit I & II (FaaS States and #NoOps):** Replaces always-on web servers with an ephemeral, stateless function that scales to zero when idle and reuses warm container memory for low-latency caching.
- **Unit III (Event-Driven Architecture):** HTTP requests from the scanner trigger a multi-stage validation pipeline: cache lookup, redirect tracing, heuristic scoring, threat feed checks, and cache persistence.
- **Unit IV (Lambda Configuration and IAM Security):** Demonstrates strict configuration limits (128 MB RAM, 6.0s timeout), environment variables for endpoint configuration, and least-privilege IAM policies.
- **Unit V (Function Foundations and API Gateway):** Uses the standard `lambda_handler(event, context)` model exposed through an Amazon API Gateway REST proxy integration with CORS and input validation.

---

## Security Considerations

- **Least-Privilege IAM:** The Lambda execution role has access only to `dynamodb:GetItem` and `dynamodb:PutItem` on the `QRThreatCache` table, plus standard CloudWatch logging actions. It cannot drop tables, read other databases, or interact with other AWS services.
- **Strict Input Validation:** URLs must begin with `http://` or `https://`. Non-standard protocols (`javascript:`, `file:`, `data:`) are rejected before any network call is initiated.
- **Zero Script Execution:** Tracing inspects only HTTP headers. Client-side JavaScript is never executed, preventing drive-by exploits or browser-targeted payload execution in the backend.
- **Timeout Bounds:** Individual HTTP hops are restricted to a 2.5-second socket timeout, and total redirect hops are capped at 5. This prevents hostile redirect loops or slowloris-style tarpits from causing function timeouts.
- **Standard Library Only:** The backend avoids third-party package dependencies, keeping deployment archives below 25 KB and removing external supply chain vulnerabilities.
