# QR-Shield Technical Architecture and System Design

Course Alignment: Serverless Computing (Professional Elective 6)  
Topics Covered: Evolution of Compute (Unit I), FaaS States and Operational Models (Unit II), Event-Driven Architecture (Unit III), AWS Lambda Execution and Security (Unit IV), Function Programming and API Gateway (Unit V).

---

## 1. System Overview and Engineering Motivation

QR-Shield is an event-driven system built to analyze URLs embedded in QR codes before end users open them on personal devices. 

When designing a backend service for QR validation, a traditional approach would be to stand up a persistent Node.js or Python web server inside a Docker container on AWS ECS, a virtual machine on EC2, or a platform like Heroku. While straightforward, that model has a fundamental economic drawback: QR code scanning is highly bursty and intermittent. A student might scan a cafeteria menu or event flyer at noon, followed by hours of zero activity. An always-on server sits idle 95% of the time, consuming memory and compute resources while running up operational costs and requiring continuous OS-level patch maintenance.

QR-Shield uses a Function-as-a-Service (FaaS) model:
- **True Scale-to-Zero:** When no one is scanning codes, zero compute instances run, incurring zero compute cost.
- **Micro-Billing:** Execution is billed down to the millisecond only while a scan is actively being evaluated.
- **Fast Cold Starts:** By strictly avoiding heavy third-party wheels (such as `requests`, `urllib3`, or headless browsers) and relying solely on the Python 3.11 standard library and the pre-installed `boto3` SDK, the deployment package stays under 25 KB. Container initialization finishes in under 150 ms.
- **Dual-Layer Caching:** Ephemeral execution context memory acts as an L1 cache across warm invocations (< 5 ms response time), backed by Amazon DynamoDB as a durable L2 cache (< 30 ms response time).

---

## 2. High-Level System Architecture

```text
[ Browser / Mobile Client ]
             │
             ▼  1. HTTPS POST /api/validate { "url": "..." }
[ Amazon API Gateway ]
             │  • Handles CORS preflight (OPTIONS)
             │  • Validates basic HTTP headers and routes payloads
             ▼  2. Passes APIGatewayProxyEvent
[ AWS Lambda: qr_validator_lambda ] (128 MB RAM, 6.0s timeout)
             │
             ├── 3. SHA-256 Cache Check (Memory dict -> DynamoDB)
             ├── 4. HTTP Redirect Tracer (up to 5 hops, HEAD with GET fallback)
             ├── 5. Deterministic Heuristic Engine (8 structured rules)
             ├── 6. Threat Intel Query (abuse.ch URLhaus)
             ├── 7. Risk Aggregation and Safety Verdict Calculation
             └── 8. Write-Through Cache (Warm memory + DynamoDB with 24h TTL)
             │
             ▼  9. Returns JSON Proxy Response with CORS headers
[ User Scanner Interface ]
```

---

## 3. Pipeline Execution Stages

### Stage 1: Request Ingestion and Input Validation
- **Endpoint:** `POST /api/validate`
- **Payload Parsing:** The function extracts the URL from either standard API Gateway proxy events (`event["body"]`) or direct JSON test events.
- **Protocol Enforceability:** The input must start with `http://` or `https://`. Malformed strings and non-web URI schemes (`javascript:`, `data:`, `file:`, `tel:`) are immediately rejected with an HTTP `400 Bad Request` response, preventing command injection or URI parsing exploits downstream.

### Stage 2: Dual-Layer Caching Strategy

Because popular QR codes (such as event flyers, campus posters, or merchant pay stands) are scanned repeatedly by many users in short succession, repeated external network requests are wasteful.

1. **Hash Generation:** The input URL is hashed using SHA-256:
   $$\text{Hash} = \text{SHA-256}(\text{URL}_{\text{normalized}})$$
2. **L1 In-Memory Cache (Warm Container Memory):** Python module-scope global variables persist across invocations as long as the Lambda container remains warm. If a matching hash exists in `_warm_cache` and its TTL is still valid, the result returns in under 5 ms.
3. **L2 Persistent Cache (Amazon DynamoDB):** If the L1 cache misses, the function queries the `QRThreatCache` table using `url_hash` as the partition key. On a hit, the payload is promoted to L1 memory and returned in under 30 ms.

### Stage 3: Multi-Hop Redirect Tracer

Attackers frequently hide destination URLs behind chains of URL shorteners (such as `bit.ly` forwarding to `tinyurl.com`, which forwards to a phishing page) to evade basic domain filters.

- **Standard Library Implementation:** Built entirely on `urllib.request` and `urllib.parse`.
- **Lightweight Probing:** Sends HTTP `HEAD` requests to inspect the `Location` header without downloading page content, HTML markup, or images.
- **405 Method Not Allowed Fallback:** Some web servers refuse `HEAD` requests. When a 405 status is received, the tracer automatically falls back to an HTTP `GET` request.
- **Relative Path Resolution:** Relative redirects (for example, `/login.php`) are resolved into absolute URLs using `urllib.parse.urljoin(current_url, location)`.
- **Boundaries and Guardrails:**
  - Maximum Hops: 5 hops.
  - Per-Hop Socket Timeout: 2.5 seconds.
  - Total Redirect Time Budget: Capped to ensure execution comfortably fits inside the 6.0-second Lambda hard timeout.

### Stage 4: Deterministic Heuristic Phishing Engine

Once the final destination URL is resolved, the heuristic engine parses the URL components (`scheme`, `netloc`, `hostname`, `path`) and evaluates them against 8 structural indicators:

| Rule ID | Condition | Added Weight | Technical Rationale |
| :--- | :--- | :---: | :--- |
| **R-01** | URLhaus threat feed match | +100 | Known, active malware or phishing host confirmed by global threat intelligence. |
| **R-02** | Raw IPv4 address hostname | +50 | Legitimate public services almost universally use domain names; raw IPs bypass domain reputation and WHOIS records. |
| **R-03** | Credential harvesting syntax (`@`) | +45 | Exploits RFC 3986 URL authority syntax (`userinfo@host`) to trick users into misreading the real domain. |
| **R-04** | Punycode / IDN homograph (`xn--`) | +40 | Uses internationalized character sets to visually spoof trusted brands (for example, replacing Latin characters with Cyrillic lookalikes). |
| **R-05** | High-risk suspicious TLD | +25 | Top-Level Domains (`.xyz`, `.top`, `.zip`, `.click`, `.tk`, `.gq`, `.work`) heavily abused in phishing campaigns due to low acquisition costs. |
| **R-06** | Phishing lure keywords | +20 each | Target terms (`kyc`, `verify`, `reward`, `claim`, `login`, `update-pan`) commonly used in financial and credential social engineering. |
| **R-07** | Insecure HTTP scheme | +20 | Plaintext connection without TLS encryption, vulnerable to on-path credential interception. |
| **R-08** | URL shortener or 2+ hops | +15 | Intentional obfuscation masking destination endpoints behind redirect intermediaries. |

### Stage 5: Threat Intelligence Integration

- The engine sends an HTTP POST query to `https://urlhaus-api.abuse.ch/v1/url/` with the final resolved URL.
- If the feed confirms the URL status as `listed`, Rule R-01 triggers (+100 score).
- **Graceful Degradation:** If the external URLhaus API times out or is unreachable, the exception is logged and the engine computes the final verdict using heuristic scores alone. The user request never fails due to an external service outage.

### Stage 6: Risk Aggregation and Safety Verdict

The total risk score sums all triggered rule weights, clamped to a maximum of 100:

$$\text{Risk Score} = \min\left(100, \sum \text{triggered weights}\right)$$

Verdict assignment follows strict thresholds:
- **SAFE (0 to 24):** Clean domains or benign unencrypted pages with minimal risk factors.
- **SUSPICIOUS (25 to 59):** Links with ambiguous or moderately risky characteristics (such as a link shortener pointing to a `.xyz` domain).
- **MALICIOUS (60 to 100):** Clear indicators of compromise, including raw IPs with phishing keywords, authority spoofing, or confirmed threat feed listings.

### Stage 7: Persistence and Automatic TTL Pruning

- Scored results are saved to DynamoDB with partition key `url_hash`.
- A Unix epoch expiration timestamp is attached:
  $$\text{TTL} = \text{Current Epoch Time} + 86400 \text{ seconds (24 Hours)}$$
- DynamoDB's built-in TTL mechanism automatically evicts expired records in the background without consuming provisioned write capacity or generating compute costs.

---

## 4. Lambda Lifecycle and Performance Engineering

### Cold Starts vs. Warm Invocations

When a request arrives and no idle container exists, AWS Lambda spins up a microVM (Firecracker), loads the Python 3.11 runtime, imports the script, and executes code outside the handler function.

```text
Cold Start (First Request):
[MicroVM Boot] -> [Runtime Init] -> [Import stdlib & boto3] -> [Handler Execution] (~200ms)
                                                                      │
                                                                      ▼
Warm Invocation (Subsequent Requests):
[Existing Container Reused] ────────────────────────────────────────> [Handler Execution] (<30ms)
```

To optimize this lifecycle:
1. **Module-Scope SDK Client Initialization:** `boto3.resource("dynamodb")` is initialized once at the module level. Subsequent invocations reuse existing TCP connections and HTTPS keep-alives.
2. **Minimal Package Footprint:** The entire handler is a single script under 20 KB. Avoiding external dependencies eliminates pip wheel unpacking overhead.
3. **Memory Configuration:** Configured at 128 MB. Because the function does not render web pages or execute client-side JavaScript, 128 MB provides ample headroom while minimizing execution billing per millisecond.

---

## 5. Security and Least-Privilege IAM Design

In accordance with AWS security best practices (Unit IV), the Lambda function runs under an IAM role (`QRShieldLambdaRole`) that grants strictly scoped permissions:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DynamoDBCacheOperations",
      "Effect": "Allow",
      "Action": [
        "dynamodb:GetItem",
        "dynamodb:PutItem"
      ],
      "Resource": "arn:aws:dynamodb:*:*:table/QRThreatCache"
    },
    {
      "Sid": "CloudWatchLogging",
      "Effect": "Allow",
      "Action": [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents"
      ],
      "Resource": "arn:aws:logs:*:*:*"
    }
  ]
}
```

- **Scope Limitation:** The role cannot scan or delete the table (`dynamodb:Scan`, `dynamodb:DeleteTable` are excluded).
- **Service Isolation:** The function has no permissions to interact with S3, EC2, RDS, or other AWS services.
