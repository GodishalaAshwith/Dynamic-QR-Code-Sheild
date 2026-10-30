# QR-Shield Deployment and Operations Guide

This guide walks through deploying and testing QR-Shield across two target environments:
1. **LocalStack (AWS Emulator):** For local offline development, testing, and lab evaluation.
2. **Vercel Serverless Edge:** For a live, public demo with zero infrastructure cost.

---

## Table of Contents

- [1. Prerequisites](#1-prerequisites)
- [2. Local Development with LocalStack](#2-local-development-with-localstack)
  - [Step 2.1: Start the LocalStack Container](#step-21-start-the-localstack-container)
  - [Step 2.2: Run the Infrastructure Provisioning Script](#step-22-run-the-infrastructure-provisioning-script)
  - [Step 2.3: Verify Deployed Resources with cURL](#step-23-verify-deployed-resources-with-curl)
  - [Step 2.4: Connect the Web Scanner to LocalStack](#step-24-connect-the-web-scanner-to-localstack)
- [3. Live Deployment on Vercel](#3-live-deployment-on-vercel)
  - [Step 3.1: Install the Vercel CLI](#step-31-install-the-vercel-cli)
  - [Step 3.2: Deploy the Project](#step-32-deploy-the-project)
- [4. Running the Test Suite](#4-running-the-test-suite)
- [5. Operational Notes and Troubleshooting](#5-operational-notes-and-troubleshooting)

---

## 1. Prerequisites

Before starting, verify you have the following installed on your machine:

| Component | Minimum Version | Notes |
| :--- | :--- | :--- |
| **Python** | 3.11+ | Required for running unit tests and evaluating local code. |
| **Docker & Docker Compose** | 20.10+ | Required to run LocalStack Community Edition locally. |
| **AWS CLI v2** | 2.13+ | Used by the deployment scripts to configure simulated AWS resources. |
| **Node.js & npm** | 18+ (optional) | Only required if deploying to Vercel via the CLI. |

---

## 2. Local Development with LocalStack

LocalStack simulates core AWS services on your local machine, allowing you to create DynamoDB tables, deploy Lambda functions, and configure API Gateway routes without needing an active AWS account or credit card.

### Step 2.1: Start the LocalStack Container

From the project root directory, run:

```bash
docker-compose up -d
```

Check that the container is up and healthy:
```bash
docker ps
```

You can confirm that the relevant services are ready by querying LocalStack's health check endpoint:
```bash
curl http://localhost:4566/_localstack/health
```

The output will confirm that `dynamodb`, `lambda`, `apigateway`, and `iam` are active.

---

### Step 2.2: Run the Infrastructure Provisioning Script

Automated provisioning scripts handle creating the table, setting up IAM policies, packaging the Lambda handler, configuring API Gateway, and publishing to the `prod` stage.

#### On Windows (PowerShell):
```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\scripts\deploy_localstack.ps1
```

#### On Linux, macOS, or WSL:
```bash
chmod +x scripts/deploy_localstack.sh
./scripts/deploy_localstack.sh
```

What the script provisions:
1. Creates the DynamoDB table `QRThreatCache` with `url_hash` as the partition key.
2. Enables native Time-To-Live (TTL) on the `ttl` attribute.
3. Creates the IAM role `QRShieldLambdaRole` and applies the least-privilege policy.
4. Packages `lambda/lambda_function.py` into a zip archive and creates the function with a 128 MB memory limit and 6.0-second timeout.
5. Configures API Gateway REST resources for `/api/validate` with both `POST` and `OPTIONS` (CORS) integrations.
6. Deploys the API to stage `prod` and prints the final invocable URL.

---

### Step 2.3: Verify Deployed Resources with cURL

Once the script completes, test the endpoint with sample inputs:

#### Test Case 1: Clean Domain (TC-01)
```bash
curl -X POST "http://localhost:4566/restapis/<API_ID>/prod/_user_request_/api/validate" \
  -H "Content-Type: application/json" \
  -d '{"url": "https://www.cbit.ac.in"}'
```
Expected output: `"Verdict": "SAFE"`, `"Risk_Score": 0`, `"cache_hit": false`.

#### Test Case 2: Phishing Indicator (TC-04)
```bash
curl -X POST "http://localhost:4566/restapis/<API_ID>/prod/_user_request_/api/validate" \
  -H "Content-Type: application/json" \
  -d '{"url": "http://45.33.32.156/kyc-verify/login"}'
```
Expected output: `"Verdict": "MALICIOUS"`, `"Risk_Score": 100`.

#### Test Case 3: Warm Cache Verification (TC-06)
Repeat the command from Test Case 2 immediately:
```bash
curl -X POST "http://localhost:4566/restapis/<API_ID>/prod/_user_request_/api/validate" \
  -H "Content-Type: application/json" \
  -d '{"url": "http://45.33.32.156/kyc-verify/login"}'
```
Expected output: `"cache_hit": true`, with an execution latency under 30 ms.

---

### Step 2.4: Connect the Web Scanner to LocalStack

1. Open `frontend/index.html` in an editor.
2. Locate the configuration section near line 765:
   ```javascript
   // Default Vercel live endpoint:
   const API_ENDPOINT = '/api/validate';

   // To point to LocalStack, replace with your local URL:
   // const API_ENDPOINT = 'http://localhost:4566/restapis/<API_ID>/prod/_user_request_/api/validate';
   ```
3. Update the `API_ENDPOINT` string to your active LocalStack URL.
4. Double-click `frontend/index.html` or open it in any modern browser to use the camera scanner, drag-and-drop QR image upload, or manual URL tester.

---

## 3. Live Deployment on Vercel

If you want to host the project online for a live demonstration or mobile phone testing, Vercel allows deploying Python serverless functions alongside static frontends at zero cost.

### Step 3.1: Install the Vercel CLI
```bash
npm install -g vercel
```

### Step 3.2: Deploy the Project
Navigate to the repository root and run:
```bash
vercel --prod
```

During the interactive CLI prompts:
- Confirm your account or team scope.
- Link to a new or existing project.
- Keep default directory settings (`./`).

Vercel automatically detects `vercel.json`, links `api/validate.py` under the `@vercel/python` runtime, and hosts `frontend/index.html` as the root web application.

Once complete, Vercel outputs your production domain (for example, `https://qr-shield.vercel.app`). Open this URL on your mobile phone to scan QR codes using your device's camera.

---

## 4. Running the Test Suite

The test suite in `tests/test_lambda.py` tests all 7 core functional requirements and edge cases. External network requests and DynamoDB calls are mocked so the suite runs quickly and deterministically without network dependencies.

Run the tests using Python's standard `unittest` module:
```bash
python -m unittest tests/test_lambda.py -v
```

All test cases should pass, confirming input sanitization, redirect resolution, heuristic rule scoring, cache lookups, and CORS handling.

---

## 5. Operational Notes and Troubleshooting

### LocalStack URL Routing: The `_user_request_` Path Segment
When calling API Gateway on LocalStack, the URL format requires `_user_request_`:
```text
http://localhost:4566/restapis/{api_id}/{stage_name}/_user_request_/{resource_path}
```
If you omit `_user_request_`, LocalStack may return `404 {"message": "Missing Authentication Token"}` or `404 Not Found`.

### Camera Permissions in Mobile Browsers
Modern mobile browsers (iOS Safari, Android Chrome) enforce security policies that permit camera access only on `https://` origins or `localhost`. When testing via camera on a physical mobile device, use the HTTPS deployment hosted on Vercel or forward your local port over an HTTPS tunnel.

### DynamoDB TTL Cleanup Frequency
DynamoDB does not delete expired records the exact millisecond their timestamp lapses. The native TTL sweeper runs as a low-priority background process, typically deleting items within 24 to 48 hours of expiration. However, QR-Shield's application logic additionally verifies `item["ttl"] > current_time` before accepting a cache hit, ensuring expired data is never returned to users even if DynamoDB has not yet physically cleared the item.
