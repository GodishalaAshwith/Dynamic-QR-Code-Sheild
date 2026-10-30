"""
QR-Shield Acceptance Test Suite (PRD Section 8)
=================================================
Validates all acceptance criteria TC-01 through TC-07 against the Lambda
and Vercel validation engines using Python's standard unittest framework.

Test Cases:
  • TC-01: Clean HTTPS Official Domain           -> SAFE (Score: 0)
  • TC-02: Unencrypted Legacy Link              -> SAFE (Score: 20)
  • TC-03: Shortened Link + Suspicious TLD       -> SUSPICIOUS (Score: 40)
  • TC-04: Raw IP + Phishing Keywords            -> MALICIOUS (Score: 100)
  • TC-05: '@' Authority Obfuscation             -> MALICIOUS (Score: 100)
  • TC-06: Warm Cache Hit Validation             -> MALICIOUS (cache_hit: True, <30ms)
  • TC-07: Invalid Payload Rejection             -> HTTP 400 Bad Request
  • TC-08: CORS Preflight (OPTIONS)              -> HTTP 200 OK
  • TC-09: Malformed JSON Rejection              -> HTTP 400 Bad Request
  • TC-10: Punycode Spoofed Domain               -> MALICIOUS / SUSPICIOUS (+40)
  • TC-11: URLhaus Threat Match                  -> MALICIOUS (+100)
"""

import json
import os
import sys
import unittest
from unittest.mock import MagicMock, patch

# Add parent directory to sys.path to import lambda_function and api.validate
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(CURRENT_DIR)
LAMBDA_DIR = os.path.join(PROJECT_ROOT, "lambda")
API_DIR = os.path.join(PROJECT_ROOT, "api")

sys.path.insert(0, LAMBDA_DIR)
sys.path.insert(0, API_DIR)

import lambda_function  # noqa: E402
import validate as vercel_validator  # noqa: E402


class MockLambdaContext:
    """Mock AWS Lambda runtime context object."""
    def __init__(self, request_id: str = "mock-req-12345"):
        self.aws_request_id = request_id
        self.function_name = "qr_validator_lambda"
        self.memory_limit_in_mb = 128
        self.invoked_function_arn = "arn:aws:lambda:us-east-1:123456789012:function:qr_validator_lambda"


class TestQRShieldAcceptanceCriteria(unittest.TestCase):
    """Rigorous tests covering PRD Section 8 Acceptance Criteria."""

    def setUp(self):
        """Reset in-memory warm caches and mock context before each test."""
        lambda_function._warm_cache.clear()
        vercel_validator._WARM_CACHE.clear()
        self.context = MockLambdaContext()

    def _make_api_gw_event(self, body_dict: dict, http_method: str = "POST") -> dict:
        """Helper to create an API Gateway proxy event."""
        return {
            "httpMethod": http_method,
            "path": "/api/validate",
            "headers": {"Content-Type": "application/json"},
            "body": json.dumps(body_dict),
            "requestContext": {
                "httpMethod": http_method,
                "path": "/api/validate",
            },
        }

    # -------------------------------------------------------------------------
    # TC-01: Clean HTTPS Official Domain -> SAFE (Score: 0)
    # -------------------------------------------------------------------------
    @patch("lambda_function._urlhaus_lookup", return_value=(0, None))
    @patch("lambda_function._trace_redirects")
    def test_tc01_clean_https_official_domain(self, mock_trace, mock_urlhaus):
        """TC-01: https://www.cbit.ac.in must yield SAFE with Risk_Score 0."""
        target_url = "https://www.cbit.ac.in"
        mock_trace.return_value = (target_url, 0, [target_url])

        event = self._make_api_gw_event({"url": target_url})
        resp = lambda_function.lambda_handler(event, self.context)

        self.assertEqual(resp["statusCode"], 200)
        body = json.loads(resp["body"])
        self.assertEqual(body["Verdict"], "SAFE")
        self.assertEqual(body["Risk_Score"], 0)
        self.assertFalse(body["cache_hit"])
        self.assertEqual(body["Final_Resolved_URL"], target_url)

    # -------------------------------------------------------------------------
    # TC-02: Unencrypted Legacy Link -> SAFE (Score: 20)
    # -------------------------------------------------------------------------
    @patch("lambda_function._urlhaus_lookup", return_value=(0, None))
    @patch("lambda_function._trace_redirects")
    def test_tc02_unencrypted_legacy_link(self, mock_trace, mock_urlhaus):
        """TC-02: http://neverssl.com triggers HTTP scheme (+20) -> SAFE with score 20."""
        target_url = "http://neverssl.com"
        mock_trace.return_value = (target_url, 0, [target_url])

        event = self._make_api_gw_event({"url": target_url})
        resp = lambda_function.lambda_handler(event, self.context)

        self.assertEqual(resp["statusCode"], 200)
        body = json.loads(resp["body"])
        self.assertEqual(body["Verdict"], "SAFE")
        self.assertEqual(body["Risk_Score"], 20)
        # Should flag unencrypted HTTP
        self.assertTrue(any("Unencrypted" in f or "HTTP" in f for f in body["Threat_Flags"]))

    # -------------------------------------------------------------------------
    # TC-03: Shortened Link + Suspicious TLD -> SUSPICIOUS (Score: 40)
    # -------------------------------------------------------------------------
    @patch("lambda_function._urlhaus_lookup", return_value=(0, None))
    @patch("lambda_function._trace_redirects")
    def test_tc03_shortened_link_suspicious_tld(self, mock_trace, mock_urlhaus):
        """TC-03: bit.ly -> https://promo-event.xyz triggers shortener (+15) & .xyz (+25) -> SUSPICIOUS 40."""
        initial_url = "https://bit.ly/promo-event-test"
        destination_url = "https://promo-event.xyz"
        mock_trace.return_value = (destination_url, 1, [initial_url, destination_url])

        event = self._make_api_gw_event({"url": initial_url})
        resp = lambda_function.lambda_handler(event, self.context)

        self.assertEqual(resp["statusCode"], 200)
        body = json.loads(resp["body"])
        self.assertEqual(body["Verdict"], "SUSPICIOUS")
        self.assertEqual(body["Risk_Score"], 40)
        self.assertEqual(body["Redirect_Hops"], 1)

    # -------------------------------------------------------------------------
    # TC-04: Raw IP + Phishing Keywords -> MALICIOUS (Score: 100)
    # -------------------------------------------------------------------------
    @patch("lambda_function._urlhaus_lookup", return_value=(0, None))
    @patch("lambda_function._trace_redirects")
    def test_tc04_raw_ip_and_phishing_keywords(self, mock_trace, mock_urlhaus):
        """TC-04: http://45.33.32.156/kyc-verify/login triggers IP(+50), HTTP(+20), 3 keywords(+60) -> capped at 100."""
        target_url = "http://45.33.32.156/kyc-verify/login"
        mock_trace.return_value = (target_url, 0, [target_url])

        event = self._make_api_gw_event({"url": target_url})
        resp = lambda_function.lambda_handler(event, self.context)

        self.assertEqual(resp["statusCode"], 200)
        body = json.loads(resp["body"])
        self.assertEqual(body["Verdict"], "MALICIOUS")
        self.assertEqual(body["Risk_Score"], 100)

    # -------------------------------------------------------------------------
    # TC-05: '@' Authority Obfuscation -> MALICIOUS (Score: 100)
    # -------------------------------------------------------------------------
    @patch("lambda_function._urlhaus_lookup", return_value=(0, None))
    @patch("lambda_function._trace_redirects")
    def test_tc05_authority_obfuscation(self, mock_trace, mock_urlhaus):
        """TC-05: https://sbi.co.in@secure-claim.top/reward triggers @ (+45), .top (+25), claim (+20), reward (+20) -> 100."""
        target_url = "https://sbi.co.in@secure-claim.top/reward"
        mock_trace.return_value = (target_url, 0, [target_url])

        event = self._make_api_gw_event({"url": target_url})
        resp = lambda_function.lambda_handler(event, self.context)

        self.assertEqual(resp["statusCode"], 200)
        body = json.loads(resp["body"])
        self.assertEqual(body["Verdict"], "MALICIOUS")
        self.assertEqual(body["Risk_Score"], 100)

    # -------------------------------------------------------------------------
    # TC-06: Warm Cache Validation -> Sub-30ms Cache Hit
    # -------------------------------------------------------------------------
    @patch("lambda_function._urlhaus_lookup", return_value=(0, None))
    @patch("lambda_function._trace_redirects")
    def test_tc06_warm_cache_validation(self, mock_trace, mock_urlhaus):
        """TC-06: Second invocation for the same URL must hit warm cache with cache_hit=True."""
        target_url = "http://45.33.32.156/kyc-verify/login"
        mock_trace.return_value = (target_url, 0, [target_url])

        # 1st call (cold hit)
        event = self._make_api_gw_event({"url": target_url})
        resp1 = lambda_function.lambda_handler(event, self.context)
        body1 = json.loads(resp1["body"])
        self.assertFalse(body1["cache_hit"])

        # 2nd call (warm hit)
        resp2 = lambda_function.lambda_handler(event, self.context)
        body2 = json.loads(resp2["body"])
        self.assertEqual(resp2["statusCode"], 200)
        self.assertTrue(body2["cache_hit"])
        self.assertEqual(body2["Verdict"], "MALICIOUS")
        self.assertEqual(body2["Risk_Score"], 100)
        # Verify latency target (< 30ms)
        self.assertLess(body2["execution_ms"], 30.0)

    # -------------------------------------------------------------------------
    # TC-07: Invalid Payload Rejection -> HTTP 400 Bad Request
    # -------------------------------------------------------------------------
    def test_tc07_invalid_payload_rejection(self):
        """TC-07: javascript:alert(1) must be rejected with HTTP 400."""
        event = self._make_api_gw_event({"url": "javascript:alert(1)"})
        resp = lambda_function.lambda_handler(event, self.context)

        self.assertEqual(resp["statusCode"], 400)
        body = json.loads(resp["body"])
        self.assertIn("error", body)
        self.assertIn("Provide a valid 'url'", body["error"])

    # -------------------------------------------------------------------------
    # TC-08: CORS Preflight (OPTIONS)
    # -------------------------------------------------------------------------
    def test_tc08_cors_preflight(self):
        """TC-08: HTTP OPTIONS request must return 200 with CORS headers."""
        event = self._make_api_gw_event({}, http_method="OPTIONS")
        resp = lambda_function.lambda_handler(event, self.context)

        self.assertEqual(resp["statusCode"], 200)
        self.assertEqual(resp["headers"]["Access-Control-Allow-Origin"], "*")
        self.assertIn("POST", resp["headers"]["Access-Control-Allow-Methods"])

    # -------------------------------------------------------------------------
    # TC-09: Malformed JSON in Body
    # -------------------------------------------------------------------------
    def test_tc09_malformed_json_body(self):
        """TC-09: Invalid non-JSON string body must return 400."""
        event = {
            "httpMethod": "POST",
            "body": "{invalid-json-data",
        }
        resp = lambda_function.lambda_handler(event, self.context)
        self.assertEqual(resp["statusCode"], 400)

    # -------------------------------------------------------------------------
    # TC-10: Punycode / Homograph Domain (R-04)
    # -------------------------------------------------------------------------
    @patch("lambda_function._urlhaus_lookup", return_value=(0, None))
    @patch("lambda_function._trace_redirects")
    def test_tc10_punycode_homograph_detection(self, mock_trace, mock_urlhaus):
        """TC-10: Punycode domain https://xn--pple-43d.com triggers R-04 (+40) -> SUSPICIOUS 40."""
        target_url = "https://xn--pple-43d.com"
        mock_trace.return_value = (target_url, 0, [target_url])

        event = self._make_api_gw_event({"url": target_url})
        resp = lambda_function.lambda_handler(event, self.context)

        self.assertEqual(resp["statusCode"], 200)
        body = json.loads(resp["body"])
        self.assertGreaterEqual(body["Risk_Score"], 40)
        self.assertTrue(any("Punycode" in f or "xn--" in f for f in body["Threat_Flags"]))

    # -------------------------------------------------------------------------
    # TC-11: URLhaus Threat Feed Match (R-01)
    # -------------------------------------------------------------------------
    @patch("lambda_function._urlhaus_lookup")
    @patch("lambda_function._trace_redirects")
    def test_tc11_urlhaus_threat_match(self, mock_trace, mock_urlhaus):
        """TC-11: Match in URLhaus threat feed gives +100 -> MALICIOUS."""
        target_url = "https://malware-drop-site.com/payload.exe"
        mock_trace.return_value = (target_url, 0, [target_url])
        mock_urlhaus.return_value = (100, {
            "rule": "R-01",
            "weight": 100,
            "description": "Listed in abuse.ch URLhaus Threat Feed (active malware/phishing distribution)",
        })

        event = self._make_api_gw_event({"url": target_url})
        resp = lambda_function.lambda_handler(event, self.context)

        self.assertEqual(resp["statusCode"], 200)
        body = json.loads(resp["body"])
        self.assertEqual(body["Verdict"], "MALICIOUS")
        self.assertEqual(body["Risk_Score"], 100)

    # -------------------------------------------------------------------------
    # TC-12: Parity Check between Lambda and Vercel engines
    # -------------------------------------------------------------------------
    @patch("validate._urlhaus_lookup", return_value=(0, None))
    @patch("validate._trace_redirects")
    @patch("lambda_function._urlhaus_lookup", return_value=(0, None))
    @patch("lambda_function._trace_redirects")
    def test_tc12_lambda_and_vercel_parity(self, mock_l_trace, mock_l_urlhaus, mock_v_trace, mock_v_urlhaus):
        """TC-12: Verifies that Lambda and Vercel engines produce identical scores and verdicts."""
        test_urls = [
            ("https://www.cbit.ac.in", 0, "SAFE"),
            ("http://neverssl.com", 20, "SAFE"),
            ("http://45.33.32.156/kyc-verify/login", 100, "MALICIOUS"),
            ("https://sbi.co.in@secure-claim.top/reward", 100, "MALICIOUS"),
        ]

        for url, expected_score, expected_verdict in test_urls:
            mock_l_trace.return_value = (url, 0, [url])
            mock_v_trace.return_value = (url, 0, [url])

            # Lambda invocation
            l_resp = lambda_function.lambda_handler(self._make_api_gw_event({"url": url}), self.context)
            l_body = json.loads(l_resp["body"])

            # Vercel invocation
            v_body = vercel_validator.validate_url(url)

            self.assertEqual(l_body["Risk_Score"], expected_score, f"Lambda score mismatch on {url}")
            self.assertEqual(v_body["Risk_Score"], expected_score, f"Vercel score mismatch on {url}")
            self.assertEqual(l_body["Verdict"], expected_verdict, f"Lambda verdict mismatch on {url}")
            self.assertEqual(v_body["Verdict"], expected_verdict, f"Vercel verdict mismatch on {url}")


if __name__ == "__main__":
    unittest.main()

