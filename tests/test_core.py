import json
from pathlib import Path
import tempfile
import unittest
from fastapi.testclient import TestClient
from prahari.api import create_app
from prahari.detectors.models import Models
from prahari.engine import Engine
from prahari.parsing import parse, views
from prahari.schemas import ScanInput


class CoreTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.models = Models()
        cls.engine = Engine(cls.models)

    def scan(self, content, kind="payload", content_type="text/plain"):
        return self.engine.scan(
            ScanInput(input_type=kind, content=content, content_type=content_type)
        )

    def test_artifacts_load(self):
        self.assertEqual(self.models.errors, {})

    def test_benign_request_allow(self):
        r = self.scan("GET /products?page=2 HTTP/1.1", "http_request")
        self.assertEqual(r.decision, "Allow")
        self.assertEqual(r.action_taken, "none")
        self.assertEqual(r.coverage["phishing"], "not_applicable")

    def test_legacy_phishing_cannot_allow_or_block(self):
        for u in ["https://www.github.com", "https://github.com/openai"]:
            r = self.scan(u, "url")
            self.assertEqual(r.decision, "Review")
            self.assertTrue(r.model_signals["phishing"]["experimental"])

    def test_all_request_families(self):
        for payload, category in [
            ("' OR 1=1--", "sqli"),
            ("<script>alert(1)</script>", "xss"),
            (";whoami", "command_injection"),
            ("../../etc/passwd", "path_traversal"),
        ]:
            r = self.scan(payload)
            self.assertIn(
                category, {f.category for f in r.findings if f.evidence_kind == "rule"}
            )
            self.assertEqual(r.decision, "Review")

    def test_multiple_families_and_double_encoding(self):
        r = self.scan(
            "GET /?file=%252e%252e%252fetc/passwd&x=%3Cscript%3E HTTP/1.1",
            "http_request",
        )
        self.assertEqual(
            {f.category for f in r.findings if f.evidence_kind == "rule"},
            {"xss", "path_traversal"},
        )
        self.assertTrue(any(f.view == "decoded" for f in r.findings))

    def test_json_plus_and_literal_encoded_plus(self):
        p = parse(
            ScanInput(
                input_type="payload",
                content='{"value":"a+b"}',
                content_type="application/json",
            )
        )
        self.assertEqual(list(views(p.components[-1]))[-1][1], "a+b")
        p = parse(
            ScanInput(
                input_type="payload",
                content="x=a%2Bb+c",
                content_type="application/x-www-form-urlencoded",
            )
        )
        self.assertEqual(list(views(p.components[1]))[-1][1], "a+b c")

    def test_repeated_parameters_preserved(self):
        p = parse(
            ScanInput(input_type="url", content="https://example.com/?x=one&x=two")
        )
        self.assertEqual(
            [c.text for c in p.components if c.name.endswith(".value")], ["one", "two"]
        )

    def test_invalid_url_rejected_ipv6_accepted(self):
        for u in [
            "not a url",
            "ftp://example.com",
            "https://x:bad/",
            "https://user:pass@example.com",
        ]:
            with self.assertRaises(ValueError):
                self.scan(u, "url")
        self.assertIsNotNone(
            parse(ScanInput(input_type="url", content="https://[::1]/")).url
        )

    def test_host_is_not_phishing_destination(self):
        r = self.scan("GET / HTTP/1.1\nHost: example.com", "http_request")
        self.assertEqual(r.coverage["phishing"], "not_applicable")

    def test_unsupported_and_ambiguous_bodies_review(self):
        for text in [
            "POST / HTTP/1.1\nContent-Type: multipart/form-data\n\nhello",
            'POST / HTTP/1.1\nContent-Type: application/json\n\n{"x":1,"x":2}',
            "POST / HTTP/1.1\nTransfer-Encoding: chunked\n\n0",
        ]:
            r = self.scan(text, "http_request")
            self.assertEqual(r.status, "partial")
            self.assertEqual(r.decision, "Review")

    def test_missing_models_review(self):
        with tempfile.TemporaryDirectory() as d:
            r = Engine(Models(d)).scan(
                ScanInput(input_type="url", content="https://example.com")
            )
        self.assertEqual(r.decision, "Review")
        self.assertEqual(r.coverage["phishing"], "error")

    def test_uncertainty_review(self):
        self.assertEqual(self.scan("zzzzqqqqxxx").decision, "Review")

    def test_demo_block_is_advisory_and_explicit(self):
        r = Engine(self.models, demo_strict=True).scan(
            ScanInput(input_type="payload", content="<script>alert(1)</script>")
        )
        self.assertEqual(r.decision, "Block")
        self.assertEqual(r.action_taken, "none")
        self.assertIn("demo-strict", r.versions["policy"])

    def test_no_raw_credentials_in_output(self):
        marker = "PRIVATE_TEST_PASSWORD_98342"
        r = self.scan(
            "POST / HTTP/1.1\nAuthorization: Bearer "
            + marker
            + '\nContent-Type: application/json\n\n{"password":"'
            + marker
            + '"}',
            "http_request",
        )
        self.assertNotIn(marker, r.model_dump_json())

    def test_api_contract_and_errors(self):
        with TestClient(create_app(self.models)) as c:
            self.assertEqual(c.get("/ready").status_code, 200)
            r = c.post(
                "/api/v1/scans",
                json={"input_type": "payload", "content": "<script>alert(1)</script>"},
            )
            self.assertEqual(r.status_code, 200)
            self.assertEqual(r.json()["action_taken"], "none")
            self.assertEqual(
                c.post(
                    "/api/v1/scans", json={"input_type": "url", "content": "nonsense"}
                ).status_code,
                422,
            )
            self.assertEqual(
                c.post(
                    "/api/v1/scans",
                    json={"input_type": "payload", "content": "x", "demo_strict": True},
                ).status_code,
                422,
            )
            secret = "DO_NOT_ECHO_THIS"
            r = c.post("/api/v1/scans", json={"input_type": secret, "content": "x"})
            self.assertNotIn(secret, r.text)
            self.assertEqual(
                c.post("/api/v1/scans", content=b"x" * 65537).status_code, 413
            )
            self.assertEqual(c.get("/docs").status_code, 200)
            self.assertIn("/api/v1/scans", c.get("/openapi.json").json()["paths"])


if __name__ == "__main__":
    unittest.main()
