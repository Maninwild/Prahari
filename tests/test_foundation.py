import tempfile
import unittest
from pathlib import Path
from fastapi.testclient import TestClient
from prahari.api import create_app
from prahari.config import Settings
from prahari.detectors.models import Models
from prahari.engine import Engine
from prahari.schemas import ScanInput


class FoundationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.models = Models()

    def test_configuration_is_validated(self):
        for values in (
            {"policy": "unknown"},
            {"review_threshold": 0},
            {"review_threshold": 91},
            {"review_threshold": float("nan")},
        ):
            with self.assertRaises(ValueError):
                Settings(**values)

    def test_url_rule_explanations_do_not_save_hostname(self):
        result = Engine(self.models).scan(
            ScanInput(input_type="url", content="http://192.0.2.1/account/verify")
        )
        self.assertTrue(
            {"URL-001", "URL-002", "URL-005"}.issubset(
                {f.rule_id for f in result.findings}
            )
        )
        self.assertNotIn("192.0.2.1", result.model_dump_json())
        self.assertEqual(result.decision, "Review")

    def test_missing_detector_cannot_make_strict_block_complete(self):
        with tempfile.TemporaryDirectory() as directory:
            result = Engine(Models(directory), demo_strict=True).scan(
                ScanInput(input_type="payload", content="<script>")
            )
        self.assertEqual(result.status, "partial")
        self.assertEqual(result.decision, "Review")

    def test_nested_encoding_and_invalid_utf8_request_review(self):
        for target in ("%25252e%25252e%25252fetc/passwd", "%FF"):
            result = Engine(self.models).scan(
                ScanInput(
                    input_type="http_request", content="GET /?x=" + target + " HTTP/1.1"
                )
            )
            self.assertEqual(result.status, "partial")
            self.assertEqual(result.decision, "Review")

    def test_corrupt_artifact_reports_unready(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            (path / "manifest.json").write_text(
                '{"request":{"file":"bad.pkl","sha256":"incorrect","version":"test"}}'
            )
            (path / "bad.pkl").write_bytes(b"not a model")
            config = Settings(model_directory=path, db_path=path / "test.db")
            with TestClient(create_app(settings=config)) as client:
                self.assertEqual(client.get("/ready").status_code, 503)
                result = client.post(
                    "/api/v1/scans",
                    json={"input_type": "payload", "content": "ordinary data"},
                ).json()
                self.assertEqual(result["decision"], "Review")

    def test_dashboard_categories_trends_and_authenticated_acknowledgements(self):
        with tempfile.TemporaryDirectory() as directory:
            config = Settings(
                db_path=Path(directory) / "test.db",
                policy="demo-strict",
                integration_key="test-secret",
            )
            with TestClient(create_app(self.models, settings=config)) as client:
                scan = client.post(
                    "/api/v1/scans",
                    json={
                        "input_type": "payload",
                        "content": "<script> ../../etc/passwd",
                    },
                ).json()
                self.assertEqual(scan["decision"], "Block")
                summary = client.get("/api/v1/dashboard/summary").json()
                self.assertEqual(summary["total"], 1)
                self.assertEqual(summary["rule_categories"]["xss"], 1)
                self.assertEqual(summary["rule_categories"]["path_traversal"], 1)
                self.assertEqual(len(summary["daily"]), 7)
                self.assertEqual(sum(day["total"] for day in summary["daily"]), 1)
                self.assertEqual(summary["enforced_blocks"], 0)
                event = {
                    "event_id": "ack-1",
                    "scan_id": scan["scan_id"],
                    "mode": "enforce",
                    "action": "blocked",
                }
                self.assertEqual(
                    client.post("/api/v1/enforcement-events", json=event).status_code,
                    401,
                )
                headers = {"X-Prahari-Key": "test-secret"}
                for _ in range(2):
                    self.assertEqual(
                        client.post(
                            "/api/v1/enforcement-events", json=event, headers=headers
                        ).status_code,
                        200,
                    )
                self.assertEqual(
                    client.get("/api/v1/dashboard/summary").json()["enforced_blocks"], 1
                )
                event["event_id"] = "conflicting-id"
                self.assertEqual(
                    client.post(
                        "/api/v1/enforcement-events", json=event, headers=headers
                    ).status_code,
                    409,
                )
                event["action"] = "allowed"
                self.assertEqual(
                    client.post(
                        "/api/v1/enforcement-events", json=event, headers=headers
                    ).status_code,
                    422,
                )
                configuration = client.get("/api/v1/config").json()
                self.assertEqual(configuration["policy"], "demo-strict")
                self.assertNotIn("test-secret", str(configuration))

    def test_unsupported_host_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            with TestClient(
                create_app(self.models, Path(directory) / "test.db")
            ) as client:
                self.assertEqual(
                    client.get(
                        "/health", headers={"Host": "untrusted.example"}
                    ).status_code,
                    400,
                )

    def test_no_secrets_returned_for_api_validation_errors(self):
        with tempfile.TemporaryDirectory() as directory:
            with TestClient(
                create_app(self.models, Path(directory) / "test.db")
            ) as client:
                marker = "PRIVATE_MARKER_8471"
                for body in (
                    {"input_type": "payload", "content": "x", "extra": marker},
                    {
                        "input_type": "url",
                        "content": "https://user:" + marker + "@example.com",
                    },
                ):
                    response = client.post("/api/v1/scans", json=body)
                    self.assertEqual(response.status_code, 422)
                    self.assertNotIn(marker, response.text)


if __name__ == "__main__":
    unittest.main()
