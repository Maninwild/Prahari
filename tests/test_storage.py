import tempfile
import unittest
from pathlib import Path
from fastapi.testclient import TestClient
from prahari.api import create_app
from prahari.detectors.models import Models


class PersistenceTests(unittest.TestCase):
    def test_restart_filters_and_private_input(self):
        with tempfile.TemporaryDirectory() as directory:
            db = Path(directory) / "scans.db"
            with TestClient(create_app(Models(), db)) as c:
                self.assertEqual(c.get("/").status_code, 200)
                self.assertEqual(c.get("/static/app.js").status_code, 200)
                r = c.post(
                    "/api/v1/scans",
                    json={
                        "input_type": "payload",
                        "content": "SECRET_MARKER_39388 <script>alert(1)</script>",
                    },
                ).json()
                scan_id = r["scan_id"]
                self.assertEqual(c.get("/api/v1/dashboard/summary").json()["total"], 1)
                self.assertEqual(
                    c.get("/api/v1/scans?decision=Allow").json()["total"], 0
                )
                self.assertEqual(
                    c.get("/api/v1/scans?decision=Review").json()["total"], 1
                )
                self.assertEqual(c.get("/api/v1/scans?limit=0").status_code, 422)
                self.assertEqual(c.get("/api/v1/scans/nonexistent").status_code, 404)
            with TestClient(create_app(Models(), db)) as c:
                self.assertEqual(
                    c.get("/api/v1/scans/" + scan_id).json()["scan_id"], scan_id
                )
                self.assertEqual(c.get("/api/v1/scans").json()["total"], 1)
            self.assertNotIn(b"SECRET_MARKER_39388", db.read_bytes())
