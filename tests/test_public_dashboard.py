"""Fixtures públicas: consulta vazia, fontes inválidas e ausência de efeitos neurais."""
import contextlib
from datetime import datetime, timezone
import hashlib
from http.client import HTTPConnection
import io
import json
from pathlib import Path
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from preview_adapter import Collector
import server


class PublicDashboard(unittest.TestCase):
    def test_default_cli_uses_empty_public_config_and_starts_no_inference(self):
        # Mock somente o loop HTTP; a leitura/parsing do config padrão é real.
        fake = unittest.mock.Mock(server_port=12345)
        with patch.object(sys, "argv", ["server.py"]), patch.object(server, "make_server", return_value=fake) as make:
            with contextlib.redirect_stdout(io.StringIO()):
                server.main()
        self.assertEqual(make.call_args.args[0].specs, [])
        self.assertEqual(make.call_args.args[2], 0)
        fake.serve_forever.assert_called_once_with()
        fake.server_close.assert_called_once_with()
        self.assertFalse(any(name == "torch" or name.startswith("torch.") for name in sys.modules))

    def test_empty_source_snapshot_has_no_invented_metrics_or_approval(self):
        payload = Collector([]).collect()
        self.assertEqual(payload["sources"], [])
        self.assertFalse(payload["mission"]["release_approved"])
        for key in ["accuracy", "latency_ms", "cost", "global_progress", "checkpoint"]:
            self.assertIsNone(payload["mission"][key])
        self.assertEqual(payload["mission"]["quality"], "NOT_VERIFIED")

    def test_missing_and_wrong_pin_sources_are_unavailable(self):
        with tempfile.TemporaryDirectory(prefix="voltolini-public-fixture-", dir=str(Path(tempfile.gettempdir()).resolve())) as td:
            path = Path(td) / "source.json"
            spec = {"id": "fixture", "path": str(path), "kind": "policy", "mode": "snapshot", "sha256": "0" * 64}
            self.assertEqual(Collector([spec]).collect()["sources"][0]["error"], "SOURCE_MISSING")
            path.write_text("{}")
            payload = Collector([spec]).collect()
            self.assertEqual(payload["sources"][0]["error"], "HASH_MISMATCH")
            self.assertIsNone(payload["sources"][0]["data"])
            self.assertIsNone(payload["mission"]["accuracy"])

    def test_http_read_only_loopback_assets_and_empty_api(self):
        service = server.make_server(Collector([]), ROOT, 0)
        thread = threading.Thread(target=service.serve_forever, daemon=True)
        thread.start()
        try:
            connection = HTTPConnection("127.0.0.1", service.server_port, timeout=3)
            connection.request("GET", "/api/preview")
            response = connection.getresponse()
            self.assertEqual(response.status, 200)
            payload = json.loads(response.read())
            self.assertEqual(payload["sources"], [])
            self.assertFalse(payload["mission"]["release_approved"])
            connection.request("POST", "/api/preview")
            response = connection.getresponse(); response.read()
            self.assertEqual(response.status, 405)
            connection.request("GET", "/", headers={"Host": "outside.example"})
            response = connection.getresponse(); response.read()
            self.assertEqual(response.status, 403)
            connection.close()
        finally:
            service.shutdown(); service.server_close(); thread.join(3)
        self.assertFalse(thread.is_alive())


if __name__ == "__main__":
    unittest.main()
