"""Regressões: aprovação falsa, bypass público e consulta com efeitos."""
import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class EvidenceAdapters(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="voltolini-r1b-adapters-", dir=str(Path(tempfile.gettempdir()).resolve()))
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.previous = Path.cwd()
        os.chdir(self.root)
        self.addCleanup(os.chdir, self.previous)
        self.first = load("first_validator", "validate_all_gates.py")
        self.second = load("second_validator", "VALIDATION_SYSTEM.py")

    def call(self, function):
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            return function()

    def fixture_dirs(self, files=False):
        for name in ["configs", "data", "docs", "evaluation", "export", "infrastructure", "manifests",
                     "model", "sdk", "tests", "training"]:
            (self.root / name).touch() if files else (self.root / name).mkdir()
        (self.root / "lab").mkdir()
        for name in ["experiments", "runs", "artifacts", "models", "backups"]:
            (self.root / "lab" / name).touch() if files else (self.root / "lab" / name).mkdir()

    def assert_fixture_gate(self, gate, method, check_id, reason):
        # Observe a avaliação REAL do adaptador, sem fabricar estado/resultado.
        calculated = []
        real_evaluate = self.first.evaluate
        def observe(*args, **kwargs):
            result = real_evaluate(*args, **kwargs)
            calculated.append(result)
            return result
        with patch.object(self.first, "evaluate", side_effect=observe):
            function = getattr(self.first, "validate_gate_" + gate[1:])
            self.assertIs(self.call(lambda: function(root=self.root)), False)
        self.assertEqual(calculated[0]["root"], str(self.root))
        self.assertEqual(next(row for row in calculated[0]["checks"] if row["id"] == check_id)["reason"], reason)
        validator = self.second.SystemValidator(root=self.root)
        self.assertIs(self.call(getattr(validator, method)), False)
        self.assertEqual(validator.gate_details["root"], str(self.root))
        self.assertEqual(next(row for row in validator.gate_details["checks"] if row["id"] == check_id)["reason"], reason)

    def test_g0_empty_not_approved(self):
        self.assert_fixture_gate("G0", "validate_g0_environment", "G0.dir.configs", "MISSING")

    def test_g0_files_cannot_replace_directories(self):
        self.fixture_dirs(files=True)
        self.assert_fixture_gate("G0", "validate_g0_environment", "G0.dir.configs", "WRONG_TYPE")

    def test_g1_empty_not_approved(self):
        self.assert_fixture_gate("G1", "validate_g1_laboratory", "G1.file.lab/config.yaml", "MISSING")

    def test_g1_empty_run_evidence_not_approved(self):
        (self.root / "lab/experiments/demo_run_01").mkdir(parents=True)
        (self.root / "lab/experiments/test_run_01").mkdir()
        (self.root / "lab/config.yaml").touch()
        (self.root / "lab/dashboard.html").touch()
        self.assert_fixture_gate("G1", "validate_g1_laboratory", "G1.file.lab/config.yaml", "EMPTY_FILE")

    def test_g2_empty_not_approved(self):
        self.assert_fixture_gate("G2", "validate_g2_data", "G2.dir.data/datasets", "MISSING")

    def test_public_g3_never_attempts_neural_import(self):
        attempted = []
        real_import = __import__
        def guarded(name, *args, **kwargs):
            if name == "torch" or name == "model" or name.startswith("model."):
                attempted.append(name)
                raise ImportError("neural import forbidden by this pure-software test")
            return real_import(name, *args, **kwargs)
        with patch("builtins.__import__", side_effect=guarded):
            self.assertIs(self.call(lambda: self.first.validate_gate_3(root=self.root)), False)
            validator = self.second.SystemValidator(root=self.root)
            self.assertIs(self.call(validator.validate_g3_model), False)
            self.assertEqual(validator.gate_details["root"], str(self.root))
        self.assertEqual(attempted, [])

    def test_public_g4_manifest_does_not_certify_native(self):
        for platform in ["ios", "android"]:
            path = self.root / "export" / platform
            path.mkdir(parents=True)
            (path / "manifest.json").write_text('{"format":"real","physical_device":true,"status":"PASS"}')
        validator = self.second.SystemValidator(root=self.root)
        self.assertIs(self.call(validator.validate_g4_execution), False)
        self.assertEqual(validator.gate_details["root"], str(self.root))
        self.assertEqual(validator.gate_details["gates"]["G4"]["reason"], "INTEGRAL_VERIFIERS_NOT_IMPLEMENTED")

    def test_adulterated_report_is_recomputed(self):
        validator = self.second.SystemValidator(root=self.root)
        validator.validation_results = {f"G{i}": True for i in range(9)}
        result = self.call(validator.generate_report)
        self.assertEqual(result, {f"G{i}": False for i in range(9)})
        self.assertEqual(validator.gate_details["root"], str(self.root))

    def test_default_root_is_not_cwd_and_calls_have_no_effects(self):
        before = sorted(str(p.relative_to(self.root)) for p in self.root.rglob("*"))
        validator = self.second.SystemValidator()
        self.assertEqual(validator.project_root, ROOT)
        self.assertIs(self.call(validator.validate_all_systems), False)
        self.assertEqual(sorted(str(p.relative_to(self.root)) for p in self.root.rglob("*")), before)
        self.assertEqual(set(validator.gate_details["gates"]), {f"G{i}" for i in range(9)})

    def test_cli_filter_cannot_reduce_release_or_write_by_default(self):
        before = sorted(str(p.relative_to(self.root)) for p in self.root.rglob("*"))
        env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
        run = subprocess.run([sys.executable, str(ROOT / "validate_all_gates.py"), "--root", str(self.root),
                              "--gates", "G0", "--json"], capture_output=True, env=env)
        self.assertEqual(run.returncode, 1)
        try:
            result = json.loads(run.stdout)
        except (ValueError, UnicodeDecodeError):
            self.fail("CLI must emit a calculated JSON snapshot, not legacy success text")
        self.assertEqual(set(result["gates"]), {f"G{i}" for i in range(9)})
        self.assertEqual(result["release_status"], "NOT_APPROVED_FOR_RELEASE")
        self.assertEqual(sorted(str(p.relative_to(self.root)) for p in self.root.rglob("*")), before)


    def test_cli_output_cannot_write_inside_selected_project(self):
        target = self.root / "must-not-write.json"
        run = subprocess.run([sys.executable, str(ROOT / "validate_all_gates.py"), "--root", str(self.root),
                              "--output", str(target), "--json"], capture_output=True,
                             env=dict(os.environ, PYTHONDONTWRITEBYTECODE="1"))
        self.assertEqual(run.returncode, 2)
        self.assertFalse(target.exists())

    def test_cli_output_case_alias_cannot_enter_selected_project(self):
        alias = self.root.with_name(self.root.name.upper())
        if not alias.exists() or not os.path.samefile(alias, self.root):
            self.skipTest("Filesystem temporário não possui alias de caixa para esta fixture")
        target = alias / "must-not-write-alias.json"
        run = subprocess.run([sys.executable, str(ROOT / "validate_all_gates.py"), "--root", str(self.root),
                              "--output", str(target), "--json"], capture_output=True,
                             env=dict(os.environ, PYTHONDONTWRITEBYTECODE="1"))
        self.assertEqual(run.returncode, 2)
        self.assertFalse((self.root / "must-not-write-alias.json").exists())


if __name__ == "__main__":
    unittest.main()
