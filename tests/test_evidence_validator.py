"""Checks reais de estrutura/JSON/hashes; nenhum positivo certifica a missão."""
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


class EvidenceValidator(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="voltolini-r1b-checks-", dir=str(Path(tempfile.gettempdir()).resolve()))
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "project"
        self.root.mkdir()
        self.evidence = Path(self.temp.name) / "evidence"
        self.evidence.mkdir()

    def core(self):
        path = ROOT / "evaluation/evidence_validator.py"
        if not path.is_file():
            self.fail("Calculated evidence evaluation is not implemented yet")
        spec = importlib.util.spec_from_file_location("evidence_core_test", path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def evaluate(self):
        return self.core().evaluate(self.root, self.evidence, now="2026-10-11T05:00:00+00:00")

    def check(self, result, identifier):
        return next(row for row in result["checks"] if row["id"] == identifier)

    def test_correct_directory_passes_local_check_but_not_gate(self):
        (self.root / "configs").mkdir()
        result = self.evaluate()
        self.assertEqual(self.check(result, "G0.dir.configs")["status"], "PASS")
        self.assertNotEqual(result["gates"]["G0"]["status"], "PASS")

    def test_file_instead_of_directory_fails_local_check(self):
        (self.root / "configs").touch()
        self.assertEqual(self.check(self.evaluate(), "G0.dir.configs")["reason"], "WRONG_TYPE")

    def test_strict_json_accepts_object_and_rejects_corrupt_variants(self):
        contracts = self.root / "data/contracts"
        contracts.mkdir(parents=True)
        path = contracts / "input_contract.json"
        for text, expected in [(' {"version":1} ', "PASS"), ('{}', "PASS"), ('', "FAIL"),
                               ('{"a":1,"a":2}', "FAIL"), ('{"a":NaN}', "FAIL"),
                               ('{"a":Infinity}', "FAIL"), ('{"a":1e999}', "FAIL"), ('[]', "FAIL")]:
            with self.subTest(text=text):
                path.write_text(text)
                self.assertEqual(self.check(self.evaluate(), "G2.file.data/contracts/input_contract.json")["status"], expected)

    def index(self, path="payload.txt", digest="ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"):
        (self.evidence / "EVIDENCE_INDEX.json").write_text(json.dumps({
            "schema_version": "voltolini.mobile-decision.evidence-references/1",
            "artifacts": [{"id": "payload", "path": path, "sha256": digest}]}))

    def test_known_hash_passes_integrity_and_changed_bytes_fail(self):
        (self.root / "payload.txt").write_text("abc")
        self.index()
        result = self.evaluate()
        self.assertEqual(self.check(result, "artifact.payload")["status"], "PASS")
        self.assertEqual(result["release_status"], "NOT_APPROVED_FOR_RELEASE")
        (self.root / "payload.txt").write_text("abcd")
        self.assertEqual(self.check(self.evaluate(), "artifact.payload")["reason"], "HASH_MISMATCH")
        (self.root / "payload.txt").unlink()
        self.assertNotEqual(self.check(self.evaluate(), "artifact.payload")["status"], "PASS")

    def test_traversal_and_symbolic_ancestor_are_not_read(self):
        (Path(self.temp.name) / "outside.txt").write_text("abc")
        self.index("../outside.txt")
        self.assertEqual(self.check(self.evaluate(), "artifact.payload")["reason"], "UNSAFE_PATH")
        (self.root / "link").symlink_to(Path(self.temp.name), target_is_directory=True)
        self.index("link/outside.txt")
        self.assertEqual(self.check(self.evaluate(), "artifact.payload")["reason"], "UNSAFE_PATH")

    def test_input_cannot_declare_pass_or_obligations(self):
        (self.evidence / "EVIDENCE_INDEX.json").write_text(json.dumps({
            "schema_version": "voltolini.mobile-decision.evidence-references/1", "artifacts": [],
            "scope": "production", "gates": {"G0": "PASS"}, "checks": [], "obligations": []}))
        result = self.evaluate()
        self.assertEqual(self.check(result, "G0.evidence.EVIDENCE_INDEX.json")["reason"], "INPUT_FIELDS_NOT_ALLOWED")
        self.assertTrue(all(row["status"] != "PASS" for row in result["gates"].values()))
        self.assertTrue(all(row["pending_obligations"] for row in result["gates"].values()))

    def test_snapshot_records_read_sources_not_live_or_measurement(self):
        (self.root / "configs").mkdir()
        result = self.evaluate()
        self.assertEqual(result["schema_version"], "voltolini.mobile-decision.gate-state/1")
        self.assertEqual(result["mode"], "snapshot")
        self.assertIsNone(result["expires_at"])
        self.assertTrue(all(row["status"] not in ("STALE", "BLOCKED") for row in result["gates"].values()))

    def test_output_is_exclusive_and_cannot_overwrite_project_or_existing_file(self):
        core = self.core()
        result = core.evaluate(self.root, self.evidence)
        with self.assertRaises(ValueError):
            core.write_snapshot(result, self.root / "state.json", protected_root=self.root)
        target = Path(self.temp.name) / "snapshot.json"
        core.write_snapshot(result, target, protected_root=self.root)
        original = target.read_bytes()
        with self.assertRaises(FileExistsError):
            core.write_snapshot(result, target, protected_root=self.root)
        self.assertEqual(target.read_bytes(), original)
        self.assertEqual(json.loads(original)["release_status"], "NOT_APPROVED_FOR_RELEASE")

    def test_output_case_alias_cannot_enter_protected_project(self):
        alias = self.root.with_name("PROJECT")
        if not alias.exists() or not os.path.samefile(alias, self.root):
            self.skipTest("Filesystem temporário não possui alias de caixa para esta fixture")
        core = self.core()
        result = core.evaluate(self.root, self.evidence)
        target = alias / "must-not-create.json"
        with self.assertRaises(ValueError):
            core.write_snapshot(result, target, protected_root=self.root)
        self.assertFalse((self.root / "must-not-create.json").exists())


if __name__ == "__main__":
    unittest.main()
