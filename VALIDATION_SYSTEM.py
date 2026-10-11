#!/usr/bin/env python3
"""Adaptador legado para estados calculados; booleans não são autoridade de aprovação."""
from pathlib import Path
from evaluation.evidence_validator import evaluate
from validate_all_gates import main


class SystemValidator:
    def __init__(self, *, root=None, evidence_dir=None):
        self.project_root = Path(root).absolute() if root else Path(__file__).absolute().parent
        self.evidence_dir = evidence_dir
        self.validation_results = {}
        self.gate_details = {}

    def _evaluate(self):
        self.gate_details = evaluate(self.project_root, self.evidence_dir)
        self.validation_results = {key: value["status"] == "PASS" for key, value in self.gate_details["gates"].items()}
        return self.gate_details

    def _gate(self, gate):
        result = self._evaluate()["gates"][gate]
        print(f"{gate}: {result['status']} ({result['reason']})")
        return result["status"] == "PASS"

    def validate_g0_environment(self):
        return self._gate("G0")

    def validate_g1_laboratory(self):
        return self._gate("G1")

    def validate_g2_data(self):
        return self._gate("G2")

    def validate_g3_model(self):
        return self._gate("G3")

    def validate_g4_execution(self):
        return self._gate("G4")

    def validate_all_systems(self):
        result = self._evaluate()
        print(result["release_status"])
        return result["release_status"] == "APPROVED_FOR_RELEASE"

    def generate_report(self):
        result = self._evaluate()
        for gate, detail in result["gates"].items():
            print(f"{gate}: {detail['status']} ({detail['reason']})")
        print(result["release_status"])
        return dict(self.validation_results)


if __name__ == "__main__":
    raise SystemExit(main())
