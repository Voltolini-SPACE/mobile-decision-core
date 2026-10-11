#!/usr/bin/env python3
"""Consulta segura do estado G0–G8; nenhuma inferência ou ensaio implícito."""
import argparse
import json
from pathlib import Path
import sys
from evaluation.evidence_validator import evaluate, write_snapshot

PROJECT_ROOT = Path(__file__).absolute().parent


def _gate(gate, *, root=None, evidence_dir=None):
    result = evaluate(root or PROJECT_ROOT, evidence_dir)
    detail = result["gates"][gate]
    print(f"{gate}: {detail['status']} ({detail['reason']})")
    return detail["status"] == "PASS"


def validate_gate_0(*, root=None, evidence_dir=None):
    return _gate("G0", root=root, evidence_dir=evidence_dir)


def validate_gate_1(*, root=None, evidence_dir=None):
    return _gate("G1", root=root, evidence_dir=evidence_dir)


def validate_gate_2(*, root=None, evidence_dir=None):
    return _gate("G2", root=root, evidence_dir=evidence_dir)


def validate_gate_3(*, root=None, evidence_dir=None):
    return _gate("G3", root=root, evidence_dir=evidence_dir)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=PROJECT_ROOT)
    parser.add_argument("--evidence-dir", type=Path)
    parser.add_argument("--gates", nargs="+", choices=[f"G{i}" for i in range(9)])
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    for path in [args.root, args.evidence_dir, args.output]:
        if path is not None and (not path.is_absolute() or ".." in path.parts):
            parser.error("Use caminhos absolutos sem travessia de diretórios")
    result = evaluate(args.root, args.evidence_dir)
    if args.output is not None:
        try:
            write_snapshot(result, args.output, protected_root=args.root)
        except (ValueError, OSError) as error:
            parser.error(f"Snapshot não criado: {error}")
    if args.json:
        print(json.dumps(result, ensure_ascii=False, allow_nan=False, indent=2))
    else:
        for gate in args.gates or result["gates"]:
            detail = result["gates"][gate]
            print(f"{gate}: {detail['status']} ({detail['reason']})")
        print(result["release_status"] + " — snapshot estrutural; ensaios integrais pendentes")
    return 0 if result["release_status"] == "APPROVED_FOR_RELEASE" else 1


if __name__ == "__main__":
    sys.exit(main())
