"""EV4: agregação categórica exata, somente leitura, sem certificar execução.

Dependência privada deliberada: _read/_json/_directory_fd do core pinado abaixo.
Manifesto até 1 MiB; cada JSONL até 8 MiB, inclusive durante a leitura.
As referências de entradas/descrições e o congelamento cego não são verificados.
"""
from datetime import datetime, timezone
from decimal import Decimal
from fractions import Fraction
import hashlib
import json
import os
from pathlib import Path
import re
import stat

from evaluation.evidence_validator import _directory_fd, _json, _read

CORE_SHA256 = "aea3eca964016fefc207b134ed2e5c8bbe8aa9bbab70f1630b9f6c41d95a9fa4"
SCHEMA = "voltolini.mobile-decision.case-metrics/1"
BUNDLE_SCHEMA = "voltolini.mobile-decision.case-bundle/1"
SCORER = "opaque-id-exact-micro/1"
POLICY = "eligible-ok-probability-gte/1"
HASH_KEYS = {"dataset_hash", "split_hash", "model_hash", "tokenizer_hash", "calibration_hash",
             "runtime_hash", "protocol_hash", "code_hash", "cases_sha256", "labels_sha256"}
IDENTITY_KEYS = HASH_KEYS | {"run_id", "cohort_id", "scorer", "policy", "threshold"}
COUNT_KEYS = {"N_all", "N_eligible", "N_accepted", "N_correct_all", "N_correct_eligible",
              "N_correct_accepted", "N_wrong_accepted", "N_errors", "N_timeouts"}
METRICS = ("accuracy_all", "accuracy_eligible", "accepted_accuracy", "coverage_eligible", "accepted_fraction_all")
JSONL_MAX_BYTES = 8 * 1024 * 1024


def _read_jsonl(path):
    """Lê um JSONL regular, limitado e estável; não relaxa o leitor do manifesto."""
    directory = _directory_fd(path.parent)
    try:
        parent_before = os.fstat(directory)
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        with os.fdopen(fd, "rb", buffering=0) as stream:
            before = os.fstat(stream.fileno())
            if not stat.S_ISREG(before.st_mode):
                raise ValueError("WRONG_TYPE")
            if before.st_size > JSONL_MAX_BYTES:
                raise ValueError("DOCUMENT_TOO_LARGE")
            digest, chunks, total = hashlib.sha256(), [], 0
            while True:
                # One bounded sentinel byte detects growth past the cap, even
                # when the initial stat was small. Never accumulate that byte.
                chunk = stream.read(min(64 * 1024, JSONL_MAX_BYTES - total + 1))
                if not chunk:
                    break
                total += len(chunk)
                if total > JSONL_MAX_BYTES:
                    raise ValueError("DOCUMENT_TOO_LARGE")
                digest.update(chunk)
                chunks.append(chunk)
            after = os.fstat(stream.fileno())
            # Rewalk nofollow ancestors so a moved/replaced parent cannot leave
            # a valid read of an obsolete directory descriptor unnoticed.
            final_directory = _directory_fd(path.parent)
            try:
                parent_final = os.fstat(final_directory)
                final = os.stat(path.name, dir_fd=final_directory, follow_symlinks=False)
            finally:
                os.close(final_directory)
            identity = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns, s.st_mode)
            if ((parent_before.st_dev, parent_before.st_ino) != (parent_final.st_dev, parent_final.st_ino)
                    or identity(before) != identity(after) or identity(after) != identity(final)
                    or total != after.st_size):
                raise ValueError("SOURCE_CHANGED_DURING_READ")
            source = {"path": str(path), "sha256": digest.hexdigest(), "bytes": total,
                      "file_modified_at": datetime.fromtimestamp(after.st_mtime, timezone.utc).isoformat()}
            return b"".join(chunks), source
    finally:
        os.close(directory)


def _require(condition, reason):
    if not condition:
        raise ValueError(reason)


def _keys(value, required, optional=()):
    _require(isinstance(value, dict) and set(value) >= set(required)
             and set(value) <= set(required) | set(optional), "INVALID_FIELDS")


def _text(value):
    _require(isinstance(value, str) and bool(value.strip()), "INVALID_STRING")
    return value


def _hash(value):
    _require(isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value), "INVALID_HASH")
    return value


def _relative(value):
    _text(value)
    _require("\\" not in value and "\0" not in value
             and all(part not in ("", ".", "..") for part in value.split("/")), "UNSAFE_PATH")
    return value


def _number(value):
    _require(type(value) in (int, float, Decimal), "INVALID_NUMBER")
    number = Decimal(str(value))
    _require(number.is_finite() and 0 <= number <= 1, "INVALID_NUMBER")
    return Fraction(number)


def _identity(value):
    _keys(value, IDENTITY_KEYS)
    _require(value["scorer"] == SCORER, "UNSUPPORTED_SCORER")
    _require(value["policy"] == POLICY, "UNSUPPORTED_POLICY")
    for key in HASH_KEYS:
        _hash(value[key])
    for key in ("run_id", "cohort_id"):
        _text(value[key])
    return {**value, "threshold": _number(value["threshold"])}


def _document(data):
    # Shared parser rejects duplicates/nonfinite/object errors; Decimal preserves
    # the lexical threshold boundary instead of rounding to binary float.
    _json(data)
    return json.loads(data, parse_float=Decimal)


def _rows(data):
    return [_document(line) for line in data.splitlines()]


def _indexed(rows):
    result = {}
    for row in rows:
        case_id = _text(row.get("case_id"))
        _require(case_id not in result, "DUPLICATE_CASE_ID")
        result[case_id] = row
    return result


def validate_counts(counts):
    """Valida inteiros e todas as restrições de subconjuntos da coorte única."""
    _keys(counts, COUNT_KEYS)
    _require(all(type(value) is int and value >= 0 for value in counts.values()), "INVALID_COUNTS")
    n, e, a = counts["N_all"], counts["N_eligible"], counts["N_accepted"]
    c, ce, ca = counts["N_correct_all"], counts["N_correct_eligible"], counts["N_correct_accepted"]
    failures = counts["N_errors"] + counts["N_timeouts"]
    _require(0 <= a <= e <= n and 0 <= ca <= ce <= c <= n and ca <= a and ce <= e
             and c-ce <= n-e and ce-ca <= e-a and counts["N_wrong_accepted"] == a-ca
             and failures <= n and a <= n-failures and c <= n-failures
             and a+c-ca+failures <= n, "INCONSISTENT_COUNTS")


def _ratio(numerator, denominator, reason):
    exact = Fraction(numerator, denominator) if denominator else None
    return {"numerator": numerator, "denominator": denominator,
            "value": float(exact) if exact is not None else None,
            "exact": str(exact) if exact is not None else None,
            "reason": None if exact is not None else reason}


def _metrics(counts):
    n, e, a = counts["N_all"], counts["N_eligible"], counts["N_accepted"]
    empty = "EMPTY_COHORT" if not n else None
    metrics = dict(zip(METRICS, [
        _ratio(counts["N_correct_all"], n, empty),
        _ratio(counts["N_correct_eligible"], e, empty or "NO_ELIGIBLE_CASES"),
        _ratio(counts["N_correct_accepted"], a, empty or "NO_ACCEPTED_CASES"),
        _ratio(a, e, empty or "NO_ELIGIBLE_CASES"), _ratio(a, n, empty)]))
    ca = counts["N_correct_accepted"]
    bounds = {"all": {"lower": _ratio(ca, n, empty), "upper": _ratio(ca+n-a, n, empty)},
              "eligible": {"lower": _ratio(ca, e, empty or "NO_ELIGIBLE_CASES"),
                           "upper": _ratio(ca+e-a, e, empty or "NO_ELIGIBLE_CASES")}}
    # A = P*C + correct_unaccepted/N, checked with exact rational arithmetic.
    identity = {}
    for name, total, correct in [("all", n, counts["N_correct_all"]),
                                  ("eligible", e, counts["N_correct_eligible"])]:
        if total:
            pc = Fraction(ca, total)  # Defined even when P is undefined (zero accepts).
            remainder = Fraction(correct-ca, total)
            _require(Fraction(correct, total) == pc+remainder, "IDENTITY_INCONSISTENT")
            identity[name] = {"accepted_correct_fraction": str(pc),
                              "unaccepted_correct_fraction": str(remainder),
                              "accuracy": str(Fraction(correct, total)),
                              "precision_times_coverage_defined": bool(a)}
        else:
            identity[name] = None
    return metrics, bounds, identity


def _aggregate(cases, labels, predictions, expected):
    _require(set(cases) == set(labels) == set(predictions), "CASE_SET_MISMATCH")
    counts = dict.fromkeys(sorted(COUNT_KEYS), 0)
    for case_id, case in cases.items():
        _keys(case, {"case_id", "input_ref", "input_sha256", "eligible", "eligibility_reason", "alternatives"})
        _relative(case["input_ref"]); _hash(case["input_sha256"]); _text(case["eligibility_reason"])
        _require(type(case["eligible"]) is bool, "INVALID_ELIGIBILITY")
        _require(isinstance(case["alternatives"], list) and len(case["alternatives"]) > 0, "INVALID_ALTERNATIVES")
        alternatives = set()
        for option in case["alternatives"]:
            _keys(option, {"id", "kind", "description_ref", "description_sha256"})
            _require(option["kind"] == "option", "UNSUPPORTED_LABEL_KIND")
            option_id = _text(option["id"])
            _require(option_id not in alternatives, "DUPLICATE_OPTION_ID")
            alternatives.add(option_id)
            _relative(option["description_ref"]); _hash(option["description_sha256"])
        label = labels[case_id]
        _keys(label, {"case_id", "expected_id"})
        _require(isinstance(label["expected_id"], str) and label["expected_id"] in alternatives, "UNKNOWN_LABEL")
        prediction = predictions[case_id]
        _keys(prediction, {"case_id", "run_id", "cohort_id", "input_sha256", "outcome", "predicted_id",
                           "selected_id", "accepted", "probability", "reason", "detail_ref", "identity"})
        _require(_identity(prediction["identity"]) == expected, "IDENTITY_MISMATCH")
        _require(prediction["run_id"] == expected["run_id"] and prediction["cohort_id"] == expected["cohort_id"], "IDENTITY_MISMATCH")
        _require(prediction["input_sha256"] == case["input_sha256"], "INPUT_HASH_MISMATCH")
        _require(type(prediction["accepted"]) is bool, "INVALID_ACCEPTED")
        outcome = prediction["outcome"]
        _require(outcome in ("ok", "error", "timeout"), "UNKNOWN_OUTCOME")
        if outcome == "ok":
            _require(isinstance(prediction["predicted_id"], str) and prediction["predicted_id"] in alternatives, "UNKNOWN_PREDICTION")
            probability = _number(prediction["probability"])
            accepted = case["eligible"] and probability >= expected["threshold"]
            correct = prediction["predicted_id"] == label["expected_id"]
            if prediction["detail_ref"] is not None:
                _relative(prediction["detail_ref"])
        else:
            _require(prediction["predicted_id"] is None and prediction["selected_id"] is None
                     and prediction["probability"] is None, "INVALID_FAILURE")
            _relative(prediction["detail_ref"])
            accepted, correct = False, False
        _require(prediction["accepted"] == accepted, "ACCEPTANCE_MISMATCH")
        _require(prediction["selected_id"] == (prediction["predicted_id"] if accepted else None), "SELECTION_MISMATCH")
        if accepted:
            _require(prediction["reason"] is None, "INVALID_ACCEPTED_REASON")
        else:
            _text(prediction["reason"])
        counts["N_all"] += 1
        counts["N_eligible"] += int(case["eligible"])
        counts["N_accepted"] += int(accepted)
        counts["N_correct_all"] += int(correct)
        counts["N_correct_eligible"] += int(correct and case["eligible"])
        counts["N_correct_accepted"] += int(correct and accepted)
        counts["N_wrong_accepted"] += int(accepted and not correct)
        counts["N_errors"] += int(outcome == "error")
        counts["N_timeouts"] += int(outcome == "timeout")
    validate_counts(counts)
    return counts


def _generated_at(now):
    if now is None:
        return datetime.now(timezone.utc).isoformat()
    if not isinstance(now, str):
        raise ValueError("INVALID_NOW")
    try:
        stamp = datetime.fromisoformat(now[:-1]+"+00:00" if now.endswith("Z") else now)
        if stamp.tzinfo is None:
            raise ValueError("INVALID_NOW")
        return stamp.astimezone(timezone.utc).isoformat()
    except (ValueError, OverflowError):
        raise ValueError("INVALID_NOW") from None


def aggregate_bundle(bundle_dir, expected_identity, *, now=None):
    """Recalcula uma coorte/run; expected_identity deve vir de fonte independente.

    VALID significa contrato/integridade/aritmética válidos, sem provar origem,
    autenticidade, execução, conteúdo das referências ou congelamento dos labels.
    Qualquer violação invalida a coorte inteira e impede publicação de métricas.
    now aceita None (relógio do coletor) ou string ISO com timezone, normalizada
    para UTC. Argumento inválido levanta ValueError("INVALID_NOW") antes de emitir
    qualquer envelope; não é uma falha do bundle.
    """
    generated_at = _generated_at(now)
    root = Path(bundle_dir)
    result = {"schema_version": SCHEMA, "validity": "INVALID", "reason_codes": [],
              "bundle_root": str(root), "source_kind": None, "source_updated_at": None,
              "generated_at": generated_at, "identity": None,
              "policy_threshold_exact": None,
              "sources": [], "counts": None,
              "metrics": {name: {"numerator": None, "denominator": None, "value": None,
                                  "exact": None, "reason": "INVALID_BUNDLE"} for name in METRICS},
              "bounds": None, "arithmetic_identity": None,
              "execution_verification": "NOT_VERIFIED", "authentication_verification": "NOT_VERIFIED",
              "label_freeze_verification": "NOT_VERIFIED", "input_reference_content_verification": "NOT_VERIFIED",
              "release_status": "NOT_APPROVED_FOR_RELEASE"}
    try:
        expected = _identity(expected_identity)
        _require(root.is_absolute() and ".." not in root.parts, "UNSAFE_PATH")
        _, core_source = _read(Path(__file__).parent / "evidence_validator.py", digest_only=True)
        _require(core_source["sha256"] == CORE_SHA256, "CORE_DEPENDENCY_CHANGED")
        data, source = _read(root / "run-manifest.json")
        result["sources"].append(source)
        manifest = _document(data)
        _keys(manifest, {"schema_version", "source_kind", "source_updated_at", "freeze_reference", "identity", "artifacts"}, {"declared_counts"})
        _require(manifest["schema_version"] == BUNDLE_SCHEMA, "UNSUPPORTED_SCHEMA")
        _require(manifest["source_kind"] in ("fixture", "historical", "replay"), "UNSUPPORTED_SOURCE_KIND")
        stamp = datetime.fromisoformat(_text(manifest["source_updated_at"]))
        _require(stamp.tzinfo is not None, "INVALID_TIMESTAMP")
        if manifest["freeze_reference"] is not None:
            _text(manifest["freeze_reference"])
        _require(_identity(manifest["identity"]) == expected, "IDENTITY_MISMATCH")
        _keys(manifest["artifacts"], {"cases", "labels", "predictions"})
        documents = {}
        for name, pin in manifest["artifacts"].items():
            _keys(pin, {"path", "sha256", "bytes"})
            _relative(pin["path"]); _hash(pin["sha256"])
            _require(type(pin["bytes"]) is int and pin["bytes"] >= 0, "INVALID_SIZE")
            data, source = _read_jsonl(root / pin["path"])
            result["sources"].append(source)
            _require(source["sha256"] == pin["sha256"] and source["bytes"] == pin["bytes"], "ARTIFACT_HASH_MISMATCH")
            if name in ("cases", "labels"):
                _require(source["sha256"] == expected[name+"_sha256"], "FROZEN_ARTIFACT_MISMATCH")
            documents[name] = _indexed(_rows(data))
        counts = _aggregate(documents["cases"], documents["labels"], documents["predictions"], expected)
        if "declared_counts" in manifest:
            validate_counts(manifest["declared_counts"])
            _require(manifest["declared_counts"] == counts, "DECLARED_COUNTS_MISMATCH")
        metrics, bounds, identity = _metrics(counts)
        # No input object supplies output status or verification state.
        result.update(validity="VALID", reason_codes=["CONTRACT_INTEGRITY_AND_ARITHMETIC_VERIFIED"],
                      source_kind=manifest["source_kind"], source_updated_at=manifest["source_updated_at"],
                      identity={**expected_identity, "threshold": float(expected["threshold"])},
                      policy_threshold_exact=str(expected["threshold"]), counts=counts, metrics=metrics,
                      bounds=bounds, arithmetic_identity=identity)
    except (OSError, ValueError, UnicodeError, RecursionError) as error:
        if isinstance(error, OSError):
            reason = "MISSING_OR_UNSAFE_ARTIFACT"
        elif isinstance(error, (json.JSONDecodeError, UnicodeError, RecursionError)):
            reason = "INVALID_JSON"
        else:
            reason = str(error)
        result["reason_codes"] = [reason]
    return result
