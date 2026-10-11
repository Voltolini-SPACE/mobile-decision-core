"""R1D.A: ZIP/refs estáticos e recibo; nenhum runner neural é implementado.

Não extrai, importa ou executa membros do ZIP, nem executa auditores históricos.
Referências são fornecidas explicitamente; pins não autenticam sua autoria.
Dependência privada pinada: evidence_validator._directory_fd/_read/_json.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import io
import json
import math
import os
from pathlib import Path
import re
import stat
import sys
import unicodedata
import zipfile

if __name__ == "__main__":
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from evaluation.evidence_validator import _directory_fd, _json, _read, write_snapshot

SCHEMA = "voltolini.mobile-decision.lineage-run/1"
CORE_SHA256 = "aea3eca964016fefc207b134ed2e5c8bbe8aa9bbab70f1630b9f6c41d95a9fa4"
LIMITS = {"archive_bytes": 8*1024*1024, "members": 1024, "member_bytes": 8*1024*1024,
          "expanded_bytes": 32*1024*1024, "expansion_ratio": 100, "path_bytes": 512}
GAPS = ["MEMBER_CONTENT_NOT_REAUDITED", "HISTORICAL_RESULTS_NOT_REEXECUTED",
        "INITIAL_FINAL_LEARNING_NOT_VERIFIED", "LICENSES_NOT_VERIFIED",
        "MLFLOW_CHAIN_NOT_VERIFIED", "FULL_G0_G1_AND_G2_G8_PENDING"]


def _require(condition, reason):
    if not condition:
        raise ValueError(reason)


def _hash(value):
    _require(isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value), "INVALID_SHA256")
    return value


def _keys(value, required):
    _require(isinstance(value, dict) and set(value) >= set(required), "INVALID_REFERENCE_SHAPE")


def _integer(value):
    _require(type(value) is int and value >= 0, "INVALID_REFERENCE_SHAPE")
    return value


def _timestamp(value):
    _require(isinstance(value, str), "INVALID_REFERENCE_SHAPE")
    try:
        timestamp = datetime.fromisoformat(value[:-1]+"+00:00" if value.endswith("Z") else value)
        _require(timestamp.tzinfo is not None, "INVALID_REFERENCE_SHAPE")
    except ValueError:
        raise ValueError("INVALID_REFERENCE_SHAPE") from None
    return value


def _core_pin():
    _, source = _read(Path(__file__).resolve().parents[1]/"evaluation/evidence_validator.py", digest_only=True)
    _require(source["sha256"] == CORE_SHA256, "CORE_DEPENDENCY_CHANGED")


def _zip_bytes(path):
    """Única leitura ZIP limitada; descritores nofollow e snapshot de identidade."""
    _require(path.is_absolute() and ".." not in path.parts, "UNSAFE_SOURCE_PATH")
    directory = _directory_fd(path.parent)
    try:
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        with os.fdopen(fd, "rb") as stream:
            before = os.fstat(stream.fileno())
            _require(stat.S_ISREG(before.st_mode), "UNSAFE_SOURCE_TYPE")
            _require(before.st_size <= LIMITS["archive_bytes"], "ARCHIVE_LIMIT_EXCEEDED")
            data = stream.read(LIMITS["archive_bytes"]+1)
            _require(len(data) <= LIMITS["archive_bytes"], "ARCHIVE_LIMIT_EXCEEDED")
            after = os.fstat(stream.fileno())
            final = os.stat(path.name, dir_fd=directory, follow_symlinks=False)
            identity = lambda s: (s.st_dev, s.st_ino, s.st_mode, s.st_size, s.st_mtime_ns)
            _require(identity(before) == identity(after) == identity(final), "SOURCE_CHANGED_DURING_READ")
            return data, {"path": str(path), "sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data),
                          "file_modified_at": datetime.fromtimestamp(after.st_mtime, timezone.utc).isoformat()}
    finally:
        os.close(directory)


def _member_path(name, directory=False):
    _require(isinstance(name, str) and name and "\\" not in name and "\0" not in name
             and ":" not in name and len(name.encode("utf-8")) <= LIMITS["path_bytes"], "UNSAFE_ARCHIVE_PATH")
    path = name[:-1] if directory and name.endswith("/") else name
    _require(all(part not in ("", ".", "..") for part in path.split("/")), "UNSAFE_ARCHIVE_PATH")
    return unicodedata.normalize("NFC", path).casefold()


def _metadata(data):
    members, seen, total = [], set(), 0
    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
    except NotImplementedError:
        # Unsupported central-directory version is a format failure, not execution.
        raise ValueError("UNSUPPORTED_ZIP_FORMAT") from None
    with archive:
        infos = archive.infolist()
        _require(len(infos) <= LIMITS["members"], "ARCHIVE_LIMIT_EXCEEDED")
        for info in infos:
            _require(info.orig_filename == info.filename, "UNSAFE_ARCHIVE_PATH")
            key = _member_path(info.filename, info.is_dir())
            _require(key not in seen, "DUPLICATE_ARCHIVE_PATH")
            seen.add(key)
            mode_type = stat.S_IFMT(info.external_attr >> 16)
            _require(mode_type in (0, stat.S_IFREG, stat.S_IFDIR)
                     and (mode_type != stat.S_IFDIR or info.is_dir()), "UNSAFE_ARCHIVE_TYPE")
            _require(not info.flag_bits & 1, "ENCRYPTED_ARCHIVE_UNSUPPORTED")
            _require(info.compress_type in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED), "UNSUPPORTED_COMPRESSION")
            total += info.file_size
            _require(0 <= info.file_size <= LIMITS["member_bytes"] and total <= LIMITS["expanded_bytes"]
                     and 0 <= info.compress_size <= len(data), "ARCHIVE_LIMIT_EXCEEDED")
            _require(info.file_size <= LIMITS["expansion_ratio"]*max(1, info.compress_size), "ARCHIVE_EXPANSION_LIMIT")
            members.append({"path": info.filename, "bytes": info.file_size, "compressed_bytes": info.compress_size,
                            "compression": info.compress_type, "directory": info.is_dir()})
    return {"members": len(members), "expanded_bytes_declared": total, "entries": members}


def _historical_claims(kind, value, members):
    """Valida forma e extrai alegações referenciadas; não recalcula scorer/header."""
    _keys(value, {"archive_sha256", "captured_at"})
    _timestamp(value["captured_at"])
    if kind == "integrity":
        _keys(value, {"manifest_entries", "members", "checks", "all_manifest_checks_pass", "safetensors_header"})
        count = _integer(value["manifest_entries"])
        _require(_integer(value["members"]) == members and isinstance(value["checks"], list)
                 and len(value["checks"]) == count and type(value["all_manifest_checks_pass"]) is bool, "INVALID_REFERENCE_SHAPE")
        for row in value["checks"]:
            _keys(row, {"path", "path_safe", "bytes_match", "sha256_match"})
            _member_path(row["path"])
            _require(all(type(row[k]) is bool for k in ("path_safe", "bytes_match", "sha256_match")), "INVALID_REFERENCE_SHAPE")
        header = value["safetensors_header"]
        _keys(header, {"tensors", "shapes"})
        tensors = _integer(header["tensors"])
        _require(isinstance(header["shapes"], dict) and len(header["shapes"]) == tensors, "INVALID_REFERENCE_SHAPE")
        for shape in header["shapes"].values():
            _require(isinstance(shape, list), "INVALID_REFERENCE_SHAPE")
            for dimension in shape:
                _integer(dimension)
        return {"manifest_entries": count, "tensors": tensors, "declared_integrity_pass": value["all_manifest_checks_pass"]}
    _keys(value, {"schema", "historical_results_recalculated"})
    _require(value["schema"] == "voltolini-original-archive-reaggregation/1", "INVALID_REFERENCE_SHAPE")
    values = value["historical_results_recalculated"]
    _keys(values, {"heldout_synthetic", "manual_diagnostic"})
    claims = {}
    for name in ("heldout_synthetic", "manual_diagnostic"):
        row = values[name]
        _keys(row, {"cases", "correct", "accuracy"})
        n, correct = _integer(row["cases"]), _integer(row["correct"])
        _require(correct <= n and type(row["accuracy"]) in (int, float)
                 and 0 <= row["accuracy"] <= 1 and math.isfinite(row["accuracy"]), "INVALID_REFERENCE_SHAPE")
        claims[name] = {"cases": n, "correct": correct, "accuracy": row["accuracy"]}
    return claims


def _references(refs, archive_hash, members):
    _require(type(refs) in (list, tuple), "INVALID_REFERENCE_SHAPE")
    references, claims, seen = [], {}, set()
    for ref in refs:
        _keys(ref, {"kind", "path", "sha256", "archive_sha256"})
        _require(set(ref) == {"kind", "path", "sha256", "archive_sha256"}, "INVALID_REFERENCE_SHAPE")
        kind = ref["kind"]
        _require(kind in ("integrity", "reaggregation", "provenance"), "INVALID_REFERENCE_KIND")
        _require(kind not in seen, "DUPLICATE_REFERENCE_KIND")
        seen.add(kind)
        _require(_hash(ref["archive_sha256"]) == archive_hash, "REFERENCE_ARCHIVE_MISMATCH")
        _require(isinstance(ref["path"], str), "INVALID_REFERENCE_SHAPE")
        path = Path(ref["path"])
        _require(path.is_absolute() and ".." not in path.parts, "UNSAFE_REFERENCE_PATH")
        data, source = _read(path)
        _require(source["sha256"] == _hash(ref["sha256"]), "REFERENCE_HASH_MISMATCH")
        link = "EXTERNAL_PIN_AND_ARCHIVE_LINK_VERIFIED"
        if kind != "provenance":
            value = _json(data)
            _require(value.get("archive_sha256") == archive_hash, "REFERENCE_ARCHIVE_MISMATCH")
            claims[kind] = _historical_claims(kind, value, members)
        else:
            _require(bool(data.strip()), "EMPTY_REFERENCE")
            link = "EXTERNAL_ASSOCIATION_ONLY"
        references.append({"kind": kind, "source": source, "archive_sha256": archive_hash,
                           "link_verification": link, "scope": "HISTORICAL_REFERENCE_NOT_REEXECUTED"})
    return references, claims


def audit_package(zip_path, expected_sha256, *, evidence_refs=()):
    """Audita pin externo/metadata; refs explícitos não são novos ensaios.

    evidence_refs: lista de {kind, path absoluto, sha256, archive_sha256}.
    kind: integrity/reaggregation (JSON estrito com link interno) ou provenance
    (bytes pinados, associação externa declarada). Default vazio não busca fontes.
    INVALID não publica alegações históricas; nenhum status de gate é aceito.
    """
    path = Path(zip_path)
    result = {"schema_version": SCHEMA, "validity": "INVALID", "reason_codes": [],
              "generated_at": datetime.now(timezone.utc).isoformat(),
              "scope": "STATIC_ARCHIVE_AND_REFERENCED_HISTORY_ONLY", "expected_archive_sha256": None,
              "archive": {"path": str(path), "sha256": None, "bytes": None, "file_modified_at": None},
              "archive_metadata": None, "limits": dict(LIMITS), "historical_references": [], "historical_claims": {},
              "current_verification": "NOT_VERIFIED", "execution_verification": "NOT_VERIFIED",
              "learning_verification": "NOT_VERIFIED", "mlflow_verification": "NOT_VERIFIED",
              "license_verification": "NOT_VERIFIED", "gates_verification": "NOT_VERIFIED",
              "gaps": list(GAPS), "release_status": "NOT_APPROVED_FOR_RELEASE"}
    try:
        _hash(expected_sha256)
        result["expected_archive_sha256"] = expected_sha256
        _core_pin()
        data, source = _zip_bytes(path)
        result["archive"] = source
        _require(source["sha256"] == expected_sha256, "ARCHIVE_HASH_MISMATCH")
        metadata = _metadata(data)
        references, claims = _references(evidence_refs, expected_sha256, metadata["members"])
        result.update(validity="VALID", reason_codes=["ARCHIVE_PIN_METADATA_AND_REFERENCE_CONTRACT_VERIFIED"],
                      current_verification="ZIP_PIN_METADATA_AND_REFERENCE_LINKS_ONLY", archive_metadata=metadata,
                      historical_references=references, historical_claims=claims)
    except (OSError, ValueError, UnicodeError, RecursionError, zipfile.BadZipFile) as error:
        if isinstance(error, OSError):
            reason = "MISSING_OR_UNSAFE_SOURCE"
        elif isinstance(error, zipfile.BadZipFile):
            reason = "INVALID_ZIP"
        elif isinstance(error, (json.JSONDecodeError, UnicodeError, RecursionError)):
            reason = "INVALID_JSON"
        else:
            reason = str(error)
        result["reason_codes"] = [reason]
    return result


def write_receipt(receipt, output, *, source_zip):
    """Criação exclusiva fora do projeto e da pasta da fonte, por identidadeFS."""
    _core_pin()
    source_zip = Path(source_zip)
    _require(source_zip.is_absolute() and ".." not in source_zip.parts, "UNSAFE_SOURCE_PATH")
    _require(isinstance(receipt, dict) and receipt.get("archive", {}).get("path") == str(source_zip), "SOURCE_RECEIPT_MISMATCH")
    write_snapshot(receipt, output, protected_root=source_zip.parent)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    audit = commands.add_parser("audit", help="somente pin/metadata e referências históricas")
    audit.add_argument("--source-zip", required=True)
    audit.add_argument("--expected-sha256", required=True)
    audit.add_argument("--evidence-ref", nargs=4, action="append", default=[], metavar=("KIND", "PATH", "SHA256", "ARCHIVE_SHA256"))
    audit.add_argument("--output", help="arquivo novo fora do projeto/fonte; default stdout somente leitura")
    args = parser.parse_args(argv)
    refs = [dict(zip(("kind", "path", "sha256", "archive_sha256"), values)) for values in args.evidence_ref]
    result = audit_package(args.source_zip, args.expected_sha256, evidence_refs=refs)
    if args.output:
        try:
            write_receipt(result, args.output, source_zip=args.source_zip)
        except (OSError, ValueError) as error:
            print(json.dumps({"output_error": type(error).__name__, "reason": str(error)}), file=sys.stderr)
            return 2
    print(json.dumps(result, ensure_ascii=False, allow_nan=False, indent=2))
    return 0 if result["validity"] == "VALID" else 1


if __name__ == "__main__":
    raise SystemExit(main())
