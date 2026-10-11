"""Consulta estrutural de evidências. Não executa ensaios nem certifica seus relatos."""
from datetime import datetime, timezone
import errno
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat

SCHEMA = "voltolini.mobile-decision.gate-state/1"
OBLIGATIONS = {
    "G0": ["E0_AUDIT_REPRODUCED_AND_REVIEWED", "ENVIRONMENT_AND_LINEAGE_VERIFIED"],
    "G1": ["REAL_MLFLOW_CHAIN_TWO_RUNS_REPRODUCED", "RECOVERY_ISOLATION_AND_FIRST_IMPROVEMENT_VERIFIED"],
    "G2": ["DATA_SPLITS_SEMANTIC_DEDUP_VERIFIED", "TOKENIZER_DYNAMIC_CONTRACT_EXECUTED"],
    "G3": ["OWN_MODEL_LEARNING_AND_RESERVED_QUALITY_VERIFIED"],
    "G4": ["REAL_NATIVE_EXPORT_SDK_PHYSICAL_OFFLINE_PARITY_VERIFIED"],
    "G5": ["PROFILED_ABLATIONS_AND_NONREGRESSION_VERIFIED"],
    "G6": ["FINAL_QUALITY_AND_PAIRED_PHYSICAL_P95_PROTOCOL_VERIFIED"],
    "G7": ["TWO_INDEPENDENT_SAFE_INTEGRATIONS_VERIFIED"],
    "G8": ["CLEAN_REPRODUCTION_LICENSES_ATOMIC_INSTALL_ROLLBACK_VERIFIED"],
}


def _directory_fd(path, forbidden_identities=None):
    path = Path(path)
    if not path.is_absolute() or ".." in path.parts:
        raise ValueError("UNSAFE_PATH")
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    try:
        info = os.fstat(fd)
        if forbidden_identities and (info.st_dev, info.st_ino) in forbidden_identities:
            raise ValueError("OUTPUT_MUST_BE_OUTSIDE_PROJECT")
        for part in path.parts[1:]:
            new = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = new
            info = os.fstat(fd)
            if forbidden_identities and (info.st_dev, info.st_ino) in forbidden_identities:
                raise ValueError("OUTPUT_MUST_BE_OUTSIDE_PROJECT")
        return fd
    except BaseException:
        os.close(fd)
        raise


def _stat(path):
    directory = _directory_fd(path.parent)
    try:
        result = os.stat(path.name, dir_fd=directory, follow_symlinks=False)
        if stat.S_ISLNK(result.st_mode):
            raise ValueError("UNSAFE_PATH")
        return result
    finally:
        os.close(directory)


def _read(path, digest_only=False):
    directory = _directory_fd(path.parent)
    try:
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        with os.fdopen(fd, "rb") as stream:
            before = os.fstat(stream.fileno())
            if not stat.S_ISREG(before.st_mode):
                raise ValueError("WRONG_TYPE")
            if not digest_only and before.st_size > 1024 * 1024:
                raise ValueError("DOCUMENT_TOO_LARGE")
            digest = hashlib.sha256()
            chunks = []
            while True:
                chunk = stream.read(1024 * 1024)
                if not chunk:
                    break
                digest.update(chunk)
                if not digest_only:
                    chunks.append(chunk)
            after = os.fstat(stream.fileno())
            final = os.stat(path.name, dir_fd=directory, follow_symlinks=False)
            identity = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_mode)
            if identity(before) != identity(after) or identity(after) != identity(final):
                raise ValueError("SOURCE_CHANGED_DURING_READ")
            source = {"path": str(path), "sha256": digest.hexdigest(), "bytes": after.st_size,
                      "file_modified_at": datetime.fromtimestamp(after.st_mtime, timezone.utc).isoformat()}
            return b"".join(chunks), source
    finally:
        os.close(directory)


def _json(data):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("INVALID_JSON")
            result[key] = value
        return result
    def invalid(_):
        raise ValueError("INVALID_JSON")
    value = json.loads(data, object_pairs_hook=pairs, parse_constant=invalid)
    def finite(item):
        if isinstance(item, float) and not math.isfinite(item):
            raise ValueError("INVALID_JSON")
        if isinstance(item, dict):
            for child in item.values():
                finite(child)
        elif isinstance(item, list):
            for child in item:
                finite(child)
    finite(value)
    if not isinstance(value, dict):
        raise ValueError("JSON_OBJECT_REQUIRED")
    return value


def _reason(error):
    if isinstance(error, FileNotFoundError):
        return "NOT_VERIFIED", "MISSING"
    if isinstance(error, OSError):
        return "FAIL", "UNSAFE_PATH" if error.errno in (errno.ELOOP, errno.ENOTDIR) else "UNREADABLE"
    if isinstance(error, (json.JSONDecodeError, UnicodeDecodeError, RecursionError)):
        return "FAIL", "INVALID_JSON"
    return "FAIL", str(error)


def evaluate(root, evidence_dir=None, *, now=None):
    """Retorna checks reais e obrigações integrais pendentes; não aceita estados de entrada."""
    root = Path(root).absolute()
    evidence_dir = Path(evidence_dir).absolute() if evidence_dir else root / "state/evidence"
    checks, sources = [], []
    def add(identifier, gate, status, reason):
        row = {"id": identifier, "gate": gate, "scope": "structural", "status": status,
               "reason": reason, "execution_verification": "NOT_VERIFIED"}
        checks.append(row)
        return row
    def directory(rel, gate):
        try:
            info = _stat(root / rel)
            if not stat.S_ISDIR(info.st_mode):
                raise ValueError("WRONG_TYPE")
            add(f"{gate}.dir.{rel}", gate, "PASS", "DIRECTORY_VERIFIED")
        except (OSError, ValueError) as error:
            add(f"{gate}.dir.{rel}", gate, *_reason(error))
    def file(path, identifier, gate, json_object=False):
        try:
            data, source = _read(path)
            sources.append(source)
            if not data.strip():
                raise ValueError("EMPTY_FILE")
            value = _json(data) if json_object else None
            row = add(identifier, gate, "PASS", "JSON_OBJECT_VERIFIED" if json_object else "NONEMPTY_FILE_VERIFIED")
            return row, value
        except (OSError, ValueError, RecursionError) as error:
            return add(identifier, gate, *_reason(error)), None
    for rel in ["configs", "data", "docs", "evaluation", "export", "infrastructure", "lab", "manifests",
                "model", "sdk", "tests", "training", "lab/experiments", "lab/runs", "lab/artifacts", "lab/models", "lab/backups"]:
        directory(rel, "G0")
    for rel in ["lab/config.yaml", "lab/dashboard.html", "lab/experiments/demo_run_01/metrics.json",
                "lab/experiments/demo_run_01/params.json", "lab/experiments/demo_run_01/README.md"]:
        file(root / rel, f"G1.file.{rel}", "G1", rel.endswith(".json"))
    directory("lab/experiments/demo_run_01", "G1")
    for rel in ["data/datasets", "data/tokenizer", "data/contracts"]:
        directory(rel, "G2")
    for rel in ["data/contracts/input_contract.json", "data/contracts/output_contract.json"]:
        file(root / rel, f"G2.file.{rel}", "G2", True)
    for name in ["AUDIT_RETURN.json", "ENVIRONMENT.json", "MODEL_LINEAGE.json"]:
        file(evidence_dir / name, f"G0.evidence.{name}", "G0", True)
    index_row, index = file(evidence_dir / "EVIDENCE_INDEX.json", "G0.evidence.EVIDENCE_INDEX.json", "G0", True)
    if index is not None:
        valid = (set(index) == {"schema_version", "artifacts"}
                 and index["schema_version"] == "voltolini.mobile-decision.evidence-references/1"
                 and isinstance(index["artifacts"], list))
        if not valid:
            index_row.update(status="FAIL", reason="INPUT_FIELDS_NOT_ALLOWED")
        else:
            seen = set()
            for artifact in index["artifacts"]:
                if (not isinstance(artifact, dict) or set(artifact) != {"id", "path", "sha256"}
                        or not isinstance(artifact["id"], str) or not artifact["id"] or artifact["id"] in seen
                        or not isinstance(artifact["path"], str)
                        or not isinstance(artifact["sha256"], str)
                        or not re.fullmatch(r"[0-9a-f]{64}", artifact["sha256"])):
                    index_row.update(status="FAIL", reason="INVALID_ARTIFACT_REFERENCE")
                    continue
                seen.add(artifact["id"])
                try:
                    rel = Path(artifact["path"])
                    if rel.is_absolute() or ".." in rel.parts or not rel.parts:
                        raise ValueError("UNSAFE_PATH")
                    _, source = _read(root / rel, digest_only=True)
                    sources.append(source)
                    if source["sha256"] != artifact["sha256"]:
                        raise ValueError("HASH_MISMATCH")
                    add("artifact." + artifact["id"], "G0", "PASS", "HASH_VERIFIED")
                except (OSError, ValueError) as error:
                    add("artifact." + artifact["id"], "G0", *_reason(error))
    gates = {}
    for gate, obligations in OBLIGATIONS.items():
        local = [row for row in checks if row["gate"] == gate]
        gates[gate] = {"status": "FAIL" if any(row["status"] == "FAIL" for row in local) else "NOT_VERIFIED",
                       "checks": [row["id"] for row in local], "pending_obligations": list(obligations),
                       "reason": "LOCAL_EVIDENCE_INVALID" if any(row["status"] == "FAIL" for row in local)
                       else "INTEGRAL_VERIFIERS_NOT_IMPLEMENTED"}
    return {"schema_version": SCHEMA, "mode": "snapshot", "root": str(root),
            "evaluated_at": now or datetime.now(timezone.utc).isoformat(), "expires_at": None,
            "freshness": "NOT_CERTIFIED", "sources": sources, "checks": checks, "gates": gates,
            "release_status": "APPROVED_FOR_RELEASE" if all(g["status"] == "PASS" for g in gates.values())
            else "NOT_APPROVED_FOR_RELEASE",
            "limitations": ["STRUCTURE_JSON_HASH_ONLY", "NO_EXECUTION_AUTHENTICATION", "NO_FULL_AGGREGATION",
                            "NO_HISTORICAL_INVALIDATION", "NO_REAL_MLFLOW_OR_NEURAL_OR_PHYSICAL_RUNNERS"],
            "criteria_sources": {}}


def write_snapshot(result, output, *, protected_root):
    """Cria snapshot operacional explicitamente solicitado, sem overwrite ou escrita no projeto."""
    output, protected = Path(output), Path(protected_root).absolute()
    protected_roots = [protected, Path(__file__).absolute().parents[1]]
    if (not output.is_absolute() or ".." in output.parts
            or any(output == item or item in output.parents for item in protected_roots)):
        raise ValueError("OUTPUT_MUST_BE_OUTSIDE_PROJECT")
    protected_identities = set()
    for path in protected_roots:
        try:
            protected_fd = _directory_fd(path)
        except FileNotFoundError:
            continue
        try:
            info = os.fstat(protected_fd)
            protected_identities.add((info.st_dev, info.st_ino))
        finally:
            os.close(protected_fd)
    payload = (json.dumps(result, ensure_ascii=False, allow_nan=False, indent=2) + "\n").encode()
    directory = _directory_fd(output.parent, forbidden_identities=protected_identities)
    try:
        fd = os.open(output.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory)
        with os.fdopen(fd, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        os.close(directory)
