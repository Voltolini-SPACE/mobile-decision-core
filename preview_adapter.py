"""Read-only projection of allowlisted local evidence. No product imports."""
import hashlib
from fractions import Fraction
import json
import math
import os
from pathlib import Path
import stat
from datetime import datetime, timedelta, timezone


def read_bytes(path):
    path = Path(path)
    if not path.is_absolute() or '..' in path.parts:
        raise ValueError('UNSAFE_PATH')
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in path.parts[1:-1]:
            new = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd); fd = new
        file_fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
        with os.fdopen(file_fd, 'rb') as stream:
            before = os.fstat(stream.fileno())
            if not stat.S_ISREG(before.st_mode) or before.st_size > 1048576:
                raise ValueError('SOURCE_SIZE_OR_TYPE')
            raw = stream.read(1048577)
            after = os.fstat(stream.fileno())
            current = os.stat(path.name, dir_fd=fd, follow_symlinks=False)
            identity = lambda x: (x.st_dev, x.st_ino, x.st_size, x.st_mtime_ns, x.st_mode)
            if len(raw) > 1048576 or identity(before) != identity(after) or identity(after) != identity(current):
                raise ValueError('SOURCE_CHANGED_DURING_READ')
            return raw, datetime.fromtimestamp(after.st_mtime, timezone.utc).isoformat()
    finally:
        os.close(fd)


def strict_json(raw):
    def pairs(items):
        result = {}
        for k, v in items:
            if k in result: raise ValueError('JSON_DUPLICATE')
            result[k] = v
        return result
    def invalid(_): raise ValueError('JSON_NONFINITE')
    result = json.loads(raw, object_pairs_hook=pairs, parse_constant=invalid)
    def finite(value):
        if isinstance(value, float) and not math.isfinite(value): raise ValueError('JSON_NONFINITE')
        if isinstance(value, dict):
            for x in value.values(): finite(x)
        if isinstance(value, list):
            for x in value: finite(x)
    finite(result)
    if not isinstance(result, dict): raise ValueError('JSON_OBJECT_REQUIRED')
    return result


SCHEMAS = {
    'gates': 'voltolini.mobile-decision.gate-state/1',
    'acceptance': 'voltolini.mobile-decision.r1b.acceptance/1',
    'tests': 'voltolini.mobile-decision.r1b.focused-review/2',
    'guard': 'voltolini.mobile-decision.harness-guard/1',
    'ownership': 'voltolini.mobile-decision.case-metrics.ownership/1',
    'policy': 'voltolini.mobile-decision.preview-policy/1',
    'smoke': 'voltolini.mobile-decision.runtime-smoke/1',
    'learning_snapshot': 'voltolini.mobile-decision.learning-snapshot/1',
    'calibration_snapshot': 'voltolini.mobile-decision.calibration-snapshot/1',
    'b1_progress': 'voltolini.mobile-decision.cpu-progress/1',
    'b1_reconciliation': 'voltolini.mobile-decision.output-reconciliation/1',
}



def nonnegative_integer(value):
    if type(value) is not int or value < 0: raise ValueError('B1_INVALID_COUNT')
    return value


def timestamp(value):
    if not isinstance(value, str): raise ValueError('B1_TIMESTAMP')
    stamp = datetime.fromisoformat(value.replace('Z', '+00:00'))
    if stamp.tzinfo is None: raise ValueError('B1_TIMESTAMP')
    return value  # Preserve the source timestamp; collection never renews it.


def b1_projection(kind, data):
    if data['gate_approval'] is not False: raise ValueError('B1_SCOPE')
    if not isinstance(data['variant'], str) or not data['variant'].strip(): raise ValueError('B1_TEXT')
    common = {'variant': data['variant'], 'gate_approval': False}
    if kind == 'b1_progress':
        expected = nonnegative_integer(data['expected_cases'])
        completed = data['completed_cases']
        if completed is not None and nonnegative_integer(completed) > expected: raise ValueError('B1_INVALID_COUNT')
        if not isinstance(data['stage'], str) or not data['stage'].strip(): raise ValueError('B1_TEXT')
        finished = data.get('execution_finished')
        if finished is not None and type(finished) is not bool: raise ValueError('B1_RETURN_STATE')
        optional = ['source_updated_at', 'output_reconciliation', 'resource_run_acceptance', 'watchdog_abort_reason', 'second_variant', 'next_step', 'baseline_resource_acceptance', 'method_parity', 'protocol_order_conformity']
        for key in optional:
            value = data.get(key)
            if value is not None and (not isinstance(value, str) or not value.strip()): raise ValueError('B1_TEXT')
        if data.get('resource_run_acceptance') not in (None, 'NOT_VERIFIED', 'VALID_SAMPLED_WATCHDOG_WITH_DECLARED_LIMITATIONS'): raise ValueError('B1_SCOPE')
        if data.get('baseline_resource_acceptance') not in (None, 'NOT_VERIFIED'): raise ValueError('B1_SCOPE')
        if data.get('method_parity') not in (None, 'PASS_DIAGNOSTIC_ONLY'): raise ValueError('B1_SCOPE')
        if data.get('protocol_order_conformity') not in (None, 'NOT_VERIFIED'): raise ValueError('B1_SCOPE')
        for key in ['global_quality', 'cost']:
            if data[key] is not None: raise ValueError('B1_UNVERIFIED_METRIC')
        if data.get('inference_latency') is not None: raise ValueError('B1_UNVERIFIED_METRIC')
        timestamp(data['observed_at'])
        if data.get('source_updated_at') is not None: timestamp(data['source_updated_at'])
        return {**common, **{key: data.get(key) for key in optional}, 'stage': data['stage'],
                'completed_cases': completed, 'expected_cases': expected, 'execution_finished': finished,
                'global_quality': None, 'inference_latency': None, 'cost': None,
                'dispatch_at': None, 'watchdog_abort_field_present': 'watchdog_abort_reason' in data,
                'source_kind': 'coordination_record_not_live_execution'}
    if data['resource_run_acceptance'] != 'NOT_VERIFIED': raise ValueError('B1_SCOPE')
    if data['output_reconciliation'] != 'VALID_DIAGNOSTIC_SNAPSHOT': raise ValueError('B1_RECONCILIATION')
    if not isinstance(data['watchdog_abort_reason'], str) or not data['watchdog_abort_reason'].strip(): raise ValueError('B1_TEXT')
    timestamp(data['recorded_at'])
    cases = data['observed_cases']
    if not isinstance(cases, dict) or set(cases) != {'test', 'diagnostic'}: raise ValueError('B1_COHORTS')
    counts = {key: nonnegative_integer(value) for key, value in cases.items()}
    pairs = nonnegative_integer(data['ordered_pairs'])
    if pairs != sum(counts.values()): raise ValueError('B1_PAIR_COUNT')
    for key in ['duplicates', 'unknown_or_missing', 'input_pin_mismatches', 'output_contract_mismatches']:
        if nonnegative_integer(data[key]) != 0: raise ValueError('B1_RECONCILIATION')
    for key in ['source_sha256', 'payload_sha256']:
        value = data[key]
        if not isinstance(value, str) or len(value) != 64 or any(c not in '0123456789abcdef' for c in value):
            raise ValueError('B1_INVALID_PIN')
    return {**common, 'output_reconciliation': data['output_reconciliation'], 'watchdog_abort_reason': data['watchdog_abort_reason'],
            'resource_run_acceptance': data['resource_run_acceptance'], 'observed_cases': counts, 'ordered_pairs': pairs,
            'source_sha256': data['source_sha256'], 'payload_sha256': data['payload_sha256'],
            'source_kind': 'diagnostic_snapshot_known_synthetic_not_blind',
            'global_quality': None, 'inference_latency': None, 'cost': None}


def learning_projection(data):
    if (data['source_kind'] != 'historical' or data['scope'] != 'selection200_development_not_blind'
            or data['status'] != 'ACCEPTED_SCRATCH_PARAMETER_UPDATE_AND_SELECTION_ONLY'
            or data['gate_approval'] is not False
            or data['gates'] != {f'G{i}': 'NOT_VERIFIED' for i in range(9)}):
        raise ValueError('LEARNING_SCOPE')
    timestamp(data['source_updated_at'])
    for key in ('cost', 'inference_latency', 'global_quality'):
        if data[key] is not None: raise ValueError('LEARNING_GLOBAL_METRIC')
    pins = {}
    for key in ('initial_checkpoint_sha256', 'final_checkpoint_sha256', 'execution_receipt_sha256', 'validation_receipt_sha256'):
        value = data[key]
        if not isinstance(value, str) or len(value) != 64 or any(c not in '0123456789abcdef' for c in value):
            raise ValueError('LEARNING_PIN')
        pins[key] = value
    counts = {key: nonnegative_integer(data[key]) for key in ('completed_epochs', 'training_optimizer_steps',
        'selected_epoch', 'checkpoint_optimizer_steps', 'tensors', 'parameters', 'changed_parameters')}
    if (not 0 < counts['selected_epoch'] <= counts['completed_epochs']
            or counts['checkpoint_optimizer_steps'] > counts['training_optimizer_steps']
            or counts['changed_parameters'] > counts['parameters']):
        raise ValueError('LEARNING_LINEAGE_COUNTS')
    result = {**pins, **counts, 'source_kind': data['source_kind'], 'scope': data['scope'],
        'status': data['status'], 'source_updated_at': data['source_updated_at'],
        'gate_approval': False, 'gates': dict(data['gates']),
        'global_quality': None, 'cost': None, 'inference_latency': None}
    for stage in ('selection_initial', 'selection_final'):
        d = data[stage]
        c = {key: nonnegative_integer(d[key]) for key in ('N_all', 'N_eligible', 'N_correct_all',
            'N_correct_eligible', 'N_accepted', 'N_correct_accepted', 'N_wrong_accepted', 'N_errors', 'N_timeouts')}
        n, e, correct, ce, a, ca, wrong, errors, timeouts = c.values()
        if (n != 200 or e != 200 or not ca <= ce <= correct <= n or not ca <= a <= e
                or wrong != a-ca or errors+timeouts > n-e or a+correct-ca+errors+timeouts > n):
            raise ValueError('LEARNING_SELECTION_COUNTS')
        ratios = {'accuracy': correct/n, 'coverage': a/e, 'accepted_accuracy': ca/a if a else None}
        for key, expected in ratios.items():
            actual = d[key]
            if expected is None:
                if actual is not None: raise ValueError('LEARNING_RATIO')
            elif type(actual) not in (int, float) or not math.isfinite(actual) or actual != expected:
                raise ValueError('LEARNING_RATIO')
        result[stage] = {**c, **ratios, 'accepted_accuracy_reason': None if a else 'NO_ACCEPTED_CASES'}
    resources = data.get('resources', {})
    if not isinstance(resources, dict): raise ValueError('LEARNING_RESOURCES')
    output = {}
    for key in ('elapsed_seconds', 'observed_peak_rss_bytes', 'rss_samples'):
        value = resources.get(key)
        if value is not None and (type(value) not in ((int, float) if key == 'elapsed_seconds' else (int,))
                                  or not math.isfinite(value) or value < 0):
            raise ValueError('LEARNING_RESOURCES')
        output[key] = value
    gaps = resources.get('monitor_gaps')
    if gaps is not None and not isinstance(gaps, list): raise ValueError('LEARNING_RESOURCES')
    output['monitor_gap_count'] = len(gaps) if gaps is not None else None
    result['resources'] = output
    next_step = data.get('next_step')
    if next_step is not None and (not isinstance(next_step, str) or not next_step.strip()):
        raise ValueError('LEARNING_NEXT')
    result['next_step'] = next_step
    return result


def calibration_projection(data):
    if (data['source_kind'] != 'historical' or data['scope'] != 'known_development_calibration200_not_blind'
            or data['status'] != 'TARGET_NOT_MET' or data['chosen_metrics_reason'] != 'TARGET_NOT_MET'
            or data['gate_approval'] is not False or data['release_approved'] is not False
            or data['gates'] != {f'G{i}': 'NOT_VERIFIED' for i in range(9)}
            or data['tracking'] != 'NOT_EXECUTED_AT_SNAPSHOT'):
        raise ValueError('CALIBRATION_SCOPE')
    timestamp(data['source_updated_at'])
    null_keys = ('chosen_threshold', 'chosen_precision', 'chosen_coverage', 'global_quality', 'inference_latency', 'cost')
    if any(data[k] is not None for k in null_keys): raise ValueError('CALIBRATION_NULL_POLICY')
    if data['targets'] != {'accepted_precision': .99, 'coverage_eligible': .8, 'ece': .05}:
        raise ValueError('CALIBRATION_TARGETS')
    pins = {}
    for key in ('result_sha256', 'fit_receipt_sha256', 'independent_review_sha256', 'checkpoint_sha256'):
        value = data[key]
        if not isinstance(value, str) or len(value) != 64 or any(c not in '0123456789abcdef' for c in value):
            raise ValueError('CALIBRATION_PIN')
        pins[key] = value
    counts = {k: nonnegative_integer(data[k]) for k in ('N_all', 'N_eligible', 'N_correct_all',
        'temperature_grid_count', 'threshold_grid_count', 'feasible_thresholds')}
    if (counts['N_all'] != 200 or counts['N_eligible'] != 200 or counts['N_correct_all'] > 200
            or counts['temperature_grid_count'] != 181 or counts['threshold_grid_count'] != 1001
            or counts['feasible_thresholds'] != 0):
        raise ValueError('CALIBRATION_COUNTS')
    def ratio(actual, expected):
        if expected is None:
            if actual is not None: raise ValueError('CALIBRATION_RATIO')
        elif type(actual) not in (int, float) or not math.isfinite(actual) or actual != expected:
            raise ValueError('CALIBRATION_RATIO')
    ratio(data['accuracy_all'], counts['N_correct_all']/200)
    temperature = data['chosen_temperature']; index = nonnegative_integer(temperature['index'])
    if index > 180 or temperature['exact'] != str(Fraction(20+index, 40)):
        raise ValueError('CALIBRATION_TEMPERATURE')
    ratio(temperature['value'], float(Fraction(20+index, 40)))
    reference = data['reference_T1_tau095']
    if reference['scope'] != 'descriptive_reference_only_not_chosen_policy':
        raise ValueError('CALIBRATION_REFERENCE_IDENTITY')
    c = {k: nonnegative_integer(reference['counts'][k]) for k in ('N_all', 'N_eligible', 'N_correct_all',
        'N_correct_eligible', 'N_accepted', 'N_correct_accepted', 'N_wrong_accepted', 'N_errors', 'N_timeouts')}
    n, e, correct, ce, a, ca, wrong, errors, timeouts = c.values()
    if (n != 200 or e != 200 or correct != counts['N_correct_all'] or ce != correct
            or not ca <= correct <= n or not ca <= a <= e or wrong != a-ca
            or errors != 0 or timeouts != 0 or a+correct-ca > n):
        raise ValueError('CALIBRATION_REFERENCE_COUNTS')
    ratio(reference['precision'], ca/a if a else None); ratio(reference['coverage'], a/e)
    ece = data['ece15']
    if (ece['scope'] != 'fitted_development_diagnostic_optimistic_not_G6'
            or type(ece['value']) not in (int, float) or not math.isfinite(ece['value']) or not 0 <= ece['value'] <= 1):
        raise ValueError('CALIBRATION_ECE')
    next_step = data.get('next_step')
    if next_step is not None and (not isinstance(next_step, str) or not next_step.strip()):
        raise ValueError('CALIBRATION_NEXT')
    return {**pins, **counts, **{k: None for k in null_keys}, 'source_kind': data['source_kind'],
        'scope': data['scope'], 'status': data['status'], 'source_updated_at': data['source_updated_at'],
        'accuracy_all': data['accuracy_all'], 'chosen_temperature': {k: temperature[k] for k in ('index', 'exact', 'value')},
        'chosen_metrics_reason': 'TARGET_NOT_MET', 'targets': dict(data['targets']),
        'reference_T1_tau095': {'counts': c, 'precision': reference['precision'], 'coverage': reference['coverage'],
            'scope': reference['scope']}, 'ece15': {'value': ece['value'], 'scope': ece['scope']},
        'tracking': 'NOT_EXECUTED_AT_SNAPSHOT', 'next_step': next_step,
        'gate_approval': False, 'release_approved': False, 'gates': dict(data['gates'])}


def project(kind, data):
    if kind in SCHEMAS and data.get('schema', data.get('schema_version')) != SCHEMAS[kind]:
        raise ValueError('SOURCE_SCHEMA')
    if kind == 'learning_snapshot': return learning_projection(data)
    if kind == 'calibration_snapshot': return calibration_projection(data)
    if kind in ('b1_progress', 'b1_reconciliation'): return b1_projection(kind, data)
    if kind == 'gates':
        gates = data['gates']
        if set(gates) != {f'G{i}' for i in range(9)}: raise ValueError('GATES_MISSING')
        return {'gates': {k: {'status': v['status'], 'reason': v['reason']} for k, v in gates.items()},
                'release_status': data['release_status'], 'freshness': data['freshness'],
                'expires_at': data['expires_at'], 'limitations': data['limitations']}
    if kind == 'acceptance':
        return {k: data[k] for k in ['scope', 'accepted', 'independent_tests', 'independent_skips', 'release_approved', 'next']}
    if kind == 'tests':
        return {'verdict': data['verdict'], 'tests': data['tests']['tests'], 'exit': data['tests']['exit'],
                'skipped': data['tests']['skipped'], 'gate_approval': data['gate_approval']}
    if kind == 'guard':
        return {'last_turn': data['turnBoundary']['lastTurn'],
                'open_turn': data['turnBoundary']['openTurnStartSeq'],
                'queued_adjustment': data['inbox_metadata']['old_r1a_adjustment_pending'],
                'action': data['action']}
    if kind == 'ownership': return {k: data[k] for k in ['phase', 'owner']}
    if kind == 'policy': return {k: data[k] for k in ['decision', 'scope', 'reserve_gib', 'origin']}
    if kind == 'smoke':
        remote, inference, scoring = data['remote'], data['inference'], data['scoring_on_mac']
        output = inference['output']
        if data['ssh_exit'] != 0 or remote['child_exit'] != 0 or remote['abort_reason'] is not None:
            raise ValueError('SMOKE_NOT_FINISHED')
        if data['gate_approval'] is not False or inference['device'] != 'cpu':
            raise ValueError('SMOKE_SCOPE')
        stamp = datetime.fromisoformat(inference['observed_at'].replace('Z', '+00:00'))
        if stamp.tzinfo is None: raise ValueError('SMOKE_TIMESTAMP')
        for value in [output['top_probability'], remote['elapsed_seconds']]:
            if type(value) not in (int, float) or value < 0: raise ValueError('SMOKE_NUMBER')
        if output['top_probability'] > 1: raise ValueError('SMOKE_NUMBER')
        correct = output['candidate_id'] == scoring['expected_id']
        if scoring['candidate_correct'] is not correct or type(scoring['accepted']) is not bool:
            raise ValueError('SMOKE_SCORING')
        if type(output['abstained']) is not bool or scoring['accepted'] == output['abstained']:
            raise ValueError('SMOKE_ACCEPTANCE')
        if output['abstained'] and output['selected_id'] is not None: raise ValueError('SMOKE_SELECTION')
        unverified = 'Absolute interpreter path' in data['runtime_identity_correction']['not_proven']
        return {'source_kind': 'snapshot_finished', 'case_id': scoring['case_id'],
                'candidate_id': output['candidate_id'], 'expected_id': scoring['expected_id'],
                'candidate_correct': correct, 'selected_id': output['selected_id'],
                'accepted': scoring['accepted'], 'abstained': output['abstained'],
                'reported_top_probability': output['top_probability'], 'device': inference['device'],
                'duration_including_imports_seconds': remote['elapsed_seconds'],
                'runtime_executable_identity': 'NOT_VERIFIED' if unverified else 'UNAVAILABLE',
                'inference_latency_ms': None, 'global_quality': None, 'cost': None,
                'learning': 'NOT_VERIFIED', 'mlflow': 'NOT_VERIFIED', 'release_approved': False}
    if kind == 'capacity':
        probe = data.get('ssh', data)
        if probe['exit'] != 0: raise ValueError('CAPACITY_PROBE_FAILED')
        values = strict_json(probe['stdout'])
        if any(type(values.get(k)) is not int or values[k] < 0 for k in ['MemAvailable', 'SwapFree']):
            raise ValueError('CAPACITY_INVALID')
        return {'memory_available_kib': values['MemAvailable'], 'swap_free_kib': values['SwapFree']}
    raise ValueError('SOURCE_KIND')


class Collector:
    def __init__(self, specs, clock=None):
        self.specs = specs
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        self.previous = {}

    def source(self, spec, now):
        base = {'id': spec['id'], 'path': spec['path'], 'kind': spec['kind'], 'mode': spec['mode'],
                'collected_at': now.isoformat(), 'recorded_at': None, 'source_modified_at': None,
                'sha256': None, 'expires_at': None, 'error': None, 'data': None}
        try:
            raw, modified = read_bytes(spec['path']); digest = hashlib.sha256(raw).hexdigest()
            if spec.get('sha256') and digest != spec['sha256']: raise ValueError('HASH_MISMATCH')
            document = strict_json(raw); data = project(spec['kind'], document)
            timestamp = next((document[k] for k in ['evaluated_at', 'observed_at', 'captured_at', 'recorded_at', 'at'] if document.get(k)), None)
            if spec['kind'] == 'smoke': timestamp = document['inference']['observed_at']
            if spec['kind'] in ('learning_snapshot', 'calibration_snapshot'): timestamp = document['source_updated_at']
            status = 'SNAPSHOT'; expiry = None
            if spec['mode'] == 'record':
                if not isinstance(timestamp, str): raise ValueError('RECORD_TIMESTAMP_MISSING')
                recorded = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                if recorded.tzinfo is None: raise ValueError('RECORD_TIMEZONE_MISSING')
                expiry = (recorded + timedelta(seconds=spec['ttl_seconds'])).isoformat()
                status = 'CURRENT_RECORD' if recorded <= now <= datetime.fromisoformat(expiry) else 'STALE'
            base.update(sha256=digest, source_modified_at=modified, recorded_at=timestamp,
                        data=data, expires_at=expiry, status=status)
            self.previous[spec['id']] = dict(base)
        except (OSError, ValueError, KeyError, TypeError, AttributeError, OverflowError, RecursionError) as exc:
            previous = self.previous.get(spec['id'])
            if previous: base.update(previous, collected_at=now.isoformat())
            error = 'SOURCE_MISSING' if isinstance(exc, FileNotFoundError) else 'SOURCE_INVALID_OR_UNREADABLE'
            if isinstance(exc, ValueError) and str(exc) == 'HASH_MISMATCH': error = 'HASH_MISMATCH'
            base.update(status='STALE' if previous else 'UNAVAILABLE', error=error)
        return base

    def collect(self):
        now = self.clock()
        sources = [self.source(s, now) for s in self.specs]
        policy = next((s['data'] for s in sources if s['kind'] == 'policy'), None)
        return {'schema': 'voltolini.mobile-decision.preview/1', 'mode': 'preview_read_only',
                'collected_at': now.isoformat(), 'sources': sources,
                'mission': {'release_approved': False, 'cost': None, 'global_progress': None,
                            'run_id': None, 'checkpoint': None, 'cohort': None, 'denominator': None,
                            'accuracy': None, 'latency_ms': None, 'case_count': None, 'memory_mb': None,
                            'target_accuracy': None, 'training': 'NOT_VERIFIED', 'quality': 'NOT_VERIFIED',
                            'export': 'NOT_VERIFIED', 'physical_device': 'NOT_VERIFIED',
                            'mlflow': 'NOT_VERIFIED', 'capacity_current': None,
                            'inference_policy': policy}}
