"""Converte uma coorte reconciliada para EV4; somente stdlib e memória.

API build_bundle retorna {'files': {caminho relativo: bytes}, 'identity': dict}.
Não escreve, executa modelos, agrega métricas ou certifica origem/congelamento.
Inputs são projeções estritas B1, não eventos brutos. Erros/timeouts devem ser
reconciliados pelo caller com input_sha256: ausências nunca são inventadas.
"""
from datetime import datetime, timezone
from decimal import Decimal
from fractions import Fraction
import hashlib
import json
import re

SOURCE_HASHES = {'dataset_hash', 'split_hash', 'model_hash', 'tokenizer_hash',
                 'calibration_hash', 'runtime_hash', 'protocol_hash', 'code_hash'}
SEED_KEYS = SOURCE_HASHES | {'run_id', 'cohort_id', 'scorer', 'policy', 'threshold'}
SCORER = 'opaque-id-exact-micro/1'
POLICY = 'eligible-ok-probability-gte/1'
BUNDLE_SCHEMA = 'voltolini.mobile-decision.case-bundle/1'


def _require(condition, reason):
    if not condition:
        raise ValueError(reason)


def _keys(value, required, optional=()):
    _require(type(value) is dict and set(required) <= set(value)
             <= set(required) | set(optional), 'INVALID_FIELDS')


def _text(value):
    _require(type(value) is str and bool(value.strip()), 'INVALID_STRING')
    return value


def _hash(value):
    _require(type(value) is str and re.fullmatch('[0-9a-f]{64}', value), 'INVALID_HASH')
    return value


def _number(value):
    _require(type(value) in (int, float) and 0 <= value <= 1, 'INVALID_PROBABILITY')
    return Decimal(str(value))


def _encoded(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(',', ':'), allow_nan=False).encode('utf-8')


def _sha(data):
    return hashlib.sha256(data).hexdigest()


def _indexed(rows):
    _require(type(rows) in (list, tuple), 'INVALID_ROWS')
    indexed = {}
    for row in rows:
        _require(type(row) is dict, 'INVALID_FIELDS')
        case_id = _text(row.get('case_id'))
        _require(case_id not in indexed, 'DUPLICATE_CASE_ID')
        indexed[case_id] = row
    return indexed


def _inputs(record):
    _keys(record, {'case_id', 'inputs'})
    case = record['inputs']
    _keys(case, {'type', 'question', 'state', 'context', 'options'})
    _require(case['type'] in ('choice', 'boolean', 'ordinal'), 'UNSUPPORTED_CASE_TYPE')
    for name in ('question', 'state', 'context'):
        _text(case[name])
    options = case['options']
    _require(type(options) is list and 2 <= len(options) <= 32, 'INVALID_OPTION_COUNT')
    ids, values = [], []
    for option in options:
        _keys(option, {'id', 'description'} | ({'value'} if case['type'] != 'choice' else set()))
        ids.append(_text(option['id']))
        _text(option['description'])
        if case['type'] == 'boolean':
            _require(type(option['value']) is bool, 'INVALID_BOOLEAN_VALUE')
            values.append(option['value'])
        elif case['type'] == 'ordinal':
            value = option['value']
            _require(type(value) in (int, float) and -1e100 < value < 1e100, 'INVALID_ORDINAL_VALUE')
            values.append(value)
    _require(len(ids) == len(set(ids)), 'DUPLICATE_OPTION_ID')
    if case['type'] == 'boolean':
        _require(set(values) == {True, False}, 'INVALID_BOOLEAN_VALUES')
    if case['type'] == 'ordinal':
        _require(len(values) == len(set(values)), 'INVALID_ORDINAL_VALUES')
    return case, ids


def _timestamp(value):
    _text(value)
    try:
        stamp = datetime.fromisoformat(value[:-1]+'+00:00' if value.endswith('Z') else value)
        _require(stamp.tzinfo is not None, 'INVALID_TIMESTAMP')
        return stamp.astimezone(timezone.utc).isoformat()
    except (ValueError, OverflowError):
        raise ValueError('INVALID_TIMESTAMP') from None


def _prediction(outcome, ids, threshold, input_hash):
    status = outcome.get('status')
    _require(status in ('OK', 'ERROR', 'TIMEOUT'), 'UNSUPPORTED_OUTCOME')
    required = {'case_id', 'input_sha256', 'status'}
    _keys(outcome, required | ({'output'} if status == 'OK' else set()),
          {'error_type'} if status != 'OK' else set())
    _hash(outcome['input_sha256'])
    _require(outcome['input_sha256'] == input_hash, 'INPUT_HASH_MISMATCH')
    if status != 'OK':
        if 'error_type' in outcome:
            _text(outcome['error_type'])
        return {'outcome': status.lower(), 'predicted_id': None, 'selected_id': None,
                'accepted': False, 'probability': None, 'reason': status}
    output = outcome['output']
    _keys(output, {'candidate_id', 'selected_id', 'abstained', 'probabilities'}, {'top_probability'})
    probabilities = output['probabilities']
    _require(type(probabilities) is dict and set(probabilities) == set(ids), 'PROBABILITY_IDS_MISMATCH')
    numbers = [_number(probabilities[option_id]) for option_id in ids]
    # Rational sum/tolerance never round or mutate the caller's Decimal context.
    total = sum(Fraction(number) for number in numbers)
    _require(abs(total-1) <= Fraction(1, 1000000), 'INVALID_PROBABILITY_SUM')
    # Python max chooses the first frozen option on ties, regardless of map order.
    top_index = max(range(len(ids)), key=lambda i: numbers[i])
    predicted_id, probability = ids[top_index], probabilities[ids[top_index]]
    _require(output['candidate_id'] == predicted_id, 'ARGMAX_MISMATCH')
    if 'top_probability' in output:
        _require(_number(output['top_probability']) == numbers[top_index], 'TOP_PROBABILITY_MISMATCH')
    accepted = numbers[top_index] >= threshold
    _require(type(output['abstained']) is bool and output['abstained'] == (not accepted), 'ABSTENTION_MISMATCH')
    _require(output['selected_id'] == (predicted_id if accepted else None), 'SELECTION_MISMATCH')
    return {'outcome': 'ok', 'predicted_id': predicted_id,
            'selected_id': predicted_id if accepted else None, 'accepted': accepted,
            'probability': probability, 'reason': None if accepted else 'BELOW_FROZEN_THRESHOLD'}


def build_bundle(records, labels, outcomes, *, identity_seed, source_updated_at, source_kind):
    """Construção determinística, ValueError em contrato inválido, sem efeito externo.

    identity_seed: 8 hashes fonte + run_id/cohort_id/scorer/policy/threshold.
    cases/labels SHA são derivados, nunca aceitos do caller. Elegibilidade congelada:
    todo caso válido choice/boolean/ordinal com2..32 opções é elegível para scorer
    categórico exato; não equivale a métrica ordinal/boolean ou generalização.
    source_kind exige fixture/historical/replay; historical pode representar snapshot
    novo, sem autenticá-lo. A entrada/descrição é guardada em bytes, não só em refs.
    """
    _keys(identity_seed, SEED_KEYS)
    for key in SOURCE_HASHES:
        _hash(identity_seed[key])
    for key in ('run_id', 'cohort_id'):
        _text(identity_seed[key])
    _require(identity_seed['scorer'] == SCORER, 'UNSUPPORTED_SCORER')
    _require(identity_seed['policy'] == POLICY, 'UNSUPPORTED_POLICY')
    threshold = _number(identity_seed['threshold'])
    _require(source_kind in ('fixture', 'historical', 'replay'), 'UNSUPPORTED_SOURCE_KIND')
    timestamp = _timestamp(source_updated_at)
    records, labels, outcomes = _indexed(records), _indexed(labels), _indexed(outcomes)
    _require(set(records) == set(labels) == set(outcomes), 'CASE_SET_MISMATCH')
    files, cases, label_rows, predictions = {}, [], [], []

    def reference(prefix, data, suffix):
        digest = _sha(data)
        path = prefix+'/'+digest+suffix
        _require(path not in files or files[path] == data, 'REFERENCE_HASH_COLLISION')
        files[path] = data
        return path, digest

    for case_id, record in records.items():
        case, ids = _inputs(record)
        label = labels[case_id]
        _keys(label, {'case_id', 'expected_id'})
        _require(type(label['expected_id']) is str and label['expected_id'] in ids, 'UNKNOWN_LABEL')
        input_ref, input_hash = reference('inputs', _encoded(case), '.json')
        alternatives = []
        for option in case['options']:
            ref, digest = reference('descriptions', option['description'].encode('utf-8'), '.txt')
            alternatives.append({'id': option['id'], 'kind': 'option', 'description_ref': ref, 'description_sha256': digest})
        cases.append({'case_id': case_id, 'input_ref': input_ref, 'input_sha256': input_hash,
                      'eligible': True, 'eligibility_reason': 'PROJECTED_SUPPORTED_TYPE_2_TO_32_OPTIONS_EXACT_ID',
                      'alternatives': alternatives})
        label_rows.append({'case_id': case_id, 'expected_id': label['expected_id']})
        prediction = _prediction(outcomes[case_id], ids, threshold, input_hash)
        detail_ref, _ = reference('outcomes', _encoded(outcomes[case_id]), '.json')
        predictions.append({'case_id': case_id, 'run_id': identity_seed['run_id'], 'cohort_id': identity_seed['cohort_id'],
                            'input_sha256': input_hash, 'detail_ref': detail_ref, **prediction})
    for name, rows in (('cases', cases), ('labels', label_rows)):
        files[name+'.jsonl'] = b''.join(_encoded(row)+b'\n' for row in rows)
    identity = {**identity_seed, 'cases_sha256': _sha(files['cases.jsonl']), 'labels_sha256': _sha(files['labels.jsonl'])}
    files['predictions.jsonl'] = b''.join(_encoded({**row, 'identity': identity})+b'\n' for row in predictions)
    artifacts = {name: {'path': name+'.jsonl', 'sha256': _sha(files[name+'.jsonl']), 'bytes': len(files[name+'.jsonl'])}
                 for name in ('cases', 'labels', 'predictions')}
    files['run-manifest.json'] = _encoded({'schema_version': BUNDLE_SCHEMA, 'source_kind': source_kind,
        'source_updated_at': timestamp, 'freeze_reference': None, 'identity': identity, 'artifacts': artifacts})+b'\n'
    return {'files': files, 'identity': identity}
