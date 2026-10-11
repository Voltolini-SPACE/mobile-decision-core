"""Oráculos literais EV4; fixtures não comprovam inferência ou labels cegos."""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


class CaseMetrics(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="voltolini-ev4-cases-", dir=str(Path(tempfile.gettempdir()).resolve()))
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name)

    def core(self):
        path = ROOT / "evaluation/case_metrics.py"
        if not path.is_file():
            self.fail("Case aggregation API not implemented: contract-first failure, not a behavioral regression")
        spec = importlib.util.spec_from_file_location("case_metrics_test", path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def write(self, name, rows):
        (self.path / name).write_text(''.join(json.dumps(row, ensure_ascii=False) + '\n' for row in rows))

    def artifact(self, name):
        data = (self.path / name).read_bytes()
        return {"path": name, "sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)}

    def bundle(self, rows=None):
        # Literal oracle: eligible, expected, predicted, outcome, probability, accepted.
        rows = rows if rows is not None else [(True,"A","A","ok",.97,True), (True,"A","B","ok",.96,True),
            (True,"B","B","ok",.60,False), (True,"A",None,"timeout",None,False),
            (False,"A","A","ok",.99,False), (False,"B",None,"error",None,False)]
        cases, labels, predictions = [], [], []
        for index, (eligible, expected, predicted, outcome, probability, accepted) in enumerate(rows):
            case_id = str(index + 1)
            input_sha = hashlib.sha256(('input-' + case_id).encode()).hexdigest()
            cases.append({"case_id":case_id,"input_ref":"inputs/"+case_id+".txt","input_sha256":input_sha,
                "eligible":eligible,"eligibility_reason":"frozen fixture rule","alternatives":[
                    {"id":"A","kind":"option","description_ref":"descriptions/A.txt","description_sha256":"a"*64},
                    {"id":"B","kind":"option","description_ref":"descriptions/B.txt","description_sha256":"b"*64}]})
            labels.append({"case_id":case_id,"expected_id":expected})
            predictions.append({"case_id":case_id,"run_id":"fixture-run-1","cohort_id":"fixture-cohort-1",
                "input_sha256":input_sha,"outcome":outcome,"predicted_id":predicted,
                "selected_id":predicted if accepted else None,"accepted":accepted,"probability":probability,
                "reason":None if accepted else "fixture abstention/error", "detail_ref":None if outcome=="ok" else "errors/"+case_id+".json"})
        self.write('cases.jsonl',cases);self.write('labels.jsonl',labels)
        identity={"run_id":"fixture-run-1","cohort_id":"fixture-cohort-1","scorer":"opaque-id-exact-micro/1",
            "policy":"eligible-ok-probability-gte/1","threshold":.95,
            **{key:"c"*64 for key in ["dataset_hash","split_hash","model_hash","tokenizer_hash","calibration_hash","runtime_hash","protocol_hash","code_hash"]},
            "cases_sha256":self.artifact('cases.jsonl')['sha256'],"labels_sha256":self.artifact('labels.jsonl')['sha256']}
        for row in predictions:row['identity']=copy.deepcopy(identity)
        self.write('predictions.jsonl',predictions)
        manifest={"schema_version":"voltolini.mobile-decision.case-bundle/1","source_kind":"fixture",
            "source_updated_at":"2026-10-11T05:00:00+00:00","freeze_reference":None,"identity":copy.deepcopy(identity),
            "artifacts":{key:self.artifact(name) for key,name in [('cases','cases.jsonl'),('labels','labels.jsonl'),('predictions','predictions.jsonl')]}}
        (self.path/'run-manifest.json').write_text(json.dumps(manifest))
        return identity

    def alter(self, filename, mutate):
        rows=[json.loads(line) for line in (self.path/filename).read_text().splitlines()]
        mutate(rows);self.write(filename,rows)
        manifest=json.loads((self.path/'run-manifest.json').read_text())
        key={'cases.jsonl':'cases','labels.jsonl':'labels','predictions.jsonl':'predictions'}[filename]
        manifest['artifacts'][key]=self.artifact(filename)
        (self.path/'run-manifest.json').write_text(json.dumps(manifest))

    def aggregate(self, expected):
        return self.core().aggregate_bundle(self.path,expected,now="2026-10-11T06:00:00+00:00")

    def test_six_case_literal_oracle_includes_timeout_and_error(self):
        result=self.aggregate(self.bundle())
        self.assertEqual(result['validity'],'VALID')
        self.assertEqual(result['counts'],{'N_all':6,'N_eligible':4,'N_accepted':2,'N_correct_all':3,
            'N_correct_eligible':2,'N_correct_accepted':1,'N_wrong_accepted':1,'N_errors':1,'N_timeouts':1})
        self.assertEqual({k:v['value'] for k,v in result['metrics'].items()},{'accuracy_all':.5,'accuracy_eligible':.5,
            'accepted_accuracy':.5,'coverage_eligible':.5,'accepted_fraction_all':1/3})
        self.assertEqual(result['bounds']['all']['lower']['exact'],'1/6')
        self.assertEqual(result['bounds']['all']['upper']['exact'],'5/6')
        self.assertEqual(result['bounds']['eligible']['lower']['exact'],'1/4')
        self.assertEqual(result['bounds']['eligible']['upper']['exact'],'3/4')
        self.assertEqual(result['release_status'],'NOT_APPROVED_FOR_RELEASE')
        self.assertEqual(result['execution_verification'],'NOT_VERIFIED')
        self.assertEqual(result['label_freeze_verification'],'NOT_VERIFIED')

    def test_three_cases_literal_oracle(self):
        result=self.aggregate(self.bundle([(True,'A','A','ok',.97,True),(True,'B','B','ok',.97,True),(True,'A','B','ok',.6,False)]))
        self.assertEqual(result['counts'],{'N_all':3,'N_eligible':3,'N_accepted':2,'N_correct_all':2,
            'N_correct_eligible':2,'N_correct_accepted':2,'N_wrong_accepted':0,'N_errors':0,'N_timeouts':0})
        self.assertEqual(result['metrics']['accuracy_all']['exact'],'2/3')
        self.assertEqual(result['metrics']['accepted_accuracy']['value'],1)

    def test_zero_accepted_precision_is_null(self):
        result=self.aggregate(self.bundle([(True,'A','A','ok',.5,False),(True,'A','B','ok',.6,False)]))
        self.assertEqual(result['metrics']['accuracy_all']['value'],.5)
        self.assertIsNone(result['metrics']['accepted_accuracy']['value'])
        self.assertEqual(result['metrics']['accepted_accuracy']['reason'],'NO_ACCEPTED_CASES')
        self.assertEqual(result['metrics']['coverage_eligible']['value'],0)

    def test_zero_eligible_and_empty_cohort_reasons(self):
        result=self.aggregate(self.bundle([(False,'A','A','ok',.99,False),(False,'B','B','ok',.99,False)]))
        self.assertEqual(result['metrics']['accuracy_all']['value'],1)
        self.assertEqual(result['metrics']['accuracy_eligible']['reason'],'NO_ELIGIBLE_CASES')
        self.assertIsNone(result['metrics']['coverage_eligible']['value'])
        result=self.aggregate(self.bundle([]));self.assertEqual(result['validity'],'VALID')
        self.assertTrue(all(v==0 for v in result['counts'].values()))
        self.assertTrue(all(m['value'] is None and m['reason']=='EMPTY_COHORT' for m in result['metrics'].values()))

    def test_threshold_inclusive_with_exact_decimal_below(self):
        expected=self.bundle([(True,'A','A','ok',.95,True)])
        self.assertEqual(self.aggregate(expected)['counts']['N_accepted'],1)
        # This decimal rounds to .95 in binary float: policy must still reject it.
        text=(self.path/'predictions.jsonl').read_text().replace('"probability": 0.95','"probability": 0.94999999999999999').replace('"accepted": true','"accepted": false').replace('"selected_id": "A"','"selected_id": null').replace('"reason": null','"reason": "below threshold"')
        (self.path/'predictions.jsonl').write_text(text)
        manifest=json.loads((self.path/'run-manifest.json').read_text());manifest['artifacts']['predictions']=self.artifact('predictions.jsonl');(self.path/'run-manifest.json').write_text(json.dumps(manifest))
        result=self.aggregate(expected);self.assertEqual(result['validity'],'VALID');self.assertEqual(result['counts']['N_accepted'],0)

    def test_removed_timeout_or_duplicate_invalidates_whole_bundle(self):
        for mutate in [lambda rows:rows.pop(3),lambda rows:rows.append(copy.deepcopy(rows[0]))]:
            expected=self.bundle();self.alter('predictions.jsonl',mutate);result=self.aggregate(expected)
            self.assertEqual(result['validity'],'INVALID');self.assertIsNone(result['counts'])

    def test_declared_correct_is_never_authority(self):
        expected=self.bundle();self.alter('predictions.jsonl',lambda rows:rows[1].update(correct=True))
        self.assertEqual(self.aggregate(expected)['validity'],'INVALID')

    def test_labels_pin_and_input_hash_cannot_be_replaced(self):
        expected=self.bundle();self.alter('labels.jsonl',lambda rows:rows[0].update(expected_id='B'))
        self.assertEqual(self.aggregate(expected)['validity'],'INVALID')
        expected=self.bundle();self.alter('predictions.jsonl',lambda rows:rows[0].update(input_sha256='f'*64))
        self.assertEqual(self.aggregate(expected)['validity'],'INVALID')

    def test_acceptance_selected_and_failures_are_recomputed(self):
        mutations=[(4,{'accepted':True,'selected_id':'A'}),(0,{'selected_id':'B'}),(3,{'accepted':True}),
                   (0,{'accepted':False,'selected_id':None}),(0,{'predicted_id':'unknown'})]
        for index,updates in mutations:
            expected=self.bundle();self.alter('predictions.jsonl',lambda rows:rows[index].update(updates))
            self.assertEqual(self.aggregate(expected)['validity'],'INVALID')

    def test_mixed_run_cohort_identity_and_unsupported_scorer(self):
        for field,value in [('run_id','other-run'),('cohort_id','other-cohort')]:
            expected=self.bundle();self.alter('predictions.jsonl',lambda rows:rows[0].update({field:value}));self.assertEqual(self.aggregate(expected)['validity'],'INVALID')
        expected=self.bundle();expected['model_hash']='e'*64;self.assertEqual(self.aggregate(expected)['validity'],'INVALID')
        expected=self.bundle();expected['scorer']='macro/1';result=self.aggregate(expected)
        self.assertEqual(result['reason_codes'],['UNSUPPORTED_SCORER'])

    def test_invalid_probability_boolean_nonfinite_and_json_duplicate(self):
        for value in [True,'0.99',float('nan'),float('inf'),-0.1,1.1]:
            expected=self.bundle();self.alter('predictions.jsonl',lambda rows:rows[0].update(probability=value));self.assertEqual(self.aggregate(expected)['validity'],'INVALID')
        expected=self.bundle();path=self.path/'run-manifest.json';path.write_text('{"identity":{},"identity":{}}')
        self.assertEqual(self.aggregate(expected)['validity'],'INVALID')

    def test_unsupported_none_matches_never_drops_cases(self):
        expected=self.bundle();self.alter('cases.jsonl',lambda rows:rows[0]['alternatives'][0].update(kind='none_matches'))
        # Keep externally expected byte pin coherent for this declared unsupported fixture.
        manifest=json.loads((self.path/'run-manifest.json').read_text());expected['cases_sha256']=manifest['artifacts']['cases']['sha256'];manifest['identity']['cases_sha256']=expected['cases_sha256'];(self.path/'run-manifest.json').write_text(json.dumps(manifest))
        result=self.aggregate(expected);self.assertEqual(result['validity'],'INVALID');self.assertIsNone(result['counts'])
        self.assertEqual(result['reason_codes'],['UNSUPPORTED_LABEL_KIND'])

    def test_full_count_invariants_reject_difference_counterexamples(self):
        core=self.core()
        for counts in [dict(N_all=3,N_eligible=2,N_accepted=0,N_correct_all=3,N_correct_eligible=0,N_correct_accepted=0,N_wrong_accepted=0,N_errors=0,N_timeouts=0),
                       dict(N_all=3,N_eligible=3,N_accepted=2,N_correct_all=3,N_correct_eligible=3,N_correct_accepted=0,N_wrong_accepted=2,N_errors=0,N_timeouts=0),
                       dict(N_all=1000,N_eligible=1000,N_accepted=950,N_correct_all=920,N_correct_eligible=920,N_correct_accepted=931,N_wrong_accepted=19,N_errors=0,N_timeouts=0)]:
            with self.assertRaises(ValueError):core.validate_counts(counts)

    def test_path_and_hash_errors_do_not_publish_metrics(self):
        expected=self.bundle();manifest=json.loads((self.path/'run-manifest.json').read_text());manifest['artifacts']['cases']['path']='../outside.jsonl';(self.path/'run-manifest.json').write_text(json.dumps(manifest))
        self.assertEqual(self.aggregate(expected)['validity'],'INVALID')
        expected=self.bundle();(self.path/'predictions.jsonl').write_text('{}\n');result=self.aggregate(expected)
        self.assertEqual(result['validity'],'INVALID');self.assertTrue(all(m['value'] is None for m in result['metrics'].values()))

    def test_symlink_and_missing_artifact_are_rejected(self):
        expected=self.bundle();path=self.path/'predictions.jsonl';path.rename(self.path/'other.jsonl');path.symlink_to('other.jsonl')
        self.assertEqual(self.aggregate(expected)['validity'],'INVALID')
        path.unlink();self.assertEqual(self.aggregate(expected)['validity'],'INVALID')

    def test_threshold_identity_and_declared_counts_cannot_lie(self):
        for threshold in [True,'0.95',float('nan'),float('inf'),-.01,1.01]:
            expected=self.bundle();expected['threshold']=threshold;self.assertEqual(self.aggregate(expected)['validity'],'INVALID')
        expected=self.bundle();self.alter('predictions.jsonl',lambda rows:rows[0]['identity'].update(calibration_hash='e'*64))
        self.assertEqual(self.aggregate(expected)['validity'],'INVALID')
        for counts in [{'N_all':True},{'N_all':999}]:
            expected=self.bundle();manifest=json.loads((self.path/'run-manifest.json').read_text());manifest['declared_counts']=counts;(self.path/'run-manifest.json').write_text(json.dumps(manifest))
            self.assertEqual(self.aggregate(expected)['validity'],'INVALID')

    def test_opaque_id_is_not_a_magic_none_matches_class(self):
        expected=self.bundle([(True,'A','A','ok',.97,True)])
        # A literal opaque ID named NONE_MATCHES remains an ordinary option.
        self.alter('cases.jsonl',lambda rows:rows[0]['alternatives'][0].update(id='NONE_MATCHES'))
        self.alter('labels.jsonl',lambda rows:rows[0].update(expected_id='NONE_MATCHES'))
        manifest=json.loads((self.path/'run-manifest.json').read_text())
        for key in ['cases','labels']:expected[key+'_sha256']=manifest['artifacts'][key]['sha256']
        manifest['identity']=copy.deepcopy(expected);(self.path/'run-manifest.json').write_text(json.dumps(manifest))
        self.alter('predictions.jsonl',lambda rows:rows[0].update(predicted_id='NONE_MATCHES',selected_id='NONE_MATCHES',identity=copy.deepcopy(expected)))
        result=self.aggregate(expected);self.assertEqual(result['validity'],'VALID');self.assertEqual(result['counts']['N_correct_accepted'],1)

    def test_readonly_contract_and_decimal_identity_are_serializable(self):
        from decimal import Decimal
        expected=self.bundle();expected['threshold']=Decimal('0.95')
        before={p.name:p.read_bytes() for p in self.path.iterdir()}
        result=self.aggregate(expected);self.assertEqual(result['validity'],'VALID')
        json.dumps(result,allow_nan=False)
        self.assertEqual(before,{p.name:p.read_bytes() for p in self.path.iterdir()})
        contract=json.loads((ROOT/'evaluation/contracts/case-metrics-v1.schema.json').read_text())
        self.assertEqual(contract['properties']['schema_version']['const'],result['schema_version'])
        self.assertEqual(set(contract['required']),set(result))

    def test_disjoint_accepted_correct_and_failure_require_three_cases(self):
        counts={'N_all':2,'N_eligible':2,'N_accepted':1,'N_correct_all':1,
                'N_correct_eligible':1,'N_correct_accepted':0,'N_wrong_accepted':1,
                'N_errors':1,'N_timeouts':0}
        with self.assertRaisesRegex(ValueError,'INCONSISTENT_COUNTS'):
            self.core().validate_counts(counts)

    def test_disjoint_union_literal_boundary_three_is_valid(self):
        counts={'N_all':3,'N_eligible':2,'N_accepted':1,'N_correct_all':1,
                'N_correct_eligible':1,'N_correct_accepted':0,'N_wrong_accepted':1,
                'N_errors':1,'N_timeouts':0}
        self.assertIsNone(self.core().validate_counts(counts))

    def test_now_rejects_invalid_arguments_before_emitting_envelope(self):
        expected=self.bundle()
        for now in [42,True,False,'','not-a-timestamp','2026-10-11T06:00:00']:
            with self.subTest(now=now):
                with self.assertRaisesRegex(ValueError,'INVALID_NOW'):
                    self.core().aggregate_bundle(self.path,expected,now=now)

    def test_now_normalizes_offset_and_z_to_utc(self):
        expected=self.bundle()
        for now in ['2026-10-11T03:10:15-03:00','2026-10-11T06:10:15Z']:
            with self.subTest(now=now):
                result=self.core().aggregate_bundle(self.path,expected,now=now)
                self.assertEqual(result['validity'],'VALID')
                self.assertEqual(result['generated_at'],'2026-10-11T06:10:15+00:00')

    def test_now_none_uses_timezone_aware_collector_time(self):
        from datetime import datetime,timezone
        expected=self.bundle();before=datetime.now(timezone.utc)
        result=self.core().aggregate_bundle(self.path,expected)
        after=datetime.now(timezone.utc);stamp=datetime.fromisoformat(result['generated_at'])
        self.assertEqual(result['validity'],'VALID')
        self.assertEqual(stamp.utcoffset().total_seconds(),0)
        self.assertLessEqual(before,stamp);self.assertLessEqual(stamp,after)


    def test_scaled_800_case_oracle_exceeds_one_mib_without_dropping_failures(self):
        expected=self.bundle([(True,'A','A','ok',.97,True)]*200
            +[(True,'A','B','ok',.96,True)]*200
            +[(True,'A','A','ok',.60,False)]*200
            +[(True,'A',None,'timeout',None,False)]*200)
        self.assertGreater((self.path/'predictions.jsonl').stat().st_size,1024**2)
        result=self.aggregate(expected)
        self.assertEqual(result['validity'],'VALID',result['reason_codes'])
        self.assertEqual(result['counts'],{'N_all':800,'N_eligible':800,'N_accepted':400,
            'N_correct_all':400,'N_correct_eligible':400,'N_correct_accepted':200,
            'N_wrong_accepted':200,'N_errors':0,'N_timeouts':200})
        self.assertTrue(all(m['exact']=='1/2' for m in result['metrics'].values()))
        self.assertEqual(result['bounds']['all']['lower']['exact'],'1/4')
        self.assertEqual(result['bounds']['all']['upper']['exact'],'3/4')
        self.assertEqual(result['execution_verification'],'NOT_VERIFIED')
        self.assertEqual(result['release_status'],'NOT_APPROVED_FOR_RELEASE')

    def repin_capacity_fixture(self, expected):
        manifest=json.loads((self.path/'run-manifest.json').read_text())
        for name in ('cases','labels'):
            manifest['artifacts'][name]=self.artifact(name+'.jsonl')
            expected[name+'_sha256']=manifest['artifacts'][name]['sha256']
        manifest['identity']=copy.deepcopy(expected)
        rows=[json.loads(line) for line in (self.path/'predictions.jsonl').read_text().splitlines()]
        for row in rows:row['identity']=copy.deepcopy(expected)
        self.write('predictions.jsonl',rows)
        manifest['artifacts']['predictions']=self.artifact('predictions.jsonl')
        (self.path/'run-manifest.json').write_text(json.dumps(manifest))

    def test_each_jsonl_allows_exactly_eight_mib_but_not_one_byte_more(self):
        for name in ('cases','labels','predictions'):
            with self.subTest(name=name):
                expected=self.bundle([(True,'A','A','ok',.97,True)])
                path=self.path/(name+'.jsonl');original=path.read_bytes()
                path.write_bytes(original[:-1]+b' '*(8*1024**2-len(original))+b'\n')
                if name!='predictions':self.repin_capacity_fixture(expected)
                else:
                    manifest=json.loads((self.path/'run-manifest.json').read_text())
                    manifest['artifacts'][name]=self.artifact(path.name)
                    (self.path/'run-manifest.json').write_text(json.dumps(manifest))
                result=self.aggregate(expected)
                self.assertEqual(result['validity'],'VALID',result['reason_codes'])
                self.assertEqual(result['counts']['N_all'],1)
                with path.open('ab') as stream:stream.write(b' ')
                result=self.aggregate(expected)
                self.assertEqual(result['reason_codes'],['DOCUMENT_TOO_LARGE'])
                self.assertIsNone(result['counts'])

    def test_manifest_still_rejects_more_than_one_mib(self):
        expected=self.bundle();(self.path/'run-manifest.json').write_bytes(b' '*(1024**2+1))
        result=self.aggregate(expected)
        self.assertEqual(result['reason_codes'],['DOCUMENT_TOO_LARGE']);self.assertIsNone(result['counts'])

    def test_jsonl_symlink_ancestor_and_nonregular_file_are_rejected(self):
        expected=self.bundle();safe=self.path/'safe';safe.mkdir()
        (self.path/'predictions.jsonl').rename(safe/'predictions.jsonl')
        (self.path/'alias').symlink_to(safe,target_is_directory=True)
        manifest=json.loads((self.path/'run-manifest.json').read_text())
        manifest['artifacts']['predictions']['path']='alias/predictions.jsonl'
        (self.path/'run-manifest.json').write_text(json.dumps(manifest))
        result=self.aggregate(expected)
        self.assertEqual(result['validity'],'INVALID');self.assertIsNone(result['counts'])
        manifest['artifacts']['predictions']['path']='pipe.jsonl'
        (self.path/'run-manifest.json').write_text(json.dumps(manifest));os.mkfifo(self.path/'pipe.jsonl')
        result=self.aggregate(expected)
        self.assertEqual(result['reason_codes'],['WRONG_TYPE']);self.assertIsNone(result['counts'])

    def test_jsonl_content_mutation_during_read_is_rejected(self):
        expected=self.bundle();path=self.path/'predictions.jsonl';target=path.stat()
        real_fstat=os.fstat;changed=False
        def mutate(fd):
            nonlocal changed
            info=real_fstat(fd)
            if not changed and (info.st_dev,info.st_ino)==(target.st_dev,target.st_ino):
                changed=True
                with path.open('r+b') as stream:stream.write(b' ')
            return info
        with patch('os.fstat',side_effect=mutate):result=self.aggregate(expected)
        self.assertEqual(result['reason_codes'],['SOURCE_CHANGED_DURING_READ']);self.assertIsNone(result['counts'])

    def test_growing_jsonl_stops_reading_at_eight_mib_plus_sentinel(self):
        expected=self.bundle();path=self.path/'predictions.jsonl';target=path.stat()
        real_fstat=os.fstat;real_fdopen=os.fdopen;changed=False;read_bytes=[]
        def grow(fd):
            nonlocal changed
            info=real_fstat(fd)
            if not changed and (info.st_dev,info.st_ino)==(target.st_dev,target.st_ino):
                changed=True
                with path.open('ab') as stream:stream.write(b' '*(9*1024**2))
            return info
        class ObservedStream:
            def __init__(self,stream):self.stream=stream
            def __enter__(self):return self
            def __exit__(self,*args):return self.stream.__exit__(*args)
            def fileno(self):return self.stream.fileno()
            def read(self,size):
                raw=self.stream.read(size);read_bytes.append(len(raw));return raw
        def observed(fd,*args,**kwargs):
            info=real_fstat(fd);stream=real_fdopen(fd,*args,**kwargs)
            return ObservedStream(stream) if (info.st_dev,info.st_ino)==(target.st_dev,target.st_ino) else stream
        with patch('os.fstat',side_effect=grow),patch('os.fdopen',side_effect=observed):result=self.aggregate(expected)
        self.assertEqual(result['reason_codes'],['DOCUMENT_TOO_LARGE']);self.assertIsNone(result['counts'])
        self.assertGreater(sum(read_bytes),8*1024**2);self.assertLessEqual(sum(read_bytes),8*1024**2+1)

    def test_jsonl_leaf_replacement_with_identical_bytes_is_rejected(self):
        expected=self.bundle();path=self.path/'predictions.jsonl';target=path.stat();real_fstat=os.fstat;seen=0
        def replace(fd):
            nonlocal seen
            info=real_fstat(fd)
            if (info.st_dev,info.st_ino)==(target.st_dev,target.st_ino):
                seen+=1
                if seen==2:
                    alternate=self.path/'replacement.jsonl';alternate.write_bytes(path.read_bytes());alternate.replace(path)
            return info
        with patch('os.fstat',side_effect=replace):result=self.aggregate(expected)
        self.assertEqual(result['reason_codes'],['SOURCE_CHANGED_DURING_READ']);self.assertIsNone(result['counts'])

    def test_jsonl_ancestor_replacement_with_identical_bytes_is_rejected(self):
        expected=self.bundle();folder=self.path/'nested';folder.mkdir()
        path=folder/'predictions.jsonl';(self.path/'predictions.jsonl').rename(path)
        manifest=json.loads((self.path/'run-manifest.json').read_text())
        manifest['artifacts']['predictions']['path']='nested/predictions.jsonl'
        (self.path/'run-manifest.json').write_text(json.dumps(manifest))
        target=path.stat();real_fstat=os.fstat;seen=0
        def replace(fd):
            nonlocal seen
            info=real_fstat(fd)
            if (info.st_dev,info.st_ino)==(target.st_dev,target.st_ino):
                seen+=1
                if seen==2:
                    raw=path.read_bytes();folder.rename(self.path/'old-nested');folder.mkdir();path.write_bytes(raw)
            return info
        with patch('os.fstat',side_effect=replace):result=self.aggregate(expected)
        self.assertEqual(result['reason_codes'],['SOURCE_CHANGED_DURING_READ']);self.assertIsNone(result['counts'])


if __name__ == '__main__':unittest.main()
