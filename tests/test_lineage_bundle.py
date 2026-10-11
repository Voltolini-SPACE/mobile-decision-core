"""Oráculos literais do conversor puro; integração chama o EV4 aceito."""
from pathlib import Path
from copy import deepcopy
from decimal import localcontext, Inexact, Underflow, ROUND_DOWN
import hashlib
import importlib.util
import json
import os
import sys
import tempfile
import unittest

sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from evaluation.case_metrics import aggregate_bundle


def encoded(value):
    return json.dumps(value,ensure_ascii=False,sort_keys=True,separators=(',',':'),allow_nan=False).encode('utf-8')


def sha(data):return hashlib.sha256(data).hexdigest()


class LineageBundle(unittest.TestCase):
    def setUp(self):
        self.records=[{'case_id':'c'+str(i),'inputs':{'type':'choice','question':'Escolha?','state':'ativo','context':'nenhum',
            'options':[{'id':'a','description':'Descrição A'},{'id':'b','description':'Descrição B'}]}} for i in range(3)]
        self.labels=[{'case_id':'c'+str(i),'expected_id':'a'} for i in range(3)]
        self.seed={k:format(i,'x')*64 for i,k in enumerate(['dataset_hash','split_hash','model_hash','tokenizer_hash','calibration_hash','runtime_hash','protocol_hash','code_hash'])}
        self.seed.update(run_id='r1',cohort_id='test',scorer='opaque-id-exact-micro/1',policy='eligible-ok-probability-gte/1',threshold=.95)
        self.outcomes=[self.ok(0,.6),self.failure(1,'ERROR'),self.failure(2,'TIMEOUT')]

    def ok(self,i,prob,candidate='a',threshold=None):
        threshold=self.seed['threshold'] if threshold is None else threshold
        return {'case_id':'c'+str(i),'input_sha256':sha(encoded(self.records[i]['inputs'])),'status':'OK',
            'output':{'candidate_id':candidate,'selected_id':candidate if prob>=threshold else None,'abstained':prob<threshold,
                      'probabilities':{'a':prob if candidate=='a' else 1-prob,'b':prob if candidate=='b' else 1-prob}}}

    def failure(self,i,status):
        return {'case_id':'c'+str(i),'input_sha256':sha(encoded(self.records[i]['inputs'])),'status':status}

    def builder(self):
        path=ROOT/'evaluation/lineage_bundle.py'
        if not path.is_file():self.fail('Converter API absent: contract-first, not behavioral regression')
        spec=importlib.util.spec_from_file_location('lineage_bundle_tests',path);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        return module.build_bundle

    def build(self,**extra):
        args={'identity_seed':self.seed,'source_updated_at':'2026-10-11T01:00:00+00:00','source_kind':'fixture'};args.update(extra)
        return self.builder()(self.records,self.labels,self.outcomes,**args)

    def aggregate(self,result):
        with tempfile.TemporaryDirectory(prefix='voltolini-bundle-',dir=str(Path(tempfile.gettempdir()).resolve())) as td:
            for path,data in result['files'].items():
                target=Path(td)/path;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(data)
            return aggregate_bundle(Path(td),result['identity'],now='2026-10-11T01:00:00Z')

    def test_three_cases_keep_error_timeout_and_zero_accepted_denominators(self):
        result=self.aggregate(self.build())
        self.assertEqual(result['validity'],'VALID',result['reason_codes'])
        self.assertEqual(result['counts'],{'N_all':3,'N_eligible':3,'N_accepted':0,'N_correct_all':1,'N_correct_eligible':1,'N_correct_accepted':0,'N_wrong_accepted':0,'N_errors':1,'N_timeouts':1})
        self.assertEqual(result['metrics']['accuracy_all']['exact'],'1/3')
        self.assertEqual(result['metrics']['accepted_accuracy']['reason'],'NO_ACCEPTED_CASES')
        self.assertIsNone(result['metrics']['accepted_accuracy']['value'])
        self.assertEqual(result['execution_verification'],'NOT_VERIFIED')
        self.assertEqual(result['authentication_verification'],'NOT_VERIFIED')
        self.assertEqual(result['label_freeze_verification'],'NOT_VERIFIED')
        self.assertEqual(result['release_status'],'NOT_APPROVED_FOR_RELEASE')

    def test_six_literal_cases_mix_wrong_accepted_unaccepted_correct_and_failures(self):
        self.records=self.records+[deepcopy(self.records[0]) for _ in range(3)]
        for i,r in enumerate(self.records):r['case_id']='c'+str(i)
        self.labels=[{'case_id':'c'+str(i),'expected_id':'b' if i==3 else 'a'} for i in range(6)]
        self.seed['threshold']=.75
        self.outcomes=[self.ok(0,.95),self.ok(1,.8,'b'),self.ok(2,.6),self.ok(3,.65,'b'),self.failure(4,'ERROR'),self.failure(5,'TIMEOUT')]
        result=self.aggregate(self.build())
        self.assertEqual(result['validity'],'VALID',result['reason_codes'])
        self.assertEqual(result['counts'],{'N_all':6,'N_eligible':6,'N_accepted':2,'N_correct_all':3,'N_correct_eligible':3,'N_correct_accepted':1,'N_wrong_accepted':1,'N_errors':1,'N_timeouts':1})
        self.assertEqual(result['metrics']['accuracy_all']['exact'],'1/2')
        self.assertEqual(result['metrics']['accepted_accuracy']['exact'],'1/2')
        self.assertEqual(result['metrics']['coverage_eligible']['exact'],'1/3')
        self.assertEqual(result['bounds']['all']['lower']['exact'],'1/6')
        self.assertEqual(result['bounds']['all']['upper']['exact'],'5/6')

    def test_reference_payloads_and_artifact_pins_include_actual_bytes(self):
        built=self.build();files=built['files'];manifest=json.loads(files['run-manifest.json'])
        cases=[json.loads(x) for x in files['cases.jsonl'].splitlines()]
        for case,record in zip(cases,self.records):
            self.assertEqual(files[case['input_ref']],encoded(record['inputs']))
            self.assertEqual(sha(files[case['input_ref']]),case['input_sha256'])
            for ref,option in zip(case['alternatives'],record['inputs']['options']):
                self.assertEqual(files[ref['description_ref']],option['description'].encode('utf-8'))
                self.assertEqual(sha(files[ref['description_ref']]),ref['description_sha256'])
        for name,pin in manifest['artifacts'].items():
            self.assertEqual(sha(files[pin['path']]),pin['sha256']);self.assertEqual(len(files[pin['path']]),pin['bytes'])
        self.assertEqual(built['identity']['cases_sha256'],sha(files['cases.jsonl']))
        self.assertEqual(built['identity']['labels_sha256'],sha(files['labels.jsonl']))
        self.assertIsNone(manifest['freeze_reference'])
        for prediction in [json.loads(x) for x in files['predictions.jsonl'].splitlines()]:
            self.assertEqual(prediction['identity'],built['identity'])
            self.assertIn(prediction['detail_ref'],files)
        self.assertTrue(all(not path.startswith('/') and '..' not in path.split('/') for path in files))

    def test_builder_is_deterministic_pure_and_does_not_modify_arguments(self):
        args=deepcopy((self.records,self.labels,self.outcomes,self.seed))
        with tempfile.TemporaryDirectory(prefix='voltolini-pure-',dir=str(Path(tempfile.gettempdir()).resolve())) as td:
            previous=os.getcwd()
            try:
                os.chdir(td);one=self.build();two=self.build();self.assertEqual(list(Path(td).iterdir()),[])
            finally:os.chdir(previous)
        self.assertEqual(one,two);self.assertEqual(args,(self.records,self.labels,self.outcomes,self.seed))
        self.labels.reverse();self.outcomes.reverse();self.assertEqual(self.build(),one)

    def test_missing_unknown_and_duplicate_case_sets_are_rejected(self):
        original=deepcopy((self.records,self.labels,self.outcomes))
        for collection in ('records','labels','outcomes'):
            for change in ('missing','duplicate','unknown'):
                with self.subTest(collection=collection,change=change):
                    self.records,self.labels,self.outcomes=deepcopy(original);rows=getattr(self,collection)
                    if change=='missing':rows.pop()
                    elif change=='duplicate':rows.append(deepcopy(rows[0]))
                    else:rows[0]['case_id']='unknown'
                    with self.assertRaises(ValueError):self.build()

    def test_unknown_label_and_option_ids_cannot_be_scored(self):
        self.labels[0]['expected_id']='missing'
        with self.assertRaises(ValueError):self.build()
        self.labels[0]['expected_id']='a';self.outcomes[0]['output']['candidate_id']='missing'
        with self.assertRaises(ValueError):self.build()
        self.outcomes[0]=self.ok(0,.6);self.records[0]['inputs']['options'][1]['id']='a'
        with self.assertRaises(ValueError):self.build()

    def test_changed_input_hash_and_forged_identity_fields_are_rejected(self):
        self.outcomes[0]['input_sha256']='f'*64
        with self.assertRaises(ValueError):self.build()
        for field,value in [('model_hash','f'*64),('run_id','other'),('cohort_id','other'),('identity',{})]:
            with self.subTest(field=field):
                self.outcomes[0]=self.ok(0,.6);self.outcomes[0][field]=value
                with self.assertRaises(ValueError):self.build()

    def test_forged_accepted_correct_and_unprojected_label_fields_are_rejected(self):
        for field in ('accepted','correct','status'):
            with self.subTest(field=field):
                self.outcomes[0]=self.ok(0,.6);self.outcomes[0]['output'][field]=True
                with self.assertRaises(ValueError):self.build()
        self.outcomes[0]=self.ok(0,.6);self.records[0]['inputs']['expected_id']='a'
        with self.assertRaises(ValueError):self.build()

    def test_invalid_probabilities_distribution_and_argmax_are_rejected(self):
        for distribution in [{'a':float('nan'),'b':.4},{'a':float('inf'),'b':.4},{'a':True,'b':0},{'a':-.1,'b':1.1},{'a':.6,'b':.3},{'a':.6},{'a':.6,'b':.4,'x':0}]:
            with self.subTest(distribution=distribution):
                self.outcomes[0]=self.ok(0,.6);self.outcomes[0]['output']['probabilities']=distribution
                with self.assertRaises(ValueError):self.build()
        self.outcomes[0]=self.ok(0,.6);self.outcomes[0]['output']['candidate_id']='b'
        with self.assertRaises(ValueError):self.build()
        self.outcomes[0]=self.ok(0,.6);self.outcomes[0]['output']['top_probability']=.7
        with self.assertRaises(ValueError):self.build()

    def test_sum_tolerance_and_optional_matching_top_are_supported(self):
        self.outcomes[0]['output']['probabilities']['b']=.40000002
        self.outcomes[0]['output']['top_probability']=.6
        self.assertEqual(self.aggregate(self.build())['validity'],'VALID')

    def test_threshold_boundary_ties_and_option_order_are_exact(self):
        self.seed['threshold']=.5;self.outcomes[0]=self.ok(0,.5)
        self.outcomes[0]['output']['probabilities']={'b':.5,'a':.5}
        self.assertEqual(self.aggregate(self.build())['counts']['N_accepted'],1)
        self.outcomes[0]['output']['candidate_id']='b';self.outcomes[0]['output']['selected_id']='b'
        with self.assertRaises(ValueError):self.build()
        self.seed['threshold']=.75;self.outcomes[0]=self.ok(0,.75)
        self.assertEqual(self.aggregate(self.build())['counts']['N_accepted'],1)
        self.outcomes[0]=self.ok(0,.7499999999999999)
        self.assertEqual(self.aggregate(self.build())['counts']['N_accepted'],0)

    def test_selection_abstention_and_failure_payloads_are_checked(self):
        for key,value in [('selected_id','a'),('abstained',False),('abstained',1)]:
            with self.subTest(key=key,value=value):
                self.outcomes[0]=self.ok(0,.6);self.outcomes[0]['output'][key]=value
                with self.assertRaises(ValueError):self.build()
        self.outcomes[0]=self.ok(0,.6)
        for status in ('ABORTED','NOT_EXECUTED','ok'):
            self.outcomes[1]['status']=status
            with self.assertRaises(ValueError):self.build()
        self.outcomes[1]=self.failure(1,'ERROR');self.outcomes[1]['output']={}
        with self.assertRaises(ValueError):self.build()
        self.outcomes[1]=self.failure(1,'ERROR');self.outcomes[1]['error_type']='RuntimeError'
        self.assertEqual(self.aggregate(self.build())['counts']['N_errors'],1)

    def test_projection_types_bounds_and_all_options_eligible(self):
        for count in (1,33):
            with self.subTest(count=count):
                old=deepcopy(self.records[0]);self.records[0]['inputs']['options']=[{'id':str(i),'description':'d'} for i in range(count)]
                with self.assertRaises(ValueError):self.build()
                self.records[0]=old
        for kind,values in [('boolean',[True,False]),('ordinal',[1,2.5])]:
            with self.subTest(kind=kind):
                c=self.records[0]['inputs'];c['type']=kind
                for o,value in zip(c['options'],values):o['value']=value
                self.outcomes[0]=self.ok(0,.6)
                self.assertEqual(self.aggregate(self.build())['counts']['N_eligible'],3)
                c['options'][1]['value']=values[0];self.outcomes[0]['input_sha256']=sha(encoded(c))
                with self.assertRaises(ValueError):self.build()
        self.records[0]['inputs']['type']='none_matches'
        with self.assertRaises(ValueError):self.build()

    def test_empty_cohort_is_explicit_and_not_false_success(self):
        self.records=[];self.labels=[];self.outcomes=[];result=self.aggregate(self.build())
        self.assertEqual(result['validity'],'VALID');self.assertEqual(result['counts']['N_all'],0)
        self.assertEqual(result['metrics']['accuracy_all']['reason'],'EMPTY_COHORT')
        self.assertEqual(result['release_status'],'NOT_APPROVED_FOR_RELEASE')

    def context_snapshot(self, context):
        return (context.prec, context.rounding, context.Emin, context.Emax, context.capitals, context.clamp,
                dict(context.flags), dict(context.traps))

    def test_probability_sum_above_tolerance_is_rejected_in_all_decimal_contexts(self):
        for values in ((.6000009, .4000009), (.6, .3999989)):
            for precision, trap in ((6, False), (28, False), (6, True), (28, True)):
                with self.subTest(values=values, precision=precision, trap=trap):
                    self.outcomes[0]=self.ok(0,.6)
                    self.outcomes[0]['output']['probabilities']={'a':values[0],'b':values[1]}
                    with localcontext() as context:
                        context.prec=precision;context.rounding=ROUND_DOWN;context.traps[Inexact]=trap
                        context.clear_flags();context.flags[Underflow]=True;before=self.context_snapshot(context)
                        with self.assertRaisesRegex(ValueError, '^INVALID_PROBABILITY_SUM$'):self.build()
                        self.assertEqual(self.context_snapshot(context),before)

    def test_sum_tolerance_is_inclusive_and_success_bytes_ignore_decimal_context(self):
        # Exact decimal sums:1,1+1e-6,1-1e-6,1. Boundary is inclusive.
        for values in ((.6,.4), (.6,.400001), (.6,.399999), (.6000009,.3999991)):
            self.seed['threshold']=values[0];self.outcomes[0]=self.ok(0,values[0])
            self.outcomes[0]['output']['probabilities']={'a':values[0],'b':values[1]}
            self.outcomes[0]['output']['top_probability']=values[0]
            identical=None
            for precision, trap in ((6, False), (28, False), (6, True), (28, True)):
                with self.subTest(values=values, precision=precision, trap=trap):
                    with localcontext() as context:
                        context.prec=precision;context.rounding=ROUND_DOWN;context.traps[Inexact]=trap
                        context.clear_flags();context.flags[Underflow]=True;before=self.context_snapshot(context)
                        built=self.build();self.assertEqual(self.context_snapshot(context),before)
                    if identical is None:identical=built
                    else:self.assertEqual(built,identical)
                    prediction=json.loads(built['files']['predictions.jsonl'].splitlines()[0])
                    self.assertTrue(prediction['accepted']);self.assertEqual(prediction['selected_id'],'a')
                    self.assertEqual(prediction['probability'],values[0])

    def test_fine_threshold_comparison_and_caller_context_remain_exact(self):
        for threshold, accepted in ((.6000009,True), (.6000009000000001,False)):
            self.seed['threshold']=threshold;self.outcomes[0]=self.ok(0,.6000009)
            self.outcomes[0]['output']['probabilities']={'a':.6000009,'b':.3999991}
            identical=None
            for precision, trap in ((6, False), (28, False), (6, True), (28, True)):
                with self.subTest(threshold=threshold, precision=precision, trap=trap):
                    with localcontext() as context:
                        context.prec=precision;context.traps[Inexact]=trap;context.clear_flags()
                        before=self.context_snapshot(context);built=self.build()
                        self.assertEqual(self.context_snapshot(context),before)
                    if identical is None:identical=built
                    else:self.assertEqual(built,identical)
                    prediction=json.loads(built['files']['predictions.jsonl'].splitlines()[0])
                    self.assertEqual(prediction['accepted'],accepted)
                    self.assertEqual(prediction['selected_id'],'a' if accepted else None)

    def test_identity_seed_source_kind_and_time_are_strict(self):
        seed=deepcopy(self.seed)
        for key,value in [('model_hash','bad'),('threshold',True),('threshold',float('nan')),('scorer','other'),('policy','other'),('cases_sha256','a'*64)]:
            with self.subTest(key=key):
                self.seed=deepcopy(seed);self.seed[key]=value
                with self.assertRaises(ValueError):self.build()
        self.seed=seed
        for kind in (None,'production','live'):
            with self.assertRaises(ValueError):self.build(source_kind=kind)
        for stamp in (42,True,'','2026-10-11T01:00:00','invalid'):
            with self.assertRaises(ValueError):self.build(source_updated_at=stamp)
        built=self.build(source_kind='historical',source_updated_at='2026-10-11T03:00:00+02:00')
        self.assertEqual(json.loads(built['files']['run-manifest.json'])['source_updated_at'],'2026-10-11T01:00:00+00:00')


if __name__=='__main__':unittest.main()
