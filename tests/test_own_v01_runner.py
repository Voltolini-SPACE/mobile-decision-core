"""Fixtures ZIP pequenas: auditoria/recibo não são execução ou aprovação."""
from pathlib import Path
import hashlib
import importlib.util
import json
import os
import stat
import struct
import subprocess
import sys
import tempfile
import unittest
import zipfile

sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))


class OwnArchiveAudit(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='voltolini-lineage-audit-',dir=str(Path(tempfile.gettempdir()).resolve()))
        self.addCleanup(self.temp.cleanup)
        self.path=Path(self.temp.name);self.sources=self.path/'sources';self.sources.mkdir()
        self.output=self.path/'receipts';self.output.mkdir()
        self.archive=self.sources/'own.zip'

    def module(self):
        path=ROOT/'lab/own_v01_runner.py'
        if not path.is_file():self.fail('Audit API absent: contract-first, not behavioral regression')
        spec=importlib.util.spec_from_file_location('own_archive_audit_tests',path)
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        return module

    def make_zip(self,entries=None,compression=zipfile.ZIP_STORED):
        with zipfile.ZipFile(self.archive,'w',compression=compression) as z:
            for name,data in entries or [('mobile-decision/readme.txt',b'own source'),('mobile-decision/src/core.py',b'raise RuntimeError("NEVER_EXECUTE_ARCHIVE")')]:z.writestr(name,data)
        return self.digest(self.archive)

    def digest(self,path):return hashlib.sha256(path.read_bytes()).hexdigest()

    def refs(self,archive_hash):
        integrity={'archive_sha256':archive_hash,'captured_at':'2026-10-11T01:00:00+00:00',
            'manifest_entries':1,'members':2,'checks':[{'path':'readme.txt','path_safe':True,'bytes_match':True,'sha256_match':True}],
            'all_manifest_checks_pass':True,'safetensors_header':{'tensors':1,'shapes':{'x':[2]}}}
        reaggregation={'schema':'voltolini-original-archive-reaggregation/1','archive_sha256':archive_hash,'captured_at':'2026-10-11T01:01:00+00:00',
            'historical_results_recalculated':{'heldout_synthetic':{'cases':2,'correct':1,'accuracy':.5},'manual_diagnostic':{'cases':1,'correct':0,'accuracy':0}}}
        result=[]
        for kind,value in [('integrity',integrity),('reaggregation',reaggregation)]:
            p=self.sources/(kind+'.json');p.write_text(json.dumps(value));result.append({'kind':kind,'path':str(p),'sha256':self.digest(p),'archive_sha256':archive_hash})
        p=self.sources/'provenance.md';p.write_text('Historical evidence, never a fresh model run.')
        result.append({'kind':'provenance','path':str(p),'sha256':self.digest(p),'archive_sha256':archive_hash})
        return result

    def audit(self,pin=None,refs=()):return self.module().audit_package(self.archive,pin or self.digest(self.archive),evidence_refs=refs)

    def test_positive_metadata_and_pinned_historical_refs_remain_unverified_execution(self):
        pin=self.make_zip();refs=self.refs(pin);before={p.name:p.read_bytes() for p in self.sources.iterdir()}
        result=self.audit(pin,refs)
        self.assertEqual(result['validity'],'VALID')
        self.assertEqual(result['archive_metadata']['members'],2)
        self.assertEqual(result['historical_claims']['integrity']['manifest_entries'],1)
        self.assertEqual(result['historical_claims']['reaggregation']['heldout_synthetic'],{'cases':2,'correct':1,'accuracy':.5})
        self.assertEqual(len(result['historical_references']),3)
        self.assertEqual(result['execution_verification'],'NOT_VERIFIED');self.assertEqual(result['mlflow_verification'],'NOT_VERIFIED')
        self.assertEqual(result['release_status'],'NOT_APPROVED_FOR_RELEASE')
        self.assertEqual(before,{p.name:p.read_bytes() for p in self.sources.iterdir()})
        json.dumps(result,allow_nan=False)

    def test_no_reference_defaults_do_not_invent_historical_claims(self):
        self.make_zip();result=self.audit();self.assertEqual(result['validity'],'VALID')
        self.assertEqual(result['historical_references'],[]);self.assertEqual(result['historical_claims'],{})

    def test_wrong_zip_pin_and_wrong_ref_pin_are_invalid(self):
        pin=self.make_zip();self.assertEqual(self.audit('0'*64)['reason_codes'],['ARCHIVE_HASH_MISMATCH'])
        refs=self.refs(pin);refs[0]['sha256']='f'*64;result=self.audit(pin,refs)
        self.assertEqual(result['validity'],'INVALID');self.assertEqual(result['historical_claims'],{})

    def test_refs_bound_to_other_zip_are_rejected_even_with_correct_file_pin(self):
        pin=self.make_zip();refs=self.refs(pin);refs[0]['archive_sha256']='e'*64
        self.assertEqual(self.audit(pin,refs)['reason_codes'],['REFERENCE_ARCHIVE_MISMATCH'])
        refs=self.refs(pin);p=Path(refs[0]['path']);value=json.loads(p.read_text());value['archive_sha256']='e'*64;p.write_text(json.dumps(value));refs[0]['sha256']=self.digest(p)
        self.assertEqual(self.audit(pin,refs)['reason_codes'],['REFERENCE_ARCHIVE_MISMATCH'])

    def test_reference_json_shape_duplicate_and_nonfinite_are_invalid(self):
        pin=self.make_zip()
        for content in ['[]','{"archive_sha256":"a","archive_sha256":"b"}','{"x":NaN}',json.dumps({'archive_sha256':pin})]:
            with self.subTest(content=content):
                refs=self.refs(pin);p=Path(refs[0]['path']);p.write_text(content);refs[0]['sha256']=self.digest(p)
                self.assertEqual(self.audit(pin,refs)['validity'],'INVALID')

    def test_duplicate_names_are_invalid(self):
        import warnings
        with warnings.catch_warnings():
            warnings.simplefilter('ignore',UserWarning);self.make_zip([('same.txt',b'1'),('same.txt',b'2')])
        self.assertEqual(self.audit()['reason_codes'],['DUPLICATE_ARCHIVE_PATH'])

    def test_traversal_absolute_windows_and_case_alias_names_are_invalid(self):
        for name in ['../bad','/absolute','x/../bad','C:/bad','x\\bad']:
            with self.subTest(name=name):
                self.make_zip([(name,b'1')]);self.assertEqual(self.audit()['validity'],'INVALID')
        self.make_zip([('Pkg/one',b'1'),('pkg/ONE',b'2')]);self.assertEqual(self.audit()['reason_codes'],['DUPLICATE_ARCHIVE_PATH'])

    def test_symlink_special_member_and_source_symlink_are_invalid(self):
        for mode in [stat.S_IFLNK|0o777,stat.S_IFIFO|0o600]:
            info=zipfile.ZipInfo('pkg/link');info.create_system=3;info.external_attr=mode<<16
            self.make_zip([(info,b'elsewhere')]);self.assertEqual(self.audit()['reason_codes'],['UNSAFE_ARCHIVE_TYPE'])
        pin=self.make_zip();saved=self.sources/'saved.zip';self.archive.rename(saved);self.archive.symlink_to(saved)
        self.assertEqual(self.audit(pin)['validity'],'INVALID')

    def test_declared_member_size_and_expansion_ratio_are_bounded_without_reading_payload(self):
        self.make_zip([('pkg/small',b'123')]);data=bytearray(self.archive.read_bytes());offset=data.index(b'PK\x01\x02');struct.pack_into('<I',data,offset+24,8*1024*1024+1);self.archive.write_bytes(data)
        self.assertEqual(self.audit()['reason_codes'],['ARCHIVE_LIMIT_EXCEEDED'])
        self.make_zip([('pkg/repeated',b'0'*4096)],zipfile.ZIP_DEFLATED)
        self.assertEqual(self.audit()['reason_codes'],['ARCHIVE_EXPANSION_LIMIT'])

    def test_unsupported_compression_and_encrypted_metadata_are_rejected(self):
        self.make_zip([('pkg/small',b'abc')]);data=bytearray(self.archive.read_bytes());offset=data.index(b'PK\x01\x02');struct.pack_into('<H',data,offset+8,1);self.archive.write_bytes(data)
        self.assertEqual(self.audit()['reason_codes'],['ENCRYPTED_ARCHIVE_UNSUPPORTED'])
        self.make_zip([('pkg/small',b'abc')]);data=bytearray(self.archive.read_bytes());offset=data.index(b'PK\x01\x02');struct.pack_into('<H',data,offset+10,12);self.archive.write_bytes(data)
        self.assertEqual(self.audit()['reason_codes'],['UNSUPPORTED_COMPRESSION'])

    def test_receipt_output_is_exclusive_and_outside_source(self):
        self.make_zip();module=self.module();result=self.audit();output=self.output/'receipt.json'
        module.write_receipt(result,output,source_zip=self.archive);self.assertEqual(json.loads(output.read_text())['validity'],'VALID')
        before=output.read_bytes()
        with self.assertRaises(FileExistsError):module.write_receipt(result,output,source_zip=self.archive)
        self.assertEqual(before,output.read_bytes())
        with self.assertRaises(ValueError):module.write_receipt(result,self.sources/'output.json',source_zip=self.archive)
        self.assertFalse((self.sources/'output.json').exists())

    def test_receipt_case_alias_and_symbolic_ancestor_cannot_enter_source(self):
        self.make_zip();module=self.module();result=self.audit();alias=self.path/'SOURCES'
        if not alias.exists():self.skipTest('Filesystem case-sensitive; identity case-alias test requires case-insensitive filesystem')
        with self.assertRaises(ValueError):module.write_receipt(result,alias/'out.json',source_zip=self.archive)
        self.assertFalse((self.sources/'out.json').exists())

    def test_receipt_symbolic_ancestor_and_product_output_are_rejected(self):
        self.make_zip();module=self.module();result=self.audit()
        link=self.path/'linked';link.symlink_to(self.sources,target_is_directory=True)
        with self.assertRaises((OSError,ValueError)):module.write_receipt(result,link/'out.json',source_zip=self.archive)
        with self.assertRaises(ValueError):module.write_receipt(result,ROOT/'r1d-must-not-create.json',source_zip=self.archive)
        self.assertFalse((ROOT/'r1d-must-not-create.json').exists())

    def test_archive_count_total_and_source_size_limits(self):
        self.make_zip([('pkg/'+str(i),b'') for i in range(1025)])
        self.assertEqual(self.audit()['reason_codes'],['ARCHIVE_LIMIT_EXCEEDED'])
        self.make_zip([('padding',b'1'*150000)]+[('pkg/'+str(i),b'x') for i in range(5)])
        data=bytearray(self.archive.read_bytes());start=0
        while True:
            offset=data.find(b'PK\x01\x02',start)
            if offset<0:break
            name_size=struct.unpack_from('<H',data,offset+28)[0];name=data[offset+46:offset+46+name_size]
            if name.startswith(b'pkg/'):
                struct.pack_into('<I',data,offset+20,100000);struct.pack_into('<I',data,offset+24,7*1024*1024)
            start=offset+46+name_size
        self.archive.write_bytes(data);self.assertEqual(self.audit()['reason_codes'],['ARCHIVE_LIMIT_EXCEEDED'])
        with self.archive.open('wb') as stream:stream.truncate(8*1024*1024+1)
        self.assertEqual(self.audit('0'*64)['reason_codes'],['ARCHIVE_LIMIT_EXCEEDED'])

    def test_malformed_expected_pin_cannot_leak_outside_output_contract(self):
        self.make_zip();result=self.audit('not-a-hash')
        self.assertEqual(result['validity'],'INVALID');self.assertEqual(result['reason_codes'],['INVALID_SHA256'])
        self.assertIsNone(result['expected_archive_sha256'])

    def test_reference_accuracy_large_integer_is_invalid_without_overflow(self):
        pin=self.make_zip();refs=self.refs(pin);p=Path(refs[1]['path']);value=json.loads(p.read_text())
        value['historical_results_recalculated']['heldout_synthetic']['accuracy']=10**500
        p.write_text(json.dumps(value));refs[1]['sha256']=self.digest(p)
        result=self.audit(pin,refs)
        self.assertEqual(result['validity'],'INVALID')
        self.assertEqual(result['reason_codes'],['INVALID_REFERENCE_SHAPE'])
        self.assertEqual(result['historical_claims'],{})

    def cli(self,pin,*extra):
        return subprocess.run([sys.executable,'-B',str(ROOT/'lab/own_v01_runner.py'),'audit',
            '--source-zip',str(self.archive),'--expected-sha256',pin,*extra],cwd=self.path,capture_output=True,text=True)

    def unsupported_version(self):
        data=bytearray(self.archive.read_bytes())
        struct.pack_into('<H',data,data.index(b'PK\x01\x02')+6,99)
        self.archive.write_bytes(data)
        return self.digest(self.archive)

    def assert_unsupported_envelope(self,result):
        self.assertEqual(result['validity'],'INVALID')
        self.assertEqual(result['reason_codes'],['UNSUPPORTED_ZIP_FORMAT'])
        self.assertIsNone(result['archive_metadata'])
        self.assertEqual(result['historical_references'],[])
        self.assertEqual(result['historical_claims'],{})
        self.assertEqual(result['execution_verification'],'NOT_VERIFIED')
        self.assertEqual(result['mlflow_verification'],'NOT_VERIFIED')
        self.assertEqual(result['release_status'],'NOT_APPROVED_FOR_RELEASE')

    def test_unsupported_zip_version_api_has_invalid_envelope_and_supported_control(self):
        pin=self.make_zip([('pkg/a.txt',b'plain')]);supported=self.archive.read_bytes()
        self.assertEqual(self.audit(pin)['validity'],'VALID')
        self.assertEqual(self.archive.read_bytes(),supported)
        pin=self.unsupported_version();before=self.archive.read_bytes()
        self.assert_unsupported_envelope(self.audit(pin))
        self.assertEqual(self.archive.read_bytes(),before)
        self.assertEqual(list(self.output.iterdir()),[])

    def test_unsupported_zip_version_cli_emits_json_exit1_and_supported_control(self):
        pin=self.make_zip([('pkg/a.txt',b'plain')]);supported=self.archive.read_bytes()
        control=self.cli(pin);self.assertEqual(control.returncode,0,control.stderr)
        self.assertEqual(json.loads(control.stdout)['validity'],'VALID')
        self.assertEqual(self.archive.read_bytes(),supported)
        pin=self.unsupported_version();before={str(p.relative_to(self.path)):p.read_bytes() for p in self.path.rglob('*') if p.is_file()}
        result=self.cli(pin);self.assertEqual(result.returncode,1,result.stderr)
        self.assertTrue(result.stdout,result.stderr)
        self.assert_unsupported_envelope(json.loads(result.stdout))
        self.assertEqual(result.stderr,'')
        self.assertEqual(before,{str(p.relative_to(self.path)):p.read_bytes() for p in self.path.rglob('*') if p.is_file()})

    def test_cli_default_from_external_cwd_has_no_writes_and_no_neural_commands(self):
        pin=self.make_zip();before={str(p.relative_to(self.path)):p.read_bytes() for p in self.path.rglob('*') if p.is_file()}
        result=self.cli(pin);self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(json.loads(result.stdout)['validity'],'VALID')
        self.assertEqual(before,{str(p.relative_to(self.path)):p.read_bytes() for p in self.path.rglob('*') if p.is_file()})
        for command in ['train','evaluate']:
            result=subprocess.run([sys.executable,'-B',str(ROOT/'lab/own_v01_runner.py'),command],cwd=self.path,capture_output=True,text=True)
            self.assertEqual(result.returncode,2);self.assertIn('invalid choice',result.stderr)

    def test_cli_output_exclusive_and_case_alias_guard(self):
        pin=self.make_zip();output=self.output/'cli.json';result=self.cli(pin,'--output',str(output))
        self.assertEqual(result.returncode,0,result.stderr);before=output.read_bytes()
        self.assertEqual(self.cli(pin,'--output',str(output)).returncode,2);self.assertEqual(before,output.read_bytes())
        alias=self.path/'SOURCES'
        if not alias.exists():self.skipTest('Filesystem case-sensitive; CLI identity alias requires case-insensitive filesystem')
        result=self.cli(pin,'--output',str(alias/'alias.json'))
        self.assertEqual(result.returncode,2);self.assertIn('OUTPUT_MUST_BE_OUTSIDE_PROJECT',result.stderr)
        self.assertFalse((self.sources/'alias.json').exists())


if __name__=='__main__':unittest.main()
