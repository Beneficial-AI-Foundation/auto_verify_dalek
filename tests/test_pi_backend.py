"""Trusted Pi binding and public CLI guards, with no authentication or inference."""
from __future__ import annotations
import contextlib
import copy
import concurrent.futures
import threading
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest import mock

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from autofv import agent_lane, contracts, experiment, pi_backend, provider_config, runtime_profile
from tests.test_fvs_offline import packet


class PiBackendTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / 'candidate').mkdir()
        key = Ed25519PrivateKey.generate()
        self.key_path = self.root / 'attestation-key'
        self.key_path.write_bytes(key.private_bytes(serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw, serialization.NoEncryption()))
        self.key_path.chmod(0o600)
        now = time.time_ns() // 1_000_000
        self.runtime = {'schema':'autofv-pi-runtime-identity/v1','protocol_version':1,
            'node_sha256':'1'*64,'bridge_sha256':'2'*64,'package_lock_sha256':'3'*64,
            'packages':runtime_profile.PI_PACKAGES}
        self.config = {'schema':'autofv-run/v3','model':runtime_profile.PI_MODEL,
            'role_profile':runtime_profile.PI_PROFILE_ID,'source_packet':packet(),
            'max_wall_seconds':120,'max_cost_usd':None,'max_invocations':8}
        self.record = {'schema':pi_backend.RECORD_SCHEMA,'role_profile':runtime_profile.profile(),
            'runtime_identity':self.runtime,'node_executable':sys.executable,
            'credential_store_path':str(self.root / 'never-read-oauth-store.json'),
            'receipt_signing_key_path':str(self.key_path),'preflight_path':str(self.root/'preflight.json'),
            'suite_artifact_path':str(self.root/'suite.json'),
            'qualification_paths':{name:str(self.root/(name+'.json')) for name in pi_backend._QUALIFICATION_FIELDS},
            'grant':{'schema':'autofv-pi-run-grant/v1','config_sha256':provider_config.canonical_sha256(self.config),'approval_id':'synthetic-no-live-authority',
                'account_binding_sha256':'4'*64,'original_started_epoch_ms':now-1000,
                'original_deadline_epoch_ms':now+60000,'max_invocations':8,
                'acknowledgements':{'no_server_output_cap':True,'unknown_subscription_cost':True,
                    'best_effort_remote_abort':True},
                'qualification':{name:'5'*64 for name in pi_backend._QUALIFICATION_FIELDS}}}
        self.path = self.root/'runtime.json'
        self.write_record()
        self.run = {'run_id':'synthetic-backend','run_root':str(self.root),'evidence_dir':str(self.root/'evidence'),
            'input_root':str(self.root/'candidate'), 'base_commit':'c'*40,
            'lock':{'fixed_proxy':{'path':'/fixture','proxy_id':'fixture-proxy','route_id':'fixture-route'}}}
        self.addCleanup(provider_config.release_provider,self.run)
        self.addCleanup(pi_backend.release,self.run)

    def write_record(self):
        self.path.write_bytes(contracts.canonical_json_bytes(self.record)+b'\n')

    def configure(self):
        with mock.patch.object(pi_backend,'_verify_runtime'), mock.patch.dict(os.environ,{'AUTOFV_RUN_TOKEN':'synthetic-fixed-token'}):
            return pi_backend.configure(self.run,self.config,self.path,tool_schemas=list(agent_lane._TOOL_SCHEMAS))

    def test_binding_has_no_api_key_or_numeric_cost_and_does_not_read_store(self):
        public = self.configure()
        self.assertEqual(public['endpoint'],'https://api.openai.com/v1/responses')
        self.assertNotIn('pricing',public)
        self.assertEqual(self.run['cost_classification'],'subscription_cost_unknown')
        self.assertEqual(provider_config.provider_binding(self.run).api_key,bytearray())
        self.assertFalse(Path(self.record['credential_store_path']).exists())
        self.assertEqual(self.run['budget_started_epoch_ns'], self.record['grant']['original_started_epoch_ms']*1_000_000)
        self.assertEqual(provider_config.validate_public_binding(public),public)

    def test_grant_configuration_cannot_be_changed(self):
        self.config['source_packet']['sources'][0]['content'] += '\n'
        with self.assertRaisesRegex(contracts.ContractError, 'approval limits'):
            self.configure()

    def test_same_approval_cannot_allocate_two_fresh_runs_even_with_record_copy(self):
        self.configure()
        second = copy.deepcopy(self.run)
        for name in ('provider_binding','pi_allocation_sha256','runtime_record_sha256'):
            second.pop(name,None)
        second['run_id'] = 'second-fresh-run'
        root = self.root / 'second-run'
        root.mkdir()
        second['run_root'] = str(root)
        copied = self.root / 'copied-record.json'
        copied.write_bytes(self.path.read_bytes())
        with mock.patch.object(pi_backend,'_verify_runtime'), mock.patch.dict(os.environ,{'AUTOFV_RUN_TOKEN':'synthetic-fixed-token'}):
            with self.assertRaisesRegex(contracts.ContractError, 'already allocated'):
                pi_backend.configure(second,self.config,copied,tool_schemas=list(agent_lane._TOOL_SCHEMAS))
        self.assertIsNone(provider_config.provider_binding(second))
        self.assertFalse(pi_backend._PROCESSES)

    def test_concurrent_fresh_runs_share_one_approval_allocation(self):
        barrier = threading.Barrier(2)
        runs = []
        for index in range(2):
            run = copy.deepcopy(self.run)
            root = self.root / f'concurrent-{index}'
            root.mkdir()
            run.update(run_id=f'concurrent-{index}',run_root=str(root))
            runs.append(run)
            self.addCleanup(provider_config.release_provider,run)
            self.addCleanup(pi_backend.release,run)
        def allocate(run):
            barrier.wait()
            try:
                pi_backend.configure(run,self.config,self.path,tool_schemas=list(agent_lane._TOOL_SCHEMAS))
                return 'allocated'
            except contracts.ContractError as exc:
                return str(exc)
        with mock.patch.object(pi_backend,'_verify_runtime'), mock.patch.dict(os.environ,{'AUTOFV_RUN_TOKEN':'synthetic-fixed-token'}), concurrent.futures.ThreadPoolExecutor(2) as pool:
            outcomes = list(pool.map(allocate,runs))
        self.assertEqual(outcomes.count('allocated'),1)
        self.assertEqual(sum('already allocated' in x for x in outcomes),1)
        self.assertFalse(pi_backend._PROCESSES)

    def test_restart_reuses_allocation_and_missing_or_changed_authority_stops(self):
        from autofv import pi_allocation
        self.configure()
        pi_backend.finalize_allocation(self.run)
        binding = provider_config.provider_binding(self.run)
        record_path = pi_allocation._path(self.record)
        original = record_path.read_bytes()
        digest = self.run['pi_allocation_sha256']
        pi_backend.release(self.run)
        provider_config.release_provider(self.run)
        self.configure()
        self.assertEqual(self.run['pi_allocation_sha256'],digest)
        pi_allocation.verify(self.run,self.record,provider_config.provider_binding(self.run))
        for mutation in ('missing','changed'):
            with self.subTest(mutation=mutation):
                pi_backend.release(self.run)
                provider_config.release_provider(self.run)
                if mutation == 'missing':
                    record_path.unlink()
                else:
                    record_path.write_bytes(original.replace(b'synthetic-backend',b'synthetic-tamperx'))
                with self.assertRaises((contracts.ContractError,provider_config.ProviderConfigError)):
                    self.configure()
                record_path.write_bytes(original)
                record_path.chmod(0o600)

    def test_guest_project_path_cannot_substitute_for_host_boundary(self):
        self.run.pop('input_root')
        self.run['project_dir'] = '/volume/work/project'
        with self.assertRaisesRegex(contracts.ContractError,'actual host input root'):
            self.configure()

    def test_private_aliases_and_runtime_record_rejected_before_source_snapshot_or_worker(self):
        target = self.root / 'candidate'
        (target / 'autofv.json').write_text('{}')
        config = self.root / 'config.json'
        config.write_bytes(contracts.canonical_json_bytes(self.config) + b'\n')
        alias = self.root / 'source-alias'
        alias.symlink_to(target, target_is_directory=True)
        for field in ('credential_store_path', 'receipt_signing_key_path', 'runtime_record'):
            with self.subTest(field=field):
                value = copy.deepcopy(self.record)
                path = self.path
                if field == 'runtime_record':
                    path = alias / 'runtime.json'
                else:
                    value[field] = str(alias / 'synthetic-private-file')
                path.write_bytes(contracts.canonical_json_bytes(value) + b'\n')
                with mock.patch.object(experiment.results, 'validate_output_root'), \
                     mock.patch.object(experiment.results, 'new_attempt_identity', return_value={}), \
                     mock.patch.object(experiment, '_persist_unallocated_attempt', return_value={'outcome':'invalid_config'}) as failed, \
                     mock.patch.object(experiment.results, 'snapshot_input', side_effect=AssertionError('source snapshot forbidden')), \
                     mock.patch.object(experiment.worker, 'prepare_run', side_effect=AssertionError('worker forbidden')), \
                     mock.patch.object(experiment, 'validate_target', side_effect=AssertionError('source inspection forbidden')):
                    result = experiment.run_experiment(target, config, runtime_record=path)
                self.assertEqual(result['outcome'], 'invalid_config')
                self.assertIsNone(failed.call_args.kwargs['accepted_source'])
                self.assertIn('outside', str(failed.call_args.kwargs['detail']))
        self.write_record()

    def test_expired_or_policy_unaccepted_grant_stops_before_private_key_read(self):
        for change in ('expired','unaccepted'):
            with self.subTest(change=change):
                value=copy.deepcopy(self.record)
                if change=='expired':
                    value['grant']['original_started_epoch_ms']=1
                    value['grant']['original_deadline_epoch_ms']=1000
                else:
                    value['grant']['acknowledgements']['no_server_output_cap']=False
                self.path.write_bytes(contracts.canonical_json_bytes(value)+b'\n')
                with self.assertRaises(contracts.ContractError): self.configure()
        self.assertIsNone(provider_config.provider_binding(self.run))

    def test_key_inside_candidate_or_world_readable_is_rejected(self):
        self.key_path.chmod(0o644)
        with self.assertRaisesRegex(contracts.ContractError,'private'): self.configure()
        self.key_path.chmod(0o600)
        self.record['credential_store_path']=str(self.root/'candidate'/'auth.json')
        self.write_record()
        with self.assertRaisesRegex(contracts.ContractError,'outside'): self.configure()

    def test_fake_qualification_hashes_do_not_authorize_dispatch(self):
        self.configure()
        with self.assertRaises((contracts.ContractError,FileNotFoundError)):
            pi_backend.authorize_prepared(self.run)
        self.assertFalse(pi_backend._PROCESSES)

    def test_doctor_uses_only_metadata_even_with_missing_store_and_key(self):
        self.key_path.unlink()
        observed={'runtime_identity':self.runtime,'credential_accessed':False,'model_dispatched':False}
        with mock.patch('autofv.pi_process.runtime_diagnostic',return_value=observed), \
             mock.patch.object(pi_backend,'configure',side_effect=AssertionError('configure forbidden')):
            report=pi_backend.diagnostic(self.path)
        self.assertEqual(report['status'],'metadata_match')
        self.assertFalse(report['live_qualified'])
        self.assertFalse(report['authentication_checked'])

    def test_doctor_reports_runtime_mismatch(self):
        with mock.patch('autofv.pi_process.runtime_diagnostic',return_value={'runtime_identity':{}}):
            report=pi_backend.diagnostic(self.path)
        self.assertEqual(report['status'],'blocked')
        self.assertIn('installed_runtime_identity_mismatch',report['blockers'])

    def test_public_cli_rejects_api_pi_flag_mixture_before_run(self):
        for extra in (['--env-file','/tmp/no-file'],['--selection-record','/tmp/no-file'],['--fresh-pair-preflight']):
            with mock.patch.object(sys,'argv',['autofv','run','/tmp/target','--config','/tmp/config',
                                             '--runtime-record',str(self.path),*extra]), \
                 mock.patch.object(experiment,'run_experiment',side_effect=AssertionError('run forbidden')), \
                 contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as error:
                experiment.main()
            self.assertEqual(error.exception.code,2)

    def test_public_cli_doctor_reaches_metadata_only_path(self):
        with mock.patch.object(sys,'argv',['autofv','doctor','--runtime-record',str(self.path)]), \
             mock.patch('autofv.pi_process.runtime_diagnostic',return_value={'runtime_identity':self.runtime}), \
             contextlib.redirect_stdout(io.StringIO()) as output:
            experiment.main()
        self.assertFalse(json.loads(output.getvalue())['live_qualified'])
