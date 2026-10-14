"""Public CLI vertical slice with real Pi SDK IPC and synthetic HTTP wire data.

No OAuth, entitlement check, live request, Docker, Lean, or VM is performed.
Only preparation/compiler/verifier effects and qualification are test fixtures.
The outer graph, DeepAgents, model journal, both fixed HTTP hops, Pi supervisor,
SDK encoding/stream decoding, native continuation, and accounting are production.
"""
from __future__ import annotations

import ast
import copy
import hashlib
import http.server
import io
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from contextlib import ExitStack
from unittest import mock

from autofv import (agent_lane, axiom_audit, contracts, experiment, fvs_adapter,
    fvs_packet, fvs_profile, model, pi_backend, pi_process, provider_config, provider_service,
    provider_transport, result_audit, results, run_state, runtime_profile, subscription_journal,
    subscription_receipts, terminal_verifier, verifier, verifier_bundle, worker,
    worker_proxy, worker_runtime)
from tests import test_fvs_offline as fixture
from tests.test_clean_verifier import _preparation_manifest
from tests.test_generic_role_e2e import patch
from tests.test_provider_service import _install_trusted_authorization_fixture

HERE = Path(__file__).resolve().parent
LEAF, ROOT, ROOT_SPEC = 'probe:Arithmetic.increment', 'probe:Arithmetic.root', 'probe:Arithmetic.root_spec'
TOKEN = 'SYNTHETIC_CLI_RELAY_TOKEN'


def sha(value):
    return provider_config.canonical_sha256(value)


def write_json(path, value):
    path.write_bytes(contracts.canonical_json_bytes(value) + b'\n')


class PiCliE2ETests(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.temp = self.stack.enter_context(tempfile.TemporaryDirectory(prefix='pi-cli-e2e-'))
        self.root = Path(self.temp).resolve()
        self.node = Path(shutil.which('node') or '/missing-node').resolve()
        self.assertTrue(self.node.is_file(), 'pinned Pi runtime tests require Node')
        self.assertTrue((pi_process.runtime_path() / 'node_modules/@earendil-works/pi-ai/package.json').is_file(),
                        'install pinned runtime packages before Pi CLI qualification')
        self.target = self.root / 'target'
        self.target.mkdir()
        self.project = self.root / 'project'
        self.run_root = self.root / 'run'
        self.run_root.mkdir()
        self.requests = self.root / 'wire-requests.jsonl'
        self.requests.touch()
        self.roles, self.verifications, self.processes, self.payloads = [], [], [], []
        self.capture_state = None
        self.production_qualification = pi_backend._qualification_artifacts
        self._inputs()
        self._runtime_record()
        self._network_guards()
        self._relay()
        self._patches()

    def _inputs(self):
        self.packet = fixture.packet()
        root_source = 'import Arithmetic\nnamespace Arithmetic\ndef root (n : Nat) := increment n\n@[step]\ntheorem root_spec (n : Nat) : ∃ result, root n = ok result := by sorry\nend Arithmetic\n'
        self.packet['sources'][-1] = fvs_packet.source('Root.lean', 'lean', root_source)
        for source in self.packet['sources']:
            if source['surface'] != 'rust':
                (self.target / source['path']).write_text(source['content'])
        self.manifest = {'schema':'autofv/v1', 'targets':[{'function':'crate::root','spec':'Arithmetic.root_spec'}], 'verify':['lake','build']}
        write_json(self.target / 'autofv.json', self.manifest)
        public = self.root / 'public'
        self.rust_root = public / 'curve25519-dalek/src'
        self.rust_root.mkdir(parents=True)
        (self.rust_root / 'increment.rs').write_text(self.packet['sources'][1]['content'])
        def git(*args):
            return subprocess.run(['git','-C',str(public),*args],check=True,capture_output=True).stdout.decode().strip()
        git('init','-q')
        git('remote','add','origin',fixture.IDENTITY['repository'])
        git('add','.')
        git('-c','user.name=Synthetic','-c','user.email=synthetic@invalid','commit','-qm','synthetic source')
        self.packet['source_identity']['revision'] = git('rev-parse','HEAD')
        self.packet['packet_sha256'] = sha({k:v for k,v in self.packet.items() if k != 'packet_sha256'})
        self.config = {'schema':'autofv-run/v3','model':runtime_profile.PI_MODEL,
            'role_profile':runtime_profile.PI_PROFILE_ID,'source_packet':self.packet,
            'max_wall_seconds':600,'max_cost_usd':None,'max_invocations':40}
        self.config_path = self.root / 'config.json'
        write_json(self.config_path,self.config)
        self.graph = {'frozen_targets':[ROOT],'selected_nodes':[LEAF,ROOT],
            'term_dependencies':[[ROOT,LEAF]],'type_dependencies':[],
            'source_paths':{LEAF:'Arithmetic.lean',ROOT:'Root.lean',ROOT_SPEC:'Root.lean'},
            'supplied_specs':{ROOT:ROOT_SPEC}}
        self.graph['graph_sha256'] = sha(self.graph)
        self.graph.update(probe_rust_sha256='1'*64,probe_aeneas_sha256='2'*64)
        self.preparation = _preparation_manifest({'graph':self.graph})
        self.preparation.update(source=self.packet['source_identity'], files=[{
            'path':str(p.relative_to(self.target)), 'sha256':hashlib.sha256(p.read_bytes()).hexdigest(),
            'size':p.stat().st_size} for p in sorted(self.target.iterdir())])
        self.preparation['tree_sha256'] = sha(self.preparation['files'])
        self.preparation['manifest_sha256'] = sha({k:v for k,v in self.preparation.items() if k != 'manifest_sha256'})
        self.preparation_path = self.root / 'preparation.json'
        write_json(self.preparation_path,self.preparation)
        for name in ('probe-rust.json','probe-aeneas.json','dependencies.tar'):
            (self.root / name).write_bytes(b'synthetic preparation boundary\n')
        self.reference_path = self.root / 'reference.json'
        self.reference = {'leaves':[{'declaration':'Arithmetic.root','spec':'Arithmetic.root_spec',
            'source':'Root.lean','statement':'∀ n : Nat, ∃ result, Arithmetic.root n = ok result',
            'proof':'by intro n; rfl'}]}
        write_json(self.reference_path,self.reference)
        spec_patch, proof_patch = fixture.patch(fixture.SPEC), fixture.patch(fixture.PROOF)
        root_spec = root_source.replace('import Arithmetic\n', 'import Arithmetic\n-- Synthetic root specification reviewed.\n')
        root_spec_patch = patch('Root.lean',root_source,root_spec)
        root_patch = patch('Root.lean',root_source,root_spec.replace('by sorry','by rfl'))
        root_canon = 'theorem root_spec (n : Nat) : ∃ result, root n = ok result'
        triage = 'triage:' + json.dumps({'findings':[],'summary':'Synthetic author checked the complete passing review.'})
        def submit(p, evidence):
            return {'name':'submit_candidate','arguments':{'patch':p,'claimed_status':'candidate','evidence':evidence}}
        self.actions = [
            submit(root_spec_patch,['Synthetic graph scout']),
            submit(root_spec_patch,['Synthetic frozen dependency plan']),
            submit(spec_patch,['Synthetic implementation research']),
            {'name':'read_allowed','arguments':{'path':'Arithmetic.lean'}},
            submit(spec_patch,['statement:'+fixture.CANON]),
            submit(spec_patch,[fixture.PASS]),
            submit(spec_patch,['statement:'+fixture.CANON,triage]),
            {'name':'read_allowed','arguments':{'path':'Arithmetic.lean'}},
            submit(proof_patch,['statement:'+fixture.CANON]),
            submit(proof_patch,[fixture.PASS]),
            submit(proof_patch,['statement:'+fixture.CANON,triage]),
            submit(root_spec_patch,['Synthetic root research']),
            submit(root_spec_patch,['statement:'+root_canon]),
            submit(root_spec_patch,[fixture.PASS]),
            submit(root_spec_patch,['statement:'+root_canon,triage]),
            submit(root_patch,['statement:'+root_canon]),
            submit(root_patch,[fixture.PASS]),
            submit(root_patch,['statement:'+root_canon,triage]),
        ]
        self.fixture_path = self.root / 'wire-fixture.json'
        write_json(self.fixture_path, {'requests':str(self.requests),'actions':self.actions})

    def _runtime_record(self):
        private = self.root / 'managed'
        private.mkdir(mode=0o700)
        self.store = private / 'credentials.json'
        now = time.time_ns() // 1_000_000
        # Provision through the production Node helper; Python sees only its
        # public store path/account binding, never the signed credential envelope.
        script = '''
import { pathToFileURL } from 'node:url';
const { initializeManagedStore } = await import(pathToFileURL(process.argv[1]).href);
const metadata = await initializeManagedStore(process.argv[2], {
  type:'oauth', access:'SYNTHETIC_ACCESS', refresh:'SYNTHETIC_REFRESH',
  expires:Date.now()+86400000, clientId:'SYNTHETIC_CLIENT', scopes:['chatgpt.tokens.use.direct']
});
process.stdout.write(JSON.stringify(metadata));
'''
        provisioned = subprocess.run([str(self.node),'--input-type=module','-e',script,
            str(pi_process.runtime_path()/'managed-store.mjs'),str(self.store)],
            cwd=private,env=pi_process.minimal_environment(self.node,private),
            capture_output=True,check=True,timeout=15)
        metadata = json.loads(provisioned.stdout)
        self.assertEqual(set(metadata),{'store_path','account_binding_sha256'})
        self.assertEqual(metadata['store_path'],str(self.store))
        self.assertEqual(provisioned.stderr,b'')
        key = private / 'receipt-key'
        key.write_bytes(bytes(range(1,33)))
        key.chmod(0o600)
        self.record = {'schema':'autofv-pi-runtime-record/v1','role_profile':runtime_profile.profile(),
            'runtime_identity':pi_process.runtime_diagnostic(self.node)['runtime_identity'],
            'grant':{'schema':'autofv-pi-run-grant/v1','config_sha256':provider_config.canonical_sha256(self.config),'approval_id':'unittest-synthetic-only',
                'account_binding_sha256':metadata['account_binding_sha256'],'original_started_epoch_ms':now-1000,
                'original_deadline_epoch_ms':now+599000,'max_invocations':40,
                'acknowledgements':{'no_server_output_cap':True,'unknown_subscription_cost':True,'best_effort_remote_abort':True},
                'qualification':{'isolation_sha256':'8'*64,'callback_cancellation_sha256':'9'*64,'entitlement_sha256':'a'*64}},
            'node_executable':str(self.node),'credential_store_path':str(self.store),
            'receipt_signing_key_path':str(key),'preflight_path':str(self.run_root / 'deterministic-preflight.json'),
            'suite_artifact_path':str(self.run_root / 'retained-suite.json'),
            'qualification_paths':{name:str(private / name) for name in ('isolation_sha256','callback_cancellation_sha256','entitlement_sha256')}}
        self.record_path = self.root / 'runtime.json'
        write_json(self.record_path,self.record)

    def _network_guards(self):
        original = socket.socket.connect
        def connect(sock, address):
            if sock.family in (socket.AF_INET,socket.AF_INET6):
                self.assertIn(address[0],('127.0.0.1','::1'))
            return original(sock,address)
        self.stack.enter_context(mock.patch.object(socket.socket,'connect',connect))
        original_resolver = socket.getaddrinfo
        def resolve(host,*args,**kwargs):
            self.assertIn(host,(None,'','localhost','127.0.0.1','::1'))
            return original_resolver(host,*args,**kwargs)
        self.stack.enter_context(mock.patch.object(socket,'getaddrinfo',side_effect=resolve))
        self.stack.enter_context(mock.patch.dict(os.environ,{'AUTOFV_RUN_TOKEN':TOKEN,
            'NO_PROXY':'127.0.0.1,localhost','OPENAI_API_KEY':'SYNTHETIC_AMBIENT_KEY_MUST_NOT_REACH_NODE',
            'NODE_OPTIONS':'--invalid-synthetic-preload-option'}))

    def _relay(self):
        self.stack.enter_context(mock.patch.object(provider_service,'_serve',side_effect=lambda handler:
            provider_service._BoundedHTTPServer(('127.0.0.1',0),handler)))
        self.relay = None

    def _start_relay(self, run):
        self.stack.enter_context(mock.patch.dict(os.environ,{
            'AUTOFV_PROXY_BASE':run['proxy_base'],'AUTOFV_PROXY_PATH':run['lock']['fixed_proxy']['path'],
            'AUTOFV_PROXY_TIMEOUT_SECONDS':str(provider_transport.request_timeout_seconds(run))}))
        tree = ast.parse(worker_proxy._RELAY_PROGRAM)
        self.assertIn('serve_forever',ast.unparse(tree.body[-1]))
        scope = {'__name__':'synthetic_pi_relay'}
        exec(compile(ast.Module(body=tree.body[:-1],type_ignores=[]),'<production-relay>','exec'),scope)
        class FixtureRelay(http.server.ThreadingHTTPServer):
            def handle_error(self,request,client_address):
                # A real SIGINT closes the production client before the relay can
                # send its terminal transport error. This disconnect is expected.
                if isinstance(sys.exception(),(BrokenPipeError,ConnectionResetError)):
                    return
                super().handle_error(request,client_address)
        self.relay = FixtureRelay(('127.0.0.1',0),scope['Handler'])
        self.relay_thread = threading.Thread(target=self.relay.serve_forever,daemon=True)
        self.relay_thread.start()
        self.stack.enter_context(mock.patch.object(worker_proxy,'RELAY_PORT',self.relay.server_port))
        def close():
            self.relay.shutdown(); self.relay.server_close(); self.relay_thread.join(2)
            self.assertFalse(self.relay_thread.is_alive())
        self.stack.callback(close)

    def _patches(self):
        case = self
        class InterceptedProcess(pi_process.PiProcess):
            def _spawn(self):
                env = {**pi_process.minimal_environment(self.node,self.directory),'AUTOFV_TEST_FIXTURE':str(case.fixture_path)}
                process = subprocess.Popen([str(self.node),'--import',str(HERE / 'fixtures/pi-cli/intercept.mjs'),
                    str(pi_process.runtime_path() / 'transport.mjs'),str(self.store_path),self.account_binding_sha256],
                    stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,cwd=self.directory,env=env,
                    start_new_session=True,close_fds=True,shell=False,bufsize=0)
                case.processes.append(process)
                return process
            def generate_one(self, payload):
                case.payloads.append(copy.deepcopy(payload))
                return super().generate_one(payload)
        self.stack.enter_context(mock.patch.object(pi_process,'PiProcess',InterceptedProcess))
        self.stack.enter_context(mock.patch.object(worker,'prepare_run',side_effect=self._prepare))
        self.stack.enter_context(mock.patch.object(experiment,'_load_prepared_inputs',return_value=(
            self.preparation,self.graph,{'schema':'autofv-prepared-graph-binding/v1','receipt_sha256':'a'*64},
            {'probe-rust':str(self.root/'probe-rust.json'),'probe-aeneas':str(self.root/'probe-aeneas.json'),
             'dependency-cache':str(self.root/'dependencies.tar')})))
        # A unittest-scoped authorization bootstrap, never a production bypass flag.
        def synthetic_qualification(record,binding):
            self.assertEqual(record['grant']['approval_id'],'unittest-synthetic-only')
            self.assertEqual(binding['runtime_identity'],self.record['runtime_identity'])
        self.stack.enter_context(mock.patch.object(pi_backend,'_qualification_artifacts',side_effect=synthetic_qualification))
        self.stack.enter_context(mock.patch.object(worker_proxy,'_ensure_proxy_relay',return_value=('synthetic-loopback','127.0.0.1')))
        self.stack.enter_context(mock.patch.object(worker_proxy,'_docker',side_effect=self._proxy_client))
        self.stack.enter_context(mock.patch.object(worker_runtime,'_git',side_effect=lambda _run,*args:self._git(*args)))
        self.stack.enter_context(mock.patch.object(worker_runtime,'_docker',side_effect=self._compiler))
        self.stack.enter_context(mock.patch.object(worker,'check_lane',return_value='sealed_runtime:exit=0:synthetic compiler fixture; not Lean proof'))
        self.stack.enter_context(mock.patch.object(verifier,'verify_run',side_effect=self._verify))
        original_role = agent_lane.run_role_conversation
        async def observe_role(state,job,tools):
            self.roles.append(copy.deepcopy(job))
            return await original_role(state,job,tools)
        self.stack.enter_context(mock.patch.object(agent_lane,'run_role_conversation',side_effect=observe_role))
        original_finish = experiment._finish_attempt
        def finish(run,state,**kwargs):
            self.capture_state = state
            return original_finish(run,state,**kwargs)
        self.stack.enter_context(mock.patch.object(experiment,'_finish_attempt',side_effect=finish))

    def _git(self,*args):
        return subprocess.run(['git',*args],cwd=self.project,check=True,capture_output=True).stdout

    def _prepare(self,target,manifest,lock,*,before_worker):
        shutil.copytree(target,self.project)
        self._git('init','-q'); self._git('add','.')
        self._git('-c','user.name=Synthetic','-c','user.email=synthetic@invalid','commit','-qm','synthetic prepared target')
        commit = self._git('rev-parse','HEAD').decode().strip()
        run = {'run_id':'synthetic-public-pi-cli','run_root':str(self.run_root),'project_dir':str(self.project),
            'input_root':str(target),'evidence_dir':str(self.run_root/'evidence'),'volume':'synthetic-volume',
            'agent_worker_id':'synthetic-agent','execution_tier':'simulation','cost_classification':'synthetic_fixture',
            'snapshot_sha256':worker.hash_tree(target),'manifest_sha256':sha(manifest),
            'image_digest':lock['image']['image_digest'],'control_bundle_sha256':worker.control_manifest(lock)[0]['bundle_sha256'],
            'worker_inventory_sha256':'2'*64,'native_decide_policy_sha256':lock['native_decide_policy_sha256'],
            'fixed_proxy_sha256':sha(lock['fixed_proxy']),'base_commit':commit,'events':['validated'],'lock':lock}
        run['accepted'] = {'accepted_commit':commit,'accepted_tree_sha256':hashlib.sha256(self._git('archive','HEAD')).hexdigest()}
        before_worker(run)
        worker_proxy._record_proxy_policy(run)
        self.stack.callback(provider_service.release,run)
        _install_trusted_authorization_fixture(run,self.run_root)
        self._start_relay(run)
        return run

    def _proxy_client(self,*argv,input_bytes,check=False):
        self.assertFalse(check)
        index = argv.index('-c')
        self.assertEqual(argv[index+1],worker_proxy._PROXY_CLIENT_PROGRAM)
        output = io.BytesIO()
        with mock.patch.object(sys,'stdin',io.TextIOWrapper(io.BytesIO(input_bytes))), \
             mock.patch.object(sys,'stdout',io.TextIOWrapper(output,write_through=True)), \
             mock.patch.object(sys,'argv',['synthetic-client',argv[index+2],argv[index+3]]):
            exec(compile(worker_proxy._PROXY_CLIENT_PROGRAM,'<production-client>','exec'),{'__name__':'__main__'})
            raw = output.getvalue()
        return subprocess.CompletedProcess(argv,0,raw,b'')

    def _compiler(self,*argv,input_bytes=None,**kwargs):
        if any('lake env lean' in arg for arg in argv):
            return subprocess.CompletedProcess(argv,0,b'synthetic consumer check\nAUTOFV_FEASIBILITY_EXIT=0',b'')
        return subprocess.CompletedProcess(argv,0,b'a'*64+b'\n',b'')

    def _verify(self,run,expected,*,verification_state=None):
        state = verification_state or run['verification_state']
        partial = verification_state is not None
        self.verifications.append(('scoped' if partial else 'terminal',copy.deepcopy(state)))
        inventory = axiom_audit.expected_inventory(state,{'leaves':[]} if partial else self.reference)
        body = {'schema':'autofv-verifier-partial-report/v1' if partial else 'autofv-verifier-report/v1',
            'run_id':run['run_id'],'agent_worker_id':run['agent_worker_id'],
            'verifier_worker_id':'synthetic-scoped-verifier' if partial else 'synthetic-terminal-verifier',
            'bundle_sha256':'3'*64,**{k:v for k,v in expected.items() if k not in terminal_verifier.TERMINAL_REPORT_FIELDS},
            'checks':{name:not partial or name != 'meaning' for name in verifier_bundle.REPORT_CHECKS},
            'failures':[],'native_decide_uses':[],'accepted_native_decide_uses':[],'hidden_native_decide_uses':[],
            'compiler_assumptions':verifier.compiler_assumptions(run['lock'],run),
            'axiom_inventory':inventory,'axiom_inventory_sha256':axiom_audit.inventory_identity_sha256(inventory),
            'meaning':{} if partial else {'reference_integrity':True,'statement_equivalence':True,'non_vacuity':True,'broken_implementation_rejected':True},
            'sorry_count_before':1,'sorry_count_after':0,'evidence_level':'P1' if partial else 'L4','verdict':'SCOPED_PASS' if partial else 'PASS'}
        if partial:
            body.update(partial_target=state['partial_target'],root_status='unverified')
        core = {**body,'report_sha256':sha(body)}
        if partial:
            forged = {**body,'verifier_worker_id':run['agent_worker_id']}
            forged['report_sha256'] = sha(forged)
            with self.assertRaises(verifier.VerifierError):
                verifier.validate_partial_report(forged,run,expected,state['partial_target'],state)
            return core
        body.update(core_report=core,counterexample_certificate_sha256=None,
            **terminal_verifier.terminal_expectations(run,state),target_states=state['target_states'],terminal_status='verified')
        report = {**body,'report_sha256':sha(body)}
        forged = copy.deepcopy(report)
        forged['verifier_worker_id'] = run['agent_worker_id']
        forged['core_report']['verifier_worker_id'] = run['agent_worker_id']
        forged['core_report']['report_sha256'] = sha({k:v for k,v in forged['core_report'].items() if k != 'report_sha256'})
        forged['report_sha256'] = sha({k:v for k,v in forged.items() if k != 'report_sha256'})
        with self.assertRaises(verifier.VerifierError):
            verifier.validate_report(forged,run,expected)
        return report

    def _cli(self,*extra,expect_success=True):
        args = ['autofv','run',str(self.target),'--config',str(self.config_path),'--runtime-record',str(self.record_path),
            '--preparation-manifest',str(self.preparation_path),'--preparation-evidence',str(self.root),
            '--preparation-cache',str(self.root/'dependencies.tar'),'--verifier-reference',str(self.reference_path),
            '--execution-mode','full','--public-rust-root',str(self.rust_root),*extra]
        output = io.StringIO()
        with mock.patch.object(sys,'argv',args),mock.patch.object(sys,'stdout',output):
            try:
                experiment.main()
            except SystemExit as exc:
                self.assertEqual(exc.code,0 if expect_success else 1,
                    json.loads(output.getvalue()).get('termination_detail') if output.getvalue() else 'CLI emitted no result')
        result = json.loads(output.getvalue())
        if not expect_success:
            self.assertNotEqual(result['outcome'],'success')
        return result

    def test_public_cli_complete_run_native_continuation_and_recorded_replay(self):
        result = self._cli()
        self.assertEqual(result['outcome'],'success')
        self.assertEqual(result['schema'],'autofv-result/v3')
        self.assertFalse(result['scored'])
        self.assertEqual(result['execution_tier'],'simulation')
        self.assertIsNone(result['cost_usd'])
        self.assertEqual(result['cost_classification'],'subscription_cost_unknown')
        self.assertTrue(result['dispatch_accounting_complete'])
        self.assertFalse(result['monetary_cost_known'])
        wire = [json.loads(line) for line in self.requests.read_text().splitlines()]
        self.assertEqual(len(wire),len(self.actions))
        self.assertEqual(result['invocations_used'],len(wire))
        self.assertEqual(result['tokens'],{'input':12*len(wire),'output':8*len(wire),'total':20*len(wire)})
        self.assertEqual(result['model_retries'],0)
        self.assertEqual(result['calls']['compaction'],0)
        self.assertEqual(len(self.processes),1)
        self.assertEqual([kind for kind,_ in self.verifications],['scoped','terminal'])
        self.assertEqual(self.verifications[0][1]['accepted_nodes'],[LEAF])
        self.assertEqual(self.verifications[1][1]['accepted_nodes'],sorted([LEAF,ROOT]))
        role_names = [job['role'] for job in self.roles]
        self.assertEqual(role_names,['scout','dependency_planner',
            'scout','specifier','spec_reviewer','specifier','prover','proof_reviewer','repair',
            'scout','specifier','spec_reviewer','specifier','prover','proof_reviewer','repair'])
        self.assertLess(role_names.index('specifier'),role_names.index('spec_reviewer'))
        self.assertLess(role_names.index('spec_reviewer'),role_names.index('prover'))
        self.assertLess(role_names.index('prover'),role_names.index('proof_reviewer'))
        conversations = [agent_lane.role_conversation_spec(job)['conversation_id'] for job in self.roles]
        self.assertEqual(len(conversations),len(set(conversations)))
        for payload in self.payloads:
            if payload['request']['role'] in ('spec_reviewer','proof_reviewer'):
                self.assertEqual([m['role'] for m in payload['messages']],['system','user'])
                self.assertEqual(payload['continuations'],[])
        self.assertNotIn('sorry',(self.project/'Arithmetic.lean').read_text())
        self.assertNotIn('sorry',(self.project/'Root.lean').read_text())
        continued = wire[4]['body']['input']
        self.assertTrue(any(item.get('type') == 'reasoning' and item.get('encrypted_content') == 'PRIVATE_CLI_ENCRYPTED_4' for item in continued))
        self.assertTrue(any(item.get('type') == 'function_call_output' and item.get('call_id') == 'call_4' for item in continued))
        self.assertTrue(any(item.get('type') == 'message' and item.get('id') == 'msg_4' and item.get('phase') == 'commentary' for item in continued))
        self.assertNotIn(self.payloads[3]['request']['request_id']+'-tool',json.dumps(continued))
        private = self.run_root/'provider-private/subscription-journal.json'
        self.assertIn('PRIVATE_CLI_ENCRYPTED_4',private.read_text())
        self.assertNotIn('PRIVATE_CLI_ENCRYPTED', (self.run_root/'evidence/subscription-journal.json').read_text())
        for path in (self.run_root/'evidence').rglob('*.json'):
            self.assertNotIn('PRIVATE_CLI_ENCRYPTED',path.read_text(),str(path))
            self.assertNotIn('SYNTHETIC_ACCESS',path.read_text(),str(path))
        self.assertTrue(all(process.poll() is not None for process in self.processes))
        checkpoint = run_state._load_checkpoint(self.run_root,{})
        state = checkpoint['state']
        public = checkpoint['run']['provider_binding']
        retained_exchanges = json.loads((self.run_root/'evidence/l0/model-receipts.json').read_text())
        result_audit._validate_accounting(result,retained_exchanges,self.run_root)
        reduced = subscription_receipts.reduce_accounting(checkpoint['run'],state,binding=public,require_private=False)
        self.assertTrue(reduced['dispatch_accounting_complete'])
        fvs_adapter.validate_evidence(state['fvs_evidence'],binding=public,exchanges=state['model_exchanges'])
        reviews = [stage for stage in state['fvs_evidence'].values()
                   if stage.get('role') in ('spec_reviewer','proof_reviewer')]
        self.assertEqual(len(reviews),4)
        self.assertTrue(all(stage['read_only_tools'] for stage in reviews))
        self.assertTrue(all(row['status'] == 'completed' for row in state['role_tool_outcomes'].values()))
        record = json.loads(private.read_text())['records'][4]
        before = self.requests.read_bytes()
        # Completed journal replay authenticates the exact native continuation and
        # uses the production dispatcher without initializing another SDK process.
        checkpoint['run']['lock'] = contracts.load_toolchain_lock()
        pi_backend.configure(checkpoint['run'],self.config,self.record_path,tool_schemas=list(agent_lane._TOOL_SCHEMAS))
        self.stack.callback(provider_service.release,checkpoint['run'])
        binding = provider_config.provider_binding(checkpoint['run'])
        messages = self.payloads[4]['messages']
        replay = subscription_journal.dispatch(checkpoint['run'],binding,record['request'],messages,
            mock.Mock(side_effect=AssertionError('completed exchange must not generate')))
        self.assertEqual(replay,(record['response'],record['receipt']))
        self.assertEqual(self.requests.read_bytes(),before)
        req = record['request']
        replay = model._model_request(self.capture_state, request_id=req['request_id'],role=req['role'],
            input_hashes=req['input_hashes'],messages=messages,conversation_id=req['conversation_id'])
        self.assertEqual(replay,(record['response'],record['receipt']))
        provider_service.release(checkpoint['run'])
        prior_count = len(self.processes)
        resumed = self._cli('--resume-from',str(self.run_root))
        self.assertEqual(resumed,result)
        self.assertEqual(len(self.processes),prior_count)
        self.assertEqual(self.requests.read_bytes(),before)
        provider_service.release(checkpoint['run'])
        original = private.read_bytes()
        tampered = json.loads(original)
        tampered['records'][4]['continuation']['native']['tool_call_id'] = 'tampered'
        write_json(private,tampered)
        with self.assertRaises((contracts.ContractError,provider_config.ProviderConfigError)):
            model._model_request(self.capture_state,request_id=req['request_id'],role=req['role'],
                input_hashes=req['input_hashes'],messages=messages,conversation_id=req['conversation_id'])
        private.write_bytes(original)
        self.assertEqual(self.requests.read_bytes(),before)

    def test_missing_terminal_usage_quarantines_dispatch_without_retry(self):
        write_json(self.fixture_path,{'requests':str(self.requests),'actions':self.actions,'missing_usage':True})
        result = self._cli(expect_success=False)
        self.assertEqual(result['invocations_used'],1)
        self.assertFalse(result['dispatch_accounting_complete'])
        self.assertFalse(result['monetary_cost_known'])
        self.assertIsNone(result['cost_usd'])
        self.assertEqual(len(self.requests.read_text().splitlines()),1)
        self.assertEqual(len(self.processes),1)
        self.assertTrue(all(process.poll() is not None for process in self.processes))
        records = json.loads((self.run_root/'provider-private/subscription-journal.json').read_text())['records']
        self.assertEqual([row['status'] for row in records],['dispatched'])
        self.assertIsNone(records[0]['receipt'])
        self.assertEqual(result['model_retries'],0)
        self.assertIsNone(result['unresolved_provider_requests'][0]['usage'])


    def test_interrupt_reaps_inflight_node_before_terminal_audit(self):
        write_json(self.fixture_path,{'requests':str(self.requests),'actions':self.actions,'hang':True})
        observations, failures = [], []
        prior_sigint = signal.getsignal(signal.SIGINT)
        finished = threading.Event()
        def interrupt_inflight():
            deadline = time.monotonic() + 15
            while not self.requests.stat().st_size:
                if finished.wait(0.01):
                    return
                if time.monotonic() >= deadline:
                    failures.append('Node did not reach the intercepted provider request')
                    break
            if not failures and (len(self.processes) != 1 or self.processes[0].poll() is not None):
                failures.append('Expected one live Pi child when interrupting')
            os.kill(os.getpid(),signal.SIGINT)
            if not finished.wait(5):
                failures.append('First SIGINT did not stop the CLI within five seconds')
                # Test watchdog only: a second signal prevents a broken controller
                # from stalling the host suite for its full provider timeout.
                os.kill(os.getpid(),signal.SIGINT)
        original_audit = experiment._final_terminal_audit
        def audit_after_stop(state):
            observations.append('terminal_audit')
            self.assertEqual(len(self.processes),1)
            self.assertTrue(all(process.poll() is not None for process in self.processes),
                            'Pi child must be reaped before final verification begins')
            self.assertTrue(state['run']['pi_admission_stopped'])
            self.assertEqual(len(self.requests.read_text().splitlines()),1)
            records = json.loads((self.run_root/'provider-private/subscription-journal.json').read_text())['records']
            self.assertEqual([row['status'] for row in records],['dispatched'])
            return original_audit(state)
        thread = threading.Thread(target=interrupt_inflight,daemon=True)
        thread.start()
        try:
            with mock.patch.object(experiment,'_final_terminal_audit',side_effect=audit_after_stop):
                result = self._cli(expect_success=False)
        finally:
            finished.set()
            thread.join(2)
        self.assertFalse(thread.is_alive())
        self.assertEqual(failures,[])
        self.assertEqual(observations,['terminal_audit'])
        self.assertIs(signal.getsignal(signal.SIGINT),prior_sigint)
        self.assertEqual(result['termination_reason'],'interrupted')
        self.assertEqual(result['invocations_used'],1)
        self.assertEqual(result['model_attempts'],0)
        self.assertEqual(result['model_retries'],0)
        self.assertFalse(result['dispatch_accounting_complete'])
        self.assertIsNone(result['cost_usd'])
        self.assertFalse(self.capture_state.get('role_tool_outcomes'))
        self.assertEqual(len(self.requests.read_text().splitlines()),1)
        self.assertTrue(all(process.poll() is not None for process in self.processes))

    def test_public_cli_requires_actual_qualification_without_test_bootstrap(self):
        with mock.patch.object(pi_backend,'_qualification_artifacts',side_effect=self.production_qualification):
            result = self._cli(expect_success=False)
        self.assertEqual(result['invocations_used'],0)
        self.assertEqual(self.requests.read_bytes(),b'')
        self.assertEqual(self.processes,[])
        self.assertIsNone(result['cost_usd'])
        self.assertFalse(result['scored'])


if __name__ == '__main__':
    unittest.main()
