"""Synthetic Python/Git vertical slice; no Lean, containers or provider traffic."""

import asyncio
import base64
import copy
import difflib
import hashlib
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from autofv import agent_lane, axiom_audit, contract_feasibility, contracts, diamond
from autofv import experiment, generic_role_runtime, results, run_state, verifier, verifier_bundle, worker
from autofv import worker_runtime
from tests.test_phase1_diamond import _SignedRoleProvider, _role_test_lock
from tests.test_restart_budget import _checkpoint_state


LEAF, ROOT, SPEC = 'probe:Arithmetic.increment', 'probe:Pipeline.finish', 'probe:Pipeline.finish_spec'
SOURCES = {
    'Arithmetic/Increment.lean': 'namespace Arithmetic\ndef increment (n : Nat) : Nat := n + 1\nend Arithmetic\n',
    'Pipeline/Finish.lean': 'import Arithmetic.Increment\nnamespace Pipeline\ndef finish (n : Nat) : Nat := Arithmetic.increment n\ntheorem finish_spec (n : Nat) : finish n = n + 1 := by sorry\nend Pipeline\n',
}


def sha(value):
    return hashlib.sha256(contracts.canonical_json_bytes(value)).hexdigest()


def patch(path, old, new):
    return f'diff --git a/{path} b/{path}\n' + ''.join(difflib.unified_diff(
        old.splitlines(keepends=True), new.splitlines(keepends=True),
        fromfile=f'a/{path}', tofile=f'b/{path}'))


class GenericRoleE2ETests(unittest.TestCase):
    def setUp(self):
        real_run = subprocess.run
        def git_only(argv, *args, **kwargs):
            if not argv or argv[0] != 'git':
                raise AssertionError(f'non-Git subprocess forbidden in simulation: {argv[0]}')
            result = real_run(argv, *args, **kwargs)
            callback = getattr(self, '_after_git', None)
            if callback is not None:
                callback(argv)
            return result
        patcher = mock.patch.object(subprocess, 'run', side_effect=git_only)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_non_diamond_controller_restart_keeps_requests_receipts_and_acceptance_order(self):
        self._run(crash=True)

    def test_non_diamond_success_requires_distinct_terminal_verifier_and_is_unscored(self):
        self._run(crash=False)

    def test_recreated_non_diamond_lane_requires_authenticated_snapshot(self):
        for attack in ('missing', 'tampered'):
            with self.subTest(attack=attack):
                self._run(crash=True, snapshot_attack=attack)

    def test_initial_lanes_resume_after_prepare_checkpoint(self):
        self._run(crash=False, initialization_crash='after_prepare')

    def test_initial_lanes_resume_between_individual_worktree_creations(self):
        self._run(crash=False, initialization_crash='first_lane')

    def test_initial_snapshot_before_checkpoint_is_reconciled_without_rewrite(self):
        self._run(crash=False, initialization_crash='first_snapshot')

    def test_second_replay_interruption_preserves_frozen_dependency_baseline(self):
        for point in ('specifier', 'feasibility'):
            with self.subTest(point=point):
                self._run(crash=True, replay_crash=point)

    def _run(self, *, crash, snapshot_attack=None, initialization_crash=None, replay_crash=None):
        key = Ed25519PrivateKey.from_private_bytes(bytes(range(1, 33)))
        lock = _role_test_lock(key)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            project = root / 'project'
            project.mkdir()
            for path, text in SOURCES.items():
                destination = project / path
                destination.parent.mkdir(exist_ok=True)
                destination.write_text(text)
            def git(*args):
                return subprocess.run(('git', *args), cwd=project, capture_output=True, check=True).stdout
            git('init', '-q')
            git('add', '--all')
            git('-c', 'user.name=AutoFV', '-c', 'user.email=autofv@invalid', 'commit', '-qm', 'synthetic generic base')
            commit = git('rev-parse', 'HEAD').decode().strip()
            state = _checkpoint_state(root)
            state['run'].update(project_dir=str(project), base_commit=commit, lock=lock)
            state['accepted'] = state['working'] = {'accepted_commit': commit, 'accepted_tree_sha256': hashlib.sha256(git('archive', 'HEAD')).hexdigest()}
            state['run']['accepted'] = state['accepted']
            graph = {'frozen_targets': [ROOT], 'selected_nodes': [LEAF, ROOT],
                     'term_dependencies': [[ROOT, LEAF]], 'type_dependencies': [],
                     'source_paths': {LEAF: 'Arithmetic/Increment.lean', ROOT: 'Pipeline/Finish.lean', SPEC: 'Pipeline/Finish.lean'},
                     'supplied_specs': {ROOT: SPEC}}
            graph['graph_sha256'] = sha(graph)
            graph.update(probe_rust_sha256='1' * 64, probe_aeneas_sha256='2' * 64)
            state.update(graph=graph, checkpoint_enabled=True)
            patched = {
                'Arithmetic/Increment.lean': SOURCES['Arithmetic/Increment.lean'].replace('end Arithmetic', 'theorem increment_spec (n : Nat) : increment n = n + 1 := by rfl\nend Arithmetic'),
                'Pipeline/Finish.lean': SOURCES['Pipeline/Finish.lean'].replace('by sorry', 'by simpa [finish] using Arithmetic.increment_spec n'),
            }
            patches = {path: patch(path, SOURCES[path], value) for path, value in patched.items()}
            job_by_request = {}
            original_role = agent_lane.run_role_conversation
            async def role(current, job, tools):
                identity = agent_lane.role_conversation_spec(job)['conversation_id']
                job_by_request[identity[:16]] = job
                return await original_role(current, job, tools)
            provider = _SignedRoleProvider(key)
            calls = []
            def respond(request):
                job = job_by_request[request['request_id'].split('-')[1]]
                path = job['assigned_path']
                turn = int(request['request_id'].rsplit('-', 1)[1])
                if job['role'] == 'prover' and job['declaration'] == LEAF and turn == 1:
                    action = {'name': 'edit_assigned', 'arguments': {'patch': patches[path]}}
                else:
                    evidence = []
                    if job['role'] in {'specifier', 'spec_reviewer'}:
                        repair = job['role_context'].get('diagnostic', {}).get('status') == 'failed'
                        proposition = 'Arithmetic.increment n = n + 1' if repair else 'n ≤ Arithmetic.increment n'
                        evidence = ['statement:theorem Arithmetic.increment_spec (n : Nat) : ' + proposition]
                    action = {'name': 'submit_candidate', 'arguments': {
                        'patch': patches[path], 'claimed_status': 'candidate', 'evidence': evidence}}
                response, receipt = provider(request)
                response.update(base_commit=commit, payload={'schema': 'autofv-lane-tool-call/v1', **action})
                response['payload_sha256'] = sha(response['payload'])
                receipt['response_sha256'] = sha(response)
                unsigned = {k: v for k, v in receipt.items() if k != 'receipt_sha256'}
                unsigned['auth'] = {k: v for k, v in receipt['auth'].items() if k != 'signature'}
                raw = contracts.canonical_json_bytes(unsigned)
                receipt['auth']['signature'] = base64.b64encode(key.sign(raw)).decode()
                receipt['receipt_sha256'] = hashlib.sha256(raw).hexdigest()
                calls.append(copy.deepcopy(request))
                return response, receipt
            state['run_round'] = respond
            feasibility_sources = []
            def compiler_boundary(*argv, input_bytes=None, **_kwargs):
                if not any('lake env lean' in arg for arg in argv):
                    return subprocess.CompletedProcess(argv, 0, b'a' * 64 + b'\n', b'')
                source = input_bytes.decode()
                feasibility_sources.append(source)
                self.assertIn('example', source)
                self.assertNotIn('sorry', source)
                self.assertIn('= n + 1', source)
                # No Lean is executed: this injected compiler response exercises
                # the real lowering/diagnostic/review-repair controller path.
                weak = 'n ≤ _autofv_dep_0 n' in source
                diagnostic = b'synthetic unsolved consumer equality' if weak else b'synthetic consumer check passed'
                return subprocess.CompletedProcess(argv, 0, diagnostic + b'\nAUTOFV_FEASIBILITY_EXIT=' + (b'1' if weak else b'0'), b'')
            original_checkpoint = run_state._checkpoint_if_enabled
            interrupted = False
            replaying = replay_interrupted = False
            def after_git(argv):
                nonlocal interrupted
                if initialization_crash == 'first_lane' and not interrupted and tuple(argv[:3]) == ('git', 'worktree', 'add'):
                    interrupted = True
                    raise KeyboardInterrupt('after one initial worktree')
            self._after_git = after_git
            original_save = worker.save_lane_snapshot
            def save_snapshot(*args, **kwargs):
                nonlocal interrupted
                receipt = original_save(*args, **kwargs)
                if initialization_crash == 'first_snapshot' and not interrupted and kwargs.get('initial'):
                    interrupted = True
                    raise KeyboardInterrupt('initial snapshot durable before checkpoint')
                return receipt
            def checkpoint(current, transition):
                nonlocal interrupted, replay_interrupted
                original_checkpoint(current, transition)
                if crash and not interrupted and transition == 'candidate:proof-increment-001:accepted':
                    interrupted = True
                    raise KeyboardInterrupt('after accepted dependency checkpoint')
                if initialization_crash == 'after_prepare' and not interrupted and transition == 'lanes:prepare-role-lanes:after':
                    interrupted = True
                    raise KeyboardInterrupt('after initial lane creation checkpoint')
                if replaying and not replay_interrupted:
                    is_specifier = transition.startswith('role:') and transition.endswith(':completed') and current.get('role_progress', {}).get(transition.split(':')[1], {}).get('role') == 'specifier'
                    if (replay_crash == 'specifier' and is_specifier) or (replay_crash == 'feasibility' and transition == 'build:generic-provisional-consumer:after'):
                        replay_interrupted = True
                        raise KeyboardInterrupt('second interruption during contract replay')
            with mock.patch.object(contracts, 'load_toolchain_lock', return_value=lock), mock.patch.object(agent_lane, 'run_role_conversation', side_effect=role), mock.patch.object(worker_runtime, '_git', side_effect=lambda _run, *args: git(*args)), mock.patch.object(worker_runtime, '_docker', side_effect=compiler_boundary), mock.patch.object(diamond, '_checkpoint_if_enabled', side_effect=checkpoint), mock.patch.object(run_state, '_checkpoint_if_enabled', side_effect=checkpoint), mock.patch.object(agent_lane, '_checkpoint_if_enabled', side_effect=checkpoint), mock.patch.object(worker, 'save_lane_snapshot', side_effect=save_snapshot):
                if crash or initialization_crash:
                    with self.assertRaises(KeyboardInterrupt):
                        diamond._agent_loop(state)
                    saved = run_state._load_checkpoint(root, {})
                    state = dict(saved['state'], run=state['run'], config=state['config'], manifest=state['manifest'], run_round=respond,
                                 cost=state['cost'], checkpoint_enabled=True, checkpoint_sequence=saved['checkpoint_sequence'])
                    # Replace both canonical repository and every private lane;
                    # only host checkpoint/journal/snapshot artifacts survive.
                    if crash:
                        bundle = root / 'accepted.bundle'
                        git('bundle', 'create', str(bundle), 'HEAD')
                        project.rename(root / 'lost-project')
                        (root / 'lanes').rename(root / 'lost-lanes')
                        subprocess.run(('git', 'clone', '-q', str(bundle), str(project)), check=True, capture_output=True)
                        self.assertFalse((root / 'lanes').exists())
                        state['run']['agent_worker_id'] = 'simulated-recreated-worker'
                    run_state._recover_checkpoint_state(state, state['run'], state['manifest'])
                    if snapshot_attack:
                        snapshot = root / 'lane-snapshots' / 'proof-increment-001.json'
                        self.assertTrue(snapshot.is_file())
                        if snapshot_attack == 'missing':
                            snapshot.rename(snapshot.with_suffix('.missing'))
                        else:
                            snapshot.write_bytes(snapshot.read_bytes() + b'tampered')
                        before_calls = len(calls)
                        with self.assertRaisesRegex(worker.WorkerError, 'snapshot'):
                            diamond._agent_loop(state)
                        self.assertEqual(len(calls), before_calls)
                        return
                    if replay_crash:
                        accepted_before = copy.deepcopy(state['accepted'])
                        proof_before = state['proof_patch_sha256'][LEAF]
                        calls_before = len(calls)
                        replaying = True
                        with self.assertRaises(KeyboardInterrupt):
                            diamond._agent_loop(state)
                        saved = run_state._load_checkpoint(root, {})
                        state = dict(saved['state'], run=state['run'], config=state['config'], manifest=state['manifest'], run_round=respond,
                                     cost=state['cost'], checkpoint_enabled=True, checkpoint_sequence=saved['checkpoint_sequence'])
                        run_state._recover_checkpoint_state(state, state['run'], state['manifest'])
                        self.assertEqual(state['accepted'], accepted_before)
                        self.assertEqual(state['proof_patch_sha256'][LEAF], proof_before)
                        self.assertEqual(len(calls), calls_before)
                state.update(diamond._agent_loop(state))
            if replay_crash:
                self.assertEqual(state['proof_patch_sha256'][LEAF], proof_before)
                self.assertEqual(state['target_states'][LEAF]['accepted_commit'], accepted_before['accepted_commit'])
                self.assertIsNone(state['frozen_contract_baseline'])
            self.assertEqual(set(state['accepted_nodes']), {LEAF, ROOT})
            self.assertEqual(state['target_states'][LEAF]['status'], 'accepted')
            self.assertEqual(len(state['release_events']), 2)
            self.assertEqual(state['lane_initialization']['phase'], 'ready')
            self.assertEqual(state['lane_snapshots'][LEAF]['sequence'], 2)
            self.assertEqual(state['lane_snapshots'][ROOT]['sequence'], 1)
            self.assertEqual(len(calls), 11)
            self.assertEqual(len(state['receipts']), 11)
            self.assertEqual(len({call['request_id'] for call in calls}), 11)
            self.assertEqual(len([job for job in job_by_request.values() if job['role'] == 'spec_reviewer']), 2)
            self.assertEqual(len(state['contracts']['revision_lineage']), 1)
            self.assertEqual(
                [job_by_request[call['request_id'].split('-')[1]]['role'] for call in calls],
                ['scout', 'dependency_planner', 'specifier', 'spec_reviewer',
                 'spec_reviewer', 'prover', 'prover', 'proof_reviewer',
                 'prover', 'proof_reviewer', 'verification_adviser'],
            )
            self.assertNotIn('Diamond', repr(graph) + ''.join(feasibility_sources))
            self.assertNotIn('sorry', ''.join(feasibility_sources))
            self.assertNotIn('verifier_report', state)
            for path, expected in patched.items():
                self.assertEqual((project / path).read_text(), expected)
            events = state['run']['events']
            for call in calls:
                reserve = f"model:{call['request_id']}:reserved:explicit"
                receipt = f"proxy:{call['request_id']}"
                self.assertEqual(events.count(reserve), 1)
                self.assertEqual(events.count(receipt), 1)
                self.assertLess(events.index(reserve), events.index(receipt))
            self.assertLess(events.index('candidate_accepted:proof-increment-001'), events.index('candidate_accepted_reverified:proof-finish-001'))
            expected_events, started = [], set()
            for call in calls:
                identity = call['request_id'].split('-')[1]
                job = job_by_request[identity]
                role_name = job['role']
                if identity not in started:
                    expected_events.append(f'role:{role_name}:started')
                    started.add(identity)
                expected_events.extend((f"model:{call['request_id']}:reserved:explicit", f"proxy:{call['request_id']}"))
                edit_turn = role_name == 'prover' and job['declaration'] == LEAF and call['request_id'].endswith('001')
                expected_events.append(f"lane_tool:{role_name}:" + ('edit_assigned' if edit_turn else 'submit_candidate'))
                if not edit_turn:
                    expected_events.append(f'role:{role_name}:candidate')
                if role_name == 'spec_reviewer' and job['role_context']['diagnostic']['status'] == 'failed':
                    expected_events.extend((f'contract_revised:{LEAF}', 'statements_frozen'))
                if role_name == 'proof_reviewer':
                    expected_events.append('candidate_accepted:proof-increment-001' if job['declaration'] == LEAF else 'candidate_accepted_reverified:proof-finish-001')
            observed_events = [event for event in events if event.startswith(('role:', 'model:', 'proxy:', 'lane_tool:', 'candidate_', 'contract_revised:', 'statements_frozen'))]
            self.assertEqual(observed_events, expected_events)
            reference = b'{"leaves":[]}'
            def terminal(run, expected):
                inventory = axiom_audit.expected_inventory(run['verification_state'], {'leaves': []})
                body = {'schema': 'autofv-verifier-report/v1', 'run_id': run['run_id'],
                        'agent_worker_id': run['agent_worker_id'], 'verifier_worker_id': 'synthetic-distinct-verifier',
                        'bundle_sha256': '3' * 64, **expected,
                        'checks': {name: True for name in verifier_bundle.REPORT_CHECKS},
                        'failures': [], 'native_decide_uses': [], 'accepted_native_decide_uses': [],
                        'hidden_native_decide_uses': [], 'compiler_assumptions': verifier.compiler_assumptions(lock),
                        'axiom_inventory': inventory, 'axiom_inventory_sha256': axiom_audit.inventory_identity_sha256(inventory),
                        'meaning': {'reference_integrity': True, 'statement_equivalence': True,
                                    'non_vacuity': True, 'broken_implementation_rejected': True},
                        'sorry_count_before': 1, 'sorry_count_after': 0, 'evidence_level': 'L4', 'verdict': 'PASS'}
                report = {**body, 'report_sha256': sha(body)}
                forged = {**body, 'verifier_worker_id': run['agent_worker_id']}
                forged['report_sha256'] = sha(forged)
                with self.assertRaises(verifier.VerifierError):
                    verifier.validate_report(forged, run, expected)
                return report
            effect = verifier.VerifierInfrastructureError('synthetic verifier unavailable') if crash else terminal
            with mock.patch.object(verifier, '_trusted_reference', return_value=reference), mock.patch.object(verifier, 'verify_run', side_effect=effect), mock.patch.object(contracts, 'load_toolchain_lock', return_value=lock):
                if crash:
                    with self.assertRaises(verifier.VerifierInfrastructureError):
                        experiment._clean_verify(state)
                    self.assertNotIn('clean_verifier:PASS', events)
                    outcome, reason = 'infrastructure_failed', 'clean_verifier_infrastructure_failed'
                else:
                    state.update(experiment._clean_verify(state))
                    self.assertEqual(events[-1], 'clean_verifier:PASS')
                    outcome, reason = 'success', 'all_targets_verified'
                result, _ = results.render_attempt(state['run'], state, outcome=outcome, reason=reason)
            self.assertFalse(result['scored'])
            self.assertEqual(result['execution_tier'], 'simulation')
            self.assertEqual(result['outcome'], outcome)
