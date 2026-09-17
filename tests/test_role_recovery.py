import asyncio
import copy
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from decimal import Decimal
from pathlib import Path
from unittest import mock

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from autofv import agent_lane, contracts, diamond, model, role_journal, run_state, worker
from tests.test_agent_lane import _job
from tests.test_phase1_diamond import _SignedRoleProvider, _role_test_lock
from tests.test_restart_budget import _checkpoint_state
from tests.test_parallel_lanes import _state, _graph, ENTRIES, LEFT, POLICY


class RoleRecoveryTests(unittest.TestCase):
    def test_completed_journal_reconciles_snapshot_ahead_of_checkpoint(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            state = _checkpoint_state(root)
            old = {'sequence': 1, 'snapshot_sha256': '1' * 64}
            new = {'sequence': 2, 'snapshot_sha256': '2' * 64}
            state['lane_snapshots'] = {LEFT: old}
            def edit():
                state['lane_snapshots'][LEFT] = new
                return 'edited once'
            def checkpoint(_state, transition):
                if transition.endswith(':completed'):
                    raise KeyboardInterrupt('journal durable before checkpoint')
            with mock.patch.object(role_journal, '_checkpoint_if_enabled', side_effect=checkpoint):
                with self.assertRaises(KeyboardInterrupt):
                    role_journal.tool_outcome(state, 'conversation', 'turn-1', {'edit': True}, edit, lane_node=LEFT)
            recovered = _checkpoint_state(root)
            recovered['lane_snapshots'] = {LEFT: old}
            role_journal.reconcile_lane_snapshots(recovered)
            self.assertEqual(recovered['lane_snapshots'][LEFT], new)
            with mock.patch.object(role_journal, '_checkpoint_if_enabled'):
                replay = role_journal.tool_outcome(recovered, 'conversation', 'turn-1', {'edit': True}, lambda: self.fail('edit replayed'), lane_node=LEFT)
            self.assertEqual(replay, 'edited once')

    def test_tool_outcome_survives_crash_after_durable_completion(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = _checkpoint_state(Path(tmp).resolve())
            effect = mock.Mock(return_value='the original non-idempotent result')
            def crash(_state, transition):
                if transition.endswith(':completed'):
                    raise KeyboardInterrupt('crash after outcome fsync')
            with mock.patch.object(role_journal, '_checkpoint_if_enabled', side_effect=crash):
                with self.assertRaises(KeyboardInterrupt):
                    role_journal.tool_outcome(state, 'conversation', 'turn-1', {'edit': 'patch'}, effect)
            restored = _checkpoint_state(Path(tmp).resolve())
            result = role_journal.tool_outcome(restored, 'conversation', 'turn-1', {'edit': 'patch'}, effect)
            self.assertEqual(result, effect.return_value)
            effect.assert_called_once()

    def test_crash_during_tool_is_ambiguous_and_never_reapplied(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = _checkpoint_state(Path(tmp).resolve())
            effect = mock.Mock(side_effect=KeyboardInterrupt('after mutation'))
            with self.assertRaises(KeyboardInterrupt):
                role_journal.tool_outcome(state, 'conversation', 'turn-1', {'edit': 'patch'}, effect)
            restored = _checkpoint_state(Path(tmp).resolve())
            with self.assertRaisesRegex(contracts.ContractError, 'ambiguous'):
                role_journal.tool_outcome(restored, 'conversation', 'turn-1', {'edit': 'patch'}, effect)
            effect.assert_called_once()

    def test_tampered_tool_result_cannot_reconstruct_a_new_transcript(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = _checkpoint_state(Path(tmp).resolve())
            role_journal.tool_outcome(state, 'conversation', 'turn-1', {'read': 'file'}, lambda: 'original')
            path = next((Path(tmp) / 'role-journal').glob('*.json'))
            path.write_bytes(path.read_bytes().replace(b'original', b'tampered'))
            with self.assertRaisesRegex(contracts.ContractError, 'authentication'):
                role_journal.tool_outcome(_checkpoint_state(Path(tmp).resolve()), 'conversation', 'turn-1', {'read': 'file'}, lambda: 'new')

    def test_recovery_on_both_sides_of_acceptance_checkpoint_releases_dependent(self):
        for crash_side in ('applied', 'accepted'):
            with self.subTest(crash_side=crash_side):
                state = _state()
                lane = diamond._lane_descriptors(state['run'], _graph(), [LEFT])[0]
                state['lanes'] = [lane]
                state['target_states'] = {LEFT: {'status': 'pending'}}
                candidate = diamond._candidate_record(copy.deepcopy(ENTRIES[lane['request_id']]['response']), lane, POLICY)
                accepted = {'accepted_commit': 'b' * 40, 'accepted_tree_sha256': 'c' * 64}
                snapshot = {}
                def checkpoint(current, transition):
                    if transition == f"candidate:{candidate['request_id']}:{crash_side}":
                        snapshot.update(copy.deepcopy({k: v for k, v in current.items() if not k.startswith('_')}))
                        raise KeyboardInterrupt('power loss')
                with mock.patch.object(worker, 'accept_candidate', return_value=accepted), mock.patch.object(diamond, '_checkpoint_if_enabled', side_effect=checkpoint):
                    with self.assertRaises(KeyboardInterrupt):
                        diamond._checkpoint_candidate(state, candidate, {})
                with mock.patch.object(worker, 'inspect_resume_state', return_value={'valid': True, **accepted}), mock.patch.object(worker, 'restore_accepted') as restore, mock.patch.object(run_state, '_write_checkpoint'):
                    run_state._recover_checkpoint_state(snapshot, snapshot['run'], {})
                restore.assert_not_called()
                self.assertEqual(snapshot['proof_patch_sha256'][LEFT], candidate['patch_sha256'])
                self.assertEqual(snapshot['target_states'][LEFT]['status'], 'accepted')
                dependent = 'probe:Pipeline.finish'
                graph = {'selected_nodes': [LEFT, dependent], 'term_dependencies': [[dependent, LEFT]],
                         'source_paths': {LEFT: 'Numbers/Increment.lean', dependent: 'Pipeline/Finish.lean'}}
                jobs = []
                def run(node):
                    jobs.append((node, snapshot['proof_patch_sha256'][LEFT]))
                    return node
                complete = diamond._schedule_proofs(graph, run, lambda *_: True, accepted_nodes=snapshot['accepted_nodes'])
                self.assertEqual(complete, {LEFT, dependent})
                self.assertEqual(jobs, [(dependent, candidate['patch_sha256'])])
                self.assertEqual(len(snapshot['release_events']), 1)

    def test_out_of_order_role_receipts_are_durable_and_exactly_once(self):
        key = Ed25519PrivateKey.from_private_bytes(bytes(range(1, 33)))
        lock = _role_test_lock(key)
        provider = _SignedRoleProvider(key)
        first_started, release_first = threading.Event(), threading.Event()
        with tempfile.TemporaryDirectory() as tmp:
            state = _checkpoint_state(Path(tmp))
            state['checkpoint_enabled'] = True

            def dispatch(request):
                if request['request_id'] == 'slow':
                    first_started.set()
                    self.assertTrue(release_first.wait(5))
                return provider(request)

            state['run_round'] = dispatch
            def call(name):
                return model._model_request(state, request_id=name, role='scout',
                                            input_hashes=['1' * 64], call_kind='explicit')
            with mock.patch.object(contracts, 'load_toolchain_lock', return_value=lock):
                with ThreadPoolExecutor(max_workers=2) as pool:
                    slow = pool.submit(call, 'slow')
                    self.assertTrue(first_started.wait(5))
                    fast = pool.submit(call, 'fast')
                    try:
                        fast.result(5)
                    finally:
                        release_first.set()
                    slow.result(5)
                replay = call('fast')
            self.assertEqual([r['sequence'] for r in state['receipts']], [1, 2])
            self.assertEqual(state['cost'], Decimal('0.000002'))
            self.assertEqual(len(provider.calls), 2)
            checkpoint = run_state._load_checkpoint(Path(tmp), {})
            self.assertEqual(checkpoint['cost_usd_used'], '0.000002')
            self.assertEqual(len(checkpoint['state']['receipts']), 2)
            self.assertEqual(replay[1]['sequence'], 2)

    def test_completed_conversation_does_not_reapply_non_idempotent_edit(self):
        job = _job()
        patch = 'diff --git a/Diamond/Left.lean b/Diamond/Left.lean\n'
        actions = [
            ('edit_assigned', {'patch': patch}),
            ('submit_candidate', {'patch': patch, 'claimed_status': 'candidate', 'evidence': []}),
        ]
        responses = [({'kind': 'tool_call', 'payload': {'name': n, 'arguments': a}}, {})
                     for n, a in actions]
        edit = mock.Mock(side_effect=['edited', AssertionError('edit replayed')])
        tools = agent_lane.build_lane_tools(job, read_file=lambda _: '',
            search_files=lambda _: '', edit_assigned=edit, check_lean=lambda: 'ok')
        state = {}
        with mock.patch.object(model, '_model_request', side_effect=responses * 2):
            first = asyncio.run(agent_lane.run_role_conversation(state, job, tools))
            second = asyncio.run(agent_lane.run_role_conversation(state, job, tools))
        self.assertEqual(first, second)
        self.assertEqual(edit.call_count, 1)

    def test_acceptance_checkpoint_contains_all_dependency_release_state(self):
        state = _state()
        lane = diamond._lane_descriptors(state['run'], _graph(), [LEFT])[0]
        state['lanes'] = [lane]
        state['target_states'] = {LEFT: {'status': 'pending'}}
        state['file_owners'] = {lane['assigned_path']: LEFT}
        candidate = diamond._candidate_record(copy.deepcopy(ENTRIES[lane['request_id']]['response']), lane, POLICY)
        snapshots = []
        def checkpoint(current, transition):
            if transition.endswith(':accepted'):
                snapshots.append(copy.deepcopy({k: v for k, v in current.items() if not k.startswith('_')}))
        accepted = {'accepted_commit': 'b' * 40, 'accepted_tree_sha256': 'c' * 64}
        with mock.patch.object(worker, 'accept_candidate', return_value=accepted), mock.patch.object(diamond, '_checkpoint_if_enabled', side_effect=checkpoint):
            diamond._checkpoint_candidate(state, candidate, {})
        persisted = snapshots[-1]
        self.assertEqual(persisted['proof_patch_sha256'][LEFT], candidate['patch_sha256'])
        self.assertEqual(persisted['target_states'][LEFT]['accepted_commit'], accepted['accepted_commit'])
        self.assertEqual(persisted['target_states'][LEFT]['status'], 'accepted')
        self.assertEqual(persisted['release_events'][0]['node'], LEFT)
        self.assertEqual(persisted['file_owners'], {})


if __name__ == '__main__':
    unittest.main()
