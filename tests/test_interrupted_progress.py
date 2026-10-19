"""Offline regression for the real serial graph's interrupted-agent boundary."""
import asyncio
import copy
import json
import tempfile
import unittest
from decimal import Decimal
from contextlib import ExitStack
from pathlib import Path

from langgraph.errors import NodeCancelledError
from unittest import mock

from autofv import experiment, terminal_run, generic_role_runtime, terminal_verifier, results, worker, verifier
from autofv import result_summary
from autofv.contracts import BudgetExhausted, ContractInconclusive


class InterruptedProgressTests(unittest.TestCase):
    def drive(self, initial, error):
        state = copy.deepcopy(initial)
        latest = {
            'target_states': {'helper': {'status': 'pending'}},
            'contracts': {'frozen': {'helper_spec': {'status': 'frozen'}}},
            'fvs_evidence': {'prover': {'claimed_status': 'blocked'}},
            'accepted_nodes': [], 'role_progress': {'prover': {'turn': 2}},
            'partial_verifier_inflight': {'node': 'helper'},
        }
        def agent(local):
            local.update(copy.deepcopy(latest))
            local.pop('inflight_transition', None)
            if error is not None:
                # Interrupted agent output is not terminal acceptance authority.
                local.update(result={'accepted_pairs': 99}, l0_receipt={'status': 'PASS'},
                             verifier_report={'terminal_status': 'success'})
                raise error
            return latest
        with mock.patch.object(experiment, '_freeze', return_value={'graph': {}}), \
             mock.patch.object(experiment, '_agent_loop', side_effect=agent) as called, \
             mock.patch.object(experiment, '_clean_verify', return_value={'accepted_nodes': []}) as verify:
            graph = experiment._build_graph()
            with mock.patch.object(experiment, '_EXPERIMENT_GRAPH', graph):
                if error is None:
                    experiment._run_graph(state)
                    verify.assert_called_once()
                else:
                    cancelled = isinstance(error, asyncio.CancelledError)
                    with self.assertRaises(NodeCancelledError if cancelled else type(error)) as caught:
                        experiment._run_graph(state)
                    if cancelled:
                        self.assertEqual(caught.exception.node, 'agent')
                        self.assertIs(caught.exception.__cause__, error)
                    else:
                        self.assertIs(caught.exception, error)
                    verify.assert_not_called()
            called.assert_called_once()
        for key, value in latest.items():
            self.assertEqual(state.get(key), value, key)
        self.assertNotIn('inflight_transition', state)
        self.assertNotIn('result', state)
        self.assertNotIn('l0_receipt', state)
        self.assertNotIn('verifier_report', state)
        self.assertFalse(state['accepted_nodes'])
        return state

    def test_absent_and_replaced_channels_survive_all_exit_kinds(self):
        for initial in ({}, {'contracts': {'stale': True}, 'target_states': {'stale': {}},
                            'fvs_evidence': {'stale': {}}, 'inflight_transition': {'old': True}}):
            for error in (ContractInconclusive('FVS role blocked: prover'), RuntimeError('broken'),
                          BudgetExhausted('cost_usd', Decimal('1'), Decimal('2')),
                          KeyboardInterrupt(), asyncio.CancelledError()):
                with self.subTest(initial=initial, error=type(error).__name__):
                    self.drive(initial, error)

    def test_cancellation_reaches_controller_finalization_and_cleanup(self):
        graph = {'selected_nodes': ['probe:Example.helper'], 'frozen_targets': ['probe:Example.helper'],
                 'term_dependencies': [], 'type_dependencies': [],
                 'source_paths': {'probe:Example.helper': 'Example.lean'}, 'supplied_specs': {}}
        run = {'run_id': 'cancel-regression', 'execution_tier': 'simulation', 'base_commit': 'a'*40,
               'accepted': {'accepted_commit': 'a'*40}, 'events': [],
               'evidence_dir': 'unused-synthetic-evidence'}
        config = {'schema': 'autofv-run/v1', 'max_wall_seconds': 600, 'max_cost_usd': Decimal('1')}
        progress, final = {}, {}
        error = asyncio.CancelledError('cancelled in role')

        def role_body(state):
            self.assertEqual(state['target_states']['probe:Example.helper']['status'], 'pending')
            state['contracts'] = {'frozen': {'Example.helper_spec': {'status': 'frozen'}}}
            state['fvs_evidence'] = {'synthetic:cancel': {'claimed_status': 'blocked'}}
            state['accepted_nodes'] = []
            # Activate real audit and cleanup branches only after synthetic preparation.
            state['run'].update(preparation_manifest={'synthetic': True},
                                execution_tier='sealed_runsc', provider_binding={'synthetic': True})
            progress.update(copy.deepcopy({k: state[k] for k in
                                          ('target_states', 'contracts', 'fvs_evidence')}))
            state.update(result={'accepted_pairs': 99}, l0_receipt={'status': 'PASS'},
                         verifier_report={'terminal_status': 'success'})
            raise error

        def terminal_validation(state):
            terminal_verifier._target_states({'graph': state['graph'],
                                             'target_states': state.get('target_states', {})})
            self.assertNotIn('result', state)
            self.assertNotIn('l0_receipt', state)
            self.assertNotIn('verifier_report', state)
            return {}

        def render(_run, state, *, outcome, reason):
            final.update(copy.deepcopy(state))
            return {'outcome': outcome, 'termination_reason': reason, 'accepted_pairs': 0}, {}

        with ExitStack() as stack:
            def patch(obj, name, **kw):
                return stack.enter_context(mock.patch.object(obj, name, **kw))
            patch(results, 'validate_output_root')
            patch(experiment, '_absolute_path', side_effect=lambda p, *a, **k: Path(p))
            patch(results, 'new_attempt_identity', return_value={'attempt_id': 'synthetic', 'attempt_ledger': 'unused'})
            patch(experiment, 'validate_target', return_value=(Path.cwd(), {}))
            patch(experiment, 'validate_run_config', return_value=(Path('unused'), config))
            patch(experiment, 'load_toolchain_lock', return_value={'native_decide_policy_sha256': '0'*64})
            patch(experiment, 'validate_native_decide_policy', return_value={'selection': {}})
            patch(worker, 'prepare_run', return_value=run)
            patch(verifier, 'compiler_assumptions', return_value=[])
            patch(experiment, '_freeze', side_effect=lambda s: {'graph': copy.deepcopy(graph)})
            role = patch(generic_role_runtime, 'run_generic_role_path', side_effect=role_body)
            verify = patch(experiment, '_clean_verify', side_effect=terminal_validation)
            patch(experiment, '_EXPERIMENT_GRAPH', new=experiment._build_graph())
            patch(experiment, '_checkpoint_if_enabled')
            patch(experiment, '_charge_wall')
            for name in ('persist_verifier_report', 'persist_partial_reports', 'persist_l0_sources',
                         'reconcile_provider_finalization', '_atomic_write_once'):
                patch(results, name)
            persist = patch(results, 'persist_attempt')
            patch(results, 'render_attempt', side_effect=render)
            dispose = patch(worker, 'dispose_run')
            materialize = patch(results, 'materialize_accepted')
            release = patch(experiment.provider_service, 'release')
            audit = patch(experiment, '_final_terminal_audit', wraps=experiment._final_terminal_audit)
            finish = patch(experiment, '_finish_attempt', wraps=experiment._finish_attempt)
            try:
                result = experiment.run_experiment(Path.cwd(), Path('unused'))
            except asyncio.CancelledError:
                self.fail('raw cancellation bypassed controller classification/finalization')
            role.assert_called_once()
            audit.assert_called_once()
            verify.assert_called_once()  # terminal audit, never downstream graph verification
            finish.assert_called_once()
            dispose.assert_called_once_with(run, interrupted=False)
            materialize.assert_called_once_with(run)
            release.assert_called_once_with(run)
            persist.assert_called_once_with(run, result, {})
        self.assertEqual(result, {'outcome': 'infrastructure_failed',
                                 'termination_reason': 'controller_failed', 'accepted_pairs': 0})
        self.assertEqual(final['termination_detail'], "Node 'agent' raised asyncio.CancelledError")
        for key, value in progress.items():
            self.assertEqual(final.get(key), value, key)
        self.assertEqual(final['accepted_nodes'], [])

    def test_normal_completion_still_runs_verifier(self):
        self.drive({}, None)

    def test_successful_node_preserves_partial_reports_for_verifier_and_export(self):
        # Synthetic transport evidence, not a substitute for report validation.
        report = {field: 'synthetic-' + field for field in result_summary.HELPER_FIELDS}
        report.update(verdict='SCOPED_PASS', evidence_level='P1', root_status='unverified')
        reports = {'helper@commit': report}

        def agent(local):
            local['partial_verifier_reports'] = copy.deepcopy(reports)
            return experiment._node_update(local, accepted_nodes=['helper'])

        def verify(local):
            self.assertEqual(local.get('partial_verifier_reports'), reports)
            return {'verifier_report': {'terminal_status': 'unverified'}}

        for initial in ({}, {'partial_verifier_reports': {'stale': {}}}):
            with self.subTest(initial=initial), \
                 mock.patch.object(experiment, '_freeze', return_value={'graph': {}}), \
                 mock.patch.object(experiment, '_agent_loop', side_effect=agent), \
                 mock.patch.object(experiment, '_clean_verify', side_effect=verify):
                state = copy.deepcopy(initial)
                with mock.patch.object(experiment, '_EXPERIMENT_GRAPH', experiment._build_graph()):
                    experiment._run_graph(state)
                self.assertEqual(result_summary.helper_verification(state), [report])
                self.assertEqual(state['verifier_report']['terminal_status'], 'unverified')
                with tempfile.TemporaryDirectory() as root:
                    path = results.persist_partial_reports({'run_root': root}, state)
                    self.assertIsNotNone(path)
                    self.assertEqual(json.loads(path.read_text()), [report])

    def test_secondary_audit_error_keeps_primary_detail(self):
        state = self.drive({}, ContractInconclusive('FVS role blocked: prover'))
        state.update(run={'preparation_manifest': {}}, graph={}, accepted={},
                     termination_detail='FVS role blocked: prover')
        terminal_run.final_terminal_audit(state, verify=mock.Mock(side_effect=RuntimeError('audit failed')))
        self.assertEqual(state['termination_detail'], {
            'prior_detail': 'FVS role blocked: prover', 'terminal_audit_error': 'audit failed'})
        self.assertFalse(state['accepted_nodes'])
