"""Original Pi grants bound controller/Lean work, not only model admission.

No SDK, credentials, network, worker provisioning, or provider calls are used.
"""
from __future__ import annotations

from contextlib import ExitStack
from decimal import Decimal
import io
import json
from pathlib import Path
import sys
import unittest
from unittest import mock

from autofv import contracts, experiment, pi_backend, run_state, runtime_profile, worker_runtime
from tests.test_runtime_profile import config as pi_config


class PiOriginalDeadlineTests(unittest.TestCase):
    ORIGIN_MS = 1_000_000_000
    MONOTONIC_ORIGIN = 10_000

    def state(self, *, used=20, execution_mode='proof_only'):
        config = pi_config()
        config['max_wall_seconds'] = 120
        grant = {'original_started_epoch_ms':self.ORIGIN_MS,
                 'original_deadline_epoch_ms':self.ORIGIN_MS + 60_000}
        return {'config':config,'cost':None,
            'run':{'provider_binding':{'schema':runtime_profile.PI_BINDING_SCHEMA,'grant':grant},
                   'execution_mode':execution_mode,'preparation_manifest':{'schema':'preparation-manifest/v1'},
                   'budget_started_epoch_ns':self.ORIGIN_MS * 1_000_000},
            'wall_seconds_used':Decimal(used),'finalization_reserve_seconds':Decimal(5),
            'wall_started_monotonic_ns':(self.MONOTONIC_ORIGIN+used)*1_000_000_000,
            'wall_started_epoch_ns':self.ORIGIN_MS*1_000_000+used*1_000_000_000}

    def clock(self, used):
        stack = ExitStack()
        epoch = self.ORIGIN_MS/1000+used
        stack.enter_context(mock.patch('time.time',return_value=epoch))
        stack.enter_context(mock.patch('time.time_ns',return_value=int(epoch*1_000_000_000)))
        stack.enter_context(mock.patch('time.monotonic',return_value=self.MONOTONIC_ORIGIN+used))
        stack.enter_context(mock.patch('time.monotonic_ns',return_value=(self.MONOTONIC_ORIGIN+used)*1_000_000_000))
        return stack

    def test_sixty_second_original_grant_rejects_work_after_sixty_one_seconds(self):
        state = self.state(used=61)
        with self.clock(61),self.assertRaises(contracts.BudgetExhausted) as caught:
            run_state._check_budget(state)
        self.assertEqual(caught.exception.kind,'wall_seconds')
        self.assertLessEqual(Decimal(caught.exception.detail['limit']),Decimal(60))
        self.assertEqual(caught.exception.detail['used'],'61.000000')

    def test_helper_work_and_cleanup_keep_shorter_grant_in_full_and_proof_only_modes(self):
        for mode in ('full','proof_only'):
            with self.subTest(mode=mode),self.clock(20):
                state = self.state(execution_mode=mode)
                with run_state.helper_work_budget(state,10):
                    self.assertEqual(worker_runtime.work_timeout(120),30)
                    self.assertEqual(worker_runtime._WORK_DEADLINE.get()[2],Decimal(50))
                    with worker_runtime.cleanup_deadline():
                        self.assertEqual(worker_runtime.work_timeout(120),40)
                        self.assertEqual(worker_runtime._WORK_DEADLINE.get()[2],Decimal(60))
                self.assertIsNone(worker_runtime._WORK_DEADLINE.get())
                self.assertIsNone(worker_runtime._CLEANUP_DEADLINE.get())

    def test_finalization_reserve_cannot_extend_the_original_grant(self):
        with self.clock(20):
            state = self.state(execution_mode='full')
            with run_state.helper_work_budget(state,0):
                self.assertEqual(worker_runtime.work_timeout(120),35)
                with worker_runtime.cleanup_deadline():
                    self.assertEqual(worker_runtime.work_timeout(120),40)
            with run_state.helper_work_budget(state,0,finalizing=True):
                self.assertEqual(worker_runtime.work_timeout(120),40)
            # An already tighter enclosing operation also remains authoritative.
            with worker_runtime.work_deadline(25,wall_limit=Decimal(45),cleanup_reserve_seconds=5):
                with run_state.helper_work_budget(state,10):
                    self.assertEqual(worker_runtime.work_timeout(120),25)
                    with worker_runtime.cleanup_deadline():
                        self.assertEqual(worker_runtime.work_timeout(120),30)


    def test_external_callback_uses_shorter_grant_and_expired_work_never_starts(self):
        state = self.state(execution_mode='full')
        state['checkpoint_enabled'] = False
        def callback():
            self.assertEqual(worker_runtime.work_timeout(120),35)
            with worker_runtime.cleanup_deadline():
                self.assertEqual(worker_runtime.work_timeout(120),40)
            return 'synthetic callback completed'
        with self.clock(20):
            self.assertEqual(run_state._external_call(state,'synthetic-read',callback),
                             'synthetic callback completed')
        forbidden = mock.Mock(side_effect=AssertionError('expired callback must not run'))
        with self.clock(61),self.assertRaises(contracts.BudgetExhausted):
            run_state._external_call(self.state(used=61),'expired-read',forbidden)
        forbidden.assert_not_called()

    def test_expired_nonterminal_restore_stops_before_worker_recovery(self):
        state = self.state(used=61)
        checkpoint = {'run':state['run'],'state':{k:v for k,v in state.items() if k != 'run'},
                      'checkpoint_sequence':1,'identities':{}}
        with self.clock(61),              mock.patch.object(run_state,'_validate_provider_recovery',return_value=False),              mock.patch.object(run_state,'_recover_checkpoint_state') as recover,              self.assertRaises(contracts.BudgetExhausted):
            run_state._restore_checkpoint(checkpoint,manifest={},config=state['config'],lock={},run_round=mock.Mock())
        recover.assert_not_called()


    def test_default_full_mode_does_not_import_proof_only_stage_reserves(self):
        state = self.state(execution_mode='full')
        for stage in ('first_specification','distinct_verification','terminal_audit'):
            self.assertEqual(run_state.helper_reserve(state,stage),0)
        self.assertEqual(run_state.helper_reserve(state,'finalization'),5)
        state['run']['execution_mode'] = 'proof_only'
        self.assertEqual(run_state.helper_reserve(state,'first_specification'),2100)
        state['run']['execution_mode'] = 'full'
        explicit = {'first_specification':40,'distinct_verification':20,'terminal_audit':10,'finalization':5}
        state['config']['helper_reserves'] = explicit
        for stage,reserve in explicit.items():
            self.assertEqual(run_state.helper_reserve(state,stage),reserve)

    def test_public_cli_applies_original_remaining_grant_to_all_work(self):
        state = self.state()
        record = {'grant':state['run']['provider_binding']['grant']}
        calls = []
        def run(*args,**kwargs):
            calls.append((args,kwargs))
            self.assertLessEqual(worker_runtime.work_timeout(120),40)
            self.assertEqual(worker_runtime._CLEANUP_DEADLINE.get()[2],Decimal(60))
            with worker_runtime.cleanup_deadline():
                self.assertEqual(worker_runtime.work_timeout(120),40)
            return {'outcome':'success'}
        output = io.StringIO()
        with self.clock(20), \
             mock.patch.object(sys,'argv',['autofv','run','/synthetic/target','--config','/synthetic/config.json',
                                          '--runtime-record','/synthetic/runtime.json']), \
             mock.patch.object(experiment,'validate_run_config',return_value=(Path('/synthetic/config.json'),state['config'])), \
             mock.patch.object(pi_backend,'read_runtime_record',return_value=record), \
             mock.patch.object(experiment,'run_experiment',side_effect=run), \
             mock.patch.object(sys,'stdout',output):
            experiment.main()
        self.assertEqual(json.loads(output.getvalue()),{'outcome':'success'})
        self.assertEqual(len(calls),1)
        self.assertEqual(calls[0][1]['runtime_record'],'/synthetic/runtime.json')
        self.assertIsNone(worker_runtime._WORK_DEADLINE.get())
        self.assertIsNone(worker_runtime._CLEANUP_DEADLINE.get())


if __name__ == '__main__':
    unittest.main()
