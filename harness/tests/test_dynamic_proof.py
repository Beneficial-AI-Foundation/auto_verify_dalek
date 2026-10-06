"""Dynamic scheduling and trust-boundary regressions; no model calls."""
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
import dynamic_proof as dag


class GraphTests(unittest.TestCase):
    def setUp(self):
        self.steps = [dict(mode='spec', fn='pkg.f', path='A.lean'),
                      dict(mode='fill', fn='pkg.top', path='Top.lean')]

    def test_split_orders_dependencies_and_parent_retry(self):
        graph = dag.Graph(self.steps)
        parent = graph.ready()
        graph.split(parent, [dict(name='h1', deps=[]), dict(name='h2', deps=[0])])
        self.assertEqual(graph.ready()['fn'], 'h1')
        graph.ready()['status'] = 'accepted'
        self.assertEqual(graph.ready()['fn'], 'h2')
        graph.ready()['status'] = 'accepted'
        self.assertIs(graph.ready(), parent)
        parent['status'] = 'accepted'
        self.assertEqual(graph.ready()['fn'], 'pkg.top')

    def test_blocked_branch_does_not_block_independent_callee(self):
        steps = [dict(mode='spec', fn='pkg.a', path='A.lean', callers=['pkg.top_fn']),
                 dict(mode='spec', fn='pkg.b', path='B.lean', callers=['pkg.top_fn']),
                 dict(mode='fill', fn='pkg.top', top_fn='pkg.top_fn', path='Top.lean')]
        graph = dag.Graph(steps)
        graph.ready()['status'] = 'blocked'
        self.assertEqual(graph.ready()['fn'], 'pkg.b')
        graph.ready()['status'] = 'accepted'
        self.assertIsNone(graph.ready())

    def test_cycles_and_unknown_dependencies_are_rejected(self):
        for nodes in ({'a': {'deps': ['a']}}, {'a': {'deps': ['unknown']}}):
            with self.assertRaises(ValueError):
                dag.validate_graph(nodes)

    def test_restore_checks_source_hash_and_retries_blocked(self):
        with tempfile.TemporaryDirectory() as work:
            for s in self.steps:
                Path(work, s['path']).write_text('-- baseline\n')
            graph = dag.Graph(self.steps)
            graph.nodes['n1']['status'] = 'blocked'
            graph.save(work, work)
            with patch.object(dag.driver, 'changed_files', return_value=([], [])):
                restored = dag.Graph.restore(self.steps, work, work)
                self.assertEqual(restored.ready()['id'], 'n1')
                Path(work, 'A.lean').write_text('-- changed\n')
                with self.assertRaisesRegex(ValueError, 'source changed'):
                    dag.Graph.restore(self.steps, work, work)

    def test_proposal_rejects_cycles_duplicates_and_code_injection(self):
        good = dict(before='end P', helpers=[dict(name='P.h', type='True', deps=[], purpose='needed')])
        source, helpers = dag.validate_proposal(good, 'namespace P\nend P\n', 2)
        self.assertIn('theorem _root_.P.h : True := by', source)
        for field, value in [('deps', [0]), ('type', 'True\naxiom cheat : False'), ('name', '../escape')]:
            bad = json.loads(json.dumps(good))
            bad['helpers'][0][field] = value
            with self.assertRaises(ValueError):
                dag.validate_proposal(bad, 'end P', 2)
        good['helpers'] *= 2
        with self.assertRaises(ValueError):
            dag.validate_proposal(good, 'end P', 2)

    def test_reports_and_axiom_evidence_fail_closed(self):
        self.assertIsNone(dag.blocker_result({'result': 'too hard'}))
        self.assertIsNone(dag.blocker_result({'result': '{"blocker":{"kind":"needs_split"}}'}))
        for axioms in (None, ['sorryAx']):
            self.assertFalse(dag.clean_theorems({'h': dict(kind='theorem', axioms=axioms)}, ['h']))
        self.assertTrue(dag.clean_theorems({'h': dict(kind='theorem', axioms=['propext'])}, ['h']))


class WorkflowTests(unittest.TestCase):
    def test_blocker_refinement_helpers_parent_then_final_gate(self):
        self.exercise()

    def test_invalid_contract_does_not_spawn_refiner_or_publish(self):
        self.exercise(kind='invalid_contract', expected=False)

    def test_bad_refinement_is_not_scheduled_or_published(self):
        self.exercise(bad_proposal=True, expected=False)

    def exercise(self, kind='needs_split', bad_proposal=False, expected=True):
        with tempfile.TemporaryDirectory() as work:
            Path(work, 'A.lean').write_text('-- insertion point\n')
            steps = [dict(mode='fill', fn='pkg.top', path='A.lean')]
            args = SimpleNamespace(resume_dynamic=False, max_node_attempts=10,
                max_refinements=2, max_proof_nodes=10, max_helpers_per_split=3,
                build_timeout=20, model='test', max_turns=2, timeout=20, bundle='bundle')
            top = dict(kind='theorem', canon='top', pp='top', axioms=['sorryAx'])
            helper = dict(kind='theorem', canon='helper', pp='helper', axioms=['sorryAx'])
            calls = []
            fps = {'A': {'pkg.top': top}}
            report = dict(kind=kind, reason='needs helper', evidence='hard goal')

            def worker(prompt, tid, path, counts, local, env, settings, baseline, *rest):
                calls.append(tid)
                if len(calls) == 1:
                    outcome, detail = local.round_validator('rejected_build', {},
                        {'result': json.dumps({'blocker': report})})
                else:
                    name = 'pkg.h' if len(calls) == 2 else 'pkg.top'
                    fps['A'][name]['axioms'] = []
                    outcome, detail = local.round_validator('accepted',
                        {'g1_after': fps, 'counts_after': {'A.lean': 1 if name == 'pkg.h' else 0}}, {})
                return outcome, detail, [], [f'session-{len(calls)}']

            def refiner(*a, **kw):
                fps['A']['pkg.h'] = helper
                proposal = dict(before='-- insertion point', helpers=[
                    dict(name='pkg.h', type='True', deps=[], purpose='simplifies top')])
                if bad_proposal:
                    proposal['helpers'][0]['deps'] = [0]
                return 'ok', 0, 1, {'result': json.dumps(proposal)}, {}

            def fingerprints(*a, **kw):
                # Freeze evidence just like the real subprocess boundary.
                return json.loads(json.dumps(fps)), 0

            api = SimpleNamespace(ROOT_MODULE='Root.lean')
            api.save_partial_snapshot = lambda *a, **k: 'partial'
            published = []
            api.atomic_publish_joint = lambda *a: published.append(a)
            with patch.object(dag.driver, 'stmt_fingerprints', side_effect=fingerprints), \
                 patch.object(dag.driver, 'run_rounds', side_effect=worker), \
                 patch.object(dag.driver, 'changed_files', return_value=([], [])), \
                 patch.object(dag.driver, 'rollback'), \
                 patch.object(dag.driver, 'slot_commit'), \
                 patch.object(dag.driver, 'build_sorry_counts', return_value=(0, {'A.lean': 2}, 0, '')), \
                 patch.object(dag.agentproc, 'run_round', side_effect=refiner), \
                 patch.object(dag.agentproc, 'RECEIVED_SIGNAL', None), \
                 patch.object(dag.driver, 'gate', side_effect=lambda *a, **k: ('accepted', {'g1_after': fps})):
                self.assertEqual(dag.run(args, steps, work, work, {'A.lean': 1}, {}, '', None,
                    lambda *a: 'prove top', {}, [], lambda *a: None, api), expected)
            self.assertEqual(len(calls), 3 if expected else 1)
            self.assertEqual(len(set(calls)), len(calls))
            self.assertEqual(len(published), int(expected))
            state = json.loads(Path(work, 'graph.json').read_text())
            if expected:
                self.assertTrue(all(n['status'] == 'accepted' for n in state['nodes'].values()))
                self.assertEqual(state['events'][1]['outcome'], 'accepted_decomposition')
            else:
                self.assertEqual(state['nodes']['n1']['status'], 'blocked')
                self.assertEqual(len(state['nodes']), 1)


if __name__ == '__main__':
    unittest.main()
