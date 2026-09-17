import unittest
from unittest import mock
import subprocess

from autofv import worker, worker_runtime


def fixture(weak=False):
    graph = {
        'graph_sha256': 'a' * 64,
        'selected_nodes': ['probe:Numbers.increment', 'probe:Pipeline.finish'],
        'term_dependencies': [['probe:Pipeline.finish', 'probe:Numbers.increment']],
        'source_paths': {'probe:Numbers.increment': 'Numbers/Increment.lean',
                         'probe:Pipeline.finish': 'Pipeline/Finish.lean'},
    }
    records = {
        'probe:Numbers.increment': {'declaration': 'Numbers.increment_spec',
            'canon': 'theorem Numbers.increment_spec (n : Nat) : ' + ('n ≤ Numbers.increment n' if weak else 'Numbers.increment n = n + 1'),
            'model_fingerprint': '1' * 64},
        'probe:Pipeline.finish': {'declaration': 'Pipeline.finish_spec',
            'canon': 'theorem Pipeline.finish_spec (n : Nat) : Pipeline.finish n = n + 1',
            'model_fingerprint': '2' * 64},
    }
    sources = {
        'Numbers/Increment.lean': 'namespace Numbers\ndef increment (n : Nat) : Nat := n + 1\nend Numbers\n',
        'Pipeline/Finish.lean': 'import Numbers.Increment\nnamespace Pipeline\ndef finish (n : Nat) : Nat := Numbers.increment n\nend Pipeline\n',
    }
    return graph, records, sources


class ConsumerFeasibilityTests(unittest.TestCase):
    def test_feasibility_compiler_has_no_canonical_or_evidence_mount(self):
        graph, records, sources = fixture()
        request = worker.contract_feasibility_request(graph, records)
        lock = {'tools': {'runsc': {'runtime_name': 'runsc'}}, 'image': {'image_digest': 'sha256:' + '1' * 64}}
        run = {'lock': lock, 'volume': 'run-volume', 'base_commit': 'b' * 40}
        calls = []
        def git(_run, *args):
            return b'archive-fixture' if args[0] == 'archive' else sources[args[-1].split(':', 1)[1]].encode()
        def docker(*args, **kwargs):
            calls.append(args)
            output = b'ok\nAUTOFV_FEASIBILITY_EXIT=0\n' if any('lake env lean' in arg for arg in args) else b'a' * 64 + b'\n'
            return subprocess.CompletedProcess(args, 0, output, b'')
        with mock.patch.object(worker_runtime, '_git', side_effect=git), mock.patch.object(worker_runtime, '_docker', side_effect=docker):
            worker.check_contract_feasibility(run, request)
        compilation = [args for args in calls if any('lake env lean' in arg for arg in args)]
        self.assertEqual(len(compilation), 1)
        mounts = [compilation[0][i+1] for i,arg in enumerate(compilation[0]) if arg == '--mount']
        self.assertEqual(len(mounts), 1)
        self.assertIn('dst=/candidate', mounts[0])
        self.assertIn('volume-subpath=lanes/feasibility-', mounts[0])
        self.assertNotIn('dst=/volume', mounts[0])

    def test_consumer_obligation_abstracts_dependency_and_has_no_proof_holes(self):
        from autofv import contract_feasibility
        graph, records, sources = fixture()
        request = worker.contract_feasibility_request(graph, records)
        source = contract_feasibility.consumer_source(request, sources)
        self.assertNotIn('sorry', source)
        self.assertNotIn('admit', source)
        self.assertNotIn('Diamond', source)
        self.assertIn('_autofv_dep_0', source)
        self.assertIn('_autofv_h0', source)
        self.assertIn('example', source)
        # The implementation cannot silently supply a fact missing from the
        # contract: the consumer goal is over an arbitrary function parameter.
        obligation = source[source.index('example'):]
        self.assertNotIn('Numbers.increment', obligation)
        self.assertNotIn('Pipeline.finish', obligation)

    def test_weak_contract_reaches_real_consumer_goal_and_failure_is_retained(self):
        from autofv import contract_feasibility
        graph, records, sources = fixture(weak=True)
        request = worker.contract_feasibility_request(graph, records)
        source = contract_feasibility.consumer_source(request, sources)
        self.assertIn('n ≤ _autofv_dep_0 n', source)
        self.assertIn('= n + 1', source)
        failed = subprocess.CompletedProcess([], 0, b'unsolved goals\nAUTOFV_FEASIBILITY_EXIT=1\n', b'')
        lock = {'tools': {'runsc': {'runtime_name': 'runsc'}}, 'image': {'image_digest': 'sha256:' + '1' * 64}}
        run = {'lock': lock, 'volume': 'run-volume', 'base_commit': 'b' * 40}
        def read_source(_run, *args):
            if args[0] == 'archive':
                return b'archive-fixture'
            return sources[args[-1].split(':', 1)[1]].encode()
        def boundary(*args, **kwargs):
            if any('lake env lean' in arg for arg in args):
                return failed
            return subprocess.CompletedProcess(args, 0, b'a' * 64 + b'\n', b'')
        with mock.patch.object(worker_runtime, '_git', side_effect=read_source), mock.patch.object(worker_runtime, '_docker', side_effect=boundary) as execute:
            result = worker.check_contract_feasibility(run, request)
        self.assertEqual(result['status'], 'failed')
        self.assertEqual(result['reason'], 'consumer_proof_failed')
        self.assertIn(source.encode(), [call.kwargs.get('input_bytes') for call in execute.call_args_list])
