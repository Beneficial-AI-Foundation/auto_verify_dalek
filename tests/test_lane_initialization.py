"""Sealed initialization command planning only; no container/compiler execution."""

import subprocess
import unittest
from unittest import mock

from autofv import diamond, worker, worker_runtime
from tests.test_worker_candidate_boundary import _LOCK


class LaneInitializationTests(unittest.TestCase):
    def test_sealed_initialization_reconciles_zero_partial_and_complete_lanes(self):
        run = {'run_id': 'init-run', 'run_root': '/host/run', 'project_dir': '/volume/work/project',
               'volume': 'init-volume', 'base_commit': 'a' * 40, 'lock': _LOCK, 'events': []}
        nodes = ['probe:Arithmetic.increment', 'probe:Pipeline.finish']
        graph = {'source_paths': dict(zip(nodes, ['Arithmetic/Increment.lean', 'Pipeline/Finish.lean']))}
        lanes = diamond._lane_descriptors(run, graph, nodes)
        for existing_count in (0, 1, 2):
            with self.subTest(existing_count=existing_count):
                existing = {lane['worktree_path'] for lane in lanes[:existing_count]}
                added = []
                interrupted = False
                def git(_run, *args):
                    nonlocal interrupted
                    self.assertEqual(args[:3], ('worktree', 'add', '--detach'))
                    self.assertNotIn(args[3], existing, 'worktree-add must not replay')
                    existing.add(args[3])
                    added.append(args[3])
                    if existing_count == 0 and not interrupted:
                        interrupted = True
                        raise KeyboardInterrupt('between sealed worktree creations')
                    return b''
                def docker(*args, **kwargs):
                    if args[-3:-1] == ('test', '-e'):
                        return subprocess.CompletedProcess(args, 0 if args[-1] in existing else 1, b'', b'')
                    output = (run['base_commit'] + '\n').encode() if args[-2:] == ('rev-parse', 'HEAD') else b''
                    return subprocess.CompletedProcess(args, 0, output, b'')
                with mock.patch.object(worker_runtime, '_docker', side_effect=docker), mock.patch.object(worker_runtime, '_git', side_effect=git):
                    if existing_count == 0:
                        with self.assertRaises(KeyboardInterrupt):
                            worker.prepare_lanes(run, lanes)
                    worker.prepare_lanes(run, lanes)
                    worker.prepare_lanes(run, lanes)
                self.assertEqual(len(added), 2 - existing_count)
                self.assertEqual(existing, {lane['worktree_path'] for lane in lanes})
