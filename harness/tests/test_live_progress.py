"""Live display must precede process exit without changing raw logs or deadlines."""
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import agentproc
from live_progress import ProgressRenderer


def assistant(blocks, mid="m1"):
    return {"type": "assistant", "message": {"id": mid, "content": blocks}}


class LiveProgressTests(unittest.TestCase):
    def test_compact_tools_diagnostics_and_no_reasoning(self):
        lines = []
        r = ProgressRenderer(lines.append)
        event = assistant([
            {"type": "thinking", "thinking": "private reasoning"},
            {"type": "text", "text": "Checking the helper."},
            {"type": "tool_use", "id": "t1", "name": "Bash",
             "input": {"command": "lake build Target"}}])
        r.event(event)
        r.event(event)
        r.event({"type": "user", "message": {"content": [{
            "type": "tool_result", "tool_use_id": "t1", "is_error": True,
            "content": "noise\nerror: Target.lean:10: timeout at whnf\n" + "x" * 2000}]}})
        self.assertEqual(sum('Checking' in x for x in lines), 1)
        self.assertTrue(any('Bash  lake build Target' in x for x in lines))
        self.assertTrue(any('ERROR' in x for x in lines))
        self.assertTrue(any('timeout at whnf' in x for x in lines))
        self.assertNotIn('private reasoning', '\n'.join(lines))
        self.assertLess(max(map(len, lines)), 550)

    def test_read_content_not_dumped_and_shared_message_keeps_turn(self):
        lines = []
        r = ProgressRenderer(lines.append)
        r.event(assistant([{"type": "text", "text": "Inspecting."}]))
        r.event(assistant([{"type": "tool_use", "id": "read", "name": "Read",
                            "input": {"file_path": "Target.lean"}}]))
        r.event({"type": "user", "message": {"content": [{
            "type": "tool_result", "tool_use_id": "read", "content": "SECRET FILE BODY"}]}})
        self.assertTrue(all('[turn 1]' in x for x in lines))
        self.assertNotIn('SECRET FILE BODY', '\n'.join(lines))

    def run_child(self, code, tmp, emit=None, deadline=5):
        with mock.patch.object(agentproc, 'build_command', return_value=[sys.executable, '-u', '-c', code]):
            return agentproc.run_round('prompt', str(Path(tmp)/'trace.jsonl'),
                cwd=tmp, session_id='test', resume=False,
                deadline_seconds=deadline, progress_log=emit)

    def test_live_before_exit_partial_lines_and_verbatim_transcript(self):
        with tempfile.TemporaryDirectory() as tmp:
            event = json.dumps(assistant([{"type": "text", "text": "Working now"}]))
            terminal = json.dumps({"type": "result", "subtype": "success"})
            code = f'''import sys,time,pathlib
sys.stdout.write({event[:17]!r}); sys.stdout.flush()
time.sleep(0.05)
sys.stdout.write({event[17:]!r}+'\\n'); sys.stdout.flush()
end=time.time()+3
while not pathlib.Path('observed').exists() and time.time()<end: time.sleep(0.02)
assert pathlib.Path('observed').exists(), 'display waited for round exit'
print('non-json stderr diagnostic', file=sys.stderr, flush=True)
sys.stdout.write({terminal!r}); sys.stdout.flush()
'''
            lines = []
            def emit(line):
                lines.append(line)
                (Path(tmp)/'observed').touch()
            status, rc, _, result, _ = self.run_child(code, tmp, emit)
            self.assertEqual((status, rc), ('ok', 0))
            self.assertEqual(result['subtype'], 'success')
            self.assertTrue(any('Working now' in x for x in lines))
            self.assertEqual((Path(tmp)/'trace.jsonl').read_text(),
                             event+'\nnon-json stderr diagnostic\n'+terminal)

    def test_deadline_with_live_display(self):
        with tempfile.TemporaryDirectory() as tmp:
            event = json.dumps(assistant([{"type": "text", "text": "Waiting"}]))
            status, rc, wall, _, _ = self.run_child(
                f'import time; print({event!r}, flush=True); time.sleep(10)',
                tmp, lambda _: None, deadline=0.3)
            self.assertEqual(status, 'deadline')
            self.assertNotEqual(rc, 0)
            self.assertLess(wall, 3)

    def test_quiet_and_broken_display_do_not_change_result(self):
        terminal = json.dumps({'type':'result', 'subtype':'success'})
        event = json.dumps(assistant([{'type':'text','text':'hello'}]))
        def broken(_):
            raise BrokenPipeError()
        for emit in (None, broken):
            with self.subTest(emit=emit), tempfile.TemporaryDirectory() as tmp:
                status, rc, _, result, _ = self.run_child(
                    f'print({event!r}); print({terminal!r})', tmp, emit)
                self.assertEqual((status, rc, result['subtype']), ('ok', 0, 'success'))


if __name__ == '__main__':
    unittest.main()
