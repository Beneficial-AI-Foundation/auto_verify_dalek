"""Offline operational qualification: real framework/client/relay/service/accounting.

Only upstream inference and Docker/Lean/filesystem effects are synthetic. Both
HTTP hops use loopback; embedded client/relay programs are production source.
No real env file, reference, provider, VM or proof acceptance is used.
"""
from pathlib import Path
import ast
import asyncio
import copy
import http.server
import io
import json
import os
import subprocess
import sys
import threading
import unittest
import urllib.request
from decimal import Decimal
from unittest import mock

ROOT = Path.cwd()
sys.path.insert(0, str(ROOT))
from tests.host_regression import install_guard
from tests import test_fvs_offline as fixture
from tests.test_provider_service import _install_trusted_authorization_fixture
from autofv import (agent_lane, contracts, deepagents_lane, fvs_packet, fvs_profile,
    generic_role_runtime, model, provider_config, provider_messages, provider_service,
    provider_transport, provider_deadline, worker_proxy)


class OperationalPath(unittest.TestCase):
    def setUp(self):
        if self._testMethodName == 'test_full_file_reads_exhaust_history_before_turn_limit':
            large = fixture.packet()
            large['sources'][0] = fvs_packet.source(fixture.PATH, 'lean', fixture.ORIGINAL + '-- ' + 'x' * 60_000 + '\n')
            large['packet_sha256'] = fvs_profile.digest({k: v for k, v in large.items() if k != 'packet_sha256'})
            patcher = mock.patch.object(fixture, 'packet', return_value=large)
            patcher.start()
            self.addCleanup(patcher.stop)
        fixture.FvsOfflineTests.setUp(self)
        _install_trusted_authorization_fixture(self.run, self.root)
        self.state['run_round'] = model.agentproc.run_round
        self.state['config']['max_wall_seconds'] = 1800
        self.state['config']['max_cost_usd'] = Decimal('10')
        self.state['wall_seconds_used'] = Decimal('853.384207')
        self.state['finalization_reserve_seconds'] = Decimal('5')
        self.original_ensure_relay = worker_proxy._ensure_proxy_relay
        self.sent = []
        self.effects = []
        self.synthetic_actions = []
        self.expire_at = None
        self.latency_ns = 121_000_000_000
        self.deadlines = []
        self.clock = 1_000_000_000
        self.addCleanup(provider_service.release, self.run)
        serve = mock.patch.object(provider_service, '_serve', side_effect=lambda handler:
            provider_service._BoundedHTTPServer(('127.0.0.1', 0), handler))
        serve.start()
        self.addCleanup(serve.stop)
        base = provider_service.start(self.run)
        env = mock.patch.dict(os.environ, {'AUTOFV_PROXY_BASE': base,
            'AUTOFV_PROXY_PATH': self.binding.route_path,
            'AUTOFV_PROXY_TIMEOUT_SECONDS': str(provider_transport.request_timeout_seconds(self.run)),
            'NO_PROXY': '127.0.0.1,localhost'})
        env.start()
        self.addCleanup(env.stop)
        tree = ast.parse(worker_proxy._RELAY_PROGRAM)
        # Omit only the module's blocking server-start expression; same Handler.
        assert isinstance(tree.body[-1], ast.Expr)
        assert 'serve_forever' in ast.unparse(tree.body[-1])
        scope = {'__name__': 'synthetic_local_relay'}
        exec(compile(ast.Module(body=tree.body[:-1], type_ignores=[]), '<production-relay>', 'exec'), scope)
        self.relay_open = mock.Mock(wraps=scope['opener'].open)
        scope['opener'].open = self.relay_open
        self.relay = http.server.ThreadingHTTPServer(('127.0.0.1', 0), scope['Handler'])
        thread = threading.Thread(target=self.relay.serve_forever, daemon=True)
        thread.start()
        def close_relay():
            self.relay.shutdown()
            self.relay.server_close()
            thread.join(2)
            assert not thread.is_alive()
        self.addCleanup(close_relay)
        for target, attr, value in [
            (worker_proxy, 'RELAY_PORT', self.relay.server_port),
            (worker_proxy, '_ensure_proxy_relay', lambda run: ('synthetic-loopback', '127.0.0.1')),
            (worker_proxy, '_docker', self.docker_client),
            (provider_transport, '_open_upstream', self.upstream),
        ]:
            patcher = mock.patch.object(target, attr, value)
            patcher.start()
            self.addCleanup(patcher.stop)

    def docker_client(self, *argv, input_bytes, check=False):
        # Execute the actual worker HTTP client, without launching Docker/guests.
        self.assertFalse(check)
        index = argv.index('-c')
        self.assertEqual(argv[index + 1], worker_proxy._PROXY_CLIENT_PROGRAM)
        self.assertEqual(argv[index + 3], str(provider_transport.request_timeout_seconds(self.run)))
        output = io.BytesIO()
        with mock.patch.object(sys, 'stdin', io.TextIOWrapper(io.BytesIO(input_bytes))), \
             mock.patch.object(sys, 'stdout', io.TextIOWrapper(output, write_through=True)), \
             mock.patch.object(sys, 'argv', ['synthetic-client', argv[index + 2], argv[index + 3]]), \
             mock.patch('urllib.request.urlopen', wraps=urllib.request.urlopen) as opened:
            exec(compile(worker_proxy._PROXY_CLIENT_PROGRAM, '<production-client>', 'exec'), {'__name__': '__main__'})
            raw = output.getvalue()
            self.assertEqual(opened.call_args.kwargs['timeout'], 120)
            self.assertEqual(self.relay_open.call_args.kwargs['timeout'], 120)
        return subprocess.CompletedProcess(argv, 0, raw, b'')

    def upstream(self, request, **kwargs):
        body = json.loads(request.data)
        self.sent.append(body)
        self.assertEqual(body['reasoning'], {'effort': 'xhigh', 'exclude': True})
        self.assertLessEqual(kwargs['timeout'], 120)
        if 'deadline_monotonic_ns' in kwargs:
            self.deadlines.append(kwargs['deadline_monotonic_ns'])
        if self.expire_at == len(self.sent):
            self.clock += self.latency_ns
        name, arguments = self.synthetic_actions[len(self.sent) - 1]
        reply = fixture._provider_reply()
        reply.update(model=body['model'], provider='OpenAI' if body['model'] == fvs_profile.AUTHOR else 'Anthropic')
        reply['choices'][0]['message'].update(reasoning='synthetic-private-do-not-retain',
            reasoning_details=[{'type': 'reasoning.encrypted', 'data': 'synthetic-private-opaque'}])
        reply['choices'][0]['message']['tool_calls'][0]['function'] = {'name': name, 'arguments': json.dumps(arguments)}
        reply['usage'] = {'prompt_tokens': 100, 'completion_tokens': 10, 'total_tokens': 110,
            'prompt_tokens_details': {'cached_tokens': 0, 'cache_write_tokens': 0},
            'completion_tokens_details': {'reasoning_tokens': 5}, 'cost': 0.0003}
        return fixture._ProviderReply(reply)

    def run_role(self, role, actions, *, note_bytes=150_625, packet=None):
        self.synthetic_actions = actions
        graph = {'source_paths': {'helper': fixture.PATH}, 'graph_sha256': 'd' * 64}
        lane = {'node': 'helper', 'assigned_path': fixture.PATH, 'base_commit': 'c' * 40}
        context = {'source_packet': packet or fixture.packet(), 'public_context_note': 'x' * note_bytes}
        if role in fvs_profile.REVIEW_ROLES:
            context['reviewed_candidate'] = {'patch': fixture.patch(fixture.SPEC)}
            context['source_packet'] = fvs_packet.review_snapshot(fixture.packet(),
                path=fixture.PATH, patch=context['reviewed_candidate']['patch'])
        job = generic_role_runtime._role_job(self.state, graph, lane, role,
            statement_sha256='e' * 64, contract_fingerprint='f' * 64,
            input_hashes=[fixture.packet()['packet_sha256']], role_context=context)
        tools = agent_lane.build_lane_tools(job,
            read_file=lambda path: self.fail('FVS read must use immutable packet'),
            search_files=lambda query: self.fail('FVS search must use immutable packet'),
            edit_assigned=lambda patch: self.effects.append('edit') or 'synthetic edit complete',
            check_lean=lambda: self.effects.append('check') or 'synthetic check only; NOT Lean verification')
        return asyncio.run(agent_lane.run_role_conversation(self.state, job, tools))

    def submit(self):
        return ('submit_candidate', {'patch': fixture.patch(fixture.SPEC),
            'claimed_status': 'candidate', 'evidence': [fixture.PASS]})

    def verify_completed(self, count):
        self.assertEqual(len(self.sent), count)
        self.assertEqual(self.state['cost'], Decimal('0.0003') * count)
        self.assertFalse(self.state['pending_model_exchanges'])
        records = list((Path(self.run['evidence_dir']) / 'provider-journal').glob('*.json'))
        self.assertEqual(len(records), count)
        for p in records:
            raw = p.read_bytes()
            self.assertNotIn(b'synthetic-private-', raw)
            self.assertEqual(json.loads(raw)['status'], 'completed')
        self.assertGreater(len(contracts.canonical_json_bytes(self.sent[0]['messages'])), 150_000)
        self.assertTrue(any(m['role'] == 'tool' for m in self.sent[-1]['messages']))
        self.assertTrue(all(p['status'] == 'completed' for p in self.state['role_tool_outcomes'].values()))

    def test_scout_read_search_submit_through_actual_framework_and_http_hops(self):
        actions = [('read_allowed', {'path': fixture.PATH}), ('search_allowed', {'query': 'increment'})] * 4
        candidate = self.run_role('scout', actions + [self.submit()])
        self.assertEqual(candidate['role'], 'scout')
        self.verify_completed(9)
        self.assertFalse(self.effects)

    def test_author_edit_check_submit_through_actual_framework_and_http_hops(self):
        actions = [('read_allowed', {'path': fixture.PATH}), ('edit_assigned', {'patch': fixture.patch(fixture.SPEC)}),
            ('check_lean', {}), self.submit()]
        role = 'prover' if 'prover_' in self._testMethodName else 'specifier'
        self.run_role(role, actions)
        self.verify_completed(4)
        self.assertEqual(self.effects, ['edit', 'check'])

    def test_reviewer_readonly_tools_and_submit_through_actual_framework(self):
        actions = [('read_allowed', {'path': fixture.PATH}), ('edit_assigned', {'patch': fixture.patch(fixture.SPEC)}),
            ('check_lean', {}), self.submit()]
        role = 'proof_reviewer' if 'proof_reviewer_' in self._testMethodName else 'spec_reviewer'
        self.run_role(role, actions)
        self.verify_completed(4)
        self.assertFalse(self.effects)
        text = json.dumps(self.sent[-1]['messages'])
        self.assertIn('read_only_role', text)

    def test_prover_tool_flow_through_actual_framework(self):
        self.test_author_edit_check_submit_through_actual_framework_and_http_hops()

    def test_proof_reviewer_tool_flow_through_actual_framework(self):
        self.test_reviewer_readonly_tools_and_submit_through_actual_framework()

    def test_full_file_reads_exhaust_history_before_turn_limit(self):
        with self.assertRaises(Exception) as caught:
            self.run_role('scout', [('read_allowed', {'path': fixture.PATH})] * 3 + [self.submit()], note_bytes=90_625)
        self.assertRegex(str(caught.exception), 'provider messages|FVS complete source context')
        self.assertLessEqual(len(self.sent), 2)
        self.assertFalse(self.state['pending_model_exchanges'])
        self.assertIn('provider messages exceed their bound', str(caught.exception))

    def test_complete_initial_context_survives_framework(self):
        self.run_role('scout', [('read_allowed', {'path': fixture.PATH}), self.submit()], note_bytes=205_000)
        self.assertTrue(any('x' * 205_000 in m.get('content', '') for m in self.sent[0]['messages']),
            'Allowed complete FVS initial context was removed before provider dispatch')

    def test_role_turn_limit_stops_before_an_extra_dispatch(self):
        with self.assertRaisesRegex(Exception, 'role turn limit exhausted'):
            self.run_role('scout', [('search_allowed', {'query': 'no-synthetic-match'})] * 17)
        self.assertEqual(len(self.sent), 16)
        self.assertFalse(self.state['pending_model_exchanges'])

    def test_deadline_exhaustion_stops_without_retry_and_retains_liability(self):
        self.expire_at = 2
        self.state['wall_seconds_used'] = Decimal('853.384207')
        self.assertEqual(model._provider_timeout_seconds(self.state), 120)
        with mock.patch('time.monotonic_ns', side_effect=lambda: self.clock):
            with self.assertRaisesRegex(Exception, 'fixed proxy timeout'):
                self.run_role('scout', [('read_allowed', {'path': fixture.PATH}), self.submit()])
        self.assertEqual(len(self.sent), 2)
        self.assertEqual(len(self.state['pending_model_exchanges']), 1)
        self.assertEqual(len(self.state['receipts']), 1)
        self.assertTrue(all(x['status'] != 'completed' for x in self.state['role_progress'].values()))

    def use_loopback_upstream(self, *, delay=0):
        case = self
        class Upstream(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                length = int(self.headers['Content-Length'])
                request = urllib.request.Request('https://synthetic.invalid/reply',
                    data=self.rfile.read(length), method='POST')
                raw = case.upstream(request, timeout=30).read(1_000_001)
                if delay:
                    threading.Event().wait(delay)  # Simulated provider latency only.
                try:
                    self.send_response(200)
                    self.send_header('Content-Length', str(len(raw)))
                    self.end_headers()
                    self.wfile.write(raw)
                except (BrokenPipeError, ConnectionResetError):
                    pass  # Expected after the real deadline controller closes the socket.
            def log_message(self, *_args):
                pass
        server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Upstream)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        def close():
            server.shutdown()
            server.server_close()
            thread.join(2)
            assert not thread.is_alive()
        self.addCleanup(close)
        def redirect_fixture_only(request, **kwargs):
            local = urllib.request.Request(f'http://127.0.0.1:{server.server_port}/reply',
                data=request.data, headers=dict(request.header_items()), method=request.get_method())
            return provider_deadline.open_upstream(local, **kwargs)
        patcher = mock.patch.object(provider_transport, '_open_upstream', redirect_fixture_only)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_real_upstream_socket_and_deadline_controller_success(self):
        self.use_loopback_upstream()
        self.run_role('scout', [('read_allowed', {'path': fixture.PATH}), self.submit()])
        self.verify_completed(2)

    def test_real_socket_deadline_aborts_without_retry_or_receipt(self):
        self.use_loopback_upstream(delay=0.6)
        self.state['wall_seconds_used'] = Decimal('1794.8')  # 0.2s left after reserve.
        with self.assertRaisesRegex(Exception, 'fixed proxy timeout'):
            self.run_role('scout', [self.submit()])
        self.assertEqual(len(self.sent), 1)
        self.assertFalse(self.state['receipts'])
        self.assertEqual(len(self.state['pending_model_exchanges']), 1)

    def test_fvs_reply_after_30_seconds_keeps_original_absolute_deadline(self):
        self.expire_at = 1
        self.latency_ns = 31_000_000_000
        with mock.patch('time.monotonic_ns', side_effect=lambda: self.clock):
            self.run_role('scout', [('read_allowed', {'path': fixture.PATH}), self.submit()])
            self.assertEqual(self.deadlines[0], 121_000_000_000)
            self.assertEqual(provider_transport._remaining_seconds(self.deadlines[0]), 89)
            self.assertEqual(provider_deadline._remaining_seconds(self.deadlines[0]), 89)
        self.verify_completed(2)

    def test_registered_timeout_limits_and_unsigned_claims(self):
        messages = [{'role': 'system', 'content': 'synthetic'}, {'role': 'user', 'content': 'synthetic'}]
        request = model._model_envelope(self.state, request_id='timeout-cap', role='scout',
            input_hashes=[provider_transport.messages_sha256(messages, run=self.run)])
        provider_transport.stage_messages(self.run, request, messages, timeout_seconds=120)
        provider_transport.discard_messages(self.run, request['request_id'])
        for invalid in (120.001, True, 0, -1, float('nan'), float('inf')):
            with self.subTest(timeout=invalid), self.assertRaises(provider_transport.ProviderError):
                provider_transport.stage_messages(self.run, request, messages, timeout_seconds=invalid)
        foreign = {**self.run, 'provider_binding': copy.deepcopy(self.run['provider_binding'])}
        foreign['provider_binding']['binding_sha256'] = '0' * 64
        with self.assertRaises(provider_config.ProviderConfigError):
            provider_transport.request_timeout_seconds(foreign)
        root = self.root / 'legacy'
        root.mkdir()
        legacy = fixture._provider_run(root, contracts.load_toolchain_lock(), 'c' * 40)
        provider_config.configure_provider(legacy, env_path=fixture._provider_env(root),
            tool_schemas=list(agent_lane._TOOL_SCHEMAS), project_root=root)
        try:
            state = {**self.state, 'run': legacy}  # Even with FVS config, legacy binding owns its cap.
            self.assertEqual(model._provider_timeout_seconds(state), 30)
            bound = provider_config.provider_binding(legacy)
            legacy_request = {**request, 'input_hashes': [fvs_profile.digest(messages)]}
            provider_messages.stage_messages(bound, legacy_request, messages, timeout_seconds=30)
            provider_messages.discard_messages(bound, request['request_id'])
            with self.assertRaises(provider_transport.ProviderError):
                provider_messages.stage_messages(bound, legacy_request, messages, timeout_seconds=31)
        finally:
            provider_config.abort_configuration(legacy)

    def test_relay_reuse_pins_timeout_environment(self):
        network, relay = 'synthetic-network', 'synthetic-relay'
        base = 'http://127.0.0.1:43210'
        environment = [f'AUTOFV_PROXY_BASE={base}', f'AUTOFV_PROXY_PATH={self.binding.route_path}',
            'AUTOFV_RUN_TOKEN=synthetic-fvs-run-token']
        def inspected(timeout):
            env = environment + ([] if timeout is None else [f'AUTOFV_PROXY_TIMEOUT_SECONDS={timeout}'])
            value = [{'Config': {'Env': env}, 'NetworkSettings': {'Networks': {network: {'IPAddress': '127.0.0.1'}}}}]
            return subprocess.CompletedProcess([], 0, json.dumps(value).encode(), b'')
        with mock.patch.object(worker_proxy, '_proxy_resources', return_value=(network, relay)), \
             mock.patch.object(worker_proxy, 'lima_host_address', return_value='127.0.0.1'), \
             mock.patch.object(provider_service, 'relay_base', return_value=base), \
             mock.patch.object(worker_proxy, '_resource_matches', return_value=True), \
             mock.patch.object(worker_proxy, '_bind_proxy_client_identity'), \
             mock.patch.object(worker_proxy, '_configure_proxy_firewall'), \
             mock.patch.object(worker_proxy, '_record_proxy_policy'):
            for timeout in (None, 30, 121):
                with mock.patch.object(worker_proxy, '_docker', return_value=inspected(timeout)):
                    with self.assertRaisesRegex(Exception, 'relay identity mismatch'):
                        self.original_ensure_relay(self.run)
            with mock.patch.object(worker_proxy, '_docker', return_value=inspected(120)):
                self.assertEqual(self.original_ensure_relay(self.run), (network, '127.0.0.1'))

    def test_framework_profiles_keep_legacy_separate(self):
        for methodology, expected in [('bounded-v1', deepagents_lane._MODEL_NAME),
                                      (agent_lane._FVS_METHODOLOGY, deepagents_lane._FVS_MODEL_NAME)]:
            routed = deepagents_lane._RoutedRoleModel(self.state, {'methodology': methodology},
                {'max_output_tokens': 8192}, [], [], {})
            self.assertEqual(routed.model_name, expected)
            self.assertEqual(routed._get_ls_params()['ls_model_name'], expected)
        self.assertNotEqual(deepagents_lane._MODEL_NAME, deepagents_lane._FVS_MODEL_NAME)

    def test_remaining_wall_reserve_overrides_request_cap(self):
        self.state['wall_seconds_used'] = Decimal('1793')
        self.assertEqual(model._provider_timeout_seconds(self.state), 2)
        self.state['wall_seconds_used'] = Decimal('1795')
        with self.assertRaises(model.BudgetExhausted):
            model._provider_timeout_seconds(self.state)


if __name__ == '__main__':
    install_guard()
    names = [name for name in OperationalPath.__dict__ if name.startswith('test_')]
    result = unittest.TextTestRunner(verbosity=2).run(unittest.TestSuite(OperationalPath(n) for n in names))
    raise SystemExit(not result.wasSuccessful())
