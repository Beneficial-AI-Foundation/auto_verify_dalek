"""Prepared FVS preflight wiring; all workers, catalogs and provider replies are synthetic."""
from __future__ import annotations

import base64
import copy
import hashlib
import json
import signal
import subprocess
import unittest
import urllib.error
from contextlib import ExitStack, nullcontext
from decimal import Decimal
from pathlib import Path
from unittest import mock

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from autofv import (agent_lane, contracts, experiment, fvs_packet, fvs_profile, model, preflight_runner,
                    provider_config, provider_receipts, provider_service, provider_transport, run_state, worker, worker_runtime)
from tests import test_fvs_offline as fixtures
from tests.test_preflight_cli import _runner_raw
from tests.test_provider_transport import _ProviderReply, _provider_reply, _provider_run


def endpoint(model):
    policy = fvs_profile.profile()["models"][model]
    tiers = []
    for tier in policy["tiers"]:
        tiers.append({"min_prompt_tokens": tier["min_input_tokens"],
                      **{raw: str(Decimal(tier[local]) / 1000000) for raw, local in
                         [("prompt", "input"), ("completion", "output"),
                          ("input_cache_read", "cached"), ("input_cache_write", "write_lower"),
                          ("input_cache_write_1h", "write_upper")]}})
    prices = {key: value for key, value in tiers[0].items() if key != "min_prompt_tokens"}
    if len(tiers) > 1:
        prices["overrides"] = tiers[1:]
    return {"data": {"id": model, "endpoints": [{
        "tag": policy["provider"], "provider_name": policy["observed_provider"],
        "supported_parameters": ["reasoning", "tools", "tool_choice"],
        "max_completion_tokens": policy["max_output_tokens"],
        "supports_tool_choice": {"auto": True, "none": True,
                                 "required": model == fvs_profile.AUTHOR,
                                 "function": model == fvs_profile.AUTHOR},
        "pricing": prices}]}}


class _AlarmOnWrite(dict):
    """Delivers the installed SIGALRM handler at one chosen write, as a real alarm could."""

    alarm = None

    def __init__(self, *args, key=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.key = key

    def __setitem__(self, key, value):
        super().__setitem__(key, value)
        if self.alarm is not None and (self.key is None or key == self.key):
            alarm, self.alarm = self.alarm, None
            alarm(signal.SIGALRM, None)

    def update(self, *args, **kwargs):
        values = dict(*args, **kwargs)
        super().update(values)
        if self.alarm is not None and (self.key is None or self.key in values):
            alarm, self.alarm = self.alarm, None
            alarm(signal.SIGALRM, None)


class PreparedFvsPreflightTests(unittest.TestCase):
    bound_packet = fixtures.FvsOfflineTests.bound_packet

    def setUp(self):
        fixtures.FvsOfflineTests.setUp(self)
        network = mock.patch("socket.socket.connect", side_effect=AssertionError("unexpected network in host test"))
        network.start()
        self.addCleanup(network.stop)
        dns = mock.patch("socket.getaddrinfo", side_effect=AssertionError("unexpected DNS in host test"))
        dns.start()
        self.addCleanup(dns.stop)

    def inputs(self):
        packet, preparation, rust = self.bound_packet()
        target = self.root / "prepared"
        target.mkdir()
        for source in packet["sources"]:
            if source["surface"] != "rust":
                (target / source["path"]).write_text(source["content"])
        manifest = {"schema": "autofv/v1", "targets": [
            {"function": "Arithmetic.increment", "spec": "Arithmetic.increment_spec"}],
            "verify": ["lake", "build", "--no-build", "Mathlib"]}
        (target / "autofv.json").write_bytes(contracts.canonical_json_bytes(manifest))
        config = {**fixtures.config(), "source_packet": packet, "max_cost_usd": "1.000000"}
        config_path = self.root / "fvs-run.json"
        config_path.write_bytes(contracts.canonical_json_bytes(config) + b"\n")
        graph = {"source_paths": {"probe:Arithmetic.increment": fixtures.PATH},
                 "graph_sha256": "d" * 64, "probe_rust_sha256": "e" * 64,
                 "probe_aeneas_sha256": "f" * 64}
        receipt = {"dependency_cache_sha256": "b" * 64}
        options = {"env_file": self.root / "providers.env", "preparation_manifest": self.root / "preparation.json",
                   "probe_rust_evidence": self.root / "probe-rust.json",
                   "probe_aeneas_evidence": self.root / "probe-aeneas.json",
                   "dependency_cache": self.root / "cache.tar.zst", "public_rust_root": rust}
        self.target, self.config_path, self.config, self.manifest = target, config_path, config, manifest
        self.prepared_inputs = preparation, graph, receipt, {"dependency-cache": options["dependency_cache"]}
        self.options = options
        self.events, self.requests = [], []

    def exercise(self, **changes):
        options = {**self.options, **changes}
        output = options.pop("output", self.root / ("preflight-" + str(len(self.events))))
        self.output = output
        bad_catalog = options.pop("bad_catalog", False)
        extra_catalog_models = options.pop("extra_catalog_models", 0)
        reject_reviewer = options.pop("reject_reviewer", False)
        network_error = options.pop("network_error", False)
        cleanup_fails = options.pop("cleanup_fails", False)
        redirect = options.pop("redirect", False)
        lost_reply = options.pop("lost_reply", False)
        invalid_companion = options.pop("invalid_companion", False)
        expired = options.pop("expired", False)
        patches = options.pop("patches", ())
        seed_error = contracts.BudgetExhausted("wall_seconds", Decimal(600), Decimal(600)) if expired else None

        def prepare(target, manifest, lock, *, before_worker):
            run = _provider_run(self.root / "worker", lock, "c" * 40)
            self.prepared_run = run
            before_worker(run)
            self.events.append("worker_created")
            run.update(execution_tier="sealed_runsc", snapshot_sha256=worker.hash_tree(target),
                       manifest_sha256=fvs_profile.digest(manifest))
            return run

        def start(_run):
            self.events.append("listener_started")

        def fetch(request, *_args, **_kwargs):
            if request.get_method() == "GET":
                def metadata(value):
                    reply = _ProviderReply(value)
                    if redirect:
                        reply.status = 301  # The deadline opener never follows redirects.
                    return reply
                if request.full_url.endswith("/models"):
                    return metadata({"data": [{"id": model,
                        "supported_parameters": ["reasoning", "tools", "tool_choice"],
                        "reasoning": {"supported_efforts": ["xhigh"]}}
                        for model in [fvs_profile.AUTHOR, fvs_profile.REVIEWER]
                        + [f"unselected/synthetic-{i}" for i in range(extra_catalog_models)]]})
                model = request.full_url.removeprefix("https://openrouter.ai/api/v1/models/").removesuffix("/endpoints")
                document = endpoint(model)
                if bad_catalog:
                    extra = copy.deepcopy(document["data"]["endpoints"][0])
                    extra["tag"] += "/unknown-variant"
                    document["data"]["endpoints"].append(extra)
                return metadata(document)
            upstream = json.loads(request.data)
            self.requests.append(upstream)
            if network_error:
                raise urllib.error.URLError(OSError(61, "private synthetic network context"))
            reply = _provider_reply()
            model = upstream["model"]
            reply.update(model=model, provider="OpenAI" if model == fvs_profile.AUTHOR else "Anthropic")
            reply["choices"][0]["message"]["tool_calls"][0]["function"] = {
                "name": "submit_candidate", "arguments": json.dumps({"patch": "", "claimed_status": "blocked",
                    "evidence": ["accessibility probe only"]})}
            reply["usage"] = {"prompt_tokens": 100, "completion_tokens": 10, "total_tokens": 110,
                "prompt_tokens_details": {"cached_tokens": 0, "cache_write_tokens": 0},
                "completion_tokens_details": {"reasoning_tokens": 5}, "cost": 0.0003}
            if reject_reviewer and model == fvs_profile.REVIEWER:
                reply["usage"].pop("cost")
            return _ProviderReply(reply)

        def exchange(run, request):
            reply = provider_service.dispatch(run, request, run_token="synthetic-fvs-run-token")
            if invalid_companion:
                provider_service._journal_path(run, request["request_id"]).with_suffix(".failure").write_bytes(b"invalid companion")
            if lost_reply:
                raise worker.WorkerError("synthetic lost reply after paid completion")
            return reply

        with ExitStack() as stack:
            self.load_mock = stack.enter_context(mock.patch.object(experiment, "_load_prepared_inputs",
                                                                   return_value=self.prepared_inputs))
            self.prepare_mock = stack.enter_context(mock.patch.object(worker, "prepare_run", side_effect=prepare))
            stack.enter_context(mock.patch.object(provider_service, "start", side_effect=start))
            self.seed_mock = stack.enter_context(mock.patch.object(worker, "seed_dependency_cache",
                return_value={"cache_sha256": "b" * 64}, side_effect=seed_error))
            stack.enter_context(mock.patch.object(worker, "verify_egress", return_value={}))
            stack.enter_context(mock.patch.object(worker, "proxy_round", side_effect=exchange))
            stack.enter_context(mock.patch.object(preflight_runner, "_probe_distinct_verifier", return_value="lima:synthetic-verifier"))
            stack.enter_context(mock.patch.object(worker_runtime, "_docker", return_value=subprocess.CompletedProcess(
                ["synthetic-docker"], 0, _runner_raw(), b"")))
            self.destroy_mock = stack.enter_context(mock.patch.object(worker, "force_destroy_worker",
                side_effect=worker.WorkerError("synthetic cleanup failure") if cleanup_fails else None))
            # One opener seam for catalog GETs and paid POSTs; urllib.urlopen stays unmocked.
            self.fetch_mock = stack.enter_context(mock.patch.object(provider_transport, "_open_upstream",
                                                                    side_effect=fetch))
            for patch in patches:
                stack.enter_context(patch)
            return preflight_runner.run_fvs_preflight(self.target, self.config_path, output, **options)

    def test_cli_accepts_and_forwards_complete_prepared_inputs(self):
        argv = ["autofv", "preflight", "/target", "--config", "/config", "--output", "/output",
                "--env-file", "/env", "--preparation-manifest", "/manifest",
                "--preparation-evidence", "/probes", "--preparation-cache", "/cache",
                "--public-rust-root", "/rust", "--check-model-accessibility"]
        with mock.patch("sys.argv", argv), mock.patch.object(preflight_runner, "run_fvs_preflight",
                return_value={"status": "passed"}, create=True) as call, mock.patch("builtins.print"):
            experiment.main()
        call.assert_called_once_with("/target", "/config", "/output", env_file="/env",
            preparation_manifest="/manifest", probe_rust_evidence="/probes/probe-rust.json",
            probe_aeneas_evidence="/probes/probe-aeneas.json", dependency_cache="/cache",
            public_rust_root="/rust", check_model_accessibility=True)

    def test_sealed_only_does_not_dispatch_or_fetch_catalogs(self):
        self.inputs()
        result = self.exercise()
        self.assertEqual(result["status"], "passed")
        self.assertEqual(result["model_accessibility"], "not_requested")
        self.fetch_mock.assert_not_called()
        self.destroy_mock.assert_called_once_with(self.prepared_run)
        self.assertEqual(self.events[:2], ["listener_started", "worker_created"])
        with self.assertRaises(provider_config.ProviderConfigError):
            provider_config.provider_binding(self.prepared_run)

    def test_pair_uses_real_signed_service_and_keeps_exact_policies(self):
        self.inputs()
        result = self.exercise(check_model_accessibility=True)
        self.assertEqual(result["status"], "passed")
        self.assertEqual(result["model_accessibility"], "passed")
        self.assertEqual([x["model"] for x in self.requests], [fvs_profile.AUTHOR, fvs_profile.REVIEWER])
        self.assertEqual([x["tool_choice"] for x in self.requests], ["required", "auto"])
        self.assertEqual([x["max_tokens"] for x in self.requests], [16384, 8192])
        self.assertTrue(all(x["reasoning"] == {"effort": "xhigh", "exclude": True} for x in self.requests))
        self.assertEqual(result["reported_cost_usd"], "0.000600")
        self.assertEqual(set(result["provider_model_preflights"]), {fvs_profile.AUTHOR, fvs_profile.REVIEWER})
        for record in result["provider_model_preflights"].values():
            self.assertTrue(Path(record["path"]).is_file())
        self.assertTrue((self.output / "preflight-result.json").is_file())
        self.assertNotIn("provider-canary-secret", (self.output / "preflight-result.json").read_text())

    def test_post_call_pair_validation_reconstructs_fvs_identity(self):
        self.inputs()
        result = self.exercise(check_model_accessibility=True)
        self.assertEqual(set(result["provider_model_preflights"]), {fvs_profile.AUTHOR, fvs_profile.REVIEWER})
        for model_id, ref in result["provider_model_preflights"].items():
            with self.subTest(model=model_id):
                validated = preflight_runner.validate_reconstructed_provider_preflight(
                    ref["path"], bundle_path=self.output / "sealed/preflight-result.json",
                    env_file=self.options["env_file"])
                self.assertEqual(validated["status"], "passed")
                self.assertEqual(validated["preflight_sha256"], ref["preflight_sha256"])

    def test_post_call_reconstruction_rejects_foreign_binding_before_credentials(self):
        self.inputs()
        result = self.exercise(check_model_accessibility=True)
        path = Path(result["provider_model_preflights"][fvs_profile.AUTHOR]["path"])
        record = json.loads(path.read_bytes())
        binding = record["provider_binding"]
        binding["client_identity_sha256"] = "0" * 64
        binding["binding_sha256"] = fvs_profile.digest({k: v for k, v in binding.items() if k != "binding_sha256"})
        record["preflight_sha256"] = fvs_profile.digest({k: v for k, v in record.items() if k != "preflight_sha256"})
        path.write_bytes(contracts.canonical_json_bytes(record) + b"\n")
        provider_receipts.validate_preflight(path)  # Valid signed receipt, but a foreign binding commitment.
        with mock.patch.object(provider_config, "configure_provider") as credentials, \
             self.assertRaisesRegex(contracts.ContractError, "does not match sealed bundle"):
            preflight_runner.validate_reconstructed_provider_preflight(
                path, bundle_path=self.output / "sealed/preflight-result.json", env_file=self.options["env_file"])
        credentials.assert_not_called()

    def test_post_call_reconstruction_rejects_foreign_authorization_signer(self):
        self.inputs()
        result = self.exercise(check_model_accessibility=True)
        bundle_path = self.output / "sealed/preflight-result.json"
        bundle = json.loads(bundle_path.read_bytes())
        auth_path = Path(bundle["artifacts"]["authorization"])
        authorization = json.loads(auth_path.read_bytes())
        body = {k: v for k, v in authorization.items() if k != "auth"}
        foreign = Ed25519PrivateKey.generate()
        public = foreign.public_key()
        der = public.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        digest = hashlib.sha256(der).hexdigest()
        authentication = {"algorithm": "Ed25519", "key_id": f"autofv-provider-ed25519-{digest[:16]}",
            "public_key_der_sha256": digest, "public_key_pem": public.public_bytes(
                serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()}
        authorization["auth"] = {"algorithm": "Ed25519", "key_id": authentication["key_id"],
            "signature": base64.b64encode(foreign.sign(contracts.canonical_json_bytes(body))).decode()}
        raw = contracts.canonical_json_bytes(authorization) + b"\n"
        auth_path.write_bytes(raw)
        bundle["provider_authentication"] = authentication
        bundle["hashes"]["authorization_sha256"] = hashlib.sha256(raw).hexdigest()
        bundle_path.write_bytes(contracts.canonical_json_bytes(bundle) + b"\n")
        preflight_runner.validate_preflight_bundle(bundle_path)  # Locally consistent foreign signature.
        with mock.patch.object(provider_config, "configure_provider", wraps=provider_config.configure_provider) as credentials, \
             self.assertRaisesRegex(contracts.ContractError, "authorization signer"):
            preflight_runner.validate_reconstructed_provider_preflight(
                result["provider_model_preflights"][fvs_profile.AUTHOR]["path"],
                bundle_path=bundle_path, env_file=self.options["env_file"])
        credentials.assert_not_called()

    def test_post_call_reconstruction_keeps_signature_and_freshness_gates(self):
        self.inputs()
        result = self.exercise(check_model_accessibility=True)
        path = Path(result["provider_model_preflights"][fvs_profile.AUTHOR]["path"])
        original = path.read_bytes()
        record = json.loads(original)
        record["receipt"]["auth"]["signature"] = "invalid"
        record["preflight_sha256"] = fvs_profile.digest({k: v for k, v in record.items() if k != "preflight_sha256"})
        path.write_bytes(contracts.canonical_json_bytes(record) + b"\n")
        with mock.patch.object(provider_config, "configure_provider") as credentials, \
             self.assertRaises(provider_config.ProviderConfigError):
            preflight_runner.validate_reconstructed_provider_preflight(
                path, bundle_path=self.output / "sealed/preflight-result.json", env_file=self.options["env_file"])
        credentials.assert_not_called()
        path.write_bytes(original)
        completed = json.loads((self.output / "sealed/preflight-result.json").read_bytes())["completed_at_unix"]
        with mock.patch.object(preflight_runner.time, "time", return_value=completed + 301), \
             mock.patch.object(provider_config, "configure_provider") as credentials, \
             self.assertRaisesRegex(contracts.ContractError, "stale"):
            preflight_runner.validate_reconstructed_provider_preflight(
                path, bundle_path=self.output / "sealed/preflight-result.json", env_file=self.options["env_file"])
        credentials.assert_not_called()

    def test_same_worker_handoff_keeps_pair_cost_and_fresh_dispatch_gate(self):
        self.inputs()
        authorize = preflight_runner.authorize_prepared_run
        checked = []

        def handoff(run, repo, config_path, output, **kwargs):
            sealed = authorize(run, repo, config_path, output, **kwargs)
            _, config = contracts.validate_run_config(config_path)
            run.update(execution_mode="proof_only", fresh_pair_preflight=True)
            state = {**self.state, "run": run, "config": config, "run_round": model.agentproc.run_round,
                "receipt_rejections": [],
                "wall_started_monotonic_ns": preflight_runner.time.monotonic_ns(),
                "wall_started_epoch_ns": preflight_runner.time.time_ns(),
                "wall_seconds_used": Decimal(42), "finalization_reserve_seconds": Decimal(0)}
            path = preflight_runner.prepare_helper_handoff(state, Path(output) / "preflight-result.json")
            self.assertGreaterEqual(state["wall_seconds_used"], Decimal(42))
            self.assertEqual(state["cost"], Decimal("0.000600"))
            self.assertEqual(len(state["receipts"]), 2)
            self.assertEqual(len(self.requests), 2)
            self.destroy_mock.assert_not_called()
            self.assertIsNotNone(provider_config.provider_binding(run))
            selection = json.loads(path.read_bytes())
            self.assertFalse(selection["scope"]["spend_authorized"])
            experiment._bind_provider_selection(run, path)
            preflight_runner.validate_helper_handoff(run)
            foreign = _provider_run(self.root / "foreign-worker", contracts.load_toolchain_lock(), "c" * 40)
            foreign.update(run_id="synthetic-foreign-handoff-run", role_profile=config["role_profile"],
                           source_packet_sha256=config["source_packet"]["packet_sha256"], execution_mode="full")
            provider_config.configure_provider(foreign, env_path=self.options["env_file"],
                tool_schemas=list(agent_lane._TOOL_SCHEMAS), project_root=self.target)
            try:
                # Unsigned metadata cannot be the enforcement boundary.
                for strip_metadata in (False, True):
                    reused = copy.deepcopy(selection)
                    if strip_metadata:
                        reused.update(selected_by="ordinary", constraints={}, verification={})
                    reused_path = self.root / "reused-selection.json"
                    reused_path.write_bytes(contracts.canonical_json_bytes(reused) + b"\n")
                    with self.assertRaisesRegex(contracts.ContractError, "handoff"):
                        experiment._bind_provider_selection(dict(foreign, events=[]), reused_path)
                stripped = copy.deepcopy(selection)
                record = stripped["accessibility_evidence"][fvs_profile.AUTHOR]["provider_preflight"]
                record["request"]["input_hashes"].remove(preflight_runner.HELPER_HANDOFF_INPUT_SHA256)
                record["preflight_sha256"] = fvs_profile.digest({k: v for k, v in record.items() if k != "preflight_sha256"})
                reused_path.write_bytes(contracts.canonical_json_bytes(stripped) + b"\n")
                with self.assertRaises(provider_config.ProviderConfigError):
                    experiment._bind_provider_selection(dict(foreign, events=[]), reused_path)
                with self.assertRaisesRegex(contracts.ContractError, "handoff"):
                    experiment._bind_provider_selection(dict(run, execution_mode="full"), path)
            finally:
                provider_config.abort_configuration(foreign)
            # Only the first scored dispatch requires the still-fresh pair gate.
            messages = [{"role": "system", "content": "Synthetic helper context"},
                        {"role": "user", "content": "Synthetic helper request"}]
            with mock.patch.object(preflight_runner.time, "time", return_value=sealed["completed_at_unix"] + 301):
                with self.assertRaisesRegex(contracts.ContractError, "stale"):
                    experiment._bind_provider_selection(run, path)
                with self.assertRaisesRegex(provider_config.ProviderConfigError, "handoff"):
                    model._model_request(state, request_id="stale-helper", role="scout", input_hashes=[], messages=messages)
            self.assertEqual(len(self.requests), 2)
            state["pending_model_exchanges"].pop("stale-helper", None)
            model._model_request(state, request_id="fresh-helper", role="scout", input_hashes=[], messages=messages)
            self.assertEqual(len(self.requests), 3)
            self.assertEqual(state["cost"], Decimal("0.000900"))
            with mock.patch.object(preflight_runner.time, "time", return_value=sealed["completed_at_unix"] + 301):
                model._model_request(state, request_id="continuing-helper", role="scout", input_hashes=[], messages=messages)
            self.assertEqual(state["cost"], Decimal("0.001200"))
            self.assertEqual(len(state["receipts"]), 4)
            checked.append(run["helper_handoff"]["first_scored_request_id"])
            return sealed

        result = self.exercise(patches=[
            mock.patch.object(preflight_runner, "authorize_prepared_run", side_effect=handoff),
            mock.patch.object(preflight_runner, "_preflight_deadline", side_effect=lambda _state: nullcontext()),
        ])
        self.assertEqual(result["status"], "passed", result.get("error_detail"))
        self.assertEqual(checked, ["fresh-helper"])
        self.destroy_mock.assert_called_once_with(self.prepared_run)

    def test_handoff_subcap_rejects_before_paid_calls_and_cleans_worker(self):
        self.inputs()
        authorize = preflight_runner.authorize_prepared_run

        def handoff(run, repo, config_path, output, **kwargs):
            authorize(run, repo, config_path, output, **kwargs)
            _, config = contracts.validate_run_config(config_path)
            run.update(execution_mode="proof_only", fresh_pair_preflight=True)
            state = {**self.state, "run": run, "config": config, "receipt_rejections": [],
                "wall_started_monotonic_ns": preflight_runner.time.monotonic_ns(),
                "wall_started_epoch_ns": preflight_runner.time.time_ns(),
                "wall_seconds_used": Decimal(0), "finalization_reserve_seconds": Decimal(0)}
            with mock.patch("autofv.worker_proxy.provider_reservation_usd", return_value=Decimal("0.60")):
                return preflight_runner.prepare_helper_handoff(state, Path(output) / "preflight-result.json")

        result = self.exercise(patches=[
            mock.patch.object(preflight_runner, "authorize_prepared_run", side_effect=handoff),
            mock.patch.object(preflight_runner, "_preflight_deadline", side_effect=lambda _state: nullcontext()),
        ])
        self.assertEqual(result["status"], "failed")
        self.assertIn("USD1 sub-limit", result["error_detail"])
        self.assertEqual(self.requests, [])
        self.destroy_mock.assert_called_once_with(self.prepared_run)
        self.assertEqual(result["service_release"], "released")
        self.assertNotIn("helper_handoff", self.prepared_run)

    def test_public_helper_controller_prepares_once_and_hands_off_before_graph(self):
        self.inputs()
        self.prepared_inputs = (*self.prepared_inputs[:3],
            {k: str(v) for k, v in self.prepared_inputs[3].items()})
        for name in ("preparation_manifest", "probe_rust_evidence", "probe_aeneas_evidence", "dependency_cache"):
            self.options[name].touch()
        reference = self.root / "synthetic-reference.json"
        reference.write_text("{}")
        captured = []

        def run_controller(repo, config_path, output, **options):
            options.pop("check_model_accessibility", None)
            return experiment.run_experiment(repo, config_path, output_root=self.root / "attempts",
                verifier_reference=reference, execution_mode="proof_only", fresh_pair_preflight=True, **options)

        def graph(state, **_kwargs):
            self.prepare_mock.assert_called_once()
            self.seed_mock.assert_called_once()
            self.destroy_mock.assert_not_called()
            self.assertEqual(state["cost"], Decimal("0.000600"))
            self.assertTrue(state["run"]["fresh_pair_preflight"])
            self.assertIn("provider_selected", state["run"]["events"])
            model._model_request(state, request_id="controller-first-helper", role="scout", input_hashes=[],
                messages=[{"role": "system", "content": "Synthetic context"}, {"role": "user", "content": "Synthetic helper"}])
            self.assertEqual(state["cost"], Decimal("0.000900"))
            self.assertEqual(len(state["receipts"]), 3)
            state["verifier_report"] = {"terminal_status": "unverified"}
            captured.append(state)
            return []

        with mock.patch.object(preflight_runner, "run_fvs_preflight", side_effect=run_controller), \
             mock.patch.object(experiment.verifier, "bind_prepared_reference", return_value={"synthetic": True}), \
             mock.patch.object(experiment.verifier.counterexample, "external_reference_identity", return_value={"synthetic": True}), \
             mock.patch.object(experiment._EXPERIMENT_GRAPH, "stream", side_effect=graph), \
             mock.patch.object(experiment, "_checkpoint_if_enabled"), \
             mock.patch.object(model, "_checkpoint_if_enabled"), \
             mock.patch.object(run_state, "_checkpoint_if_enabled"), \
             mock.patch.object(experiment, "_final_terminal_audit"), \
             mock.patch.object(experiment, "_finish_attempt", return_value={"outcome": "unverified"}) as finish:
            result = self.exercise()
        self.assertEqual(result["outcome"], "unverified")
        self.assertEqual(len(captured), 1, (finish.call_args.args[1].get("termination_detail"),
                                          finish.call_args.args[0].get("events")))
        self.assertEqual(captured[0]["run"]["helper_handoff"]["first_scored_request_id"], "controller-first-helper")
        finish.assert_called_once()
        self.assertEqual(finish.call_args.kwargs["reason"], "proof_search_incomplete")
        provider_config.abort_configuration(self.prepared_run)

    def test_public_rust_drift_is_rejected_before_worker_or_credentials(self):
        self.inputs()
        (self.options["public_rust_root"] / "increment.rs").write_text("fabricated public Rust\n")
        with self.assertRaisesRegex(contracts.ContractError, "Rust"), mock.patch.object(preflight_runner,
                "configure_prepared_provider") as credentials:
            self.exercise()
        self.prepare_mock.assert_not_called()
        credentials.assert_not_called()
        self.fetch_mock.assert_not_called()
        self.assertFalse(self.output.exists())

    def test_budget_reserves_both_calls_before_any_dispatch(self):
        self.inputs()
        self.config["max_cost_usd"] = "0.000001"
        self.config_path.write_bytes(contracts.canonical_json_bytes(self.config) + b"\n")
        result = self.exercise(check_model_accessibility=True)
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["error_type"], "BudgetExhausted")
        self.assertEqual(self.requests, [])
        self.destroy_mock.assert_called_once_with(self.prepared_run)

    def test_unknown_endpoint_variant_is_rejected_before_paid_requests(self):
        self.inputs()
        result = self.exercise(check_model_accessibility=True, bad_catalog=True)
        self.assertEqual(result["status"], "failed")
        self.assertEqual(self.requests, [])
        self.destroy_mock.assert_called_once_with(self.prepared_run)

    def test_rejected_second_call_retains_first_receipt_and_liability_without_retry(self):
        self.inputs()
        result = self.exercise(check_model_accessibility=True, reject_reviewer=True)
        self.assertEqual(result["status"], "failed")
        self.assertEqual(len(self.requests), 2)
        self.assertEqual(result["reported_cost_usd"], "0.000300")
        self.assertEqual(len(result["provider_model_preflights"]), 1)
        self.assertGreater(Decimal(result["unresolved_dispatched_liability_usd"]), 0)
        self.assertEqual(Decimal(result["undispatched_reservation_usd"]), 0)
        self.assertTrue((self.output / "accounting.json").is_file())
        self.destroy_mock.assert_called_once_with(self.prepared_run)

    def test_network_failure_metadata_exports_without_clearing_liability(self):
        self.inputs()
        result = self.exercise(check_model_accessibility=True, network_error=True)
        self.assertEqual(result["status"], "failed")
        self.assertEqual(len(self.requests), 1)
        self.assertEqual(Decimal(result["reported_cost_usd"]), 0)
        self.assertGreater(Decimal(result["unresolved_dispatched_liability_usd"]), 0)
        self.assertGreater(Decimal(result["undispatched_reservation_usd"]), 0)
        self.assertFalse(result["provider_model_preflights"])
        raw = (self.output / "accounting.json").read_bytes()
        accounting = json.loads(raw)
        request_id = "preflight-accessibility-scout"
        self.assertEqual(accounting["provider_journal"][request_id]["status"], "dispatched")
        diagnostic = accounting["provider_failure_metadata"][request_id]
        self.assertEqual(diagnostic["response"]["provider_response"]["transport_error_type"], type(OSError(61, "synthetic")).__name__)
        self.assertEqual(diagnostic["response"]["provider_response"]["transport_errno"], 61)
        self.assertIsNone(diagnostic["receipt"])
        self.assertNotIn(b"private synthetic network context", raw)
        self.assertNotIn(b"private synthetic network context", (self.output / "preflight-result.json").read_bytes())

    def test_cleanup_failure_never_reports_success_or_drops_records(self):
        self.inputs()
        result = self.exercise(check_model_accessibility=True, cleanup_fails=True)
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["cleanup"], "failed")
        self.assertEqual(len(result["provider_model_preflights"]), 2)
        with self.assertRaises(provider_config.ProviderConfigError):
            provider_config.provider_binding(self.prepared_run)

    def test_redirected_catalog_is_rejected_before_paid_requests(self):
        self.inputs()
        result = self.exercise(check_model_accessibility=True, redirect=True)
        self.assertEqual(result["status"], "failed")
        self.assertEqual(self.requests, [])
        self.destroy_mock.assert_called_once_with(self.prepared_run)

    def test_completed_but_lost_reply_is_charged_and_not_retried(self):
        self.inputs()
        result = self.exercise(check_model_accessibility=True, lost_reply=True)
        self.assertEqual(result["status"], "failed")
        self.assertEqual(len(self.requests), 1)
        self.assertEqual(Decimal(result["reported_cost_usd"]), Decimal("0.000300"))
        self.assertEqual(Decimal(result["unresolved_dispatched_liability_usd"]), 0)
        self.assertGreater(Decimal(result["undispatched_reservation_usd"]), 0)
        self.assertEqual(len(result["provider_model_preflights"]), 1)

    def test_invalid_companion_cannot_suppress_completed_journal_cost_recovery(self):
        self.inputs()
        result = self.exercise(check_model_accessibility=True, lost_reply=True, invalid_companion=True)
        self.assertEqual(result["status"], "failed")
        self.assertEqual(len(self.requests), 1)
        self.assertEqual(Decimal(result["reported_cost_usd"]), Decimal("0.000300"))
        self.assertEqual(Decimal(result["unresolved_dispatched_liability_usd"]), 0)
        self.assertGreater(Decimal(result["undispatched_reservation_usd"]), 0)
        accounting = json.loads((self.output / "accounting.json").read_bytes())
        request_id = "preflight-accessibility-scout"
        self.assertEqual(accounting["provider_journal"][request_id]["status"], "completed")
        self.assertEqual(len(accounting["receipts"]), 1)
        self.assertFalse(accounting["journal_failures"])
        self.assertEqual(accounting["failure_metadata_failures"][request_id], "invalid_failure_companion")
        self.assertNotIn(request_id, accounting["provider_failure_metadata"])

    def test_companion_stat_error_cannot_skip_charge_export_and_provider_release(self):
        self.inputs()
        original_exists = Path.exists

        def faulty_exists(path):
            if path.suffix == ".failure":
                raise OSError(5, "synthetic diagnostic stat failure")
            return original_exists(path)

        result = self.exercise(check_model_accessibility=True, lost_reply=True,
            patches=(mock.patch.object(Path, "exists", faulty_exists),))
        self.assertEqual(result["status"], "failed")
        self.assertEqual(Decimal(result["reported_cost_usd"]), Decimal("0.000300"))
        self.assertEqual(result["cleanup"], "disposed")
        self.assertEqual(result["service_release"], "released")
        with self.assertRaises(provider_config.ProviderConfigError):
            provider_config.provider_binding(self.prepared_run)
        accounting = json.loads((self.output / "accounting.json").read_bytes())
        request_id = "preflight-accessibility-scout"
        self.assertEqual(accounting["provider_journal"][request_id]["status"], "completed")
        self.assertEqual(len(accounting["receipts"]), 1)
        self.assertFalse(accounting["journal_failures"])
        self.assertEqual(accounting["failure_metadata_failures"][request_id], "invalid_failure_companion")
        self.assertTrue((self.output / "preflight-result.json").is_file())

    def test_error_detail_does_not_export_suppressed_context_but_scans_its_secrets(self):
        try:
            try:
                raise OSError("private suppressed provider context")
            except OSError:
                raise provider_transport.ProviderError("provider upstream_error") from None
        except provider_transport.ProviderError as error:
            self.assertNotIn("private suppressed", preflight_runner._error_detail(error, ()))
            self.assertEqual(preflight_runner._error_detail(error, (b"private suppressed",)),
                             "redacted: provider credential marker matched")

    def test_partial_cli_inputs_are_rejected_without_launch(self):
        with mock.patch("sys.argv", ["autofv", "preflight", "/target", "--config", "/config",
                "--output", "/output", "--check-model-accessibility"]), \
             mock.patch.object(preflight_runner, "run_fvs_preflight") as prepared, \
             mock.patch.object(preflight_runner, "run_preflight") as legacy, \
             mock.patch("sys.stderr"), self.assertRaises(SystemExit) as error:
            experiment.main()
        self.assertEqual(error.exception.code, 2)
        prepared.assert_not_called()
        legacy.assert_not_called()

    def test_symlinked_output_parent_cannot_write_inside_target(self):
        self.inputs()
        alias = self.root / "output-alias"
        alias.symlink_to(self.target, target_is_directory=True)
        with self.assertRaisesRegex(contracts.ContractError, "outside the target"), \
             mock.patch.object(worker, "prepare_run") as prepare:
            self.exercise(output=alias / "evidence")
        prepare.assert_not_called()
        self.assertFalse((self.target / "evidence").exists())
        with self.assertRaisesRegex(contracts.ContractError, "outside the target"):
            preflight_runner.run_preflight(self.target, self.config_path, alias / "evidence",
                public_rust_root=self.options["public_rust_root"],
                _prepared_run={"preparation_manifest": self.prepared_inputs[0]})

    def test_wall_failure_preserves_failure_and_disposes_worker(self):
        self.inputs()
        result = self.exercise(check_model_accessibility=True, expired=True)
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["error_type"], "BudgetExhausted")
        self.assertEqual(self.requests, [])
        self.destroy_mock.assert_called_once_with(self.prepared_run)
        self.assertTrue((self.output / "preflight-result.json").is_file())

    def test_active_work_alarm_is_restored_after_expiry(self):
        state = {"run": {}, "config": {"max_wall_seconds": 10},
                 "finalization_reserve_seconds": Decimal(1)}
        with mock.patch.object(preflight_runner.signal, "getitimer", return_value=(0, 0)), \
             mock.patch.object(preflight_runner.signal, "signal") as handler, \
             mock.patch.object(preflight_runner.signal, "setitimer") as timer:
            with self.assertRaises(contracts.BudgetExhausted):
                with preflight_runner._preflight_deadline(state):
                    alarm = next(call.args[1] for call in handler.call_args_list if call.args[0] == signal.SIGALRM)
                    alarm(None, None)
        self.assertEqual(timer.call_args_list[0].args[1], 9)
        self.assertEqual(timer.call_args_list[-1].args[1], 0)
        self.assertEqual(sum(call.args[0] == signal.SIGALRM for call in handler.call_args_list), 2)

    def test_handoff_deadline_uses_only_remaining_shared_wall(self):
        state = {"run": {}, "config": {"max_wall_seconds": 1800},
            "wall_seconds_used": Decimal(1700), "finalization_reserve_seconds": Decimal(5),
            "wall_started_monotonic_ns": 1_000_000_000, "wall_started_epoch_ns": 101_000_000_000}
        with mock.patch.object(preflight_runner.signal, "getitimer", return_value=(0, 0)), \
             mock.patch.object(preflight_runner.signal, "signal"), \
             mock.patch.object(preflight_runner.signal, "setitimer") as timer, \
             mock.patch.object(run_state.time, "monotonic_ns", return_value=4_000_000_000), \
             mock.patch.object(run_state.time, "time_ns", return_value=104_000_000_000):
            with preflight_runner._preflight_deadline(state):
                self.assertEqual(timer.call_args_list[0].args[1], 92)
                self.assertEqual(state["wall_seconds_used"], Decimal(1703))
            timer.reset_mock()
            state["wall_seconds_used"] = Decimal(1795)
            with self.assertRaises(contracts.ContractError):
                with preflight_runner._preflight_deadline(state):
                    self.fail("exhausted shared wall entered handoff")
            timer.assert_not_called()

    def test_endpoint_metadata_rejects_exact_mode_price_and_fee_drift(self):
        mutations = [lambda e: e["data"]["endpoints"][0]["supports_tool_choice"].update(required=False),
                     lambda e: e["data"]["endpoints"][0]["supports_tool_choice"].update(required="true"),
                     lambda e: e["data"]["endpoints"][0]["pricing"].update(prompt="0.000001"),
                     lambda e: e["data"]["endpoints"][0]["pricing"]["overrides"][0].update(unknown_fee="1")]
        for mutate in mutations:
            with self.subTest(mutation=mutate):
                document = endpoint(fvs_profile.AUTHOR)
                mutate(document)
                with self.assertRaises(contracts.ContractError):
                    fvs_profile.public_endpoint_inventory(fvs_profile.AUTHOR, document)

    def test_cap_between_largest_single_and_pair_reservation_dispatches_nothing(self):
        self.inputs()
        self.exercise(check_model_accessibility=True)
        planned = json.loads((self.output / "accounting.json").read_text())["planned_reservations_usd"]
        smaller, larger = sorted(Decimal(value) for value in planned.values())
        self.config["max_cost_usd"] = f"{larger + smaller / 2:.6f}"
        self.assertTrue(larger < Decimal(self.config["max_cost_usd"]) < smaller + larger)
        self.config_path.write_bytes(contracts.canonical_json_bytes(self.config) + b"\n")
        sent = len(self.requests)
        result = self.exercise(check_model_accessibility=True)
        self.assertEqual((result["status"], result["error_type"], result["phase"]),
                         ("failed", "BudgetExhausted", "pair_reservation"))
        self.assertEqual(len(self.requests), sent)
        self.assertEqual(Decimal(result["reported_cost_usd"]), 0)

    def test_prepared_inputs_full_mode_and_public_root_are_forwarded_exactly(self):
        self.inputs()
        authorize = mock.patch.object(preflight_runner, "authorize_prepared_run",
                                      wraps=preflight_runner.authorize_prepared_run)
        bind = mock.patch.object(fvs_packet, "bind_original", wraps=fvs_packet.bind_original)
        with authorize as authorized, bind as bound:
            result = self.exercise(patches=())
        self.assertEqual(result["status"], "passed")
        self.assertEqual(result["execution_mode"], "full")
        o = self.options
        self.load_mock.assert_called_once_with(self.target, self.manifest, o["preparation_manifest"],
            o["probe_rust_evidence"], o["probe_aeneas_evidence"], o["dependency_cache"], execution_mode="full")
        self.seed_mock.assert_called_once_with(self.prepared_run, o["dependency_cache"], "b" * 64)
        self.assertEqual(authorized.call_args.kwargs["public_rust_root"], o["public_rust_root"])
        self.assertEqual(authorized.call_args.kwargs["env_file"], o["env_file"])
        self.assertEqual(len(bound.call_args_list), 2)
        self.assertTrue(all(call.kwargs["rust_root"] == Path(o["public_rust_root"]) for call in bound.call_args_list))

    def test_retained_records_assemble_into_a_selection_a_fresh_binding_accepts(self):
        self.inputs()
        result = self.exercise(check_model_accessibility=True)
        self.assertEqual(result["status"], "passed")
        inventory = json.loads((self.output / "public-metadata" / "inventory.json").read_text())
        evidence = {}
        for model_id, item in inventory["models"].items():
            record = json.loads(Path(result["provider_model_preflights"][model_id]["path"]).read_text())
            # Exact projection: the rich inventory keeps endpoint_catalog_sha256 as provenance only.
            evidence[model_id] = {**{k: item[k] for k in ("endpoint_inventory", "supported_parameters",
                                                          "supported_efforts", "catalog_sha256")},
                                  "provider_preflight": record}
        fresh = _provider_run(self.root / "fresh", contracts.load_toolchain_lock(), "c" * 40)
        fresh.update(role_profile=self.config["role_profile"],
                     source_packet_sha256=self.config["source_packet"]["packet_sha256"])
        provider_config.configure_provider(fresh, env_path=self.options["env_file"],
            tool_schemas=list(agent_lane._TOOL_SCHEMAS), project_root=self.target)
        self.addCleanup(provider_config.release_provider, fresh)
        public = provider_config.provider_binding(fresh).public
        fields = {"model_id", "endpoint", "endpoint_sha256", "parameters", "pricing", "pricing_sha256",
                  "tool_schema_sha256", "capability_sha256", "fixed_proxy_sha256", "proxy_id", "route_id",
                  "role_profile", "role_profile_sha256", "source_packet_sha256"}
        # A proposal only: no owner approval is invented and no request or spend is authorized.
        selection = {"schema": "autofv-retained-model-selection/v2", "status": "selected",
            "selected_at": "synthetic-test", "selected_by": "synthetic-test-not-owner-approval",
            "decision": "select-model", "scope": {"proof_smoke": True, "full_retained_run": True,
                "provider_request_authorized": False, "spend_authorized": False, "push_authorized": False,
                "dynamic_routing_allowed": False, "model_substitution_allowed": False},
            "model": {k: public[k] for k in fields}, "accessibility_evidence": evidence,
            "constraints": {}, "verification": {}}
        path = self.root / "assembled-selection.json"
        path.write_bytes(contracts.canonical_json_bytes(selection) + b"\n")
        experiment._bind_provider_selection(dict(fresh, events=[]), path)
        author, reviewer = fvs_profile.AUTHOR, fvs_profile.REVIEWER
        mutations = {
            "unprojected inventory": ("accessibility", lambda s: s["accessibility_evidence"][author].update(
                endpoint_catalog_sha256=inventory["models"][author]["endpoint_catalog_sha256"])),
            "swapped records": ("wrong-model", lambda s: s["accessibility_evidence"][author].update(
                provider_preflight=evidence[reviewer]["provider_preflight"])),
            "tampered record": ("hash mismatch", lambda s: s["accessibility_evidence"][reviewer][
                "provider_preflight"]["request"].update(role="scout")),
            "spend authorized": ("scope mismatch", lambda s: s["scope"].update(spend_authorized=True))}
        for name, (reason, mutate) in mutations.items():
            with self.subTest(mutation=name):
                bad = copy.deepcopy(selection)
                mutate(bad)
                path.write_bytes(contracts.canonical_json_bytes(bad) + b"\n")
                # A fresh run each time, so no rejection is the replay-drift guard.
                with self.assertRaisesRegex((contracts.ContractError, provider_config.ProviderConfigError), reason):
                    experiment._bind_provider_selection(dict(fresh, events=[]), path)

    def test_failed_sealed_suite_stops_listener_for_standalone_and_controller_callers(self):
        self.inputs()
        original, digests = preflight_runner.configure_prepared_provider, []

        def configure(run, *args, **kwargs):
            value = original(run, *args, **kwargs)
            digests.append(run["provider_binding_sha256"])
            provider_service._SERVICES[digests[-1]] = object()  # Inert: no listener/socket/thread.
            return value

        self.addCleanup(lambda: [provider_service._SERVICES.pop(key, None) for key in digests])
        failing = [mock.patch.object(preflight_runner, "validate_runner_result",
                                     side_effect=contracts.ContractError("synthetic sealed failure")),
                   mock.patch.object(provider_service, "_stop_service")]
        with mock.patch.object(preflight_runner, "configure_prepared_provider", side_effect=configure):
            result = self.exercise(patches=failing)
        self.assertEqual((result["status"], result["phase"]), ("failed", "sealed_suite"))
        self.assertEqual((result["cleanup"], result["service_release"]), ("disposed", "released"))
        self.assertIn("synthetic sealed failure", result["error_detail"])
        self.assertFalse(any(key in provider_service._SERVICES for key in digests))
        # Controller shape: run_experiment authorizes an already allocated, retained worker.
        run = _provider_run(self.root / "controller", contracts.load_toolchain_lock(), "c" * 40)
        run.update(role_profile=self.config["role_profile"], preparation_manifest=self.prepared_inputs[0],
                   source_packet_sha256=self.config["source_packet"]["packet_sha256"],
                   snapshot_sha256=worker.hash_tree(self.target), manifest_sha256=fvs_profile.digest(self.manifest))
        configure(run, self.target, env_file=self.options["env_file"])
        with ExitStack() as stack:
            for patch in failing:
                stack.enter_context(patch)
            stack.enter_context(mock.patch.object(preflight_runner, "_probe_distinct_verifier", return_value="lima:v"))
            stack.enter_context(mock.patch.object(worker_runtime, "_docker", return_value=subprocess.CompletedProcess(
                ["synthetic-docker"], 0, _runner_raw(), b"")))
            with self.assertRaisesRegex(contracts.ContractError, "synthetic sealed failure"):
                preflight_runner.authorize_prepared_run(run, self.target, self.config_path, self.root / "controller-out",
                    env_file=self.options["env_file"], max_age_seconds=600,
                    public_rust_root=self.options["public_rust_root"])
        self.assertNotIn(digests[-1], provider_service._SERVICES)

    def test_raced_output_claim_propagates_and_never_replaces_unowned_evidence(self):
        self.inputs()
        destination, original = self.root / "preflight-0", Path.mkdir
        sentinel = b"another run owns this evidence\n"

        def raced_mkdir(path, *args, **kwargs):
            if path == destination:
                original(path, *args, **kwargs)
                (path / "preflight-result.json").write_bytes(sentinel)
                (path / "accounting.json").write_bytes(sentinel)
                raise FileExistsError("synthetic concurrent output claim")
            return original(path, *args, **kwargs)

        with mock.patch.object(Path, "mkdir", new=raced_mkdir), self.assertRaises(FileExistsError):
            self.exercise()
        self.assertEqual((destination / "preflight-result.json").read_bytes(), sentinel)
        self.assertEqual((destination / "accounting.json").read_bytes(), sentinel)
        self.prepare_mock.assert_not_called()

    def deliver_alarm_during(self, state, commit):
        """Fire the installed handler inside one state commit, then once after it."""
        with mock.patch.object(preflight_runner.signal, "getitimer", return_value=(0, 0)), \
             mock.patch.object(preflight_runner.signal, "signal") as handler, \
             mock.patch.object(preflight_runner.signal, "setitimer") as timer:
            with self.assertRaises(contracts.BudgetExhausted):
                with preflight_runner._preflight_deadline(state):
                    alarm = next(call.args[1] for call in handler.call_args_list if call.args[0] == signal.SIGALRM)
                    commit(alarm)
                    self.assertEqual(timer.call_args_list[-1].args[1], 0.05, "expiry was not deferred")
                    alarm(signal.SIGALRM, None)  # Redelivered once the lock is released.
        self.assertEqual(timer.call_args_list[-1].args[1], 0)

    def test_alarm_inside_wall_reduction_is_redelivered_after_a_complete_reduction(self):
        state = _AlarmOnWrite(run={}, config={"max_wall_seconds": 10}, key="wall_started_epoch_ns",
            finalization_reserve_seconds=Decimal(1), wall_seconds_used=Decimal(0),
            wall_started_monotonic_ns=0, wall_started_epoch_ns=0)

        def reduce(alarm):
            state.alarm = alarm
            run_state._charge_wall(state)

        with mock.patch.object(run_state.time, "monotonic_ns", return_value=1000000000), \
             mock.patch.object(run_state.time, "time_ns", return_value=1000000000):
            self.deliver_alarm_during(state, reduce)
        self.assertIsNone(state.alarm)
        self.assertEqual((state["wall_seconds_used"], state["wall_started_monotonic_ns"]),
                         (Decimal(1), 1000000000))

    def test_alarm_inside_receipt_commit_charges_and_records_exactly_once(self):
        case = fixtures.FvsOfflineTests("test_role_routing_and_upstream_parameters_are_bound")
        case.setUp()
        self.addCleanup(case.doCleanups)
        exchange = case.exchange()
        state = _AlarmOnWrite(case.state, key="cost",
            finalization_reserve_seconds=run_state._finalization_reserve(case.state["config"]))

        def accept(alarm):
            state.alarm = alarm
            model._accept_model_exchange(state, exchange["request"], exchange["response"], exchange["receipt"],
                                         enforce_budget=False, allow_out_of_order=True)

        self.deliver_alarm_during(state, accept)
        # run_fvs_preflight's journal recovery only re-accepts exchanges that were never committed.
        self.assertIn(exchange["request"]["request_id"], state["model_exchanges"])
        self.assertEqual(state["cost"], Decimal("0.000300"))
        self.assertEqual([r["receipt_sha256"] for r in state["receipts"]], [exchange["receipt"]["receipt_sha256"]])

    def test_alarm_inside_pair_reservation_reserves_both_calls_once(self):
        case = fixtures.FvsOfflineTests("test_role_routing_and_upstream_parameters_are_bound")
        case.setUp()
        self.addCleanup(case.doCleanups)
        pending = _AlarmOnWrite()
        state = {**case.state, "pending_model_exchanges": pending,
                 "finalization_reserve_seconds": run_state._finalization_reserve(case.state["config"])}
        messages = [{"role": "system", "content": "Synthetic reservation probe."},
                    {"role": "user", "content": "Return a blocked submission."}]
        calls = [(model._model_envelope(state, request_id="reserve-" + role, role=role,
                  input_hashes=model._message_bound_hashes([], messages), sequence=sequence), messages, "explicit")
                 for sequence, role in enumerate(("scout", "spec_reviewer"), 1)]

        def reserve(alarm):
            pending.alarm = alarm
            model._reserve_provider_calls(state, calls)

        self.deliver_alarm_during(state, reserve)
        self.assertIsNone(pending.alarm, "fault injection must reach the commit")
        self.assertEqual(sorted(pending), ["reserve-scout", "reserve-spec_reviewer"])
        self.assertTrue(all(item["dispatch_state"] == "reserved" for item in pending.values()))
        model._reserve_provider_calls(state, calls)  # Replayed reservation is idempotent.
        self.assertEqual(state["pending_model_exchanges"], pending)

    def test_keyboard_interrupt_cannot_double_charge_receipt_recovery(self):
        case = fixtures.FvsOfflineTests("test_role_routing_and_upstream_parameters_are_bound")
        case.setUp()
        self.addCleanup(case.doCleanups)
        exchange = case.exchange()
        state = _AlarmOnWrite(case.state, key="cost")

        def interrupt(*_args):
            signal.raise_signal(signal.SIGINT)

        state.alarm = interrupt
        with self.assertRaises(KeyboardInterrupt):
            model._accept_model_exchange(state, exchange["request"], exchange["response"], exchange["receipt"],
                                         enforce_budget=False, allow_out_of_order=True)
        self.assertIsNone(state.alarm, "fault injection must reach the commit")
        # Exactly the completed-journal recovery condition, not an unconditional replay.
        if exchange["request"]["request_id"] not in state["model_exchanges"]:
            model._accept_model_exchange(state, exchange["request"], exchange["response"], exchange["receipt"],
                                         enforce_budget=False, allow_out_of_order=True)
        self.assertEqual(state["cost"], Decimal("0.000300"))
        self.assertEqual(len(state["receipts"]), 1)
        self.assertIn(exchange["request"]["request_id"], state["model_exchanges"])

    def test_keyboard_interrupt_cannot_lose_elapsed_wall_time(self):
        state = _AlarmOnWrite(run={}, config={"max_wall_seconds": 10}, key="wall_started_epoch_ns",
            wall_seconds_used=Decimal(0), wall_started_monotonic_ns=0, wall_started_epoch_ns=0)

        def interrupt(*_args):
            signal.raise_signal(signal.SIGINT)

        state.alarm = interrupt
        with mock.patch.object(run_state.time, "monotonic_ns", return_value=1000000000), \
             mock.patch.object(run_state.time, "time_ns", return_value=1000000000), \
             self.assertRaises(KeyboardInterrupt):
            run_state._charge_wall(state)
        self.assertIsNone(state.alarm, "fault injection must reach the commit")
        with mock.patch.object(run_state.time, "monotonic_ns", return_value=2000000000), \
             mock.patch.object(run_state.time, "time_ns", return_value=2000000000):
            run_state._charge_wall(state)
        self.assertEqual(state["wall_seconds_used"], Decimal(2))

    def test_interrupted_pair_reservation_is_retained_in_accounting(self):
        self.inputs()
        reserve = model._reserve_provider_calls

        def interrupted(*args, **kwargs):
            reserve(*args, **kwargs)
            raise KeyboardInterrupt

        result = self.exercise(check_model_accessibility=True, patches=[
            mock.patch.object(model, "_reserve_provider_calls", side_effect=interrupted)])
        accounting = json.loads((self.output / "accounting.json").read_bytes())
        pending = accounting["pending_model_exchanges"]
        self.assertEqual((result["status"], result["phase"]), ("failed", "pair_reservation"))
        self.assertEqual(len(pending), 2)
        self.assertEqual(self.requests, [])
        expected = {key: item["reservation_usd"] for key, item in pending.items()}
        self.assertEqual(accounting["planned_reservations_usd"], expected)
        self.assertEqual(Decimal(result["undispatched_reservation_usd"]),
                         sum(Decimal(amount) for amount in expected.values()))
        self.assertGreater(Decimal(result["undispatched_reservation_usd"]), 0)

    def test_failed_listener_release_keeps_liveness_visible_and_erases_credentials(self):
        self.inputs()
        configure = preflight_runner.configure_prepared_provider
        digests, bindings = [], []

        def register(run, *args, **kwargs):
            value = configure(run, *args, **kwargs)
            digests.append(run["provider_binding_sha256"])
            bindings.append(provider_config.provider_binding(run))
            provider_service._SERVICES[digests[-1]] = object()  # Inert; no sockets/threads.
            return value

        self.addCleanup(lambda: [provider_service._SERVICES.pop(key, None) for key in digests])
        with mock.patch.object(preflight_runner, "configure_prepared_provider", side_effect=register):
            result = self.exercise(patches=[mock.patch.object(provider_service, "_stop_service",
                                                            side_effect=KeyboardInterrupt)])
        self.assertEqual((result["status"], result["service_release"]), ("failed", "failed"))
        self.assertTrue(provider_service.is_running(digests[-1]), "failed stop must remain discoverable")
        self.assertIsNone(bindings[-1].signing_key)
        self.assertFalse(any(bindings[-1].api_key))
        self.assertFalse(any(bindings[-1].client_token))

    def test_listener_stop_timeout_cannot_report_success(self):
        service = mock.Mock()
        service.thread.is_alive.return_value = True
        with mock.patch.object(provider_service.threading, "Thread") as stopper:
            stopper.return_value.is_alive.return_value = False
            with self.assertRaises(provider_transport.ProviderError):
                provider_service._stop_service(service)
        service.server.server_close.assert_called_once()

    def test_listener_stop_interrupt_still_closes_sockets_and_joins(self):
        service = mock.Mock()
        with mock.patch.object(provider_service.threading, "Thread") as stopper:
            stopper.return_value.join.side_effect = KeyboardInterrupt
            with self.assertRaises(KeyboardInterrupt):
                provider_service._stop_service(service)
        service.server.close_active.assert_called_once()
        service.server.server_close.assert_called_once()
        service.thread.join.assert_called_once_with(timeout=1)

    def test_nonpositive_active_deadline_is_rejected_before_arming(self):
        state = {"run": {}, "config": {"max_wall_seconds": 1}, "finalization_reserve_seconds": Decimal(1)}
        with mock.patch.object(preflight_runner.signal, "getitimer", return_value=(0, 0)), \
             mock.patch.object(preflight_runner.signal, "setitimer") as timer, \
             self.assertRaisesRegex(contracts.ContractError, "positive"):
            with preflight_runner._preflight_deadline(state):
                pass
        timer.assert_not_called()

    def test_config_changed_during_authorization_is_rejected_before_dispatch(self):
        self.inputs()
        original = preflight_runner.authorize_prepared_run

        def drift(*args, **kwargs):
            value = original(*args, **kwargs)
            changed = {**self.config, "max_cost_usd": "0.900000"}
            self.config_path.write_bytes(contracts.canonical_json_bytes(changed) + b"\n")
            return value

        with mock.patch.object(preflight_runner, "authorize_prepared_run", side_effect=drift):
            result = self.exercise(check_model_accessibility=True)
        self.assertEqual((result["status"], result["phase"]), ("failed", "sealed_suite"))
        self.assertIn("configuration changed", result["error_detail"])
        self.assertEqual(self.requests, [])

    def test_error_detail_is_scanned_in_full_before_truncation(self):
        marker = b"provider-canary-secret"
        late = contracts.ContractError("x" * 5000 + marker.decode())
        self.assertTrue(preflight_runner._error_detail(late, (marker,)).startswith("redacted"))
        detail = preflight_runner._error_detail(contracts.ContractError("y" * 5000), (marker,))
        self.assertEqual(len(detail), 2000)

    def test_public_catalog_is_not_limited_like_a_paid_model_message(self):
        self.inputs()
        result = self.exercise(check_model_accessibility=True, extra_catalog_models=1000)
        self.assertEqual(result["status"], "passed", result)
        self.assertEqual(len(self.requests), 2)

    def test_deadline_failure_after_work_cannot_leave_a_passed_result(self):
        from contextlib import contextmanager

        @contextmanager
        def expired_on_exit(state):
            yield
            raise contracts.BudgetExhausted("wall_seconds", Decimal(600), Decimal(600))

        self.inputs()
        with mock.patch.object(preflight_runner, "_preflight_deadline", expired_on_exit):
            result = self.exercise()
        self.assertEqual(result["status"], "failed", result)
        self.assertEqual(result["error_type"], "BudgetExhausted")
        self.assertEqual(self.requests, [])

    def test_result_records_lifecycle_identities(self):
        self.inputs()
        result = self.exercise()
        self.assertEqual(result["run_id"], self.prepared_run["run_id"])
        self.assertEqual(result["retained_run_root"], self.prepared_run["run_root"])
        self.assertEqual((result["verifier_worker_id"], result["verifier_lifecycle"]),
                         ("lima:synthetic-verifier", "started_or_reused_and_retained"))
        self.assertEqual(result["service_release"], "released")


if __name__ == "__main__":
    unittest.main()
