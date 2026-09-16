from __future__ import annotations

import asyncio
import copy
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from autofv import (
    experiment,
    model,
    provider_config,
    provider_receipts,
    provider_service,
    provider_transport,
    worker,
    worker_proxy,
)
from tests.test_provider_receipts import (
    RUN_TOKEN,
    _environment,
    _messages,
    _Reply,
    _reply,
    _tools,
)
from tests.test_restart_budget import ENTRIES, LOCK, _checkpoint_state
from tests.test_results_evidence import _provider_attempt


def _provider_state(root: Path) -> tuple[dict, Path]:
    state = _checkpoint_state(root)
    state["run"]["fixed_proxy_sha256"] = provider_config.canonical_sha256(
        LOCK["fixed_proxy"]
    )
    environment = _environment(root, "provider-recovery-secret")
    with mock.patch.dict(os.environ, {"AUTOFV_RUN_TOKEN": RUN_TOKEN}, clear=False):
        provider_config.configure_provider(
            state["run"], env_path=environment, tool_schemas=_tools()
        )
    state["pending_model_exchanges"] = {}
    state["model_exchanges"] = {}
    state["receipt_rejections"] = []
    return state, environment


def _provider_exchange(state: dict, *, dispatch: bool = True):
    messages = _messages()
    request = model._model_envelope(
        state,
        request_id="provider-recovery-request-001",
        role="scout",
        input_hashes=[worker_proxy.provider_messages_sha256(messages)],
    )
    worker_proxy.stage_provider_messages(state["run"], request, messages)
    opener = mock.Mock(return_value=_Reply(_reply('{"path":"Diamond/Left.lean"}')))
    if not dispatch:
        opener.side_effect = RuntimeError("simulated interruption")
    with mock.patch("autofv.provider_transport._open_upstream", opener):
        if dispatch:
            response, receipt = provider_service.dispatch(
                state["run"], request, run_token=RUN_TOKEN
            )
            return messages, request, response, receipt, opener
        with unittest.TestCase().assertRaisesRegex(RuntimeError, "interruption"):
            provider_service.dispatch(state["run"], request, run_token=RUN_TOKEN)
    return messages, request, None, None, opener


def _install_transport_generation(
    run: dict, root: Path, *, marker: str, port: int = 19082
) -> bytes:
    address_suffix = 2 if marker == "a" else 3
    firewall = {
        "base": f"http://127.0.0.1:{port}",
        "network_id": marker * 64,
        "internal_address": f"172.18.0.{address_suffix}",
        "bridge_address": f"172.17.0.{address_suffix}",
        "upstream_address": "127.0.0.1",
        "upstream_port": port,
    }
    run["proxy_firewall"] = firewall
    run["proxy_network"] = f"fixture-volume-network-{marker}"
    run["proxy_relay"] = f"fixture-volume-relay-{marker}"
    egress = copy.deepcopy(run["egress_receipt"])
    policy = {
        key: value
        for key, value in egress["policy"].items()
        if key != "policy_sha256"
    }
    policy["firewall"] = {**firewall, "rules": []}
    egress["policy"] = {
        **policy,
        "policy_sha256": provider_config.canonical_sha256(policy),
    }
    egress.pop("evidence_sha256")
    egress["evidence_sha256"] = provider_config.canonical_sha256(egress)
    run["egress_policy_sha256"] = egress["policy"]["policy_sha256"]
    run["egress_receipt"] = egress
    run["upstream_policy_receipt"] = copy.deepcopy(egress["upstream_policy"])
    raw = experiment.canonical_json_bytes(egress) + b"\n"
    (root / "evidence" / "egress.json").write_bytes(raw)
    return raw


class ProviderRecoveryTests(unittest.TestCase):
    def test_transport_rebind_archives_authenticated_exact_bytes_before_rotation(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "run"
            run, _state = _provider_attempt(root)
            firewall = {
                "base": "http://127.0.0.1:19082",
                "network_id": "a" * 64,
                "internal_address": "172.18.0.2",
                "bridge_address": "172.17.0.2",
                "upstream_address": "127.0.0.1",
                "upstream_port": 19082,
            }
            run["proxy_firewall"] = firewall
            run["proxy_network"] = "fixture-volume-network"
            run["proxy_relay"] = "fixture-volume-relay"
            egress = copy.deepcopy(run["egress_receipt"])
            policy = {key: value for key, value in egress["policy"].items() if key != "policy_sha256"}
            policy["firewall"] = {**firewall, "rules": []}
            egress["policy"] = {
                **policy,
                "policy_sha256": provider_config.canonical_sha256(policy),
            }
            egress.pop("evidence_sha256")
            egress["evidence_sha256"] = provider_config.canonical_sha256(egress)
            run["egress_policy_sha256"] = egress["policy"]["policy_sha256"]
            run["egress_receipt"] = egress
            run["upstream_policy_receipt"] = copy.deepcopy(
                egress["upstream_policy"]
            )
            egress_path = root / "evidence" / "egress.json"
            egress_path.write_bytes(experiment.canonical_json_bytes(egress) + b"\n")
            originals = {
                name: (root / "evidence" / name).read_bytes()
                for name in ("fixed-proxy-policy.json", "egress.json")
            }

            worker_proxy.prepare_provider_transport_rebind(run)

            intent = run["provider_transport_rebind"]
            self.assertEqual(worker_proxy._provider_transport_intent(run), intent)
            history = worker_proxy._transport_history(run, intent)
            self.assertEqual(intent["phase"], "intent")
            for name, raw in originals.items():
                self.assertEqual((history / name).read_bytes(), raw)

    def test_transport_archive_distinguishes_authenticated_recovery_generations(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "run"
            run, _state = _provider_attempt(root)
            first_egress = _install_transport_generation(
                run, root, marker="a"
            )
            policy_sha256 = run["proxy_policy_sha256"]

            worker_proxy.prepare_provider_transport_rebind(run)
            first_intent = copy.deepcopy(run["provider_transport_rebind"])
            first_history = worker_proxy._transport_history(run, first_intent)

            second_egress = _install_transport_generation(
                run, root, marker="b"
            )
            self.assertEqual(run["proxy_policy_sha256"], policy_sha256)
            run["provider_transport_rebind"]["phase"] = "transport_restored"
            worker_proxy.finish_provider_transport_rebind(run)
            worker_proxy.prepare_provider_transport_rebind(run)

            second_intent = run["provider_transport_rebind"]
            second_history = worker_proxy._transport_history(run, second_intent)
            self.assertNotEqual(first_history, second_history)
            self.assertEqual(
                (first_history / "egress.json").read_bytes(), first_egress
            )
            self.assertEqual(
                (second_history / "egress.json").read_bytes(), second_egress
            )
            self.assertEqual(
                worker_proxy._provider_transport_intent(run), second_intent
            )

    def test_transport_archive_uses_complete_old_validation_identity_after_recreation(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "run"
            run, _state = _provider_attempt(root)
            firewall = {
                "base": "http://127.0.0.1:19082",
                "network_id": "a" * 64,
                "internal_address": "172.18.0.2",
                "bridge_address": "172.17.0.2",
                "upstream_address": "127.0.0.1",
                "upstream_port": 19082,
            }
            run["proxy_firewall"] = firewall
            run["proxy_network"] = "fixture-volume-network"
            run["proxy_relay"] = "fixture-volume-relay"
            egress = copy.deepcopy(run["egress_receipt"])
            policy = {
                key: value
                for key, value in egress["policy"].items()
                if key != "policy_sha256"
            }
            policy["firewall"] = {**firewall, "rules": []}
            egress["policy"] = {
                **policy,
                "policy_sha256": provider_config.canonical_sha256(policy),
            }
            egress.pop("evidence_sha256")
            egress["evidence_sha256"] = provider_config.canonical_sha256(egress)
            run["egress_policy_sha256"] = egress["policy"]["policy_sha256"]
            run["egress_receipt"] = egress
            run["upstream_policy_receipt"] = copy.deepcopy(
                egress["upstream_policy"]
            )
            (root / "evidence" / "egress.json").write_bytes(
                experiment.canonical_json_bytes(egress) + b"\n"
            )
            old_inventory = run["worker_inventory_sha256"]
            old_upstream = copy.deepcopy(run["upstream_policy_receipt"])
            worker_proxy.prepare_provider_transport_rebind(run)

            replacement_upstream = {
                **old_upstream,
                "proxy_loopback_port": 19083,
            }
            replacement_upstream.pop("policy_sha256")
            replacement_upstream["policy_sha256"] = (
                provider_config.canonical_sha256(replacement_upstream)
            )
            run["worker_inventory_sha256"] = "f" * 64
            run["upstream_policy_sha256"] = replacement_upstream["policy_sha256"]
            run["upstream_policy_receipt"] = replacement_upstream

            with mock.patch.object(
                provider_service,
                "rebind",
                return_value="http://127.0.0.1:19082",
            ) as rebind:
                worker_proxy.rebind_provider_transport(run)

            rebind.assert_called_once_with(run, required_port=19082)
            validation = run["provider_transport_rebind"]["validation"]
            self.assertEqual(
                validation["worker_inventory_sha256"], old_inventory
            )
            self.assertEqual(validation["upstream_policy_receipt"], old_upstream)

            with mock.patch.object(
                provider_service,
                "rebind",
                return_value="http://127.0.0.1:19083",
            ) as rotate:
                worker_proxy.rebind_provider_transport(run, worker_recreated=True)

            rotate.assert_called_once_with(
                run, forbidden_ports=frozenset({19082})
            )

    def test_transport_rebind_refuses_tampered_policy_or_egress_before_rotation(self):
        for artifact in ("fixed-proxy-policy.json", "egress.json"):
            with self.subTest(artifact=artifact), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary) / "run"
                run, _state = _provider_attempt(root)
                path = root / "evidence" / artifact
                value = json.loads(path.read_bytes())
                value["run_id"] = "attacker-run"
                path.write_bytes(experiment.canonical_json_bytes(value) + b"\n")

                with mock.patch.object(provider_service, "rebind") as rebind:
                    with self.assertRaises(worker.WorkerError):
                        worker_proxy.prepare_provider_transport_rebind(run)
                rebind.assert_not_called()
                self.assertFalse(
                    (root / "evidence" / "history" / "provider-transport").exists()
                )
                provider_config.release_provider(run)

    def test_transport_restore_lets_the_real_validator_establish_the_relay(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "run"
            run, _state = _provider_attempt(root)
            firewall = {
                "base": "http://127.0.0.1:19082",
                "network_id": "a" * 64,
                "internal_address": "172.18.0.2",
                "bridge_address": "172.17.0.2",
                "upstream_address": "127.0.0.1",
                "upstream_port": 19082,
            }
            run["proxy_firewall"] = firewall
            run["proxy_network"] = "fixture-volume-network"
            run["proxy_relay"] = "fixture-volume-relay"
            egress = copy.deepcopy(run["egress_receipt"])
            policy = {
                key: value
                for key, value in egress["policy"].items()
                if key != "policy_sha256"
            }
            policy["firewall"] = {**firewall, "rules": []}
            egress["policy"] = {
                **policy,
                "policy_sha256": provider_config.canonical_sha256(policy),
            }
            egress.pop("evidence_sha256")
            egress["evidence_sha256"] = provider_config.canonical_sha256(egress)
            run["egress_policy_sha256"] = egress["policy"]["policy_sha256"]
            run["egress_receipt"] = egress
            run["upstream_policy_receipt"] = copy.deepcopy(
                egress["upstream_policy"]
            )
            (root / "evidence" / "egress.json").write_bytes(
                experiment.canonical_json_bytes(egress) + b"\n"
            )
            worker_proxy.prepare_provider_transport_rebind(run)
            with mock.patch.object(provider_service, "rebind"):
                worker_proxy.rebind_provider_transport(run)

            order: list[str] = []

            def establish(candidate):
                order.append("relay")
                candidate["proxy_network"] = "replacement-network"
                candidate["proxy_relay"] = "replacement-relay"
                return "replacement-network", "172.18.0.3"

            def simulated_matrix(candidate, _fixture):
                order.append("validator")
                worker_proxy._ensure_proxy_relay(candidate)
                return {"schema": "simulated-egress"}

            with mock.patch.object(
                worker_proxy, "_firewall"
            ), mock.patch.object(
                worker_proxy, "_resource_matches", return_value=False
            ), mock.patch.object(
                worker_proxy, "_ensure_proxy_relay", side_effect=establish
            ), mock.patch.object(
                worker_proxy, "run_egress_matrix", side_effect=simulated_matrix
            ):
                worker_proxy.restore_provider_transport(run)

            self.assertEqual(order, ["validator", "relay"])

    def tearDown(self) -> None:
        for binding in list(provider_config._BINDINGS.values()):
            provider_config.release_provider(
                {"provider_binding_sha256": binding.public["binding_sha256"]}
            )

    def test_cancelled_call_retains_ambiguous_reservation_for_reconciliation(self):
        with tempfile.TemporaryDirectory() as temporary:
            state = _checkpoint_state(Path(temporary))
            entry = ENTRIES["scout-001"]
            state["run_round"] = mock.Mock(side_effect=asyncio.CancelledError)
            accepted = copy.deepcopy(state["accepted"])

            with self.assertRaises(asyncio.CancelledError):
                model._model_request(
                    state,
                    request_id=entry["request"]["request_id"],
                    role=entry["request"]["role"],
                    input_hashes=entry["request"]["input_hashes"],
                    call_kind="framework",
                )

            self.assertEqual(state["receipts"], [])
            pending = state["pending_model_exchanges"]["scout-001"]
            self.assertEqual(pending["request"], entry["request"])
            self.assertEqual(pending["call_kind"], "framework")
            self.assertEqual(pending["dispatch_state"], "ambiguous")
            self.assertEqual(state.get("model_exchanges", {}), {})
            self.assertEqual(state["accepted"], accepted)
            self.assertIn(
                "model:scout-001:reserved:framework", state["run"]["events"]
            )
            self.assertIn("model:scout-001:cancelled", state["run"]["events"])

    def test_provider_checkpoint_round_trips_stable_binding_preflight_and_journal(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state, _environment_path = _provider_state(root)
            _messages_value, request, response, receipt, _opener = _provider_exchange(
                state
            )
            state["pending_model_exchanges"] = {
                request["request_id"]: {
                    "request": request,
                    "response": response,
                    "receipt": receipt,
                    "call_kind": "explicit",
                    "reservation_usd": receipt["cost"]["amount"],
                    "dispatch_state": "completed",
                }
            }

            path = experiment._write_checkpoint(state, "model:completed")
            checkpoint = json.loads(path.read_bytes())

            for field in (
                "provider_binding",
                "provider_binding_sha256",
                "provider_preflight_sha256",
                "provider_journal",
            ):
                self.assertEqual(checkpoint["run"][field], state["run"][field])
            self.assertEqual(
                checkpoint["identities"]["provider_binding_sha256"],
                state["run"]["provider_binding_sha256"],
            )
            self.assertEqual(
                checkpoint["identities"]["provider_journal_sha256"],
                provider_config.canonical_sha256(state["run"]["provider_journal"]),
            )
            self.assertNotIn("proxy_base", checkpoint["run"])
            self.assertNotIn("provider_service", checkpoint["run"])

    def test_provider_journal_tamper_fails_before_worker_inspection(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state, environment = _provider_state(root)
            _provider_exchange(state)
            experiment._write_checkpoint(state, "model:completed")
            loaded = experiment._load_checkpoint(
                root, experiment._checkpoint_identities(state["run"])
            )
            journal = next((root / "evidence" / "provider-journal").iterdir())
            record = json.loads(journal.read_bytes())
            record["status"] = "reserved"
            journal.write_bytes(experiment.canonical_json_bytes(record) + b"\n")
            provider_config.release_provider(state["run"])
            with mock.patch.dict(
                os.environ, {"AUTOFV_RUN_TOKEN": RUN_TOKEN}, clear=False
            ):
                provider_config.configure_provider(
                    copy.deepcopy(state["run"]),
                    env_path=environment,
                    tool_schemas=_tools(),
                )

            with mock.patch.object(worker, "inspect_resume_state") as inspect:
                with self.assertRaisesRegex(
                    experiment.ContractError, "provider journal"
                ):
                    experiment._restore_checkpoint(
                        loaded,
                        manifest=state["manifest"],
                        config=state["config"],
                        lock=LOCK,
                        run_round=state["run_round"],
                    )
            inspect.assert_not_called()

    def test_recovery_rejects_signed_journal_rollback_missing_and_new_request(self):
        for attack in ("rollback", "missing", "unrelated"):
            with self.subTest(attack=attack), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                state, _environment_path = _provider_state(root)
                _messages_value, request, response, receipt, _opener = _provider_exchange(
                    state
                )
                state["pending_model_exchanges"] = {
                    request["request_id"]: {
                        "request": request,
                        "response": response,
                        "receipt": receipt,
                        "call_kind": "explicit",
                        "reservation_usd": receipt["cost"]["amount"],
                        "dispatch_state": "completed",
                    }
                }
                experiment._write_checkpoint(state, "model:completed")
                loaded = experiment._load_checkpoint(
                    root, experiment._checkpoint_identities(state["run"])
                )
                journal_path = next(
                    (root / "evidence" / "provider-journal").iterdir()
                )
                completed = json.loads(journal_path.read_bytes())
                binding = provider_config.provider_binding(state["run"])
                self.assertIsNotNone(binding)
                if attack == "rollback":
                    provider_service._write(
                        journal_path,
                        provider_service._record(
                            binding,
                            request,
                            completed["messages_sha256"],
                            "dispatched",
                        ),
                    )
                elif attack == "missing":
                    journal_path.unlink()
                else:
                    unrelated = copy.deepcopy(request)
                    unrelated["request_id"] = "provider-recovery-unrelated-002"
                    unrelated["sequence"] += 1
                    provider_service._write(
                        provider_service._journal_path(
                            state["run"], unrelated["request_id"]
                        ),
                        provider_service._record(
                            binding,
                            unrelated,
                            completed["messages_sha256"],
                            "reserved",
                        ),
                    )

                with mock.patch.object(worker, "inspect_resume_state") as inspect:
                    with self.assertRaises(experiment.ContractError):
                        experiment._restore_checkpoint(
                            loaded,
                            manifest=state["manifest"],
                            config=state["config"],
                            lock=LOCK,
                            run_round=state["run_round"],
                        )
                inspect.assert_not_called()

    def test_missing_provider_rebind_fails_before_worker_inspection(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state, _environment_path = _provider_state(root)
            experiment._write_checkpoint(state, "model:reserved")
            loaded = experiment._load_checkpoint(
                root, experiment._checkpoint_identities(state["run"])
            )
            provider_config.release_provider(state["run"])

            with mock.patch.object(worker, "inspect_resume_state") as inspect:
                with self.assertRaisesRegex(
                    experiment.ContractError, "provider binding"
                ):
                    experiment._restore_checkpoint(
                        loaded,
                        manifest=state["manifest"],
                        config=state["config"],
                        lock=LOCK,
                        run_round=state["run_round"],
                    )
            inspect.assert_not_called()

    def test_provider_identity_markers_cannot_be_hidden_by_relabeling(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state, _environment_path = _provider_state(root)
            experiment._write_checkpoint(state, "model:reserved")
            loaded = experiment._load_checkpoint(
                root, experiment._checkpoint_identities(state["run"])
            )
            loaded["run"].pop("provider_binding")
            loaded["run"].pop("provider_binding_sha256")
            loaded["run"]["cost_classification"] = "synthetic_fixture"

            with mock.patch.object(worker, "inspect_resume_state") as inspect:
                with self.assertRaisesRegex(
                    experiment.ContractError, "provider binding"
                ):
                    experiment._restore_checkpoint(
                        loaded,
                        manifest=state["manifest"],
                        config=state["config"],
                        lock=LOCK,
                        run_round=state["run_round"],
                    )
            inspect.assert_not_called()

    def test_partial_or_type_invalid_provider_state_fails_before_worker(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state, _environment_path = _provider_state(root)
            experiment._write_checkpoint(state, "model:reserved")
            loaded = experiment._load_checkpoint(
                root, experiment._checkpoint_identities(state["run"])
            )
            mutations = {
                "binding": lambda run: run.update(provider_binding=[]),
                "binding-digest": lambda run: run.update(
                    provider_binding_sha256=7
                ),
                "journal": lambda run: run.update(provider_journal=[]),
                "preflight": lambda run: run.update(provider_preflight_sha256=7),
            }
            for label, mutate in mutations.items():
                hostile = copy.deepcopy(loaded)
                mutate(hostile["run"])
                with self.subTest(label=label), mock.patch.object(
                    worker, "inspect_resume_state"
                ) as inspect:
                    with self.assertRaises(experiment.ContractError):
                        experiment._restore_checkpoint(
                            hostile,
                            manifest=state["manifest"],
                            config=state["config"],
                            lock=LOCK,
                            run_round=state["run_round"],
                        )
                inspect.assert_not_called()

    def test_recovery_rebinds_transient_transport_around_worker_inspection(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state, _environment_path = _provider_state(root)
            state["run"]["proxy_policy_sha256"] = "a" * 64
            experiment._write_checkpoint(state, "model:reserved")
            loaded = experiment._load_checkpoint(
                root, experiment._checkpoint_identities(state["run"])
            )
            observed = {**state["working"], "valid": True, "dirty": False}
            order: list[str] = []

            with mock.patch.object(
                worker_proxy,
                "prepare_provider_transport_rebind",
                side_effect=lambda _run: order.append("prepare"),
            ), mock.patch.object(
                worker_proxy,
                "rebind_provider_transport",
                side_effect=lambda _run: order.append("rebind"),
            ), mock.patch.object(
                worker,
                "inspect_resume_state",
                side_effect=lambda _run, _manifest: (
                    order.append("inspect") or observed
                ),
            ), mock.patch.object(
                worker_proxy,
                "restore_provider_transport",
                side_effect=lambda _run: order.append("restore"),
            ), mock.patch.object(
                worker_proxy,
                "finish_provider_transport_rebind",
                side_effect=lambda _run: order.append("finish"),
            ):
                experiment._restore_checkpoint(
                    loaded,
                    manifest=state["manifest"],
                    config=state["config"],
                    lock=LOCK,
                    run_round=state["run_round"],
                )

            self.assertEqual(
                order, ["prepare", "rebind", "inspect", "restore", "finish"]
            )

    def test_recreated_worker_rotates_service_then_rebuilds_its_upstream_policy(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state, _environment_path = _provider_state(root)
            state["run"]["proxy_policy_sha256"] = "a" * 64
            state["run"]["agent_worker_id"] = "lima:agent:old"
            experiment._write_checkpoint(state, "model:reserved")
            loaded = experiment._load_checkpoint(
                root, experiment._checkpoint_identities(state["run"])
            )
            observed = {**state["working"], "valid": True, "dirty": False}
            order: list[str] = []
            inspections = 0

            def prepare(run):
                order.append("prepare")
                run.setdefault(
                    "provider_transport_rebind",
                    {
                        "schema": "autofv-provider-transport-rebind/v1",
                        "binding_sha256": run["provider_binding_sha256"],
                        "phase": "intent",
                        "stale": {},
                        "validation": {"proxy_policy_sha256": "a" * 64},
                        "replacement_port": None,
                        "files": {},
                    },
                )

            def rebind(run, *, worker_recreated=False):
                label = "rebind:recreated" if worker_recreated else "rebind:surviving"
                order.append(label)
                run["provider_transport_rebind"]["phase"] = (
                    "recreated_service_rebound"
                    if worker_recreated
                    else "service_rebound"
                )

            def inspect(run, _manifest):
                nonlocal inspections
                inspections += 1
                order.append(f"inspect:{inspections}")
                run["agent_worker_id"] = f"lima:agent:new-{inspections}"
                run["upstream_policy_sha256"] = str(inspections) * 64
                return observed

            def destroy(_run):
                order.append("destroy")

            with mock.patch.object(
                worker_proxy,
                "prepare_provider_transport_rebind",
                side_effect=prepare,
            ), mock.patch.object(
                worker_proxy,
                "rebind_provider_transport",
                side_effect=rebind,
            ), mock.patch.object(
                worker,
                "inspect_resume_state",
                side_effect=inspect,
            ), mock.patch.object(
                worker, "force_destroy_worker", side_effect=destroy
            ), mock.patch.object(
                worker_proxy,
                "restore_provider_transport",
                side_effect=lambda _run: order.append("restore"),
            ), mock.patch.object(
                worker_proxy,
                "finish_provider_transport_rebind",
                side_effect=lambda run: (
                    order.append("finish")
                    or run.pop("provider_transport_rebind")
                ),
            ):
                resumed = experiment._restore_checkpoint(
                    loaded,
                    manifest=state["manifest"],
                    config=state["config"],
                    lock=LOCK,
                    run_round=state["run_round"],
                )

            self.assertEqual(
                order,
                [
                    "prepare",
                    "rebind:surviving",
                    "inspect:1",
                    "rebind:recreated",
                    "destroy",
                    "inspect:2",
                    "restore",
                    "finish",
                ],
            )
            self.assertEqual(resumed["run"]["upstream_policy_sha256"], "2" * 64)

    def test_transport_rebind_intent_survives_until_restoration_is_checkpointed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state, _environment_path = _provider_state(root)
            state["run"]["proxy_policy_sha256"] = "a" * 64
            experiment._write_checkpoint(state, "model:reserved")
            loaded = experiment._load_checkpoint(
                root, experiment._checkpoint_identities(state["run"])
            )
            observed = {**state["working"], "valid": True, "dirty": False}
            transitions: list[tuple[str, str | None]] = []

            def prepare(run):
                run.setdefault(
                    "provider_transport_rebind",
                    {
                        "schema": "autofv-provider-transport-rebind/v1",
                        "binding_sha256": run["provider_binding_sha256"],
                        "phase": "intent",
                        "stale": {},
                        "files": {},
                    },
                )

            def rebind(run):
                run["provider_transport_rebind"]["phase"] = "service_rebound"

            def restore(run):
                run["provider_transport_rebind"]["phase"] = "transport_restored"

            def finish(run):
                run.pop("provider_transport_rebind")

            def checkpoint(current, transition):
                intent = current["run"].get("provider_transport_rebind")
                transitions.append(
                    (
                        transition,
                        intent.get("phase") if isinstance(intent, dict) else None,
                    )
                )
                current["checkpoint_sequence"] += 1
                return root / "checkpoints" / "captured.json"

            with mock.patch.object(
                worker_proxy, "prepare_provider_transport_rebind", side_effect=prepare
            ), mock.patch.object(
                worker_proxy, "rebind_provider_transport", side_effect=rebind
            ), mock.patch.object(
                worker_proxy, "restore_provider_transport", side_effect=restore
            ), mock.patch.object(
                worker_proxy, "finish_provider_transport_rebind", side_effect=finish
            ), mock.patch.object(
                worker, "inspect_resume_state", return_value=observed
            ), mock.patch(
                "autofv.run_state._write_checkpoint", side_effect=checkpoint
            ):
                resumed = experiment._restore_checkpoint(
                    loaded,
                    manifest=state["manifest"],
                    config=state["config"],
                    lock=LOCK,
                    run_round=state["run_round"],
                )

            self.assertIn(
                ("provider_transport_rebind:intent", "intent"), transitions
            )
            self.assertIn(
                ("provider_transport_rebind:service", "service_rebound"), transitions
            )
            self.assertIn(
                ("provider_transport_rebind:restored", "transport_restored"),
                transitions,
            )
            self.assertIn(
                ("provider_transport_rebind:complete", None), transitions
            )
            self.assertNotIn("provider_transport_rebind", resumed["run"])

    def test_restored_transport_starts_a_fresh_live_recovery_cycle(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state, _environment_path = _provider_state(root)
            state["run"]["provider_transport_rebind"] = {
                "schema": "autofv-provider-transport-rebind/v1",
                "binding_sha256": state["run"]["provider_binding_sha256"],
                "phase": "transport_restored",
                "stale": {},
                "files": {},
            }
            path = experiment._write_checkpoint(
                state, "provider_transport_rebind:restored"
            )
            loaded = json.loads(path.read_bytes())
            observed = {**state["working"], "valid": True, "dirty": False}
            order: list[str] = []
            transitions: list[tuple[str, str | None]] = []

            def prepare(run):
                intent = run.get("provider_transport_rebind")
                order.append(
                    "prepare:"
                    + (intent.get("phase", "missing") if isinstance(intent, dict) else "new")
                )
                if intent is None:
                    run["provider_transport_rebind"] = {
                        "schema": "autofv-provider-transport-rebind/v1",
                        "binding_sha256": run["provider_binding_sha256"],
                        "phase": "intent",
                        "stale": {},
                        "files": {},
                    }

            def rebind(run, *, worker_recreated=False):
                self.assertFalse(worker_recreated)
                order.append("rebind")
                run["provider_transport_rebind"]["phase"] = "service_rebound"

            def restore(run):
                order.append("restore")
                run["provider_transport_rebind"]["phase"] = "transport_restored"

            def finish(run):
                order.append(
                    "finish:" + run["provider_transport_rebind"]["phase"]
                )
                run.pop("provider_transport_rebind")

            def checkpoint(current, transition):
                intent = current["run"].get("provider_transport_rebind")
                transitions.append(
                    (
                        transition,
                        intent.get("phase") if isinstance(intent, dict) else None,
                    )
                )
                current["checkpoint_sequence"] += 1
                return root / "checkpoints" / "captured.json"

            with mock.patch.object(
                worker_proxy, "prepare_provider_transport_rebind", side_effect=prepare
            ), mock.patch.object(
                worker_proxy, "rebind_provider_transport", side_effect=rebind
            ), mock.patch.object(
                worker_proxy, "restore_provider_transport", side_effect=restore
            ), mock.patch.object(
                worker_proxy, "finish_provider_transport_rebind", side_effect=finish
            ), mock.patch.object(
                worker,
                "inspect_resume_state",
                side_effect=lambda _run, _manifest: (
                    order.append("inspect") or observed
                ),
            ), mock.patch(
                "autofv.run_state._write_checkpoint", side_effect=checkpoint
            ):
                resumed = experiment._restore_checkpoint(
                    loaded,
                    manifest=state["manifest"],
                    config=state["config"],
                    lock=LOCK,
                    run_round=state["run_round"],
                )

            self.assertEqual(
                order,
                [
                    "prepare:transport_restored",
                    "finish:transport_restored",
                    "prepare:new",
                    "rebind",
                    "inspect",
                    "restore",
                    "finish:transport_restored",
                ],
            )
            self.assertIn(
                ("provider_transport_rebind:revalidation-intent", "intent"),
                transitions,
            )
            self.assertNotIn("provider_transport_rebind", resumed["run"])

    def test_mid_rotation_checkpoint_resumes_from_authenticated_intent(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state, _environment_path = _provider_state(root)
            state["run"]["provider_transport_rebind"] = {
                "schema": "autofv-provider-transport-rebind/v1",
                "binding_sha256": state["run"]["provider_binding_sha256"],
                "phase": "service_rebound",
                "stale": {},
                "files": {},
            }
            (root / "evidence").mkdir(exist_ok=True)
            (root / "evidence" / "fixed-proxy-policy.json").write_bytes(b"{}\n")
            path = experiment._write_checkpoint(
                state, "provider_transport_rebind:service"
            )
            loaded = json.loads(path.read_bytes())
            observed = {**state["working"], "valid": True, "dirty": False}
            order: list[str] = []

            with mock.patch.object(
                worker_proxy,
                "prepare_provider_transport_rebind",
                side_effect=lambda _run: order.append("prepare"),
            ), mock.patch.object(
                worker_proxy,
                "rebind_provider_transport",
                side_effect=lambda _run: order.append("rebind"),
            ), mock.patch.object(
                worker_proxy,
                "restore_provider_transport",
                side_effect=lambda _run: order.append("restore"),
            ), mock.patch.object(
                worker_proxy,
                "finish_provider_transport_rebind",
                side_effect=lambda run: (
                    order.append("finish")
                    or run.pop("provider_transport_rebind")
                ),
            ), mock.patch.object(
                worker, "inspect_resume_state", return_value=observed
            ):
                resumed = experiment._restore_checkpoint(
                    loaded,
                    manifest=state["manifest"],
                    config=state["config"],
                    lock=LOCK,
                    run_round=state["run_round"],
                )

            self.assertEqual(order, ["prepare", "rebind", "restore", "finish"])
            self.assertNotIn("provider_transport_rebind", resumed["run"])

    def test_exact_rebind_replays_completed_exchange_without_upstream_repayment(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state, environment = _provider_state(root)
            messages, request, response, receipt, opener = _provider_exchange(state)
            state["pending_model_exchanges"] = {
                request["request_id"]: {
                    "request": request,
                    "response": response,
                    "receipt": receipt,
                    "call_kind": "explicit",
                    "reservation_usd": receipt["cost"]["amount"],
                    "dispatch_state": "completed",
                }
            }
            experiment._write_checkpoint(state, "model:completed")
            loaded = experiment._load_checkpoint(
                root, experiment._checkpoint_identities(state["run"])
            )
            provider_config.release_provider(state["run"])
            with mock.patch.dict(
                os.environ, {"AUTOFV_RUN_TOKEN": RUN_TOKEN}, clear=False
            ):
                rebound = copy.deepcopy(state["run"])
                provider_config.configure_provider(
                    rebound, env_path=environment, tool_schemas=_tools()
                )
            observed = {**state["working"], "valid": True, "dirty": False}
            runner = mock.Mock(side_effect=AssertionError("provider repaid"))
            with mock.patch.object(
                worker, "inspect_resume_state", return_value=observed
            ):
                resumed = experiment._restore_checkpoint(
                    loaded,
                    manifest=state["manifest"],
                    config=state["config"],
                    lock=LOCK,
                    run_round=runner,
                )

            replayed = model._model_request(
                resumed,
                request_id=request["request_id"],
                role=request["role"],
                input_hashes=[],
                messages=messages,
            )
            self.assertEqual(replayed, (response, receipt))
            self.assertEqual(resumed["pending_model_exchanges"], {})
            self.assertEqual(len(resumed["receipts"]), 1)
            self.assertEqual(opener.call_count, 1)
            runner.assert_not_called()

    def test_recovery_accepts_signed_completion_after_dispatched_checkpoint(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state, environment = _provider_state(root)
            messages = _messages()
            request = model._model_envelope(
                state,
                request_id="provider-recovery-request-001",
                role="scout",
                input_hashes=[worker_proxy.provider_messages_sha256(messages)],
            )
            state["pending_model_exchanges"] = {
                request["request_id"]: {
                    "request": request,
                    "call_kind": "explicit",
                    "reservation_usd": "0.032880",
                    "dispatch_state": "dispatched",
                }
            }
            worker_proxy.stage_provider_messages(state["run"], request, messages)
            original_round = provider_transport.provider_round
            checkpoint_path = None

            def finish_after_checkpoint(run, paid_request):
                nonlocal checkpoint_path
                checkpoint_path = experiment._write_checkpoint(
                    state, "model:provider-recovery-request-001:dispatched"
                )
                return original_round(run, paid_request)

            opener = mock.Mock(
                return_value=_Reply(_reply('{"path":"Diamond/Left.lean"}'))
            )
            with mock.patch(
                "autofv.provider_transport._open_upstream", opener
            ), mock.patch.object(
                provider_transport, "provider_round", side_effect=finish_after_checkpoint
            ):
                response, receipt = provider_service.dispatch(
                    state["run"], request, run_token=RUN_TOKEN
                )
            self.assertIsNotNone(checkpoint_path)
            loaded = json.loads(checkpoint_path.read_bytes())
            self.assertNotIn("provider_preflight_sha256", loaded["run"])
            provider_config.release_provider(state["run"])
            with mock.patch.dict(
                os.environ, {"AUTOFV_RUN_TOKEN": RUN_TOKEN}, clear=False
            ):
                rebound = copy.deepcopy(state["run"])
                provider_config.configure_provider(
                    rebound, env_path=environment, tool_schemas=_tools()
                )
            observed = {**state["working"], "valid": True, "dirty": False}
            runner = mock.Mock(side_effect=AssertionError("provider repaid"))
            with mock.patch.object(
                worker, "inspect_resume_state", return_value=observed
            ):
                resumed = experiment._restore_checkpoint(
                    loaded,
                    manifest=state["manifest"],
                    config=state["config"],
                    lock=LOCK,
                    run_round=runner,
                )

            pending = resumed["pending_model_exchanges"][request["request_id"]]
            self.assertEqual(pending["dispatch_state"], "completed")
            self.assertEqual(pending["response"], response)
            self.assertEqual(pending["receipt"], receipt)
            self.assertEqual(
                resumed["run"]["provider_preflight_sha256"],
                state["run"]["provider_preflight_sha256"],
            )
            replayed = model._model_request(
                resumed,
                request_id=request["request_id"],
                role=request["role"],
                input_hashes=[],
                messages=messages,
            )
            self.assertEqual(replayed, (response, receipt))
            self.assertEqual(opener.call_count, 1)
            runner.assert_not_called()

    def test_recovery_reconstructs_first_preflight_after_signed_completion_crash(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state, environment = _provider_state(root)
            messages = _messages()
            request = model._model_envelope(
                state,
                request_id="provider-recovery-request-001",
                role="scout",
                input_hashes=[worker_proxy.provider_messages_sha256(messages)],
            )
            state["pending_model_exchanges"] = {
                request["request_id"]: {
                    "request": request,
                    "call_kind": "explicit",
                    "reservation_usd": "0.032880",
                    "dispatch_state": "dispatched",
                }
            }
            worker_proxy.stage_provider_messages(state["run"], request, messages)
            checkpoint_path = experiment._write_checkpoint(
                state, "model:provider-recovery-request-001:dispatched"
            )
            with mock.patch(
                "autofv.provider_transport._open_upstream",
                return_value=_Reply(_reply('{"path":"Diamond/Left.lean"}')),
            ):
                response, receipt = provider_service.dispatch(
                    state["run"], request, run_token=RUN_TOKEN
                )
            (root / "evidence" / "provider-preflight.json").unlink()
            state["run"].pop("provider_preflight_sha256")
            loaded = json.loads(checkpoint_path.read_bytes())
            provider_config.release_provider(state["run"])
            with mock.patch.dict(
                os.environ, {"AUTOFV_RUN_TOKEN": RUN_TOKEN}, clear=False
            ):
                rebound = copy.deepcopy(state["run"])
                provider_config.configure_provider(
                    rebound, env_path=environment, tool_schemas=_tools()
                )
            observed = {**state["working"], "valid": True, "dirty": False}
            runner = mock.Mock(side_effect=AssertionError("provider repaid"))
            with mock.patch.object(
                worker, "inspect_resume_state", return_value=observed
            ):
                resumed = experiment._restore_checkpoint(
                    loaded,
                    manifest=state["manifest"],
                    config=state["config"],
                    lock=LOCK,
                    run_round=runner,
                )

            preflight = provider_service.validate_pinned_preflight(
                root / "evidence" / "provider-preflight.json",
                run=resumed["run"],
            )
            self.assertEqual(preflight["request"], request)
            self.assertEqual(preflight["response"], response)
            self.assertEqual(preflight["receipt"], receipt)
            self.assertEqual(
                resumed["run"]["provider_preflight_sha256"],
                preflight["preflight_sha256"],
            )
            runner.assert_not_called()

    def test_unpinned_existing_preflight_may_bind_a_higher_sequence_completion(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state, _environment_path = _provider_state(root)
            messages = _messages()
            first = model._model_envelope(
                state,
                request_id="provider-preflight-order-001",
                role="scout",
                input_hashes=[worker_proxy.provider_messages_sha256(messages)],
                sequence=1,
            )
            second = model._model_envelope(
                state,
                request_id="provider-preflight-order-002",
                role="scout",
                input_hashes=[worker_proxy.provider_messages_sha256(messages)],
                sequence=2,
            )
            exchanges = {}
            with mock.patch(
                "autofv.provider_transport._open_upstream",
                return_value=_Reply(_reply('{"path":"Diamond/Left.lean"}')),
            ):
                for request in (second, first):
                    worker_proxy.stage_provider_messages(run := state["run"], request, messages)
                    response, receipt = provider_service.dispatch(
                        run, request, run_token=RUN_TOKEN
                    )
                    exchanges[request["request_id"]] = {
                        "request": request,
                        "response": response,
                        "receipt": receipt,
                        "call_kind": "explicit",
                        "dispatch_state": "completed",
                    }
            state["model_exchanges"] = exchanges
            state["pending_model_exchanges"] = {}
            preflight = provider_service.validate_pinned_preflight(
                root / "evidence" / "provider-preflight.json",
                run=state["run"],
            )
            self.assertEqual(preflight["request"]["sequence"], 2)
            state["run"].pop("provider_preflight_sha256")

            recovered = provider_receipts.validate_recovery_artifacts(
                state["run"],
                state,
                binding=provider_config.provider_binding(state["run"]),
            )

            self.assertEqual(
                recovered["provider_preflight"]["request"]["sequence"], 2
            )

    def test_rebound_dispatched_journal_remains_ambiguous_and_fails_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state, environment = _provider_state(root)
            messages, request, _response, _receipt, first_opener = _provider_exchange(
                state, dispatch=False
            )
            state["pending_model_exchanges"] = {
                request["request_id"]: {
                    "request": request,
                    "call_kind": "explicit",
                    "reservation_usd": "0.032880",
                    "dispatch_state": "ambiguous",
                }
            }
            experiment._write_checkpoint(state, "model:ambiguous")
            loaded = experiment._load_checkpoint(
                root, experiment._checkpoint_identities(state["run"])
            )
            provider_config.release_provider(state["run"])
            with mock.patch.dict(
                os.environ, {"AUTOFV_RUN_TOKEN": RUN_TOKEN}, clear=False
            ):
                provider_config.configure_provider(
                    copy.deepcopy(state["run"]),
                    env_path=environment,
                    tool_schemas=_tools(),
                )
            observed = {**state["working"], "valid": True, "dirty": False}
            with mock.patch.object(
                worker, "inspect_resume_state", return_value=observed
            ):
                resumed = experiment._restore_checkpoint(
                    loaded,
                    manifest=state["manifest"],
                    config=state["config"],
                    lock=LOCK,
                    run_round=state["run_round"],
                )
            worker_proxy.stage_provider_messages(resumed["run"], request, messages)
            second_opener = mock.Mock(side_effect=AssertionError("provider repaid"))
            with mock.patch(
                "autofv.provider_transport._open_upstream", second_opener
            ), self.assertRaisesRegex(
                provider_transport.ProviderError, "ambiguous"
            ):
                provider_service.dispatch(
                    resumed["run"], request, run_token=RUN_TOKEN
                )

            self.assertEqual(first_opener.call_count, 1)
            second_opener.assert_not_called()
            self.assertEqual(
                resumed["pending_model_exchanges"][request["request_id"]][
                    "dispatch_state"
                ],
                "ambiguous",
            )


if __name__ == "__main__":
    unittest.main()
