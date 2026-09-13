import copy
import hashlib
import inspect
import json
import os
import subprocess
import sys
import tempfile
import tomllib
import unittest
from decimal import Decimal
from pathlib import Path
from unittest import mock

from autofv import experiment, probes, results


ROOT = Path(__file__).resolve().parents[1]
LOCK_PATH = ROOT / "docker" / "autofv" / "toolchain-lock.json"


def load_lock():
    return json.loads(LOCK_PATH.read_text())


def valid_receipt():
    return {
        "schema": "autofv-model-proxy-receipt/v1",
        "proxy_id": "autofv-local-fixture-proxy-v1",
        "route_id": "autofv-infer-v1",
        "run_id": "run-001",
        "sequence": 1,
        "request_id": "request-001",
        "model_id": "fixture-model-v1",
        "request_sha256": "1" * 64,
        "response_sha256": "2" * 64,
        "status": "ok",
        "usage": {
            "input_tokens": 10,
            "output_tokens": 5,
            "total_tokens": 15,
        },
        "cost": {"amount": "0.001500", "currency": "USD"},
        "auth": {
            "algorithm": "Ed25519",
            "key_id": "autofv-local-fixture-ed25519-v1",
            "signature": (
                "TrX+dpqqOTpy7QOD+eV4L6ExcC/rSCCa/umILTcDP/"
                "D5Dt1xxu4/vza4611qsRNkFLvLqYtDctwkos2rHfCLBQ=="
            ),
        },
        "receipt_sha256": (
            "588a89eb23916e63026dd6cd5bbd5941c444feeac97fe89fb2770aa4ac8c332e"
        ),
    }


RECEIPT_EXPECTED = {
    "run_id": "run-001",
    "sequence": 1,
    "request_id": "request-001",
    "model_id": "fixture-model-v1",
    "request_sha256": "1" * 64,
    "response_sha256": "2" * 64,
}

POLICY_RATIONALE = (
    "For the vertical slice we need the most permissive option; later policy may "
    "either cap native_decide uses at a measured baseline count or allow it only "
    "for explicitly named specs A/B/C while forbidding it elsewhere."
)
POLICY_SHA256 = "bae965de1366b29fa30d89057a218d6030065d43bcf14f4f664a2e63bded7ff9"


def audited_native_decide_use():
    return {
        "spec": "Curve25519Dalek.Scalar.invert_spec",
        "declaration": "Curve25519Dalek.Scalar.invert",
        "source_path": "Curve25519Dalek/Scalar.lean",
        "source_sha256": "3" * 64,
        "expression_sha256": "4" * 64,
        "origin": "baseline",
    }


def compiler_assumptions():
    return [
        {
            "assumption": "Lean.ofReduceBool",
            "evidence": "Pinned Lean compiler source and binary identity",
            "evidence_sha256": "5" * 64,
        },
        {
            "assumption": "Lean.trustCompiler",
            "evidence": "Pinned native compiler toolchain identity",
            "evidence_sha256": "6" * 64,
        },
    ]


class ToolchainContractTests(unittest.TestCase):
    def test_package_exposes_only_the_autofv_entrypoint(self):
        data = tomllib.loads((ROOT / "pyproject.toml").read_text())
        self.assertEqual(data["build-system"]["build-backend"], "uv_build")
        self.assertEqual(data["build-system"]["requires"], ["uv_build==0.12.7"])
        self.assertEqual(
            data["project"]["scripts"], {"autofv": "autofv.experiment:main"}
        )
        self.assertIs(
            inspect.signature(experiment.run_experiment).parameters["run_round"].default,
            experiment.agentproc.run_round,
        )

        top = subprocess.run(
            [sys.executable, "-m", "autofv.experiment", "--help"],
            cwd=ROOT,
            capture_output=True,
            text=True,
        )
        run = subprocess.run(
            [sys.executable, "-m", "autofv.experiment", "run", "--help"],
            cwd=ROOT,
            capture_output=True,
            text=True,
        )
        self.assertEqual(top.returncode, 0, top.stderr)
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertIn("{inspect,run}", top.stdout)
        self.assertIn("inspect", top.stdout)
        self.assertIn("--target", run.stdout)
        self.assertIn("--run-config", run.stdout)
        for forbidden in ("--model", "--node", "--probe", "--provider", "--host"):
            self.assertNotIn(forbidden, top.stdout + run.stdout)

    def test_inspect_cli_writes_canonical_report_without_mutating_target(self):
        fixture = ROOT / "tests" / "fixtures" / "diamond"
        manifest = json.loads((fixture / "autofv.json").read_text())
        rust_raw = (ROOT / "tests" / "fixtures" / "probes" / "diamond-rust.json").read_bytes()
        aeneas_raw = (ROOT / "tests" / "fixtures" / "probes" / "diamond-aeneas.json").read_bytes()
        graph = probes.parse_probe_bytes(manifest, rust_raw, aeneas_raw)
        before = {
            path.relative_to(fixture).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in fixture.rglob("*")
            if path.is_file()
        }

        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "target-report.json"
            with (
                mock.patch.object(
                    sys,
                    "argv",
                    ["autofv", "inspect", str(fixture), "--output", str(output)],
                ),
                mock.patch.object(experiment.probes, "run_probes", return_value=graph),
            ):
                experiment.main()
            self.assertEqual(output.read_bytes(), probes.render_target_report(graph))

        after = {
            path.relative_to(fixture).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in fixture.rglob("*")
            if path.is_file()
        }
        self.assertEqual(after, before)

    def test_inspect_refuses_target_writes_and_leaves_no_partial_report(self):
        fixture = ROOT / "tests" / "fixtures" / "diamond"
        with mock.patch.object(experiment.probes, "run_probes") as run_probes:
            with self.assertRaisesRegex(
                probes.ProbeError, "inspect_output_inside_repository"
            ):
                experiment.inspect_repository(
                    fixture, fixture / "target-report.json"
                )
        run_probes.assert_not_called()

        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "target-report.json"
            output.write_bytes(b"previous report")
            with (
                mock.patch.object(
                    experiment.probes,
                    "run_probes",
                    side_effect=probes.ProbeError("incomplete evidence"),
                ),
                self.assertRaisesRegex(probes.ProbeError, "incomplete evidence"),
            ):
                experiment.inspect_repository(fixture, output)
            self.assertEqual(output.read_bytes(), b"previous report")
            self.assertEqual(list(Path(tmp).glob(".*.tmp")), [])

    def test_every_runtime_identity_is_verified_and_smoked(self):
        lock = load_lock()
        records = [lock["base_oci"], lock["model_client"], lock["verifier"]]
        records.extend(lock["packages"].values())
        records.extend(lock["tools"].values())
        self.assertGreater(len(records), 10)
        for record in records:
            with self.subTest(identity=record.get("identity")):
                self.assertTrue(record["identity"])
                self.assertTrue(record["official_origin"])
                self.assertTrue(record["pin"])
                self.assertEqual(record["legitimacy"], "verified")
                self.assertTrue(record["observed_version"])
                self.assertIsInstance(record["smoke"]["argv"], list)
                self.assertTrue(record["smoke"]["argv"])
                self.assertEqual(record["smoke"]["status"], "passed")

    def test_fixed_client_has_no_caller_selected_route_or_authorization(self):
        lock = load_lock()
        self.assertEqual(lock["model_client"]["implementation"], "urllib.request")
        proxy = lock["fixed_proxy"]
        self.assertEqual(proxy["cost_classification"], "synthetic_fixture")
        self.assertEqual((proxy["method"], proxy["path"]), ("POST", "/v1/autofv/infer"))
        self.assertEqual(proxy["base_address_source"], "trusted_launcher")
        self.assertEqual(
            set(proxy["forbidden_caller_capabilities"]),
            {
                "upstream_host",
                "authorization",
                "provider_admin",
                "file_transfer",
                "batch_jobs",
                "connect_tunnel",
            },
        )
        serialized = json.dumps(lock).lower()
        self.assertNotIn("provider_api_key", serialized)
        self.assertNotIn("private key", serialized)

    def test_verifier_contract_records_start_then_shell(self):
        verifier = load_lock()["verifier"]
        self.assertEqual(
            verifier["start_argv"], ["limactl", "start", "autofv-verifier"]
        )
        self.assertEqual(
            verifier["launcher_argv_prefix"],
            ["limactl", "shell", "autofv-verifier", "--"],
        )
        self.assertEqual(
            verifier["invocation_sequence"], ["start_argv", "launcher_argv_prefix"]
        )

    def test_invalid_input_stops_before_the_injected_launcher(self):
        calls = []

        def launcher(*args, **kwargs):
            calls.append((args, kwargs))

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / "target"
            target.mkdir()
            (target / "autofv.json").write_text(
                json.dumps(
                    {
                        "schema": "autofv/v1",
                        "targets": [{"function": "crate::top", "spec": "Top.spec"}],
                        "verify": ["lake", "build"],
                    }
                )
            )
            config = root / "run.json"
            config.write_text(
                json.dumps(
                    {
                        "schema": "autofv-run/v1",
                        "model": "fixture-model-v1",
                        "max_wall_seconds": 60,
                        "max_cost_usd": 1.0,
                        "unexpected": True,
                    }
                )
            )
            with mock.patch.dict(
                os.environ,
                {"AUTOFV_ATTEMPT_LEDGER": str(root / "attempts.jsonl")},
            ):
                result = experiment.run_experiment(
                    target, config, run_round=launcher
                )
            self.assertEqual(result["outcome"], "invalid_config")
            self.assertEqual(result["termination_reason"], "run_config_invalid")
        self.assertEqual(calls, [])

    def test_duplicate_json_keys_and_symlinked_manifest_fail_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / "target"
            target.mkdir()
            outside = root / "outside.json"
            outside.write_text(
                json.dumps(
                    {
                        "schema": "autofv/v1",
                        "targets": [{"function": "crate::top", "spec": "Top.spec"}],
                        "verify": ["lake", "build"],
                    }
                )
            )
            (target / "autofv.json").symlink_to(outside)
            with self.assertRaises(experiment.ContractError):
                experiment.validate_target(target)

            config = root / "run.json"
            config.write_text(
                '{"schema":"autofv-run/v1","schema":"autofv-run/v1",'
                '"model":"fixture-model-v1","max_wall_seconds":60,'
                '"max_cost_usd":1.0}'
            )
            with self.assertRaises(experiment.ContractError):
                experiment.validate_run_config(config)


class ProxyReceiptContractTests(unittest.TestCase):
    def validate(self, receipt=None, **overrides):
        expected = RECEIPT_EXPECTED | overrides
        return experiment.validate_proxy_receipt(
            receipt or valid_receipt(), **expected, seen_receipt_sha256=set()
        )

    def test_authenticated_receipt_returns_exact_decimal_cost(self):
        self.assertEqual(self.validate(), Decimal("0.001500"))

    def test_missing_or_unknown_fields_fail_closed(self):
        required = (
            "proxy_id",
            "route_id",
            "run_id",
            "sequence",
            "request_id",
            "model_id",
            "request_sha256",
            "response_sha256",
            "status",
            "usage",
            "cost",
            "auth",
            "receipt_sha256",
        )
        for field in required:
            receipt = valid_receipt()
            del receipt[field]
            with self.subTest(field=field), self.assertRaises(experiment.ContractError):
                self.validate(receipt)
        receipt = valid_receipt()
        receipt["authorization"] = "forbidden"
        with self.assertRaises(experiment.ContractError):
            self.validate(receipt)

    def test_duplicate_cross_run_and_reordered_receipts_fail(self):
        receipt = valid_receipt()
        with self.assertRaises(experiment.ContractError):
            experiment.validate_proxy_receipt(
                receipt,
                **RECEIPT_EXPECTED,
                seen_receipt_sha256={receipt["receipt_sha256"]},
            )
        with self.assertRaises(experiment.ContractError):
            experiment.validate_proxy_receipt(
                receipt,
                **RECEIPT_EXPECTED,
                seen_receipt_sha256=set(),
                seen_request_ids={receipt["request_id"]},
            )
        with self.assertRaises(experiment.ContractError):
            self.validate(run_id="another-run")
        with self.assertRaises(experiment.ContractError):
            self.validate(sequence=2)

    def test_hash_currency_usage_and_authentication_mismatches_fail(self):
        mutations = (
            ("request hash", lambda r: r.__setitem__("request_sha256", "3" * 64)),
            ("response hash", lambda r: r.__setitem__("response_sha256", "4" * 64)),
            ("currency", lambda r: r["cost"].__setitem__("currency", "EUR")),
            ("decimal amount", lambda r: r["cost"].__setitem__("amount", "0.0015")),
            ("usage total", lambda r: r["usage"].__setitem__("total_tokens", 99)),
            ("token type", lambda r: r["usage"].__setitem__("input_tokens", 10.0)),
            ("receipt hash", lambda r: r.__setitem__("receipt_sha256", "0" * 64)),
            ("signature", lambda r: r["auth"].__setitem__("signature", "AAAA")),
        )
        for name, mutate in mutations:
            receipt = copy.deepcopy(valid_receipt())
            mutate(receipt)
            with self.subTest(name=name), self.assertRaises(experiment.ContractError):
                self.validate(receipt)


class ControlBundleContractTests(unittest.TestCase):
    def test_hashed_control_bundle_is_copy_only_root_owned_and_read_only(self):
        bundle = load_lock()["controller_delivery"]
        self.assertEqual(bundle["kind"], "hashed_control_bundle")
        self.assertEqual(bundle["destination"], "/autofv-control")
        self.assertEqual(bundle["delivery"], "trusted_launcher_copy_to_managed_volume")
        self.assertFalse(bundle["bind_mount"])
        self.assertFalse(bundle["source_checkout_mounted"])
        self.assertEqual(bundle["owner"], {"uid": 0, "gid": 0})
        self.assertEqual(bundle["modes"], {"directory": "0555", "file": "0444"})
        self.assertEqual(bundle["verify_at"], ["before_execution", "after_execution"])

    def test_manifest_and_hash_rules_are_canonical_and_allowlisted(self):
        bundle = load_lock()["controller_delivery"]
        self.assertEqual(bundle["manifest"]["schema"], "autofv-control-bundle/v1")
        self.assertEqual(bundle["manifest"]["entry_fields"], ["path", "sha256", "size"])
        self.assertEqual(bundle["manifest"]["order"], "path_ascending_utf8")
        self.assertEqual(bundle["manifest"]["file_types"], ["regular_file"])
        self.assertEqual(
            bundle["bundle_sha256"],
            "sha256(canonical_utf8_json(manifest_without_bundle_sha256))",
        )
        roots = set(bundle["allowed_roots"])
        self.assertIn("autofv/", roots)
        self.assertIn("docker/autofv/toolchain-lock.json", roots)
        self.assertIn("harness/gates/StmtCanon.lean", roots)
        rendered = json.dumps(bundle)
        for forbidden in (".git", ".planning", "diamond-reference", "private.pem"):
            self.assertNotIn(forbidden, rendered)


class NativeDecidePolicyContractTests(unittest.TestCase):
    @staticmethod
    def rehash(lock):
        lock["native_decide_policy_sha256"] = hashlib.sha256(
            json.dumps(
                lock["native_decide_policy"],
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
                allow_nan=False,
            ).encode()
        ).hexdigest()

    def test_selected_policy_is_explicit_canonical_and_hash_bound(self):
        lock = load_lock()
        policy = experiment.validate_native_decide_policy(lock)

        self.assertEqual(policy["state"], "selected")
        self.assertTrue(policy["runnable"])
        self.assertEqual(policy["selection"], "allow_audited")
        self.assertEqual(policy["operator_rationale"], POLICY_RATIONALE)
        self.assertEqual(lock["native_decide_policy_sha256"], POLICY_SHA256)
        self.assertEqual(
            policy["downstream_fields"],
            [
                "native_decide_policy",
                "native_decide_policy_sha256",
                "native_decide_uses",
                "compiler_assumptions",
            ],
        )

    def test_missing_unknown_pending_and_hash_mismatched_policies_fail_closed(self):
        mutations = []

        missing = load_lock()
        del missing["native_decide_policy"]
        mutations.append(("missing", missing))

        for selection in ("forbid_all", "baseline_only", "operator_choice_from_env"):
            unselected = load_lock()
            unselected["native_decide_policy"]["selection"] = selection
            self.rehash(unselected)
            mutations.append((selection, unselected))

        pending = load_lock()
        pending["native_decide_policy"]["state"] = "decision_required"
        pending["native_decide_policy"]["runnable"] = False
        self.rehash(pending)
        mutations.append(("pending", pending))

        mismatched = load_lock()
        mismatched["native_decide_policy_sha256"] = "0" * 64
        mutations.append(("hash mismatch", mismatched))

        for name, lock in mutations:
            with self.subTest(name=name), self.assertRaises(experiment.ContractError):
                experiment.validate_native_decide_policy(lock)

    def test_audited_uses_require_exhaustive_inventory_and_compiler_evidence(self):
        result = experiment.evaluate_native_decide_policy(
            load_lock(),
            native_decide_uses=[audited_native_decide_use()],
            compiler_assumptions=compiler_assumptions(),
        )
        self.assertEqual(result["native_decide_policy"], "allow_audited")
        self.assertEqual(result["native_decide_policy_sha256"], POLICY_SHA256)
        self.assertEqual(result["native_decide_uses"], [audited_native_decide_use()])
        self.assertEqual(result["compiler_assumptions"], compiler_assumptions())
        self.assertIn("downgraded", result["claim_consequence"])

    def test_incomplete_or_noncanonical_audit_evidence_fails_closed(self):
        invalid_cases = []

        missing_use_field = audited_native_decide_use()
        del missing_use_field["expression_sha256"]
        invalid_cases.append(
            ("missing per-use evidence", [missing_use_field], compiler_assumptions())
        )

        invalid_origin = audited_native_decide_use()
        invalid_origin["origin"] = "unclassified"
        invalid_cases.append(
            ("unknown origin", [invalid_origin], compiler_assumptions())
        )

        duplicate_uses = [audited_native_decide_use(), audited_native_decide_use()]
        invalid_cases.append(
            ("duplicate inventory", duplicate_uses, compiler_assumptions())
        )

        missing_assumption = compiler_assumptions()[:-1]
        invalid_cases.append(
            ("missing compiler evidence", [audited_native_decide_use()], missing_assumption)
        )

        duplicate_assumptions = compiler_assumptions() + compiler_assumptions()[:1]
        invalid_cases.append(
            (
                "duplicate compiler evidence",
                [audited_native_decide_use()],
                duplicate_assumptions,
            )
        )

        for name, uses, assumptions in invalid_cases:
            with self.subTest(name=name), self.assertRaises(experiment.ContractError):
                experiment.evaluate_native_decide_policy(
                    load_lock(),
                    native_decide_uses=uses,
                    compiler_assumptions=assumptions,
                )

    def test_launch_exports_hash_bound_policy_without_environment_fallback(self):
        signature = inspect.signature(experiment.evaluate_native_decide_policy)
        self.assertIs(
            signature.parameters["native_decide_uses"].default,
            inspect.Parameter.empty,
        )
        self.assertIs(
            signature.parameters["compiler_assumptions"].default,
            inspect.Parameter.empty,
        )

        calls = []
        fake_run = {
            "run_id": "native-policy-unit-test",
            "events": [],
            "snapshot_sha256": "1" * 64,
            "manifest_sha256": "2" * 64,
            "image_digest": "sha256:" + "3" * 64,
            "control_bundle_sha256": "4" * 64,
            "execution_tier": "simulation",
            "cost_classification": "synthetic_fixture",
        }
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            fake_run["run_root"] = str(root)
            fake_run["evidence_dir"] = str(root / "evidence")
            target = root / "target"
            target.mkdir()
            (target / "autofv.json").write_text(
                json.dumps(
                    {
                        "schema": "autofv/v1",
                        "targets": [{"function": "crate::top", "spec": "Top.spec"}],
                        "verify": ["lake", "build"],
                    }
                )
            )
            config = root / "run.json"
            config.write_text(
                json.dumps(
                    {
                        "schema": "autofv-run/v1",
                        "model": "fixture-model-v1",
                        "max_wall_seconds": 60,
                        "max_cost_usd": 1.0,
                    }
                )
            )
            with (
                mock.patch.dict(
                    os.environ, {"AUTOFV_NATIVE_DECIDE_POLICY": "forbid_all"}
                ),
                mock.patch.object(
                    experiment.worker, "prepare_run", return_value=fake_run
                ),
                mock.patch.object(
                    experiment._EXPERIMENT_GRAPH,
                    "stream",
                    side_effect=experiment.ContractError("unit boundary"),
                ),
                mock.patch.object(results, "persist_attempt"),
            ):
                result = experiment.run_experiment(
                    target, config, run_round=lambda *a, **k: calls.append((a, k))
                )
        self.assertEqual(result["native_decide_policy"], "allow_audited")
        self.assertEqual(result["native_decide_policy_sha256"], POLICY_SHA256)
        self.assertEqual(calls, [])


class PreparedConfigTests(unittest.TestCase):
    fixture = ROOT / "tests" / "fixtures" / "diamond"
    target = {
        "function": "probe:autofv-diamond/0.1.0/top()",
        "spec": "Diamond.top_spec",
    }
    manifest = {
        "schema": "autofv/v1",
        "targets": [target],
        "verify": ["lake", "build"],
    }
    run_config = {
        "schema": "autofv-run/v1",
        "model": "fixture-model-v1",
        "max_wall_seconds": 300,
        "max_cost_usd": 1,
    }

    def test_prepared_fixture_is_one_canonical_supplied_target(self):
        _, manifest = experiment.validate_target(self.fixture)
        _, run_config = experiment.validate_run_config(self.fixture / "run.json")

        self.assertEqual(manifest, self.manifest)
        self.assertEqual(len(manifest["targets"]), 1)
        self.assertTrue(all(target["spec"] for target in manifest["targets"]))
        self.assertEqual(set(run_config), set(self.run_config))
        self.assertEqual(run_config["model"], "fixture-model-v1")
        self.assertEqual(run_config["max_wall_seconds"], 300)
        self.assertEqual(run_config["max_cost_usd"], Decimal("1"))

        raw_run_config = json.loads((self.fixture / "run.json").read_text())
        self.assertEqual(
            hashlib.sha256(experiment.canonical_json_bytes(manifest)).hexdigest(),
            "ccf1562758270de38094d9b2030e64ee8efcfe5e38eb7c3d0471b2c0104c29a3",
        )
        self.assertEqual(
            hashlib.sha256(
                experiment.canonical_json_bytes(raw_run_config)
            ).hexdigest(),
            "f2a6f19fbf8f9700f9cd58b2cb616317438f28fd7868506c01a1e8ec19acf92e",
        )

    def test_manifest_rejects_duplicate_empty_null_missing_and_unsafe_fields(self):
        invalid_cases = {}

        duplicate = copy.deepcopy(self.manifest)
        duplicate["targets"].append(copy.deepcopy(self.target))
        invalid_cases["duplicate target"] = duplicate

        for name, value in (("empty targets", []), ("null targets", None)):
            manifest = copy.deepcopy(self.manifest)
            manifest["targets"] = value
            invalid_cases[name] = manifest

        missing = copy.deepcopy(self.manifest)
        del missing["targets"]
        invalid_cases["missing targets"] = missing

        unknown = copy.deepcopy(self.manifest)
        unknown["proxy_url"] = "https://example.invalid"
        invalid_cases["unknown field"] = unknown

        relative_command = copy.deepcopy(self.manifest)
        relative_command["verify"] = ["./lake", "build"]
        invalid_cases["relative command"] = relative_command

        for name, manifest in invalid_cases.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as tmp:
                target = Path(tmp) / "target"
                target.mkdir()
                (target / "autofv.json").write_text(json.dumps(manifest))
                with self.assertRaises(experiment.ContractError):
                    experiment.validate_target(target)

    def test_run_config_rejects_unknown_fields_and_non_positive_budgets(self):
        invalid_cases = {}

        unknown = copy.deepcopy(self.run_config)
        unknown["worker"] = "untrusted"
        invalid_cases["unknown field"] = unknown

        for field in ("max_wall_seconds", "max_cost_usd"):
            for value in (0, -1):
                config = copy.deepcopy(self.run_config)
                config[field] = value
                invalid_cases[f"{field}={value}"] = config

        for name, config in invalid_cases.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as tmp:
                path = Path(tmp) / "run.json"
                path.write_text(json.dumps(config))
                with self.assertRaises(experiment.ContractError):
                    experiment.validate_run_config(path)

    def test_object_order_does_not_change_frozen_manifest_hash(self):
        reordered = {
            "verify": ["lake", "build"],
            "targets": [
                {
                    "spec": "Diamond.top_spec",
                    "function": "probe:autofv-diamond/0.1.0/top()",
                }
            ],
            "schema": "autofv/v1",
        }
        expected = "ccf1562758270de38094d9b2030e64ee8efcfe5e38eb7c3d0471b2c0104c29a3"
        self.assertEqual(
            hashlib.sha256(experiment.canonical_json_bytes(self.manifest)).hexdigest(),
            expected,
        )
        self.assertEqual(
            hashlib.sha256(experiment.canonical_json_bytes(reordered)).hexdigest(),
            expected,
        )

    def test_fixture_exposes_no_internal_or_secret_controls(self):
        manifest = json.loads((self.fixture / "autofv.json").read_text())
        run_config = json.loads((self.fixture / "run.json").read_text())
        self.assertEqual(set(manifest), {"schema", "targets", "verify"})
        self.assertEqual(set(run_config), set(self.run_config))

        serialized = json.dumps([manifest, run_config], sort_keys=True).lower()
        for forbidden in (
            "proxy_url",
            "receipt",
            "tool_path",
            "worker",
            "provider",
            "credential",
            "trust_override",
            "reference",
            "target_mode",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, serialized)


class PreparedProjectContractTests(unittest.TestCase):
    target = ROOT / "tests" / "fixtures" / "diamond"
    reference_path = (
        ROOT / "tests" / "fixtures" / "diamond-reference" / "reference.json"
    )

    def load_reference(self):
        return json.loads(self.reference_path.read_text())

    def test_lean_and_lake_match_the_audited_image_identity(self):
        lock = load_lock()["tools"]
        toolchain = (self.target / "lean-toolchain").read_text().strip()
        lakefile = tomllib.loads((self.target / "lakefile.toml").read_text())

        self.assertEqual(toolchain, "leanprover/lean4:v4.28.0-rc1")
        self.assertEqual(lock["lean"]["observed_version"], "Lean 4.28.0-rc1")
        self.assertEqual(lock["lean"]["pin"], lock["lake"]["pin"])
        self.assertEqual(
            lakefile,
            {
                "name": "Diamond",
                "version": "0.1.0",
                "defaultTargets": ["Diamond"],
                "lean_lib": [
                    {
                        "name": "Diamond",
                        "roots": ["Diamond.Top", "Diamond.Left", "Diamond.Right"],
                    }
                ],
            },
        )

    def test_reference_hashes_bind_independent_leaf_truth(self):
        reference = self.load_reference()
        self.assertEqual(
            set(reference),
            {
                "schema",
                "delivery",
                "artifact_role",
                "model_response_role",
                "leaves",
            },
        )
        self.assertEqual(reference["schema"], "autofv-verifier-reference/v1")
        self.assertEqual(len(reference["leaves"]), 2)

        identities = set()
        content_hashes = set()
        for leaf in reference["leaves"]:
            self.assertEqual(
                set(leaf),
                {
                    "declaration",
                    "spec",
                    "source",
                    "statement",
                    "statement_sha256",
                    "proof",
                    "proof_sha256",
                },
            )
            identities.add((leaf["declaration"], leaf["spec"], leaf["source"]))
            for field in ("statement", "proof"):
                content = leaf[field]
                self.assertIsInstance(content, str)
                self.assertTrue(content)
                self.assertNotIn("\r", content)
                digest = hashlib.sha256(content.encode("utf-8")).hexdigest()
                self.assertEqual(leaf[f"{field}_sha256"], digest)
                content_hashes.add(digest)

        self.assertEqual(
            identities,
            {
                ("Diamond.left", "Diamond.left_spec", "Diamond/Left.lean"),
                ("Diamond.right", "Diamond.right_spec", "Diamond/Right.lean"),
            },
        )
        self.assertEqual(len(content_hashes), 4)
        target_hashes = {
            hashlib.sha256(path.read_bytes()).hexdigest()
            for path in self.target.rglob("*")
            if path.is_file()
        }
        self.assertTrue(content_hashes.isdisjoint(target_hashes))

    def test_target_cannot_select_or_link_the_verifier_reference(self):
        self.assertTrue(self.reference_path.is_file())
        self.assertFalse(self.reference_path.resolve().is_relative_to(self.target.resolve()))
        self.assertFalse(any(path.is_symlink() for path in self.target.rglob("*")))

        manifest = json.loads((self.target / "autofv.json").read_text())
        manifest["reference"] = "../diamond-reference/reference.json"
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "target"
            target.mkdir()
            (target / "autofv.json").write_text(json.dumps(manifest))
            with self.assertRaises(experiment.ContractError):
                experiment.validate_target(target)

    def test_hidden_material_is_absent_from_target_and_control_bundle(self):
        reference = self.load_reference()
        target_bytes = b"\n".join(
            path.read_bytes() for path in self.target.rglob("*") if path.is_file()
        )

        bundle = load_lock()["controller_delivery"]
        control_bytes = [experiment.canonical_json_bytes(bundle)]
        control_bytes.extend(
            (ROOT / member).read_bytes()
            for member in bundle["allowed_members"]
            if (ROOT / member).is_file()
        )
        exposed_bytes = target_bytes + b"\n" + b"\n".join(control_bytes)

        hidden_values = ["diamond-reference", "reference.json"]
        for leaf in reference["leaves"]:
            hidden_values.extend(
                (
                    leaf["statement"],
                    leaf["statement_sha256"],
                    leaf["proof"],
                    leaf["proof_sha256"],
                )
            )
        for value in hidden_values:
            with self.subTest(value=value):
                self.assertNotIn(value.encode("utf-8"), exposed_bytes)

    def test_reference_is_not_deterministic_model_response_output(self):
        reference = self.load_reference()
        self.assertEqual(reference["delivery"], "clean-verifier-only")
        self.assertEqual(
            reference["artifact_role"], "provider-side verifier reference"
        )
        self.assertEqual(
            reference["model_response_role"], "generated test agent output"
        )
        self.assertNotEqual(
            reference["artifact_role"], reference["model_response_role"]
        )
        for leaf in reference["leaves"]:
            self.assertTrue(
                {"request_id", "response_sha256", "receipt_sha256"}.isdisjoint(leaf)
            )


class PreparedDiamondTests(unittest.TestCase):
    target = ROOT / "tests" / "fixtures" / "diamond"

    def test_lean_shape(self):
        top_path = self.target / "Diamond" / "Top.lean"
        left_path = self.target / "Diamond" / "Left.lean"
        right_path = self.target / "Diamond" / "Right.lean"
        top, left, right = (
            top_path.read_text(),
            left_path.read_text(),
            right_path.read_text(),
        )

        self.assertIn("import Diamond.Left", top)
        self.assertIn("import Diamond.Right", top)
        self.assertRegex(
            top,
            r"def top \(input : Nat\) : Nat :=\s+left input \+ right input",
        )
        self.assertRegex(
            top,
            r"theorem top_spec \(input : Nat\) :\s+"
            r"top input = input \* 3 \+ 1 := by\s+sorry",
        )

        self.assertNotEqual(left_path, right_path)
        self.assertNotEqual(left, right)
        self.assertRegex(
            left, r"def left \(input : Nat\) : Nat :=\s+input \+ 1"
        )
        self.assertRegex(
            right, r"def right \(input : Nat\) : Nat :=\s+input \* 2"
        )
        self.assertNotIn("right", left.lower())
        self.assertNotIn("left", right.lower())
        for source, spec in ((left, "left_spec"), (right, "right_spec")):
            self.assertNotIn(spec, source)
            self.assertNotIn("theorem ", source)
            self.assertNotIn("lemma ", source)
            self.assertNotIn("sorry", source)

        reference = json.loads(
            (
                ROOT
                / "tests"
                / "fixtures"
                / "diamond-reference"
                / "reference.json"
            ).read_text()
        )
        prepared_bytes = b"\n".join(
            path.read_bytes() for path in self.target.rglob("*") if path.is_file()
        )
        hidden = ["diamond-reference", "reference.json"]
        for leaf in reference["leaves"]:
            hidden.extend(
                leaf[field]
                for field in (
                    "statement",
                    "statement_sha256",
                    "proof",
                    "proof_sha256",
                )
            )
        for value in hidden:
            with self.subTest(hidden=value):
                self.assertNotIn(value.encode("utf-8"), prepared_bytes)

    def test_pinned_probe_truth(self):
        probe_root = ROOT / "tests" / "fixtures" / "probes"
        rust_bytes = (probe_root / "diamond-rust.json").read_bytes()
        merged_bytes = (probe_root / "diamond-aeneas.json").read_bytes()
        self.assertEqual(
            hashlib.sha256(rust_bytes).hexdigest(),
            "3136fead3bfd40b214e743ebeaa299f91fb9b12261af69b4a6a6a7f5c19f0b51",
        )
        self.assertEqual(
            hashlib.sha256(merged_bytes).hexdigest(),
            "7f8c313a422a0b9107786878f4d492943b195a90ba34c7a79464a6c51f54d08f",
        )
        rust, merged = json.loads(rust_bytes), json.loads(merged_bytes)

        self.assertEqual((rust["schema"], rust["schema-version"]), ("probe-rust/extract", "3.0"))
        self.assertEqual(
            rust["tool"],
            {"name": "probe-rust", "version": "0.10.0", "command": "extract"},
        )
        self.assertEqual(
            (
                rust["source"]["language"],
                rust["source"]["package"],
                rust["source"]["package-version"],
            ),
            ("rust", "autofv-diamond", "0.1.0"),
        )
        self.assertEqual(
            (merged["schema"], merged["schema-version"]),
            ("probe-aeneas/extract", "3.0"),
        )
        self.assertEqual(
            merged["tool"],
            {"name": "probe-aeneas", "version": "0.19.0", "command": "extract"},
        )
        self.assertEqual(
            {
                (
                    item["source"]["language"],
                    item["source"]["package"],
                    item["source"]["package-version"],
                )
                for item in merged["inputs"]
            },
            {("lean", "Diamond", "0.1.0"), ("rust", "autofv-diamond", "0.1.0")},
        )

        atoms = merged["data"]
        lean_atoms = {
            name: atom
            for name, atom in atoms.items()
            if atom.get("language") == "lean" and atom.get("is-in-package") is True
        }
        self.assertEqual(
            {name: atom["term-dependencies"] for name, atom in lean_atoms.items()},
            {
                "probe:Diamond.left": [],
                "probe:Diamond.right": [],
                "probe:Diamond.top": ["probe:Diamond.left", "probe:Diamond.right"],
                "probe:Diamond.top_spec": ["probe:Diamond.top"],
            },
        )
        self.assertEqual(
            {
                name: lean_atoms[name]["verification-status"]
                for name in (
                    "probe:Diamond.left",
                    "probe:Diamond.right",
                    "probe:Diamond.top",
                    "probe:Diamond.top_spec",
                )
            },
            {
                "probe:Diamond.left": "transitively-verified",
                "probe:Diamond.right": "transitively-verified",
                "probe:Diamond.top": "transitively-verified",
                "probe:Diamond.top_spec": "unverified",
            },
        )
        self.assertEqual(
            lean_atoms["probe:Diamond.top"]["primary-spec"],
            "probe:Diamond.top_spec",
        )
        self.assertEqual(
            lean_atoms["probe:Diamond.top_spec"]["type-dependencies"],
            ["probe:Diamond.top"],
        )
        lean_paths = {
            name: lean_atoms[name]["code-path"]
            for name in (
                "probe:Diamond.left",
                "probe:Diamond.right",
                "probe:Diamond.top",
            )
        }
        self.assertEqual(
            lean_paths,
            {
                "probe:Diamond.left": "Diamond/Left.lean",
                "probe:Diamond.right": "Diamond/Right.lean",
                "probe:Diamond.top": "Diamond/Top.lean",
            },
        )
        self.assertNotEqual(
            lean_paths["probe:Diamond.left"], lean_paths["probe:Diamond.right"]
        )

        manifest_target = json.loads((self.target / "autofv.json").read_text())[
            "targets"
        ][0]
        self.assertEqual(
            atoms[manifest_target["function"]]["translation-name"],
            "probe:Diamond.top",
        )
        self.assertEqual(
            f"probe:{manifest_target['spec']}",
            lean_atoms["probe:Diamond.top"]["primary-spec"],
        )

        rust_atoms = {
            atom["rust-qualified-name"]: atom
            for atom in atoms.values()
            if atom.get("rust-qualified-name", "").startswith("autofv_diamond::")
        }
        self.assertEqual(
            {
                name: (atom["translation-name"], atom["translation-path"])
                for name, atom in rust_atoms.items()
            },
            {
                "autofv_diamond::left": ("probe:Diamond.left", "Diamond/Left.lean"),
                "autofv_diamond::right": ("probe:Diamond.right", "Diamond/Right.lean"),
                "autofv_diamond::top": ("probe:Diamond.top", "Diamond/Top.lean"),
            },
        )
        for name, atom in rust_atoms.items():
            with self.subTest(rust=name):
                self.assertIs(atom["is-public"], True)
                self.assertIs(atom["is-public-api"], True)
                self.assertEqual(atom["charon-version"], "0.1.216")
                self.assertIs(atom["untracked"], False)

        pending = [rust, merged]
        forbidden = (
            "diamond-reference",
            "reference.json",
            "model-proxy",
            "diamond-responses",
            "fixtures/model-proxy",
        )
        while pending:
            value = pending.pop()
            if isinstance(value, dict):
                pending.extend(value.values())
            elif isinstance(value, list):
                pending.extend(value)
            elif isinstance(value, str):
                for marker in forbidden:
                    with self.subTest(marker=marker, value=value):
                        self.assertNotIn(marker, value)


if __name__ == "__main__":
    unittest.main()
