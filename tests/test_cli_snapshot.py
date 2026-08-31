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

from autofv import experiment


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
        self.assertIn("{run}", top.stdout)
        self.assertIn("--target", run.stdout)
        self.assertIn("--run-config", run.stdout)
        for forbidden in ("--model", "--node", "--probe", "--provider", "--host"):
            self.assertNotIn(forbidden, top.stdout + run.stdout)

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
            with self.assertRaises(experiment.ContractError):
                experiment.run_experiment(target, config, run_round=launcher)
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
                    }
                )
            )
            with mock.patch.dict(
                os.environ, {"AUTOFV_NATIVE_DECIDE_POLICY": "forbid_all"}
            ):
                result = experiment.run_experiment(
                    target, config, run_round=lambda *a, **k: calls.append((a, k))
                )
        self.assertEqual(result["native_decide_policy"], "allow_audited")
        self.assertEqual(result["native_decide_policy_sha256"], POLICY_SHA256)
        self.assertEqual(calls, [])


if __name__ == "__main__":
    unittest.main()
