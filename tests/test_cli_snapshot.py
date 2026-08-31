import copy
import json
import subprocess
import sys
import tempfile
import tomllib
import unittest
from decimal import Decimal
from pathlib import Path

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


class ToolchainContractTests(unittest.TestCase):
    def test_package_exposes_only_the_autofv_entrypoint(self):
        data = tomllib.loads((ROOT / "pyproject.toml").read_text())
        self.assertEqual(data["build-system"]["build-backend"], "uv_build")
        self.assertEqual(data["build-system"]["requires"], ["uv_build==0.12.7"])
        self.assertEqual(
            data["project"]["scripts"], {"autofv": "autofv.experiment:main"}
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
    def test_unselected_policy_blocks_freeze(self):
        lock = load_lock()
        self.assertEqual(lock["native_decide"]["state"], "decision_required")
        self.assertFalse(lock["native_decide"]["runnable"])
        self.assertNotIn("selected_policy", lock["native_decide"])
        with self.assertRaises(experiment.ContractError):
            experiment.validate_native_decide_policy(lock)

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
            with self.assertRaises(experiment.ContractError):
                experiment.run_experiment(
                    target, config, run_round=lambda *a, **k: calls.append((a, k))
                )
        self.assertEqual(calls, [])


if __name__ == "__main__":
    unittest.main()
