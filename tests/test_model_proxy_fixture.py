from __future__ import annotations

import base64
import copy
import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from decimal import Decimal
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Iterator

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from autofv import experiment


ROOT = Path(__file__).resolve().parents[1]
LOCK_PATH = ROOT / "docker" / "autofv" / "toolchain-lock.json"
FIXTURE_PATH = ROOT / "tests" / "fixtures" / "model-proxy" / "diamond-responses.json"
TARGET_PATH = ROOT / "tests" / "fixtures" / "diamond"
REFERENCE_PATH = ROOT / "tests" / "fixtures" / "diamond-reference" / "reference.json"
PROBE_PATH = ROOT / "tests" / "fixtures" / "probes" / "diamond-aeneas.json"
DOCKERFILE_PATH = ROOT / "docker" / "autofv" / "Dockerfile"

RUN_ID = "fixture-diamond-run-0001"
MODEL_ID = "fixture-model-v1"
PROOF_BATCH_ID = "proof-leaves-001"
RUN_TOKEN = "fixture-diamond-run-token"
REQUEST_IDS = (
    "scout-001",
    "dependency-plan-001",
    "contract-left-001",
    "contract-right-001",
    "contract-left-review-002",
    "proof-left-001",
    "proof-right-001",
    "proof-top-001",
)
PROOF_PAIR = frozenset(("proof-left-001", "proof-right-001"))
ROLES = (
    "scout",
    "dependency-planner",
    "contract-author",
    "contract-author",
    "contract-reviewer",
    "proof-author",
    "proof-author",
    "proof-author",
)
USAGE_AND_COST = {
    "scout-001": (120, 40, 160, Decimal("0.001600")),
    "dependency-plan-001": (140, 50, 190, Decimal("0.001900")),
    "contract-left-001": (200, 80, 280, Decimal("0.002800")),
    "contract-right-001": (190, 70, 260, Decimal("0.002600")),
    "contract-left-review-002": (220, 90, 310, Decimal("0.003100")),
    "proof-left-001": (240, 100, 340, Decimal("0.003400")),
    "proof-right-001": (230, 95, 325, Decimal("0.003250")),
    "proof-top-001": (260, 110, 370, Decimal("0.003700")),
}
ASSIGNED_PATHS = {
    "proof-left-001": "Diamond/Left.lean",
    "proof-right-001": "Diamond/Right.lean",
    "proof-top-001": "Diamond/Top.lean",
}
FINGERPRINT_NAMES = {
    "scout-001": (),
    "dependency-plan-001": (),
    "contract-left-001": ("Diamond.top_spec",),
    "contract-right-001": ("Diamond.top_spec",),
    "contract-left-review-002": ("Diamond.left_spec", "Diamond.top_spec"),
    "proof-left-001": ("Diamond.left_spec",),
    "proof-right-001": ("Diamond.right_spec",),
    "proof-top-001": ("Diamond.left_spec", "Diamond.right_spec", "Diamond.top_spec"),
}
SHA256 = re.compile(r"^[0-9a-f]{64}$")


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate JSON key")
        value[key] = item
    return value


def _strict_json(raw: bytes) -> Any:
    return json.loads(
        raw.decode("utf-8"),
        object_pairs_hook=_reject_duplicate_keys,
        parse_float=lambda _: (_ for _ in ()).throw(ValueError("JSON floats are forbidden")),
        parse_constant=lambda _: (_ for _ in ()).throw(
            ValueError("non-finite JSON numbers are forbidden")
        ),
    )


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _canonical_sha256(value: Any) -> str:
    return _sha256(experiment.canonical_json_bytes(value))


def _strings(value: Any) -> Iterator[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for key, item in value.items():
            yield key
            yield from _strings(item)
    elif isinstance(value, list):
        for item in value:
            yield from _strings(item)


def _deterministic_base_commit(git_contract: dict[str, Any]) -> str:
    expected = {
        "base_commit",
        "author_name",
        "author_email",
        "timestamp",
        "message",
    }
    if set(git_contract) != expected:
        raise AssertionError("fixture Git contract has the wrong fields")
    with tempfile.TemporaryDirectory() as temporary:
        repository = Path(temporary) / "diamond"
        shutil.copytree(
            TARGET_PATH,
            repository,
            ignore=shutil.ignore_patterns(
                ".git", ".lake", "target", "Cargo.lock", "__pycache__"
            ),
        )
        subprocess.run(
            ("git", "init", "-q", "--object-format=sha1"),
            cwd=repository,
            check=True,
        )
        subprocess.run(("git", "config", "core.autocrlf", "false"), cwd=repository, check=True)
        subprocess.run(("git", "config", "core.filemode", "false"), cwd=repository, check=True)
        subprocess.run(("git", "add", "--all"), cwd=repository, check=True)
        environment = os.environ.copy()
        environment.update(
            {
                "GIT_AUTHOR_NAME": git_contract["author_name"],
                "GIT_AUTHOR_EMAIL": git_contract["author_email"],
                "GIT_AUTHOR_DATE": git_contract["timestamp"],
                "GIT_COMMITTER_NAME": git_contract["author_name"],
                "GIT_COMMITTER_EMAIL": git_contract["author_email"],
                "GIT_COMMITTER_DATE": git_contract["timestamp"],
            }
        )
        subprocess.run(
            ("git", "commit", "-q", "--no-gpg-sign", "-m", git_contract["message"]),
            cwd=repository,
            env=environment,
            check=True,
        )
        return subprocess.run(
            ("git", "rev-parse", "HEAD"),
            cwd=repository,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()


class _FixtureProgram:
    """The V1 deterministic proxy state machine; it deliberately stays test-local."""

    def __init__(self, fixture: dict[str, Any], barrier: threading.Barrier | None = None):
        self._entries = {item["request"]["request_id"]: item for item in fixture["entries"]}
        self._barrier = barrier
        self._lock = threading.Lock()
        self._seen: set[str] = set()
        self._reserved: set[str] = set()
        self.intervals: dict[str, tuple[int, int]] = {}

    def invoke(self, request: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
        request_id = request.get("request_id")
        with self._lock:
            if request_id not in self._entries:
                raise ValueError("unknown request identity")
            if request_id in self._seen or request_id in self._reserved:
                raise ValueError("duplicate request identity")
            if request.get("run_id") != RUN_ID:
                raise ValueError("wrong run identity")
            expected_request = self._entries[request_id]["request"]
            if experiment.canonical_json_bytes(request) != experiment.canonical_json_bytes(
                expected_request
            ):
                raise ValueError("request envelope mismatch")

            completed_prefix = REQUEST_IDS[:5]
            if len(self._seen) < len(completed_prefix):
                if request_id != completed_prefix[len(self._seen)]:
                    raise ValueError("request arrived out of order")
                self._seen.add(request_id)
                entry = self._entries[request_id]
                return copy.deepcopy(entry["response"]), copy.deepcopy(entry["receipt"])
            if request_id in PROOF_PAIR:
                if not set(completed_prefix).issubset(self._seen):
                    raise ValueError("proof batch arrived before its dependencies")
                self._reserved.add(request_id)
            elif request_id == "proof-top-001":
                if not PROOF_PAIR.issubset(self._seen):
                    raise ValueError("top proof arrived before the proof batch")
                self._seen.add(request_id)
                entry = self._entries[request_id]
                return copy.deepcopy(entry["response"]), copy.deepcopy(entry["receipt"])
            else:
                raise ValueError("request arrived out of order")

        started = time.monotonic_ns()
        if self._barrier is not None:
            self._barrier.wait(timeout=5)
        finished = time.monotonic_ns()
        with self._lock:
            self.intervals[request_id] = (started, finished)
            self._reserved.remove(request_id)
            self._seen.add(request_id)
            entry = self._entries[request_id]
            return copy.deepcopy(entry["response"]), copy.deepcopy(entry["receipt"])


def _handler_for(
    program: _FixtureProgram,
    route: dict[str, Any],
    audit: dict[str, Any],
) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def _send(self, status: int, value: dict[str, Any]) -> None:
            raw = experiment.canonical_json_bytes(value)
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
            self._send(405 if self.path == route["path"] else 404, {"error": "rejected"})

        def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
            if self.path != route["path"]:
                self._send(404, {"error": "rejected"})
                return
            if self.headers.get("Authorization") or self.headers.get("X-AutoFV-Upstream-Host"):
                self._send(403, {"error": "caller upstream authorization forbidden"})
                return
            if self.headers.get("X-AutoFV-Run-Token") != RUN_TOKEN:
                self._send(401, {"error": "invalid run credential"})
                return
            try:
                length = int(self.headers.get("Content-Length", ""))
                if length <= 0 or length > 1_000_000:
                    raise ValueError("invalid content length")
                request = _strict_json(self.rfile.read(length))
                if not isinstance(request, dict):
                    raise ValueError("request must be an object")
                response, receipt = program.invoke(request)
            except (ValueError, json.JSONDecodeError):
                self._send(400, {"error": "request rejected"})
                return
            audit["stripped_run_credentials"] += 1
            audit["forwarded_headers"].append({})
            self._send(200, {"response": response, "receipt": receipt})

        def log_message(self, format: str, *args: Any) -> None:
            return

    return Handler


@contextmanager
def _trusted_proxy(
    fixture: dict[str, Any], route: dict[str, Any], *, barrier: threading.Barrier | None = None
) -> Iterator[tuple[str, _FixtureProgram, dict[str, Any]]]:
    program = _FixtureProgram(fixture, barrier)
    audit: dict[str, Any] = {"stripped_run_credentials": 0, "forwarded_headers": []}
    server = ThreadingHTTPServer(("0.0.0.0", 0), _handler_for(program, route, audit))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}", program, audit
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def _post(
    url: str,
    request: dict[str, Any],
    *,
    token: str = RUN_TOKEN,
    extra_headers: dict[str, str] | None = None,
) -> tuple[int, dict[str, Any]]:
    headers = {
        "Content-Type": "application/json",
        "X-AutoFV-Run-Token": token,
        **(extra_headers or {}),
    }
    wire_request = urllib.request.Request(
        url,
        data=experiment.canonical_json_bytes(request),
        headers=headers,
        method="POST",
    )
    try:
        with urllib.request.urlopen(wire_request, timeout=5) as response:
            return response.status, _strict_json(response.read())
    except urllib.error.HTTPError as error:
        return error.code, _strict_json(error.read())


class ModelProxyFixtureTests(unittest.TestCase):
    def setUp(self) -> None:
        # This is intentionally the first setup action: RED is the absent trusted fixture.
        self.fixture_raw = FIXTURE_PATH.read_bytes()
        self.fixture = _strict_json(self.fixture_raw)
        self.lock = _strict_json(LOCK_PATH.read_bytes())
        self.route = self.lock["fixed_proxy"]
        self.entries = self.fixture["entries"]
        self.by_id = {entry["request"]["request_id"]: entry for entry in self.entries}

    def test_strict_schema_identity_order_and_canonical_hashes(self) -> None:
        self.assertEqual(
            set(self.fixture),
            {
                "schema",
                "classification",
                "run_id",
                "model_id",
                "route",
                "git",
                "statement_fingerprints",
                "entries",
                "totals",
                "deployment",
            },
        )
        self.assertEqual(self.fixture["schema"], "autofv-model-proxy-fixture/v1")
        self.assertEqual(self.fixture["classification"], "deterministic-test-agent-output")
        self.assertEqual(self.fixture["run_id"], RUN_ID)
        self.assertEqual(self.fixture["model_id"], MODEL_ID)
        self.assertEqual(
            self.fixture["route"],
            {
                key: self.route[key]
                for key in ("proxy_id", "route_id", "method", "path")
            },
        )
        self.assertEqual(tuple(self.by_id), REQUEST_IDS)
        self.assertEqual(len(self.by_id), len(self.entries))

        request_fields = {
            "schema",
            "run_id",
            "sequence",
            "batch_id",
            "request_id",
            "role",
            "model_id",
            "input_hashes",
            "prompt_sha256",
        }
        response_fields = request_fields | {
            "kind",
            "assigned_path",
            "base_commit",
            "statement_fingerprints",
            "payload",
            "payload_sha256",
        }
        for sequence, (entry, request_id, role) in enumerate(
            zip(self.entries, REQUEST_IDS, ROLES, strict=True), start=1
        ):
            self.assertEqual(set(entry), {"request", "request_sha256", "response", "response_sha256", "receipt"})
            request = entry["request"]
            response = entry["response"]
            self.assertEqual(set(request), request_fields)
            self.assertEqual(set(response), response_fields)
            self.assertEqual(request["schema"], "autofv-model-request/v1")
            self.assertEqual(response["schema"], "autofv-model-response/v1")
            self.assertEqual(request["run_id"], RUN_ID)
            self.assertEqual(request["sequence"], sequence)
            self.assertEqual(request["request_id"], request_id)
            self.assertEqual(request["role"], role)
            self.assertEqual(request["model_id"], MODEL_ID)
            self.assertEqual(request["batch_id"], PROOF_BATCH_ID if request_id in PROOF_PAIR else None)
            self.assertEqual(request["input_hashes"], sorted(set(request["input_hashes"])))
            self.assertTrue(all(SHA256.fullmatch(item) for item in request["input_hashes"]))
            self.assertRegex(request["prompt_sha256"], SHA256)
            self.assertEqual(entry["request_sha256"], _canonical_sha256(request))

            for identity in ("run_id", "sequence", "batch_id", "request_id", "role", "model_id"):
                self.assertEqual(response[identity], request[identity])
            self.assertEqual(response["input_hashes"], request["input_hashes"])
            self.assertEqual(response["prompt_sha256"], request["prompt_sha256"])
            self.assertEqual(response["payload_sha256"], _canonical_sha256(response["payload"]))
            self.assertEqual(entry["response_sha256"], _canonical_sha256(response))

    def test_contract_strengthening_and_typed_candidate_envelopes(self) -> None:
        fingerprints = self.fixture["statement_fingerprints"]
        self.assertEqual(
            set(fingerprints),
            {"Diamond.left_spec", "Diamond.right_spec", "Diamond.top_spec"},
        )
        self.assertTrue(all(SHA256.fullmatch(value) for value in fingerprints.values()))
        base_commit = _deterministic_base_commit(self.fixture["git"])
        self.assertEqual(self.fixture["git"]["base_commit"], base_commit)

        statement_ids = (
            "contract-left-001",
            "contract-right-001",
            "contract-left-review-002",
        )
        declarations = (
            "Diamond.left_spec",
            "Diamond.right_spec",
            "Diamond.left_spec",
        )
        for request_id, declaration in zip(statement_ids, declarations, strict=True):
            response = self.by_id[request_id]["response"]
            payload = response["payload"]
            self.assertEqual(response["kind"], "statement")
            self.assertIsNone(response["assigned_path"])
            self.assertEqual(
                set(payload), {"schema", "declaration", "text", "text_sha256"}
            )
            self.assertEqual(payload["schema"], "autofv-statement-candidate/v1")
            self.assertEqual(payload["declaration"], declaration)
            self.assertEqual(payload["text_sha256"], _sha256(payload["text"].encode("utf-8")))

        weak = self.by_id["contract-left-001"]["response"]["payload"]["text"]
        strong = self.by_id["contract-left-review-002"]["response"]["payload"]["text"]
        self.assertNotEqual(weak, strong)
        self.assertTrue("≤" in weak or ">=" in weak or "≥" in weak)
        self.assertIn("=", strong)
        weak_hash = self.by_id["contract-left-001"]["response"]["payload"]["text_sha256"]
        self.assertIn(weak_hash, self.by_id["contract-left-review-002"]["request"]["input_hashes"])

        for request_id, assigned_path in ASSIGNED_PATHS.items():
            response = self.by_id[request_id]["response"]
            payload = response["payload"]
            expected_fingerprints = sorted(fingerprints[name] for name in FINGERPRINT_NAMES[request_id])
            self.assertEqual(response["kind"], "patch")
            self.assertEqual(response["assigned_path"], assigned_path)
            self.assertEqual(response["base_commit"], base_commit)
            self.assertEqual(response["statement_fingerprints"], expected_fingerprints)
            self.assertEqual(
                set(payload),
                {
                    "schema",
                    "format",
                    "patch",
                    "patch_sha256",
                    "assigned_path",
                    "base_commit",
                    "statement_fingerprints",
                },
            )
            self.assertEqual(payload["schema"], "autofv-candidate-patch/v1")
            self.assertEqual(payload["format"], "unified_diff")
            self.assertEqual(payload["assigned_path"], assigned_path)
            self.assertEqual(payload["base_commit"], base_commit)
            self.assertEqual(payload["statement_fingerprints"], expected_fingerprints)
            self.assertEqual(payload["patch_sha256"], _sha256(payload["patch"].encode("utf-8")))
            changed_paths = re.findall(
                r"^diff --git a/([^ ]+) b/([^\n]+)$", payload["patch"], re.MULTILINE
            )
            self.assertEqual(changed_paths, [(assigned_path, assigned_path)])
            self.assertIn(f"--- a/{assigned_path}\n", payload["patch"])
            self.assertIn(f"+++ b/{assigned_path}\n", payload["patch"])

    def test_signed_receipts_usage_cost_and_unique_total_reconciliation(self) -> None:
        authentication = self.route["receipt_schema"]["authentication"]
        public_key = serialization.load_pem_public_key(
            authentication["public_key_pem"].encode("ascii")
        )
        self.assertIsInstance(public_key, Ed25519PublicKey)
        public_der = public_key.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        self.assertEqual(_sha256(public_der), authentication["public_key_der_sha256"])

        seen_receipts: set[str] = set()
        seen_requests: set[str] = set()
        totals = [0, 0, 0]
        total_cost = Decimal("0.000000")
        for entry in self.entries:
            request = entry["request"]
            receipt = entry["receipt"]
            request_id = request["request_id"]
            expected_input, expected_output, expected_total, expected_cost = USAGE_AND_COST[request_id]
            self.assertEqual(
                receipt["usage"],
                {
                    "input_tokens": expected_input,
                    "output_tokens": expected_output,
                    "total_tokens": expected_total,
                },
            )
            self.assertEqual(receipt["cost"], {"amount": f"{expected_cost:.6f}", "currency": "USD"})
            self.assertEqual(receipt["auth"]["key_id"], authentication["key_id"])
            amount = experiment.validate_proxy_receipt(
                receipt,
                run_id=RUN_ID,
                sequence=request["sequence"],
                request_id=request_id,
                model_id=MODEL_ID,
                request_sha256=entry["request_sha256"],
                response_sha256=entry["response_sha256"],
                seen_receipt_sha256=frozenset(seen_receipts),
                seen_request_ids=frozenset(seen_requests),
            )
            unsigned = copy.deepcopy(receipt)
            signature = base64.b64decode(unsigned["auth"].pop("signature"), validate=True)
            unsigned.pop("receipt_sha256")
            public_key.verify(signature, experiment.canonical_json_bytes(unsigned))
            self.assertEqual(amount, expected_cost)
            seen_receipts.add(receipt["receipt_sha256"])
            seen_requests.add(request_id)
            totals[0] += expected_input
            totals[1] += expected_output
            totals[2] += expected_total
            total_cost += expected_cost

        self.assertEqual(len(seen_receipts), len(REQUEST_IDS))
        self.assertEqual(
            self.fixture["totals"],
            {
                "requests": len(REQUEST_IDS),
                "usage": {
                    "input_tokens": totals[0],
                    "output_tokens": totals[1],
                    "total_tokens": totals[2],
                },
                "cost": {"amount": f"{total_cost:.6f}", "currency": "USD"},
            },
        )
        first = self.entries[0]
        for mutation in ("usage", "run"):
            tampered = copy.deepcopy(first["receipt"])
            if mutation == "usage":
                tampered["usage"]["input_tokens"] += 1
            else:
                tampered["run_id"] = "wrong-run"
            with self.subTest(mutation=mutation), self.assertRaises(experiment.ContractError):
                experiment.validate_proxy_receipt(
                    tampered,
                    run_id=RUN_ID,
                    sequence=1,
                    request_id="scout-001",
                    model_id=MODEL_ID,
                    request_sha256=first["request_sha256"],
                    response_sha256=first["response_sha256"],
                    seen_receipt_sha256=frozenset(),
                    seen_request_ids=frozenset(),
                )

    def test_state_machine_fails_closed_and_proof_batch_overlaps(self) -> None:
        requests = {item["request"]["request_id"]: item["request"] for item in self.entries}
        mutations: list[tuple[str, dict[str, Any], list[str]]] = []
        unknown = copy.deepcopy(requests["scout-001"])
        unknown["request_id"] = "unknown-001"
        mutations.append(("unknown", unknown, []))
        wrong_run = copy.deepcopy(requests["scout-001"])
        wrong_run["run_id"] = "wrong-run"
        mutations.append(("wrong run", wrong_run, []))
        tampered = copy.deepcopy(requests["scout-001"])
        tampered["prompt_sha256"] = "0" * 64
        mutations.append(("tampered", tampered, []))
        extra = copy.deepcopy(requests["scout-001"])
        extra["upstream_host"] = "forbidden.invalid"
        mutations.append(("extra", extra, []))
        mutations.append(("out of order", requests["proof-top-001"], []))
        mutations.append(("duplicate", requests["scout-001"], ["scout-001"]))
        for label, request, prefix in mutations:
            with self.subTest(label=label):
                program = _FixtureProgram(self.fixture)
                for request_id in prefix:
                    program.invoke(requests[request_id])
                with self.assertRaises(ValueError):
                    program.invoke(request)

        barrier = threading.Barrier(2)
        program = _FixtureProgram(self.fixture, barrier)
        for request_id in REQUEST_IDS[:5]:
            program.invoke(requests[request_id])
        with ThreadPoolExecutor(max_workers=2) as pool:
            right = pool.submit(program.invoke, requests["proof-right-001"])
            left = pool.submit(program.invoke, requests["proof-left-001"])
            right_response, _ = right.result(timeout=10)
            left_response, _ = left.result(timeout=10)
        self.assertEqual(right_response["request_id"], "proof-right-001")
        self.assertEqual(left_response["request_id"], "proof-left-001")
        left_interval = program.intervals["proof-left-001"]
        right_interval = program.intervals["proof-right-001"]
        self.assertLess(max(left_interval[0], right_interval[0]), min(left_interval[1], right_interval[1]))
        top_response, _ = program.invoke(requests["proof-top-001"])
        self.assertEqual(top_response["request_id"], "proof-top-001")

    def test_fixed_route_rejects_caller_authority_and_strips_run_credential(self) -> None:
        expected_route = {
            "proxy_id": "autofv-local-fixture-proxy-v1",
            "route_id": "autofv-infer-v1",
            "method": "POST",
            "path": "/v1/autofv/infer",
        }
        self.assertEqual(
            {key: self.route[key] for key in expected_route},
            expected_route,
        )
        self.assertEqual(self.lock["model_client"]["implementation"], "urllib.request")
        self.assertFalse(self.lock["model_client"]["provider_abstraction"])
        with _trusted_proxy(self.fixture, self.route) as (base_url, _, audit):
            request = self.by_id["scout-001"]["request"]
            status, _ = _post(f"{base_url}/wrong", request)
            self.assertEqual(status, 404)
            get = urllib.request.Request(f"{base_url}{self.route['path']}", method="GET")
            with self.assertRaises(urllib.error.HTTPError) as error:
                urllib.request.urlopen(get, timeout=5)
            self.assertEqual(error.exception.code, 405)
            status, _ = _post(f"{base_url}{self.route['path']}", request, token="wrong")
            self.assertEqual(status, 401)
            status, _ = _post(
                f"{base_url}{self.route['path']}",
                request,
                extra_headers={"Authorization": "Bearer caller-provider-key"},
            )
            self.assertEqual(status, 403)
            status, _ = _post(
                f"{base_url}{self.route['path']}",
                request,
                extra_headers={"X-AutoFV-Upstream-Host": "provider.invalid"},
            )
            self.assertEqual(status, 403)
            status, body = _post(f"{base_url}{self.route['path']}", request)
            self.assertEqual(status, 200)
            self.assertEqual(body["response"]["request_id"], "scout-001")
            self.assertEqual(body["receipt"]["request_id"], "scout-001")
            self.assertEqual(audit["stripped_run_credentials"], 1)
            self.assertEqual(audit["forwarded_headers"], [{}])

    def test_fixture_and_deployment_state_are_proxy_side_only(self) -> None:
        self.assertEqual(
            self.fixture["deployment"],
            {
                "schema": "autofv-model-proxy-deployment/v1",
                "state": "trusted-proxy-side-only",
                "release": "request-identity-only",
                "target": False,
                "control_bundle": False,
                "image": False,
                "agent_volume": False,
                "prompts": False,
                "logs": False,
                "export": False,
            },
        )
        reference = _strict_json(REFERENCE_PATH.read_bytes())
        hidden_values = {
            "diamond-reference",
            "reference.json",
            reference["schema"],
            reference["delivery"],
            reference["artifact_role"],
        }
        for leaf in reference["leaves"]:
            hidden_values.update(
                {
                    leaf["statement"],
                    leaf["statement_sha256"],
                    leaf["proof"],
                    leaf["proof_sha256"],
                }
            )
        banned_claims = (
            "l4",
            "provider truth",
            "provider-side truth",
            "unrestricted access",
            "unrestricted model",
        )
        for value in _strings(self.fixture):
            lowered = value.lower()
            if any(secret and secret in value for secret in hidden_values):
                self.fail("verifier-only material leaked into the proxy fixture")
            if any(claim in lowered for claim in banned_claims):
                self.fail("forbidden authority claim leaked into the proxy fixture")

        fixture_hash = _sha256(self.fixture_raw).encode("ascii")
        fixture_name = str(FIXTURE_PATH.relative_to(ROOT)).encode("utf-8")
        target_bytes = b"".join(
            path.read_bytes() for path in sorted(TARGET_PATH.rglob("*")) if path.is_file()
        )
        control_bytes = b"".join(
            (TARGET_PATH / name).read_bytes() for name in ("autofv.json", "run.json")
        )
        image_bytes = DOCKERFILE_PATH.read_bytes() + LOCK_PATH.read_bytes()
        for released in (target_bytes, control_bytes, image_bytes):
            self.assertNotIn(self.fixture_raw, released)
            self.assertNotIn(fixture_hash, released)
            self.assertNotIn(fixture_name, released)
        self.assertFalse(FIXTURE_PATH.is_relative_to(TARGET_PATH))
        probe_strings = tuple(_strings(_strict_json(PROBE_PATH.read_bytes())))
        self.assertNotIn("diamond-reference", "\n".join(probe_strings).lower())

    def test_real_runsc_image_can_call_only_the_fixed_proxy_route(self) -> None:
        request = self.by_id["scout-001"]["request"]
        client = "\n".join(
            (
                "import base64, json, os, urllib.request",
                "raw = base64.b64decode(os.environ['AUTOFV_REQUEST_B64'])",
                "url = os.environ['AUTOFV_PROXY_BASE'] + os.environ['AUTOFV_PROXY_PATH']",
                "req = urllib.request.Request(url, data=raw, method=os.environ['AUTOFV_PROXY_METHOD'], headers={'Content-Type': 'application/json', 'X-AutoFV-Run-Token': os.environ['AUTOFV_RUN_TOKEN']})",
                "with urllib.request.urlopen(req, timeout=10) as reply: body = json.load(reply)",
                "assert body['response']['request_id'] == os.environ['AUTOFV_REQUEST_ID']",
                "assert body['receipt']['request_id'] == os.environ['AUTOFV_REQUEST_ID']",
            )
        )
        with _trusted_proxy(self.fixture, self.route) as (base_url, _, audit):
            # The launcher exposes an address; method and path remain locked.
            host_base = "http://host.docker.internal"
            port = urllib.parse.urlsplit(base_url).port
            argv = (
                "sudo",
                "docker",
                "run",
                "--rm",
                "--runtime",
                "runsc-hardened",
                "--read-only",
                "--user",
                "65532:65532",
                "--security-opt",
                "no-new-privileges",
                "--pids-limit",
                "256",
                "--cpus",
                "2",
                "--memory",
                "2g",
                "--tmpfs",
                "/tmp:rw,nosuid,nodev,noexec,size=64m,mode=1777",
                "--add-host",
                "host.docker.internal:host-gateway",
                "--env",
                f"AUTOFV_PROXY_BASE={host_base}:{port}",
                "--env",
                f"AUTOFV_PROXY_METHOD={self.route['method']}",
                "--env",
                f"AUTOFV_PROXY_PATH={self.route['path']}",
                "--env",
                f"AUTOFV_RUN_TOKEN={RUN_TOKEN}",
                "--env",
                "AUTOFV_REQUEST_ID=scout-001",
                "--env",
                "AUTOFV_REQUEST_B64="
                + base64.b64encode(experiment.canonical_json_bytes(request)).decode("ascii"),
                self.lock["image"]["image_digest"],
                "python",
                "-c",
                client,
            )
            completed = subprocess.run(argv, capture_output=True, text=True, timeout=30)
            self.assertEqual(
                completed.returncode,
                0,
                msg=f"fixed proxy route unavailable from pinned runsc image: {completed.stderr}",
            )
            self.assertEqual(audit["stripped_run_credentials"], 1)


if __name__ == "__main__":
    unittest.main()
