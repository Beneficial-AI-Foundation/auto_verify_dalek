"""Synthetic private IPC tests. No OAuth, real provider traffic, or VM calls."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import threading
import time
import unittest
from unittest import mock

from autofv import pi_process as pi


ROOT = pi.runtime_path()
NODE = shutil.which("node")


def payload():
    messages = [{"role": "system", "content": "Synthetic system."}, {"role": "user", "content": "Synthetic user."}]
    request = {"run_id": "fixture-run", "conversation_id": "c" * 64, "request_id": "lane-cccccccccccccccc-001",
               "sequence": 1, "role": "prover", "model_id": "gpt-6.1-sol", "profile_sha256": "a" * 64,
               "history_sha256": hashlib.sha256(pi.canonical(messages)).hexdigest()}
    schemas = json.loads((ROOT / "tool-schemas.json").read_text())
    return {"request": request, "messages": messages, "continuations": [],
            "profile": {"provider": "openai", "api": "openai-responses", "model_id": "gpt-6.1-sol", "effort": "xhigh", "tool_choice": "required"},
            "admission": {"deadline_ms": int(time.time() * 1000) + 5000, "request_id": request["request_id"], "sequence": 1},
            "tools": [{"type": "function", "function": {"name": s["name"], "description": s["description"], "parameters": s["input_schema"]}} for s in schemas]}


@unittest.skipUnless(NODE, "Node executable unavailable")
class PiProcessTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="test-pi-process-")
        self.root = Path(self.temp.name)
        self.addCleanup(self.temp.cleanup)

    def process(self, program=None, runtime="fakeRuntime()"):
        path = self.root / f"fixture-{time.monotonic_ns()}.mjs"
        path.write_text(program or f"""
import {{serve}} from {json.dumps((ROOT / 'transport.mjs').as_uri())};
import {{fakeRuntime}} from {json.dumps((ROOT / 'test/helpers.mjs').as_uri())};
import {{SDK_VERSIONS}} from {json.dumps((ROOT / 'sdk-versions.mjs').as_uri())};
serve({{createRuntime:async()=>{runtime},sdk:SDK_VERSIONS}});
""")
        class FixtureProcess(pi.PiProcess):
            def _spawn(inner):
                return subprocess.Popen([str(inner.node), str(path)], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE, cwd=inner.directory, env=pi.minimal_environment(inner.node, inner.directory),
                    start_new_session=True, close_fds=True, shell=False, bufsize=0)
        process = FixtureProcess(NODE, store_path=self.root / "not-read.json", account_binding_sha256="a" * 64,
                                 runtime_dir=self.root / "private-processes")
        self.addCleanup(process.close)
        return process

    def test_one_generation_native_state_and_duplicate_no_resend(self):
        process = self.process()
        result = process.generate_one(payload())
        self.assertEqual(result["tool_call"], {"name": "check_lean", "arguments": {}})
        self.assertEqual(result["continuation"]["native"]["tool_call_id"], "call_1|fc_1")
        self.assertNotIn("PRIVATE_SUMMARY", json.dumps(result))
        with self.assertRaisesRegex(pi.PiProcessError, "duplicate_request"):
            process.generate_one(payload())
        with self.assertRaisesRegex(pi.PiProcessError, "process_quarantined"):
            process.generate_one(payload())

    def test_environment_drops_secrets_proxy_preload_and_tracing(self):
        injected = {"OPENAI_API_KEY": "SYNTHETIC_SECRET", "NODE_OPTIONS": "--require=evil", "NODE_PATH": "/evil",
                    "HTTPS_PROXY": "http://evil", "OTEL_EXPORTER_OTLP_ENDPOINT": "http://evil", "PYTHONPATH": "/evil"}
        with mock.patch.dict(os.environ, injected):
            env = pi.minimal_environment(Path(NODE), self.root)
        self.assertFalse(set(injected) & env.keys())
        self.assertEqual(env["HOME"], str(self.root))
        self.assertEqual(env["PI_OFFLINE"], "1")

    def test_stdout_contamination_and_crash_fail_closed(self):
        hello = pi.canonical({"v": 1, "op": "hello", "protocol": pi.PROTOCOL, "packages": pi.SDK_VERSIONS}).decode()
        for tail in ["process.stdout.write('CONTAMINATION\\n');", "process.exit(17);"]:
            p = self.process(f"let n=0;process.stdin.on('data',()=>{{if(++n===1)process.stdout.write({json.dumps(hello + chr(10))});else {{{tail}}}}});")
            with self.assertRaises(pi.PiProcessError):
                p.generate_one(payload())
            self.assertIsNotNone(p.process.poll())

    def test_deadline_kills_and_reaps_uncooperative_bridge(self):
        p = self.process(runtime="({getModel(){return fakeRuntime().getModel()},stream(){return {async *[Symbol.asyncIterator](){await new Promise(()=>{})},result(){return new Promise(()=>{})}}}})")
        request = payload()
        request["admission"]["deadline_ms"] = int(time.time() * 1000) + 150
        started = time.monotonic()
        with self.assertRaisesRegex(pi.PiProcessError, "timeout"):
            p.generate_one(request)
        self.assertLess(time.monotonic() - started, 3)
        self.assertIsNotNone(p.process.poll())

    def test_cancel_from_another_thread_quarantines_and_reaps(self):
        p = self.process(runtime="({getModel(){return fakeRuntime().getModel()},stream(){return {async *[Symbol.asyncIterator](){await new Promise(()=>{})},result(){return new Promise(()=>{})}}}})")
        outcome = []
        def generate():
            try:
                p.generate_one(payload())
            except pi.PiProcessError as error:
                outcome.append(error.code)
        thread = threading.Thread(target=generate)
        thread.start()
        time.sleep(.05)
        p.cancel()
        thread.join(3)
        self.assertFalse(thread.is_alive())
        self.assertTrue(outcome)
        self.assertIsNotNone(p.process.poll())

    def test_cancel_interrupts_backpressured_stdin_without_waiting_for_request_deadline(self):
        hello = pi.canonical({"v": 1, "op": "hello", "protocol": pi.PROTOCOL, "packages": pi.SDK_VERSIONS}).decode()
        p = self.process(f"process.stdin.once('data',()=>{{process.stdout.write({json.dumps(hello + chr(10))});process.stdin.pause();}});setInterval(()=>{{}},1000);")
        value = payload()
        value["messages"][1]["content"] = "x" * 1000000
        value["request"]["history_sha256"] = hashlib.sha256(pi.canonical(value["messages"])).hexdigest()
        outcome = []
        def generate():
            try:
                p.generate_one(value)
            except pi.PiProcessError as error:
                outcome.append(error.code)
        thread = threading.Thread(target=generate)
        thread.start()
        time.sleep(.05)
        started = time.monotonic()
        p.cancel()
        thread.join(2)
        self.assertLess(time.monotonic() - started, 2)
        self.assertFalse(thread.is_alive())
        self.assertTrue(outcome)

    def test_repeated_cleanup_never_resignals_a_reaped_group(self):
        p = self.process()
        original = os.killpg
        with mock.patch.object(os, "killpg", wraps=original) as kill:
            p.cancel()
            p.cancel()
            p.close()
            self.assertEqual(kill.call_count, 2)
            self.assertTrue(p._terminated)

    def test_stderr_is_bounded_and_never_exposed(self):
        hello = pi.canonical({"v": 1, "op": "hello", "protocol": pi.PROTOCOL, "packages": pi.SDK_VERSIONS}).decode()
        p = self.process(f"let n=0;process.stdin.on('data',()=>{{if(++n===1)process.stdout.write({json.dumps(hello + chr(10))});else process.stderr.write('SECRET_CANARY'.repeat(10000));}});")
        with self.assertRaises(pi.PiProcessError) as caught:
            p.generate_one(payload())
        self.assertEqual(caught.exception.code, "stderr_limit")
        self.assertNotIn("SECRET_CANARY", str(caught.exception))

    def test_metadata_diagnostic_does_not_need_store(self):
        if not (ROOT / "node_modules").is_dir():
            self.skipTest("exact SDK not installed")
        diagnostic = pi.runtime_diagnostic(NODE)
        self.assertFalse(diagnostic["credential_accessed"])
        self.assertFalse(diagnostic["model_dispatched"])
        self.assertEqual(diagnostic["runtime_identity"]["packages"], pi.SDK_VERSIONS)
        for key in ["node_sha256", "bridge_sha256", "package_lock_sha256"]:
            self.assertRegex(diagnostic["runtime_identity"][key], "^[0-9a-f]{64}$")

    def test_package_resources_resolve_without_checkout_cwd(self):
        prior = Path.cwd()
        try:
            os.chdir(self.root)
            self.assertTrue((pi.runtime_path() / "transport.mjs").is_file())
        finally:
            os.chdir(prior)

    def test_continuation_binds_full_request_and_opaque_allowlist(self):
        result = self.process().generate_one(payload())
        request = payload()["request"]
        full = {k: v for k, v in request.items() if k != "profile_sha256"}
        full["input_hashes"] = [request["profile_sha256"]]
        pi.validate_continuation(result["continuation"], full, result)
        altered = json.loads(json.dumps(result["continuation"]))
        altered["native"]["content"][0]["thinkingSignature"] = json.dumps({"id": "fc_evil", "type": "function_call", "summary": []})
        with self.assertRaises(pi.PiProcessError):
            pi.validate_continuation(altered, full, result)
        full["conversation_id"] = "d" * 64
        with self.assertRaises(pi.PiProcessError):
            pi.validate_continuation(result["continuation"], full, result)

    def test_runtime_identity_binds_installed_code_and_trusted_controller(self):
        root = self.root / "autofv" / "pi_runtime"
        root.mkdir(parents=True)
        for name in ["transport.mjs", "tool-schemas.json", "package.json", "package-lock.json"]:
            (root / name).write_text("{}")
        modules = root / "node_modules" / "fixture-package"
        modules.mkdir(parents=True)
        dependency = modules / "index.js"
        dependency.write_text("export const fixture = 1;")
        controller = root.parent / "pi_backend.py"
        controller.write_text("fixture = 1")
        with mock.patch.object(pi, "runtime_path", return_value=root):
            first = pi._runtime_identity(Path(NODE), pi.SDK_VERSIONS)
            dependency.write_text("export const fixture = 2;")
            second = pi._runtime_identity(Path(NODE), pi.SDK_VERSIONS)
            self.assertNotEqual(first["bridge_sha256"], second["bridge_sha256"])
            self.assertEqual(first["package_lock_sha256"], second["package_lock_sha256"])
            controller.write_text("fixture = 2")
            third = pi._runtime_identity(Path(NODE), pi.SDK_VERSIONS)
            self.assertNotEqual(second["bridge_sha256"], third["bridge_sha256"])
            (modules / "outside.js").symlink_to(self.root / "autofv" / "pi_backend.py")
            with self.assertRaisesRegex(pi.PiProcessError, "sdk_symlink_outside_runtime"):
                pi._runtime_identity(Path(NODE), pi.SDK_VERSIONS)

    def test_nonprivate_runtime_parent_rejected(self):
        directory = self.root / "public"
        directory.mkdir(mode=0o755)
        with self.assertRaisesRegex(pi.PiProcessError, "unsafe_runtime_directory"):
            pi.PiProcess(NODE, store_path=self.root / "absent", account_binding_sha256="a" * 64, runtime_dir=directory)


class WireTests(unittest.TestCase):
    def test_malformed_bounded_noncanonical_frames(self):
        for raw in [b'{"v":1,"v":1}', b'{"v":1.0}', b'{"v":1,"n":NaN}', b'\xff', b'[]']:
            with self.assertRaises(pi.PiProcessError):
                pi._decode(raw)
        with self.assertRaises(pi.PiProcessError):
            pi.canonical({"n": 1.5})


@unittest.skipUnless(os.environ.get("AUTOFV_PI_TEST_WHEEL"), "set AUTOFV_PI_TEST_WHEEL to the freshly built wheel")
class InstalledWheelTests(unittest.TestCase):
    def test_installed_wheel_resources_outside_source_tree(self):
        import sys
        import zipfile
        with tempfile.TemporaryDirectory(prefix="pi-wheel-test-") as directory:
            with zipfile.ZipFile(os.environ["AUTOFV_PI_TEST_WHEEL"]) as archive:
                names = archive.namelist()
                self.assertFalse(any("node_modules/" in name or name.endswith(("/credential.json", "/provisioning.json", "/auth.json")) for name in names))
                for resource in ["transport.mjs", "managed-store.mjs", "setup.mjs", "tool-schemas.json", "package.json", "package-lock.json"]:
                    self.assertIn("autofv/pi_runtime/" + resource, names)
                archive.extractall(directory)
            result = subprocess.run([sys.executable, "-c", "from autofv.pi_process import runtime_path; print(runtime_path()); assert (runtime_path()/'transport.mjs').is_file()"],
                cwd=directory, env={"PATH": os.environ.get("PATH", ""), "PYTHONPATH": directory},
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=15)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue(result.stdout.strip().startswith(directory))


if __name__ == "__main__":
    unittest.main()
