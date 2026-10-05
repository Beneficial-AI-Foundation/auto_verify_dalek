"""The committed host entry point guards every module before discovery; no packet is ever sent."""
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

RUNNER = Path(__file__).resolve().parent / "host_regression.py"

PROBE = textwrap.dedent('''
    import importlib, socket, subprocess, sys, unittest
    from pathlib import Path

    def guarded():
        return all(getattr(f, "autofv_host_guard", False)
                   for f in (socket.socket.connect, socket.socket.connect_ex, socket.getaddrinfo))

    GUARDED_AT_IMPORT = guarded()

    class Probe(unittest.TestCase):
        def test_discovered_import_was_already_guarded(self):
            self.assertTrue(GUARDED_AT_IMPORT)

        def test_dotted_import_name_is_guarded_too(self):
            sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
            self.assertTrue(importlib.import_module("tests.test_probe").GUARDED_AT_IMPORT)

        def test_popen_and_legacy_dns_cannot_escape_the_guard(self):
            functions = (subprocess.Popen, socket.gethostbyname, socket.gethostbyname_ex)
            self.assertTrue(all(getattr(f, "autofv_host_guard", False) for f in functions))
            # Never reach a real subprocess or DNS implementation if installation is missing.
            with self.assertRaises(AssertionError):
                subprocess.Popen(["docker", "version"])
            with self.assertRaises(AssertionError):
                # Empty PATH prevents any real launcher even if the guard regresses.
                subprocess.Popen(["sandbox-exec", "-p", "(version 1)", "limactl", "start", "fixture"],
                                 env={"PATH": ""})
            with self.assertRaises(AssertionError):
                subprocess.Popen(["git", "status"], executable="docker")
            with self.assertRaises(AssertionError):
                subprocess.run("docker version", shell=True)
            with self.assertRaises(AssertionError):
                subprocess.Popen(["sh", "-c", "docker version"])
            with self.assertRaises(AssertionError):
                socket.gethostbyname("example.invalid")
            with self.assertRaises(AssertionError):
                socket.gethostbyname_ex("example.invalid")

        def test_external_and_guest_attempts_are_refused(self):
            self.assertTrue(guarded())  # Stop here, before any real connect, if unguarded.
            with self.assertRaises(AssertionError):
                socket.socket().connect(("192.0.2.1", 9))
            with self.assertRaises(AssertionError):
                socket.getaddrinfo("example.invalid", 443)
            with self.assertRaises(AssertionError):
                subprocess.run(["docker", "version"])
            listener = socket.create_server(("127.0.0.1", 0))
            with listener, socket.create_connection(listener.getsockname()):
                pass
''')


class HostGuardTests(unittest.TestCase):
    def test_entry_point_guards_before_discovery_and_fails_on_any_attempt(self):
        with tempfile.TemporaryDirectory() as root:
            (Path(root) / "tests").mkdir()
            (Path(root) / "tests" / "test_probe.py").write_text(PROBE)
            (Path(root) / "tests" / "test_split_audit_proto.py").write_text(
                "raise AssertionError('excluded unrelated prototype was imported')\n")
            completed = subprocess.run([sys.executable, str(RUNNER)], cwd=root,
                                       capture_output=True, text=True, timeout=60)
        output = completed.stdout + completed.stderr
        self.assertIn("NOT IMPORTED: tests/test_split_audit_proto.py", output)
        self.assertIn("HOST TESTS: 4 UNEXERCISED GUEST/IMAGE METHODS: 0", output)
        self.assertIn("Ran 4 tests", output)
        self.assertIn("\nOK", output)
        self.assertIn("['non-loopback connection', 'non-loopback DNS', 'docker', 'docker', 'sandbox-exec', 'docker', 'shell', 'docker', 'non-loopback DNS', 'non-loopback DNS']", output)
        self.assertEqual(completed.returncode, 1, "a refused attempt must still fail the host run")


if __name__ == "__main__":
    unittest.main()
