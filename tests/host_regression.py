"""Supported host regression entry point: guest-free, with non-loopback network refused.

Run from the repository root: `.venv/bin/python tests/host_regression.py`.
The guard is installed before discovery, so it covers every module under whatever name
it is imported. Live guest/image methods are reported as unexercised, never silently
enabled; run one only by explicit id (`python -m unittest <id>`) under separate approval.
"""
import ipaddress
import shlex
import socket
import subprocess
import unittest
from pathlib import Path

blocked: list[str] = []

LIVE_METHODS = frozenset({
    "test_linux_isolation.LinuxIsolationTests.test_claim_collision_and_export_before_disposal",
    "test_linux_isolation.LinuxIsolationTests.test_dirty_working_state_survives_export_and_worker_recreation",
    "test_linux_isolation.LinuxIsolationTests.test_export_rejects_unaccepted_head_without_destroying_worker",
    "test_linux_isolation.LinuxIsolationTests.test_preparation_failure_destroys_worker_but_export_failure_retains_it",
    "test_linux_isolation.LinuxIsolationTests.test_runtime_inspection_and_external_deny_matrix",
    "test_linux_isolation.LinuxIsolationTests.test_worker_contract_rejects_mutable_or_mismatched_inputs",
    "test_linux_isolation.ProxyAccountingTests.test_real_proxy_policy_accounting_and_retained_surface_scans",
    "test_phase1_diamond.Phase1DiamondTests.test_one_full_sealed_concurrent_diamond",
    "test_image_contract.ImageBuildTests.test_actual_image_inspection_matches_the_lock",
    "test_model_proxy_fixture.ModelProxyFixtureTests.test_real_runsc_image_can_call_only_the_fixed_proxy_route",
})
LIVE_CLASSES = ("test_image_contract.RuntimeSmokeTests.",)
GUEST_COMMANDS = frozenset({"sudo", "docker", "limactl", "lima", "podman", "lake"})
SHELL_WRAPPERS = frozenset({"env", "rtk", "sandbox-exec"})
SHELLS = frozenset({"sh", "bash", "zsh", "fish"})


def _loopback(host) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _guarded(function):
    function.autofv_host_guard = True
    return function


def install_guard() -> None:
    """Refuse non-loopback TCP/DNS and unmocked guest/build commands process-wide."""
    real_popen = subprocess.Popen

    def refusing(original):
        def connect(connection, address, *args):
            if connection.family in {socket.AF_INET, socket.AF_INET6} and not _loopback(address[0]):
                blocked.append("non-loopback connection")
                raise AssertionError("external connection forbidden in host regression")
            return original(connection, address, *args)
        return _guarded(connect)

    def resolver(original):
        def dns(host, *args, **kwargs):
            if host not in (None, "", "0.0.0.0", "::") and not _loopback(host):
                blocked.append("non-loopback DNS")
                raise AssertionError("external DNS forbidden in host regression")
            return original(host, *args, **kwargs)
        return _guarded(dns)

    def popen(argv, *args, **kwargs):
        executable = kwargs.get("executable") or (argv[0] if isinstance(argv, (tuple, list)) else argv)
        name = Path(executable).name
        if name in SHELLS and isinstance(argv, (tuple, list)) and len(argv) > 2 and argv[1] == "-c":
            # ponytail: literal commands only; arbitrary shell expansion is not a sandbox. Keep fixtures trusted.
            lexer = shlex.shlex(argv[2], posix=True, punctuation_chars=True)
            lexer.whitespace_split = True
            forbidden = next((Path(token).name for token in lexer
                              if Path(token).name in GUEST_COMMANDS | SHELL_WRAPPERS), None)
            name = name if forbidden is None else forbidden
        if kwargs.get("shell") or name in GUEST_COMMANDS | SHELL_WRAPPERS:
            blocked.append("shell" if kwargs.get("shell") else name)
            raise AssertionError("unmocked guest/build or shell command refused by host regression")
        return real_popen(argv, *args, **kwargs)

    socket.socket.connect = refusing(socket.socket.connect)
    socket.socket.connect_ex = refusing(socket.socket.connect_ex)
    socket.getaddrinfo = resolver(socket.getaddrinfo)
    socket.gethostbyname = resolver(socket.gethostbyname)
    socket.gethostbyname_ex = resolver(socket.gethostbyname_ex)
    subprocess.Popen = _guarded(popen)  # Covers run/call/check_output as well as direct Popen.


def _flatten(items):
    for item in items:
        if isinstance(item, unittest.TestSuite):
            yield from _flatten(item)
        else:
            yield item


def main() -> int:
    install_guard()
    selected, excluded = [], []
    loader = unittest.TestLoader()
    for source in sorted(Path("tests").glob("test_*.py")):
        if source.name == "test_split_audit_proto.py":
            print("NOT IMPORTED:", source, flush=True)
            continue
        for test in _flatten(loader.discover("tests", pattern=source.name)):
            live = test.id() in LIVE_METHODS or any(marker in test.id() for marker in LIVE_CLASSES)
            (excluded if live else selected).append(test)
    print("HOST TESTS:", len(selected), "UNEXERCISED GUEST/IMAGE METHODS:", len(excluded), flush=True)
    for identity in sorted(test.id() for test in excluded):
        print("NOT VALIDATED:", identity, flush=True)
    result = unittest.TextTestRunner(verbosity=1).run(unittest.TestSuite(selected))
    print("BLOCKED GUEST COMMANDS OR EXTERNAL NETWORK:", blocked, flush=True)
    return int(not result.wasSuccessful() or bool(blocked))


if __name__ == "__main__":
    raise SystemExit(main())
