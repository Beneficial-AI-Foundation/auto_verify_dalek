#!/usr/bin/env python3
"""Local Lake feedback, not a proof-acceptance gate (Linux/POSIX).

Only the standard library is needed; this file is copied into agent sandboxes.
A detached supervisor owns the build and watches a pipe from the CLI process.
Even SIGKILL of the agent/CLI closes that pipe and triggers build-group cleanup.
"""
import argparse
import fcntl
import json
import math
import os
from pathlib import Path
import re
import select
import signal
import subprocess
import sys
import time
import uuid

import proof_state

EXIT_CODES = {"success": 0, "failure": 1, "timeout": 124,
              "busy": 75, "interrupted": 130, "error": 2}
ANSI = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
LOCATION = re.compile(
    r"^(?:(error|warning|info):\s*)?(.+?\.lean):(\d+):(\d+):\s*"
    r"(?:(error|warning|info):\s*)?(.*)$")


def summarize(log_path):
    """Stream logs with bounded diagnostic memory. No invented goal/location."""
    first_error, block, last = None, [], None
    warnings = sorries = 0
    with open(log_path, encoding="utf-8", errors="replace") as stream:
        for raw in stream:
            line = ANSI.sub("", raw.rstrip())
            if not line:
                continue
            last = line[-2000:]
            match = LOCATION.match(line)
            severity = (match[1] or match[5] or "error") if match else None
            if severity == "warning" or line.startswith("warning:"):
                warnings += 1
            if "declaration uses" in line and "sorry" in line:
                sorries += 1
            is_error = severity == "error" or line.startswith("error:")
            if first_error is None and is_error:
                first_error = {"message": (match[6] if match else line)[:4000],
                               "file": match[2] if match else None,
                               "line": int(match[3]) if match else None,
                               "column": int(match[4]) if match else None}
                block = [line[:2000]]
            elif block and len(block) < 30:
                if match or line.startswith(("error:", "warning:", "info:", "✖", "✔", "⚠")):
                    # Stop at the next diagnostic/build event.
                    if first_error is not None:
                        first_error.setdefault("diagnostic", "\n".join(block))
                    block = []
                elif "diagnostic" not in first_error:
                    block.append(line[:2000])
    if first_error is not None:
        first_error.setdefault("diagnostic", "\n".join(block))
    diagnostic = first_error["diagnostic"] if first_error else ""
    return {"first_error": first_error,
            "goal_text": diagnostic if "unsolved goals" in diagnostic else None,
            "last_output": last, "warning_count": warnings,
            "sorry_warning_count": sorries,
            "timeout_declaration": None}


def _kill_group(proc):
    if proc is not None:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        proc.wait()


def check(work, module, timeout, log_dir, cancel_fd=None, snapshot_paths=(), obligation=None):
    """One serialized check. Only helper-managed builds share this lock.

    cancel_fd becomes readable/EOF when the caller disappears. Artifacts live
    outside editable proof sources; the lock is shared per real workspace.
    """
    work = Path(work).resolve()
    log_dir = Path(log_dir).resolve()
    log_dir.mkdir(parents=True, exist_ok=True)
    stem = time.strftime("%Y%m%dT%H%M%S") + "-" + uuid.uuid4().hex[:12]
    log_path = log_dir / (stem + ".log")
    result_path = log_dir / (stem + ".json")
    command = ["lake", "build"] + ([module] if module else [])
    started = time.monotonic()
    result = {"schema_version": 1, "status": "error", "finished": False,
              "exit_code": None, "elapsed_seconds": 0, "command": command,
              "workspace": str(work), "module": module, "timeout_seconds": timeout,
              "obligation": obligation, "obligation_source": "caller_label",
              "log_path": str(log_path), "result_path": str(result_path),
              "acceptance_checked": False, "task_id": os.environ.get("LEAN_CHECK_TASK_ID"),
              "started_at_ns": time.time_ns(), "checkpoint_path": None}
    proc = None
    # Lake already writes here; no new source-file exception is required.
    lock_dir = work / ".lake"
    lock_dir.mkdir(exist_ok=True)
    with open(log_path, "wb") as log, open(lock_dir / "harness-check.lock", "a") as lock:
        try:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                result.update(status="busy", message="Another local check owns this workspace; retry after it ends.")
            else:
                before = proof_state.context(work)
                sources = proof_state.capture(work, snapshot_paths)
                result["context_before"] = {k: before[k] for k in ("sha256", "scope")}
                result["source_hashes"] = proof_state.hashes(sources)
                proc = subprocess.Popen(command, cwd=work, stdout=log,
                                        stderr=subprocess.STDOUT,
                                        stdin=subprocess.DEVNULL, start_new_session=True)
                while True:
                    if cancel_fd is not None and select.select([cancel_fd], [], [], 0)[0]:
                        result["status"] = "interrupted"
                        break
                    rc = proc.poll()
                    if rc is not None:
                        result.update(status="success" if rc == 0 else "failure", finished=True)
                        break
                    if time.monotonic() - started >= timeout:
                        result["status"] = "timeout"
                        break
                    time.sleep(0.05)
        except (KeyboardInterrupt, SystemExit):
            result["status"] = "interrupted"
        except OSError as exc:
            result.update(status="error", message=str(exc))
        finally:
            # Also remove background descendants after a normal Lake exit.
            _kill_group(proc)
            if proc is not None:
                result["exit_code"] = proc.returncode
        if "context_before" in result:
            after = proof_state.context(work)
            result["context_after"] = {k: after[k] for k in ("sha256", "scope")}
            result["sources_unchanged"] = (
                before["sha256"] == after["sha256"] and
                all(before["files"].get(p) == sha == after["files"].get(p)
                    for p, sha in result["source_hashes"].items()))
            if result["status"] == "success" and result["sources_unchanged"] and sources:
                result["checkpoint_path"] = proof_state.snapshot(
                    log_dir / (stem + ".checkpoint"), sources, "checked_module",
                    module=module, context_sha256=after["sha256"], check_result=str(result_path),
                    dependency_closure_checked=False)
    result["elapsed_seconds"] = round(time.monotonic() - started, 3)
    result.update(summarize(log_path))
    result_path.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n")
    return result


def _positive_seconds(value):
    number = float(value)
    if not math.isfinite(number) or number <= 0:
        raise argparse.ArgumentTypeError("timeout must be finite and positive")
    return number


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    target = parser.add_mutually_exclusive_group(required=True)
    target.add_argument("module", nargs="?", help="Lean module name, e.g. Curve25519Dalek.Specs.Foo")
    target.add_argument("--full", action="store_true", help="full build only; does not run acceptance gates")
    parser.add_argument("--work", default=".")
    parser.add_argument("--timeout", type=_positive_seconds, default=120)
    parser.add_argument("--log-dir", help="default: <workspace>/.lake/harness-checks")
    parser.add_argument("--obligation", help="stable Lean declaration name being worked on; diagnostic label, not verification")
    parser.add_argument("--snapshot-path", action="append", default=[],
                        help="relative editable Lean source to preserve after a stable successful build")
    args = parser.parse_args()
    if args.module and (not re.fullmatch(r"[^\W\d][\w']*(?:\.[^\W\d][\w']*)*", args.module)):
        parser.error("expected a module name, not a filename, option, or Lake target expression")
    work = Path(args.work).resolve()
    if not ((work / "lakefile.toml").is_file() or (work / "lakefile.lean").is_file()):
        parser.error("--work must be a Lake project root")
    log_dir = args.log_dir or os.environ.get("LEAN_CHECK_LOG_DIR") or work / ".lake" / "harness-checks"
    try:
        paths = args.snapshot_path or json.loads(os.environ.get("LEAN_CHECK_EDITABLE_PATHS", "[]"))
        if not isinstance(paths, list) or not all(isinstance(p, str) for p in paths):
            raise ValueError("snapshot paths must be a list of relative Lean paths")
        for path in paths:
            proof_state.source_path(work, path)
    except ValueError as exc:
        parser.error(str(exc))
    read_fd, write_fd = os.pipe()
    pid = os.fork()
    if pid == 0:
        os.close(write_fd)
        os.setsid()
        def interrupted(_signum, _frame):
            raise KeyboardInterrupt
        for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
            signal.signal(sig, interrupted)
        try:
            try:
                result = check(work, args.module, args.timeout, log_dir, read_fd, paths, args.obligation)
            except (OSError, KeyboardInterrupt) as exc:
                # Even failure to create/write the log directory must not look
                # like an empty successful check. No durable log is promised.
                result = {"schema_version": 1,
                          "status": "interrupted" if isinstance(exc, KeyboardInterrupt) else "error",
                          "message": str(exc), "finished": False, "exit_code": None,
                          "elapsed_seconds": None, "log_path": None,
                          "result_path": None, "first_error": None,
                          "goal_text": None, "acceptance_checked": False}
            try:
                print(json.dumps(result, ensure_ascii=False), flush=True)
            except BrokenPipeError:
                pass  # durable JSON/log already saved, caller was killed
            code = EXIT_CODES[result["status"]]
        finally:
            os.close(read_fd)
        os._exit(code)
    os.close(read_fd)
    # Do not let compiler descendants inherit this lifeline. The supervisor
    # has closed its write end, so agent SIGKILL reliably produces EOF.
    def cancel(_signum, _frame):
        nonlocal write_fd
        if write_fd is not None:
            os.close(write_fd)
            write_fd = None
    for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(sig, cancel)
    try:
        _, status = os.waitpid(pid, 0)
    finally:
        if write_fd is not None:
            os.close(write_fd)
    return os.waitstatus_to_exitcode(status)


if __name__ == "__main__":
    sys.exit(main())
