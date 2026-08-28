#!/usr/bin/env python3
"""Agent-invocation layer for driver.py — ported from CryptoProver run.py.

What this module owns (driver.py must not reimplement any of it):

  * Explicit session UUIDs + `--resume` multi-round continuation. The session
    is identified by an explicit UUID rather than `claude -c` ("most recent
    session in this directory"): `-c` is mtime-based and globally scoped to
    the OAuth user, so a concurrent *interactive* Claude Code session in the
    same repo always wins the tiebreaker and quietly hijacks the harness's
    continuation rounds (CryptoProver curve_eq_20260518: 6 of 10 rounds were
    re-routed that way).

  * Process-group lifecycle. claude is spawned with `start_new_session=True`
    and always killed with `os.killpg`: claude's own children (lake build,
    background bash) would otherwise survive as orphans. `subprocess.run`'s
    `timeout=` kills only the direct child — the exact gap this replaces.

  * Wall-clock deadline. `proc.wait(timeout=...)` counts against
    time.monotonic(), which freezes during machine sleep (CryptoProver once
    ran 7.8h past a 90-min budget on a sleeping laptop). We poll in short
    slices against time.time().

  * SIGTERM/SIGINT/SIGHUP handler that propagates the kill to the live
    process group, so killing the driver never orphans a claude tree.

  * Optional wire proxy (wire_proxy.py) recording raw API requests via
    ANTHROPIC_BASE_URL — the only capture method that works with the
    native-binary claude. Best-effort: any failure leaves env untouched and
    the run proceeds straight to api.anthropic.com.
"""
import hashlib
import json
import os
import shutil
import signal
import subprocess
import sys
import time
import uuid

HERE = os.path.dirname(os.path.abspath(__file__))

# Module-level handle to the live claude subprocess so a signal to the driver
# can propagate the kill to the whole process group.
_LIVE_PROC = None
_WIRE_PROC = None
RECEIVED_SIGNAL = None  # driver checks this after each round


def new_session_id():
    return str(uuid.uuid4())


# ── signal handling ──────────────────────────────────────────────────────
def install_signal_handler():
    def _handler(signum, _frame):
        global RECEIVED_SIGNAL
        RECEIVED_SIGNAL = signum
        proc = _LIVE_PROC
        if proc is not None and proc.poll() is None:
            print(f"\n[agent] signal {signum} — killing claude process group "
                  f"{proc.pid}", flush=True)
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            kill_wire_proxy()
            # Let run_round return so the driver can rollback + persist a
            # ledger record before exiting 128+signum.
            return
        kill_wire_proxy()
        raise SystemExit(128 + signum)

    for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(sig, _handler)


# ── wire proxy (best-effort) ─────────────────────────────────────────────
def start_wire_proxy(out_dir, env):
    """Spawn wire_proxy.py on a free localhost port and point env's
    ANTHROPIC_BASE_URL at it. On ANY failure: warn, leave env untouched."""
    global _WIRE_PROC
    import atexit
    import socket
    try:
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()
        os.makedirs(out_dir, exist_ok=True)
        log = open(os.path.join(out_dir, "wire_proxy.log"), "w")
        proc = subprocess.Popen(
            [sys.executable, os.path.join(HERE, "wire_proxy.py"),
             str(port), out_dir],
            stdout=log, stderr=subprocess.STDOUT)
        deadline = time.time() + 5
        while time.time() < deadline:      # wait for the listener to bind
            try:
                import socket as _s
                with _s.create_connection(("127.0.0.1", port), timeout=0.2):
                    break
            except OSError:
                time.sleep(0.05)
        else:
            raise RuntimeError("listener did not bind within ~5s")
        env["ANTHROPIC_BASE_URL"] = f"http://127.0.0.1:{port}"
        _WIRE_PROC = proc
        atexit.register(kill_wire_proxy)
        print(f"[agent] wire proxy on 127.0.0.1:{port} -> "
              f"{out_dir}/wire_requests.jsonl", flush=True)
    except Exception as e:
        print(f"[agent] wire proxy failed to start ({e}); continuing "
              f"without wire logging", flush=True)


def kill_wire_proxy():
    global _WIRE_PROC
    proc = _WIRE_PROC
    if proc is not None and proc.poll() is None:
        try:
            proc.terminate()
        except ProcessLookupError:
            pass
    _WIRE_PROC = None


# ── isolation: fresh config dir + sealed env ─────────────────────────────
# The agent must not share state with the operator's interactive Claude Code:
#   * ~/.claude/projects/<cwd-slug>/memory  — auto-memory written by
#     interactive sessions in this repo would silently flow into the
#     experiment agent's context (and vice versa);
#   * ~/.claude/settings.json + plugins/hooks/skills + ~/.claude.json MCP
#     servers (probe-lean etc.) — unrecorded capabilities;
#   * .claude/settings.local.json — the operator's permission allowlist.
# Fix: every driver run gets its own CLAUDE_CONFIG_DIR seeded with ONLY the
# OAuth credentials file, `--setting-sources user` (so the repo's
# .claude/settings*.json are not read), `--settings <offline>` for the
# network deny-list, and `--strict-mcp-config` with no MCP config (= no MCP
# servers). Session files (needed by --resume) live in that same dir, so it
# must persist for the whole run. The dir is kept under the ledger as
# evidence of exactly what the agent could see.
CREDENTIALS_FILE = ".credentials.json"


def make_config_dir(run_dir):
    """Create <run_dir>/claude_config holding only the credentials file.
    Returns (config_dir, seeded: bool)."""
    real_home = os.environ.get("CLAUDE_CONFIG_DIR") \
        or os.path.join(os.path.expanduser("~"), ".claude")
    cfg = os.path.join(run_dir, "claude_config")
    os.makedirs(cfg, exist_ok=True)
    os.chmod(cfg, 0o700)  # holds a credentials copy; gitignored too
    src = os.path.join(real_home, CREDENTIALS_FILE)
    seeded = False
    if os.path.isfile(src):
        shutil.copy2(src, os.path.join(cfg, CREDENTIALS_FILE))
        os.chmod(os.path.join(cfg, CREDENTIALS_FILE), 0o600)
        seeded = True
    return cfg, seeded


def isolated_env(base_env, config_dir):
    """Copy of base_env with every CLAUDE* variable removed (the driver may
    itself be running inside an interactive Claude Code session, whose
    CLAUDECODE / CLAUDE_CODE_SESSION_ID / messaging-socket vars would link
    the child to it) and CLAUDE_CONFIG_DIR pointing at the fresh dir.
    ANTHROPIC_* (API key / wire-proxy base URL) is kept."""
    env = {k: v for k, v in base_env.items() if not k.startswith("CLAUDE")}
    env["CLAUDE_CONFIG_DIR"] = config_dir
    return env


# ── filesystem sandbox (bubblewrap) ──────────────────────────────────────
# DEC-08 minimum: no host checkout history, no sibling repositories, no
# credentials, no shared writable caches. The config-dir isolation above only
# hides Claude Code's own state; the agent's Bash/Read tools still saw the
# whole host filesystem. bwrap gives the agent a private mount namespace:
#   * /usr, /etc read-only; /proc, /dev, /tmp fresh
#   * $HOME is an empty tmpfs — sibling checkouts, ~/.cache/mathlib,
#     ~/.gitconfig, ~/.ssh, ~/.claude … do not exist
#   * read-only: ~/.elan (toolchains) and the claude binary
#   * read-write: the repo at its real path (so lake paths resolve), with
#     `.git`, `ledger/`, `harness/` replaced by empty tmpfs — no history,
#     no other targets' transcripts, no gate code / frozen statements
#   * the run's CLAUDE_CONFIG_DIR (under ledger/) bound back in read-write
# Not covered: network. Loopback + host network are shared (--share-net) so
# the API / wire proxy are reachable; the settings deny-list remains the
# only network control. Still no broker (DEC-08 stays OPEN on that point).
SANDBOX_HIDDEN = (".git", "ledger", "harness")


def _claude_binary_paths():
    exe = shutil.which("claude")
    if not exe:
        raise RuntimeError("claude not on PATH")
    real = os.path.realpath(exe)
    paths = {exe, real}
    # bun/node single-file builds sometimes sit in a versions dir that is
    # consulted at start-up; expose the whole dir read-only.
    paths.add(os.path.dirname(real))
    return sorted(paths)


def bwrap_prefix(repo, config_dir, hidden=SANDBOX_HIDDEN, extra_ro=()):
    """argv prefix that runs the rest of the command inside bwrap."""
    if not shutil.which("bwrap"):
        raise RuntimeError("bwrap (bubblewrap) not installed")
    home = os.path.expanduser("~")
    repo = os.path.abspath(repo)
    config_dir = os.path.abspath(config_dir)
    argv = ["bwrap", "--unshare-all", "--share-net", "--die-with-parent",
            "--ro-bind", "/usr", "/usr", "--ro-bind", "/etc", "/etc",
            "--symlink", "usr/lib", "/lib", "--symlink", "usr/lib64", "/lib64",
            "--symlink", "usr/bin", "/bin", "--symlink", "usr/sbin", "/sbin",
            "--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp",
            "--tmpfs", home,
            "--ro-bind", os.path.join(home, ".elan"), os.path.join(home, ".elan")]
    for p in list(_claude_binary_paths()) + list(extra_ro):
        argv += ["--ro-bind", p, p]
    argv += ["--bind", repo, repo]
    for h in hidden:
        full = os.path.join(repo, h)
        if os.path.exists(full):
            argv += ["--tmpfs", full]
    # config dir lives under ledger/ (hidden) — bind it back in, writable
    argv += ["--bind", config_dir, config_dir]
    argv += ["--setenv", "HOME", home, "--chdir", repo, "--"]
    return argv


def sandbox_selftest(prefix, repo, config_dir):
    """Run probes inside the sandbox and return {check: bool}. Every check
    must be True before a scored run; the dict is recorded in the ledger."""
    home = os.path.expanduser("~")
    allowed_home = {os.path.relpath(repo, home).split(os.sep)[0], ".elan"}
    for p in _claude_binary_paths():
        if p.startswith(home + os.sep):
            allowed_home.add(os.path.relpath(p, home).split(os.sep)[0])
    probes = {
        "no_git_history": f"! git -C {repo} rev-parse HEAD >/dev/null 2>&1",
        "no_ledger_transcripts": f"[ \"$(ls -A {repo}/ledger | wc -l)\" = 1 ]",
        "no_harness": f"[ -z \"$(ls -A {repo}/harness)\" ]",
        "no_ssh_or_gitconfig":
            f"[ ! -e {home}/.ssh ] && [ ! -e {home}/.gitconfig ]",
        "no_mathlib_cache": f"[ ! -e {home}/.cache ]",
        "config_dir_writable": f"touch {config_dir}/.rw && rm {config_dir}/.rw",
        "repo_writable": f"touch {repo}/.rw && rm {repo}/.rw",
        "lake_runs": "lake --version >/dev/null",
        "claude_runs": "claude --version >/dev/null",
    }
    out = {}
    # $HOME holds only the repo, ~/.elan and the claude install dir
    r = subprocess.run(prefix + ["ls", "-A", home], capture_output=True,
                       text=True, timeout=120)
    out["home_only_allowed"] = (r.returncode == 0 and
                                set(r.stdout.split()) == allowed_home)
    for name, sh in probes.items():
        r = subprocess.run(prefix + ["bash", "-c", sh],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                           timeout=120)
        out[name] = (r.returncode == 0)
    return out


def sha256_file(path):
    with open(path, "rb") as fh:
        return hashlib.sha256(fh.read()).hexdigest()


# ── command construction ─────────────────────────────────────────────────
def build_command(prompt, session_id, resume, model, max_turns,
                  allowed_tools, continue_message=None, settings_path=None):
    """One noninteractive claude invocation. Round 1 pins the session UUID
    with --session-id; later rounds resume exactly that UUID. Tool flags are
    per-invocation, so they are repeated on every round."""
    flags = ["--output-format", "stream-json", "--verbose",
             "--max-turns", str(max_turns),
             "--allowedTools", allowed_tools,
             "--setting-sources", "user",
             "--strict-mcp-config"]
    if settings_path:
        flags += ["--settings", settings_path]
    if model:
        flags += ["--model", model]
    if resume:
        message = continue_message or "continue"
        return ["claude", "--resume", session_id, "-p", *flags, message]
    return ["claude", "-p", "--session-id", session_id, *flags, prompt]


# ── round execution ──────────────────────────────────────────────────────
def _bounded_wait(wall_deadline):
    """A polling wait that cannot sleep past the wall-clock deadline."""
    if wall_deadline is None:
        return None
    return min(30.0, max(0.01, wall_deadline - time.time()))


def run_round(prompt, transcript_path, *, cwd, session_id, resume,
              model="", max_turns=30, allowed_tools="",
              deadline_seconds=None, continue_message=None, env=None,
              settings_path=None, sandbox_prefix=None):
    """Run one claude round; stream-json goes verbatim to transcript_path.

    Returns (status, returncode, wall_seconds, result_event, provenance)
    where status is "ok" | "deadline" | "signal". The process group is
    always SIGKILLed at the end — even on clean exit — to reap any
    background children claude left behind.
    """
    global _LIVE_PROC
    cmd = build_command(prompt, session_id, resume, model, max_turns,
                        allowed_tools, continue_message, settings_path)
    if sandbox_prefix:
        cmd = list(sandbox_prefix) + cmd
    t0 = time.time()
    killed_deadline = False
    with open(transcript_path, "w") as fh:
        proc = subprocess.Popen(
            cmd, cwd=cwd, stdout=fh, stderr=subprocess.STDOUT,
            stdin=subprocess.DEVNULL, text=True, env=env,
            start_new_session=True)
        _LIVE_PROC = proc
        wall_deadline = (time.time() + deadline_seconds) \
            if deadline_seconds else None
        while True:
            try:
                proc.wait(timeout=_bounded_wait(wall_deadline))
                break
            except subprocess.TimeoutExpired:
                if RECEIVED_SIGNAL is not None:
                    try:
                        proc.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        pass
                    break
                if wall_deadline and time.time() >= wall_deadline:
                    killed_deadline = True
                    print(f"[agent] deadline ({deadline_seconds:.0f}s) "
                          f"exceeded — killing process group {proc.pid}",
                          flush=True)
                    try:
                        os.killpg(proc.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    try:
                        proc.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        pass
                    break
        # Post-completion sweep: claude may have left background children
        # (build loops etc.) alive after the main process returned.
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        _LIVE_PROC = None

    wall = time.time() - t0
    result_event, provenance = last_result_event(transcript_path)
    if RECEIVED_SIGNAL is not None:
        status = "signal"
    elif killed_deadline:
        status = "deadline"
    else:
        status = "ok"
    return status, proc.returncode, wall, result_event, provenance


def last_result_event(transcript_path):
    """Last stream `result` event + parser provenance. A valid terminal
    result is not necessarily the final physical line: claude can emit
    task metadata afterwards, so scan the whole file."""
    last_event, last_result = {}, {}
    last_event_line = last_result_line = parse_errors = 0
    try:
        with open(transcript_path, encoding="utf-8", errors="replace") as f:
            for n, line in enumerate(f, start=1):
                if not line.strip():
                    continue
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    parse_errors += 1
                    continue
                if not isinstance(event, dict):
                    continue
                last_event, last_event_line = event, n
                if event.get("type") == "result":
                    last_result, last_result_line = event, n
    except OSError:
        pass
    return last_result, {
        "last_event_type": last_event.get("type") if last_event else None,
        "last_result_seen": bool(last_result),
        "result_followed_by_metadata": bool(
            last_result_line and last_event_line > last_result_line),
        "parse_errors": parse_errors,
    }
