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
import shlex
import signal
import subprocess
import sys
import time
import uuid

from live_progress import LiveTranscript

HERE = os.path.dirname(os.path.abspath(__file__))

# Module-level handle to the live claude subprocess so a signal to the driver
# can propagate the kill to the whole process group.
_LIVE_PROCS = set()   # every running claude process (one per slot)
_LIVE_LOCK = __import__('threading').Lock()
_WIRE_PROC = None
RECEIVED_SIGNAL = None  # driver checks this after each round


def new_session_id():
    return str(uuid.uuid4())


# ── signal handling ──────────────────────────────────────────────────────
def install_signal_handler():
    def _handler(signum, _frame):
        global RECEIVED_SIGNAL
        RECEIVED_SIGNAL = signum
        with _LIVE_LOCK:
            live = [p for p in _LIVE_PROCS if p.poll() is None]
        if live:
            for proc in live:
                print(f"\n[agent] signal {signum} — killing claude process "
                      f"group {proc.pid}", flush=True)
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


# Auth policy: the isolated agent authenticates ONLY via the operator's
# Anthropic-account OAuth credentials file. API keys are not an accepted
# fallback: make_config_dir refuses to proceed without the credentials file,
# and isolated_env strips ANTHROPIC_API_KEY / ANTHROPIC_AUTH_TOKEN so a key
# in the operator's shell can never reach the child.
API_KEY_VARS = ("ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN")


def make_config_dir(run_dir):
    """Create <run_dir>/claude_config holding only the credentials file.
    Returns (config_dir, seeded: bool); seeded is always True on return.
    Raises RuntimeError when the operator has no OAuth credentials file."""
    real_home = os.environ.get("CLAUDE_CONFIG_DIR") \
        or os.path.join(os.path.expanduser("~"), ".claude")
    src = os.path.join(real_home, CREDENTIALS_FILE)
    if not os.path.isfile(src):
        raise RuntimeError(
            f"no Anthropic-account credentials at {src}; run `claude login` "
            "first (API keys are not accepted by this harness)")
    cfg = os.path.join(run_dir, "claude_config")
    os.makedirs(cfg, exist_ok=True)
    os.chmod(cfg, 0o700)  # holds a credentials copy; gitignored too
    shutil.copy2(src, os.path.join(cfg, CREDENTIALS_FILE))
    os.chmod(os.path.join(cfg, CREDENTIALS_FILE), 0o600)
    return cfg, True


def isolated_env(base_env, config_dir):
    """Copy of base_env with every CLAUDE* variable removed (the driver may
    itself be running inside an interactive Claude Code session, whose
    CLAUDECODE / CLAUDE_CODE_SESSION_ID / messaging-socket vars would link
    the child to it), API-key variables removed (account OAuth is the only
    permitted auth), and CLAUDE_CONFIG_DIR pointing at the fresh dir.
    ANTHROPIC_BASE_URL (wire proxy) is kept."""
    env = {k: v for k, v in base_env.items()
           if not k.startswith("CLAUDE") and k not in API_KEY_VARS}
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
# `.lake/packages` in a slot is a symlink to the main checkout's; the target
# is bound read-only, so all slots share mathlib/aeneas without a copy and
# no slot can write into it (self-test `packages_readonly`).


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


def bwrap_prefix(repo, config_dir, hidden=SANDBOX_HIDDEN, extra_ro=(), sealed_ro=(), read_only=False):
    """argv prefix that runs the rest of the command inside bwrap.
    extra_ro: files/dirs outside repo the agent process must read (e.g. the
    --settings file, which lives in the main checkout, not the slot)."""
    if not shutil.which("bwrap"):
        raise RuntimeError("bwrap (bubblewrap) not installed")
    home = os.path.expanduser("~")
    repo = os.path.abspath(repo)
    config_dir = os.path.abspath(config_dir)
    check_tool = prepare_check_tool(config_dir)
    argv = ["bwrap", "--unshare-all", "--share-net", "--die-with-parent",
            "--ro-bind", "/usr", "/usr", "--ro-bind", "/etc", "/etc",
            "--symlink", "usr/lib", "/lib", "--symlink", "usr/lib64", "/lib64",
            "--symlink", "usr/bin", "/bin", "--symlink", "usr/sbin", "/sbin",
            "--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp",
            "--tmpfs", home,
            "--ro-bind", os.path.join(home, ".elan"), os.path.join(home, ".elan")]
    pk = os.path.join(repo, ".lake", "packages")
    shared_pk = os.path.realpath(pk) if os.path.islink(pk) else None
    for p in list(_claude_binary_paths()) + list(extra_ro) \
            + ([shared_pk] if shared_pk else []):
        argv += ["--ro-bind", p, p]
    argv += ["--ro-bind" if read_only else "--bind", repo, repo]
    for h in hidden:
        full = os.path.join(repo, h)
        if os.path.exists(full):
            argv += ["--tmpfs", full]
    # config dir lives under ledger/ (hidden) — bind it back in, writable
    argv += ["--bind", config_dir, config_dir]
    # Bind after the writable config parent so skill inputs cannot be edited.
    for p in [os.path.dirname(check_tool), *sealed_ro]:
        argv += ["--ro-bind", p, p]
    argv += ["--setenv", "HOME", home, "--chdir", repo, "--"]
    return argv


def sandbox_selftest(prefix, repo, config_dir, extra_ro=()):
    """Run probes inside the sandbox and return {check: bool}. Every check
    must be True before a scored run; the dict is recorded in the ledger."""
    home = os.path.expanduser("~")
    allowed_home = {os.path.relpath(repo, home).split(os.sep)[0], ".elan"}
    for p in _claude_binary_paths():
        if p.startswith(home + os.sep):
            allowed_home.add(os.path.relpath(p, home).split(os.sep)[0])
    probes = {
        "no_git_history": f"! git -C {repo} rev-parse HEAD >/dev/null 2>&1",
        "no_ledger_transcripts":
            f"[ ! -e {repo}/ledger ] || [ \"$(ls -A {repo}/ledger | wc -l)\" = 1 ]",
        "packages_readonly":
            f"! touch {repo}/.lake/packages/.rw 2>/dev/null",
        "no_harness": f"[ -z \"$(ls -A {repo}/harness)\" ]",
        "no_ssh_or_gitconfig":
            f"[ ! -e {home}/.ssh ] && [ ! -e {home}/.gitconfig ]",
        "no_mathlib_cache": f"[ ! -e {home}/.cache ]",
        "config_dir_writable": f"touch {config_dir}/.rw && rm {config_dir}/.rw",
        "repo_writable": f"touch {repo}/.rw && rm {repo}/.rw",
        **{f"readable:{os.path.basename(p)}": f"[ -r {p} ]" for p in extra_ro},
        "lake_runs": "lake --version >/dev/null",
        "claude_runs": "claude --version >/dev/null",
        "lean_check_runs": "/usr/bin/python3 " + shlex.quote(
            os.path.join(config_dir, "local_check_tool", "lean_check.py")) + " --help >/dev/null",
        "lean_check_readonly": "! test -w " + shlex.quote(
            os.path.join(config_dir, "local_check_tool", "lean_check.py")),
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


def prepare_check_tool(directory):
    """Expose checker + state helpers, never the hidden harness/gates."""
    tool_dir = os.path.join(directory, "local_check_tool")
    os.makedirs(tool_dir, exist_ok=True)
    for name in ("lean_check.py", "proof_state.py", "compact_reminder.py"):
        source = os.path.join(HERE, name)
        target = os.path.join(tool_dir, name)
        if not os.path.exists(target) or sha256_file(source) != sha256_file(target):
            temporary = target + "." + uuid.uuid4().hex
            try:
                shutil.copyfile(source, temporary)
                os.replace(temporary, target)
            finally:
                if os.path.exists(temporary):
                    os.unlink(temporary)
    return os.path.join(tool_dir, "lean_check.py")


# ── command construction ─────────────────────────────────────────────────
def prepare_compact_recovery(runtime, prompt, message, instructions, settings_path):
    """Keep recovery files in the existing read-only sandbox tool mount."""
    root = os.path.join(runtime, "local_check_tool", "recovery-" + uuid.uuid4().hex)
    os.makedirs(root)
    files = {"workflow.md": prompt, "round-context.md": message}
    if instructions:
        files["lean-check.md"] = instructions
    for name, content in files.items():
        with open(os.path.join(root, name), "w") as fh:
            fh.write(content)
    settings = {}
    if settings_path:
        with open(settings_path) as fh:
            settings = json.load(fh)
    if settings.get("disableAllHooks"):
        raise ValueError("Compaction recovery requires hooks; settings disableAllHooks is true")
    hook = os.path.join(runtime, "local_check_tool", "compact_reminder.py")
    command = "/usr/bin/python3 " + shlex.quote(hook) + " " + shlex.quote(root)
    settings.setdefault("hooks", {}).setdefault("SessionStart", []).append({
        "matcher": "compact", "hooks": [{"type": "command", "command": command,
                                           "timeout": 10}]})
    target = os.path.join(root, "settings.json")
    with open(target, "w") as fh:
        json.dump(settings, fh, indent=2)
    return target, {"enabled": True, "event": "SessionStart", "matcher": "compact",
                    "settings_path": target, "settings_sha256": sha256_file(target),
                    "hook_path": hook, "hook_sha256": sha256_file(hook),
                    "files": {os.path.join(root, name): sha256_file(os.path.join(root, name))
                              for name in files}}


def tool_names(allowed_tools):
    """Base tool names from an --allowedTools spec: "Bash(lake build*)" → Bash.
    Used for --tools, which filters tool *availability* (the subagent tool
    Agent/Task, WebFetch, Skill, … simply do not exist), whereas
    --allowedTools is only the permission allowlist: a tool absent from it
    can still be invoked when the permission system auto-approves it, which
    is how the Agent tool ran in the 2026-08-28 smoke run."""
    names = []
    for spec in allowed_tools.split(","):
        base = spec.strip().split("(", 1)[0]
        if base and base not in names:
            names.append(base)
    return ",".join(names)


def build_command(prompt, session_id, resume, model, max_turns,
                  allowed_tools, continue_message=None, settings_path=None,
                  skill_plugin=None):
    """One noninteractive claude invocation. Round 1 pins the session UUID
    with --session-id; later rounds resume exactly that UUID. Tool flags are
    per-invocation, so they are repeated on every round.

    --tools restricts the built-in toolset to the base names in
    allowed_tools (no Agent/Task subagents, no WebFetch/WebSearch, no
    Skill by default); --disable-slash-commands drops every skill unless an
    explicit skill_plugin is supplied. --allowedTools auto-approves the listed
    patterns within the toolset; it is not a tool availability boundary."""
    flags = ["--output-format", "stream-json", "--verbose",
             "--max-turns", str(max_turns),
             "--tools", tool_names(allowed_tools),
             "--allowedTools", allowed_tools,
             "--setting-sources", "user",
             "--strict-mcp-config"]
    if skill_plugin:
        flags += ["--plugin-dir", skill_plugin]
    else:
        flags.append("--disable-slash-commands")
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
              settings_path=None, sandbox_prefix=None, skill_plugin=None,
              progress_log=None, stop_check=None, local_checks=True):
    """Run one claude round; stream-json goes verbatim to transcript_path.

    Returns (status, returncode, wall_seconds, result_event, provenance)
    where status is "ok" | "deadline" | "signal" | "review_requested". The process group is
    always SIGKILLed at the end — even on clean exit — to reap any
    background children claude left behind.
    """
    # A single integration point covers generic, bottom-up and to_bytes runs,
    # including resumed/reset sessions. Logs live outside the source allowlist.
    runtime = (env["CLAUDE_CONFIG_DIR"] if sandbox_prefix else
               os.path.dirname(os.path.abspath(transcript_path)))
    check_tool = prepare_check_tool(runtime)
    check_logs = os.path.join(runtime, "local_checks")
    os.makedirs(check_logs, exist_ok=True)
    check_command = "/usr/bin/python3 " + shlex.quote(check_tool)
    check_instructions = (
        "\n\nLocal Lean check tool (provided by the harness):\n"
        f"From the workspace root run: {check_command} MODULE --timeout 120\n"
        "Use the actual dotted module name in place of MODULE. Use this tool "
        "for incremental compilation instead of managing lake/timeout/background "
        "processes yourself. It runs lake build and returns JSON with status, "
        "exit_code, elapsed_seconds, first_error, goal_text when printed by Lean, "
        "last_output, and durable log_path/result_path. Read those logs as needed. "
        "Checks in one workspace are serialized: busy means no check ran. "
        "timeout/interrupted/error are not success, even with empty diagnostics. "
        "The tool creates harness-managed logs/build artifacts; this does not "
        "authorize editing additional proof sources. Do not edit the tool. "
        "Keep reporting changes, results, and next steps. Compilation can succeed "
        "with sorry: success is local compilation only, never proof acceptance.\n"
        f"For the final full build use: {check_command} --full --timeout 1200\n"
        "The harness independently runs its acceptance gates afterward.\n")
    if (env or {}).get("LEAN_REVIEW_ENABLED") == "1":
        check_instructions += (
            "Diagnosis review is enabled. Add --obligation DECLARATION to local "
            "checks, using the stable Lean name of the obligation you are working "
            "on. Keep this label across retries; change it when moving to another "
            "obligation. It is a diagnostic label, not verified attribution. "
            "Repeated failures may end this round for independent review; the next "
            "available round receives advisory feedback.\n")
    if local_checks:
        prompt += check_instructions
        if resume:
            continue_message = (continue_message or "continue") + check_instructions
        allowed_tools += f",Bash({check_command} *)"
    else:
        check_instructions = ""
    env = dict(env if env is not None else os.environ)
    env["LEAN_CHECK_LOG_DIR"] = check_logs
    effective_message = continue_message if resume else prompt
    message_path = transcript_path + ".prompt.txt"
    with open(message_path, "w") as fh:
        fh.write(effective_message)
    settings_path, compact_recovery = prepare_compact_recovery(
        runtime, prompt, effective_message, check_instructions, settings_path)
    cmd = build_command(prompt, session_id, resume, model, max_turns,
                        allowed_tools, continue_message, settings_path, skill_plugin)
    if sandbox_prefix:
        cmd = list(sandbox_prefix) + cmd
    # nice -n 19 the whole agent subtree: claude itself is API-bound, but
    # every `lake build` / `lean` it spawns via Bash inherits the niceness,
    # so agent iteration builds run at batch priority like the gate builds.
    cmd = ["nice", "-n", "19"] + cmd
    t0 = time.time()
    killed_deadline = False
    stopped_for_review = None
    with open(transcript_path, "w") as fh:
        proc = subprocess.Popen(
            cmd, cwd=cwd, stdout=fh, stderr=subprocess.STDOUT,
            stdin=subprocess.DEVNULL, text=True, env=env,
            start_new_session=True)
        with _LIVE_LOCK:
            _LIVE_PROCS.add(proc)
        display = LiveTranscript(transcript_path, progress_log) if progress_log else None
        if display:
            display.start()
        wall_deadline = (time.time() + deadline_seconds) \
            if deadline_seconds else None
        while True:
            try:
                wait = _bounded_wait(wall_deadline)
                proc.wait(timeout=min(wait or 5, 5) if stop_check else wait)
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
                if stop_check:
                    stopped_for_review = stop_check(check_logs)
                    if stopped_for_review:
                        try:
                            os.killpg(proc.pid, signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                        proc.wait(timeout=5)
                        break
        # Post-completion sweep: claude may have left background children
        # (build loops etc.) alive after the main process returned.
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        with _LIVE_LOCK:
            _LIVE_PROCS.discard(proc)
        if display:
            display.close()

    wall = time.time() - t0
    result_event, provenance = last_result_event(transcript_path)
    provenance["compact_recovery"] = compact_recovery
    provenance["local_check"] = {
        "enabled": local_checks,
        "tool_sha256": sha256_file(check_tool), "tool_path": check_tool,
        "state_helper_sha256": sha256_file(os.path.join(os.path.dirname(check_tool), "proof_state.py")),
        "log_dir": check_logs, "effective_message_path": message_path,
        "allowed_tools": allowed_tools,
        "instructions_sha256": hashlib.sha256(check_instructions.encode()).hexdigest(),
        "effective_message_sha256": hashlib.sha256(
            effective_message.encode()).hexdigest()}
    if RECEIVED_SIGNAL is not None:
        status = "signal"
    elif killed_deadline:
        status = "deadline"
    elif stopped_for_review:
        status = "review_requested"
    else:
        status = "ok"
    if stopped_for_review:
        provenance["review_trigger"] = stopped_for_review
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
