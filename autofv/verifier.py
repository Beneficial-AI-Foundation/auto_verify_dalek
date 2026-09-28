"""Independent clean-worker execution and exact report validation."""

from __future__ import annotations

import copy
import hashlib
import io
import re
import os
import secrets
import shlex
import signal
import stat
import subprocess
import tarfile
import threading
import time
from pathlib import Path, PurePosixPath
from typing import Any

from . import (
    axiom_audit,
    contracts,
    counterexample,
    dependency_cache,
    probes,
    terminal_verifier,
    verifier_bundle,
    worker,
    worker_runtime,
)
from .verifier_bundle import (
    INVOCATION_FIELDS,
    MAX_MEMBER_BYTES,
    VerifierError,
    VerifierInfrastructureError,
    _canonical_bytes,
    _safe_path,
    _sha256,
    _strict_json,
    _valid_invocation,
    build_bundle,
    verify_bundle,
)

VERIFIER_VM = "autofv-verifier"
REFERENCE_PATH = (
    Path(__file__).resolve().parents[1]
    / "tests"
    / "fixtures"
    / "diamond-reference"
    / "reference.json"
)
def _trusted_reference(run: dict[str, Any]) -> bytes:
    """Compatibility facade for trusted hidden-reference selection."""
    return counterexample.trusted_reference(run, legacy_path=REFERENCE_PATH)


def bind_prepared_reference(
    run: dict[str, Any], path: str | Path
) -> dict[str, str]:
    """Bind a trusted external reference without retaining its bytes."""
    return counterexample.bind_reference(run, path)


def _command_detail(completed: subprocess.CompletedProcess[bytes]) -> str:
    return "\n".join(
        part
        for part in (
            completed.stdout.decode("utf-8", "replace").strip(),
            completed.stderr.decode("utf-8", "replace").strip(),
        )
        if part
    )[-4000:]


# ponytail: fixed per-command ceilings; derive them from the run's absolute
# deadline once the smoke/full wall envelope for verification is decided.
COMMAND_TIMEOUT_SECONDS = 1200
MAX_COMMAND_OUTPUT_BYTES = 64 * 1024 * 1024


def _bounded_run(
    argv: tuple[str, ...], input_bytes: bytes | None, timeout: float
) -> subprocess.CompletedProcess[bytes]:
    """Run with a wall deadline and per-stream cap, killing the process group."""
    process = subprocess.Popen(
        argv,
        stdin=subprocess.PIPE if input_bytes is not None else subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )
    captured: dict[str, bytes] = {}
    overflow = threading.Event()

    def drain(name: str, stream: Any) -> None:
        data = bytearray()
        while chunk := stream.read(1 << 16):
            if len(data) + len(chunk) > MAX_COMMAND_OUTPUT_BYTES:
                overflow.set()
                break
            data += chunk
        captured[name] = bytes(data)

    readers = [
        threading.Thread(target=drain, args=(name, stream), daemon=True)
        for name, stream in (("stdout", process.stdout), ("stderr", process.stderr))
    ]
    for reader in readers:
        reader.start()
    deadline = time.monotonic() + timeout
    try:
        if input_bytes is not None:
            try:
                process.stdin.write(input_bytes)
                process.stdin.close()
            except BrokenPipeError:
                pass
        while process.poll() is None:
            if overflow.is_set() or time.monotonic() >= deadline:
                raise VerifierInfrastructureError(
                    "clean verifier command output exceeded its bound"
                    if overflow.is_set()
                    else "clean verifier command timed out"
                )
            time.sleep(0.05)
    except BaseException:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait()
        raise
    for reader in readers:
        reader.join()
    if overflow.is_set():
        raise VerifierInfrastructureError("clean verifier command output exceeded its bound")
    return subprocess.CompletedProcess(
        argv, process.returncode, captured.get("stdout", b""), captured.get("stderr", b"")
    )


def _shell(
    *argv: str, input_bytes: bytes | None = None, timeout: int | None = None
) -> subprocess.CompletedProcess[bytes]:
    completed = _bounded_run(
        ("limactl", "shell", VERIFIER_VM, "--", *argv),
        input_bytes,
        timeout or COMMAND_TIMEOUT_SECONDS,
    )
    if completed.returncode:
        detail = _command_detail(completed)
        raise VerifierInfrastructureError(
            f"clean verifier command failed: {detail or argv[0]}"
        )
    return completed


def _docker(
    *argv: str, input_bytes: bytes | None = None, timeout: int | None = None
) -> subprocess.CompletedProcess[bytes]:
    """Name every container so a killed host client cannot orphan it in the VM."""
    if argv[:1] != ("run",) or "--name" in argv:
        return _shell("sudo", "docker", *argv, input_bytes=input_bytes, timeout=timeout)
    name = f"autofv-verify-cmd-{secrets.token_hex(8)}"
    try:
        return _shell(
            "sudo", "docker", "run", "--name", name, *argv[1:],
            input_bytes=input_bytes, timeout=timeout,
        )
    except BaseException:
        try:
            _shell("sudo", "docker", "rm", "-f", name, timeout=60)
        except VerifierInfrastructureError:
            pass
        raise


def _check_quiet_verifier_vm() -> None:
    instance = worker_runtime.inspect_lima_instance(VERIFIER_VM)
    if (
        instance is None or instance.get("status") != "Running"
        or instance.get("cpus") != 2
        or instance.get("memory") != 8 * 1024**3
    ):
        raise VerifierInfrastructureError("clean verifier VM resource limit mismatch")


def _check_verifier_runtime(lock: dict[str, Any]) -> None:
    runtime = lock["tools"]["runsc"]
    try:
        docker_version = _docker(
            "version", "--format", "{{.Server.Version}}"
        ).stdout.decode("utf-8", "strict").strip()
        runsc_version = _shell("runsc", "--version").stdout.decode(
            "utf-8", "strict"
        ).splitlines()[0]
        runtimes = _strict_json(
            _docker("info", "--format", "{{json .Runtimes}}").stdout,
            "verifier_runtime",
        )
    except (KeyError, IndexError, UnicodeError, VerifierError) as exc:
        raise VerifierInfrastructureError(
            "clean verifier runtime identity is unreadable"
        ) from exc
    configured = runtimes.get(runtime["runtime_name"])
    if (
        docker_version
        != lock["tools"]["docker"]["observed_version"].removeprefix("Docker ")
        or runsc_version != f"runsc version {runtime['pin']}"
        or not isinstance(configured, dict)
        or configured.get("path") != "/usr/bin/runsc"
        or configured.get("runtimeArgs") != runtime["runtime_args"]
    ):
        raise VerifierInfrastructureError(
            "clean verifier runtime identity mismatch"
        )


def _runtime_argv(
    image: str,
    volume: str,
    *command: str,
    workdir: str = "/project",
    runtime: str = "runsc-hardened",
    read_only_volume: bool = False,
    dependency_volume: str | None = None,
) -> tuple[str, ...]:
    dependency_mount = (
        (
            "--mount",
            f"type=volume,src={dependency_volume},dst=/project/dependencies,volume-nocopy,readonly",
        )
        if dependency_volume is not None
        else ()
    )
    dependency_env = (
        (
            "--env",
            "CI=1",
            "--env",
            (
                "PATH=/project/dependencies/toolchain/bin:/opt/autofv-venv/bin:"
                "/opt/git/bin:/opt/lean/bin:/opt/rust-bin:/usr/local/bin:"
                "/usr/bin:/bin"
            ),
        )
        if dependency_volume is not None
        else ()
    )
    return (
        "run",
        "--rm",
        "--pull",
        "never",
        "--runtime",
        runtime,
        "--read-only",
        "--network",
        "none",
        "--user",
        worker.AGENT_UID,
        "--workdir",
        workdir,
        "--env",
        "LEAN_NUM_THREADS=1",
        "--security-opt",
        "no-new-privileges",
        "--pids-limit",
        "256",
        "--cpus",
        "2",
        "--memory",
        "4g",
        "--memory-swap",
        "4g",
        "--tmpfs",
        "/tmp:rw,noexec,nosuid,nodev,size=64m",
        "--tmpfs",
        "/home/autofv/.cache:rw,noexec,nosuid,nodev,size=64m",
        "--env",
        "CARGO_NET_OFFLINE=true",
        *dependency_env,
        "--mount",
        (
            f"type=volume,src={volume},dst=/project,volume-nocopy"
            + (",readonly" if read_only_volume else "")
        ),
        *dependency_mount,
        image,
        *command,
    )


def compiler_assumptions(lock: dict[str, Any]) -> list[dict[str, str]]:
    """Bind the two allow_audited compiler assumptions to the pinned tools."""
    evidence = {
        "Lean.ofReduceBool": (
            f"{lock['tools']['lean']['pin']} / {lock['tools']['lean']['observed_version']}"
        ),
        "Lean.trustCompiler": (
            f"{lock['tools']['rustc']['pin']} / {lock['tools']['rustc']['observed_version']}"
        ),
    }
    return [
        {
            "assumption": assumption,
            "evidence": evidence[assumption],
            "evidence_sha256": _sha256(evidence[assumption].encode()),
        }
        for assumption in ("Lean.ofReduceBool", "Lean.trustCompiler")
    ]


def _prepared_probe_evidence(run: dict[str, Any]) -> tuple[bytes, bytes]:
    sources = run.get("prepared_probe_sources")
    receipt = run.get("prepared_graph_receipt")
    receipt_fields = {
        "schema",
        "execution_mode",
        "preparation_manifest_sha256",
        "probe_rust_sha256",
        "probe_aeneas_sha256",
        "target_report_sha256",
        "graph_sha256",
        "dependency_cache_sha256",
        "dependency_cache_size",
        "receipt_sha256",
    }
    receipt_body = (
        {key: value for key, value in receipt.items() if key != "receipt_sha256"}
        if isinstance(receipt, dict)
        else {}
    )
    preparation = run.get("preparation_manifest")
    if (
        not isinstance(sources, dict)
        or set(sources) != {"probe-rust", "probe-aeneas", "dependency-cache"}
        or not isinstance(receipt, dict)
        or set(receipt) != receipt_fields
        or receipt.get("schema") != "autofv-prepared-graph-binding/v1"
        or receipt.get("receipt_sha256") != _sha256(_canonical_bytes(receipt_body))
        or not isinstance(preparation, dict)
        or receipt.get("preparation_manifest_sha256")
        != preparation.get("manifest_sha256")
        or receipt.get("execution_mode") != run.get("execution_mode")
        or any(
            receipt.get(name) != run.get(name)
            for name in (
                "probe_rust_sha256",
                "probe_aeneas_sha256",
                "graph_sha256",
            )
        )
    ):
        raise VerifierError("clean verifier prepared probe binding is missing")
    raw_by_name = {}
    for name in ("probe-rust", "probe-aeneas"):
        try:
            source = Path(sources[name])
            if source.is_symlink():
                raise OSError("symlinked prepared probe evidence")
            path = source.resolve(strict=True)
            before = path.stat()
            if not path.is_file() or before.st_size > MAX_MEMBER_BYTES:
                raise OSError("unsafe prepared probe evidence")
            if any(
                path.is_relative_to(Path(run[root]).resolve(strict=True))
                for root in ("input_root", "run_root")
                if isinstance(run.get(root), str)
            ):
                raise OSError("prepared probe evidence crossed a run boundary")
            raw = path.read_bytes()
            after = path.stat()
        except (OSError, TypeError) as exc:
            raise VerifierError("clean verifier prepared probe evidence is invalid") from exc
        if before != after or len(raw) != before.st_size:
            raise VerifierError("clean verifier prepared probe evidence changed")
        expected = receipt.get(name.replace("-", "_") + "_sha256")
        if _sha256(raw) != expected:
            raise VerifierError("clean verifier prepared probe identity mismatch")
        raw_by_name[name] = raw
    try:
        graph = probes.parse_probe_bytes(
            run["manifest"],
            raw_by_name["probe-rust"],
            raw_by_name["probe-aeneas"],
        )
    except (KeyError, probes.ProbeError) as exc:
        raise VerifierError("clean verifier prepared probe evidence is invalid") from exc
    if (
        graph["graph_sha256"] != receipt["graph_sha256"]
        or _sha256(probes.render_target_report(graph))
        != receipt["target_report_sha256"]
    ):
        raise VerifierError("clean verifier prepared graph identity mismatch")
    return raw_by_name["probe-rust"], raw_by_name["probe-aeneas"]


def _prepared_dependency_cache(run: dict[str, Any]) -> Path:
    sources = run.get("prepared_probe_sources")
    prepared = run.get("prepared_graph_receipt")
    receipt = run.get("dependency_cache_receipt")
    if (
        not isinstance(sources, dict)
        or not isinstance(prepared, dict)
        or not isinstance(receipt, dict)
        or set(receipt) != {"schema", "sha256", "size", "receipt_sha256"}
        or receipt.get("schema") != "autofv-dependency-cache-binding/v1"
        or receipt.get("receipt_sha256")
        != _sha256(
            _canonical_bytes(
                {key: value for key, value in receipt.items() if key != "receipt_sha256"}
            )
        )
        or receipt.get("sha256") != prepared.get("dependency_cache_sha256")
        or receipt.get("size") != prepared.get("dependency_cache_size")
    ):
        raise VerifierError("clean verifier dependency cache binding is invalid")
    try:
        source = Path(sources["dependency-cache"])
        if source.is_symlink():
            raise OSError("symlinked dependency cache")
        path = source.resolve(strict=True)
        before = path.stat()
        digest = hashlib.sha256()
        with path.open("rb") as stream:
            while chunk := stream.read(8 * 1024 * 1024):
                digest.update(chunk)
        after = path.stat()
    except (KeyError, OSError, TypeError) as exc:
        raise VerifierError("clean verifier dependency cache is invalid") from exc
    if (
        before != after
        or not stat.S_ISREG(before.st_mode)
        or before.st_size != receipt["size"]
        or digest.hexdigest() != receipt["sha256"]
    ):
        raise VerifierError("clean verifier dependency cache identity mismatch")
    return path


def _seed_verifier_dependency_cache(
    run: dict[str, Any], image: str, volume: str,
    repository_bundle: bytes, base_commit: str,
) -> None:
    archive = _prepared_dependency_cache(run)
    receipt = run["dependency_cache_receipt"]
    try:
        with dependency_cache.validated_archive(
            archive, receipt["sha256"], receipt["size"]
        ) as staged:
            _seed_verified_dependency_cache(run, image, volume, repository_bundle, base_commit, staged)
    except dependency_cache.CacheError as exc:
        raise VerifierInfrastructureError(str(exc)) from exc


def _seed_verified_dependency_cache(
    run: dict[str, Any], image: str, volume: str,
    repository_bundle: bytes, base_commit: str, archive: Path,
) -> None:
    _docker("volume", "create", volume)
    _docker(
        "run", "--rm", "--pull", "never", "--network", "none",
        "--user", "0:0", "--mount",
        f"type=volume,src={volume},dst=/packages,volume-nocopy",
        image, "sh", "-eu", "-c", f"chown {worker.AGENT_UID} /packages",
    )
    extract = _runtime_argv(
        image, volume, "tar", "-xf", "-", "-C", "/project"
    )
    name = f"autofv-verify-cmd-{secrets.token_hex(8)}"
    command = "zstd -dc | " + shlex.join(
        ("sudo", "docker", *extract[:2], "-i", "--name", name, *extract[2:])
    )
    try:
        with archive.open("rb") as stream:
            completed = subprocess.run(
                ("limactl", "shell", VERIFIER_VM, "--", "sh", "-eu", "-c", command),
                stdin=stream,
                capture_output=True,
                timeout=COMMAND_TIMEOUT_SECONDS,
            )
    except (OSError, subprocess.TimeoutExpired) as exc:
        try:
            _shell("sudo", "docker", "rm", "-f", name, timeout=60)
        except VerifierInfrastructureError:
            pass
        raise VerifierInfrastructureError(
            "clean verifier dependency cache seed failed"
        ) from exc
    if completed.returncode:
        raise VerifierInfrastructureError(
            "clean verifier dependency cache seed failed: "
            + _command_detail(completed)
        )
    warm_volume = f"{volume}-warm"
    _docker("volume", "create", warm_volume)
    try:
        def warm_argv(image: str, project_volume: str, *command: str, **options: Any) -> tuple[str, ...]:
            args = list(_runtime_argv(image, project_volume, *command, **options))
            args[args.index(image):args.index(image)] = [
                "--env", "CI=1", "--env", "LEAN_NUM_THREADS=1", "--env",
                "PATH=/project/dependencies/toolchain/bin:/opt/autofv-venv/bin:"
                "/opt/git/bin:/opt/lean/bin:/opt/rust-bin:/usr/local/bin:/usr/bin:/bin",
                "--mount",
                f"type=volume,src={volume},dst=/project/dependencies,volume-nocopy",
            ]
            return tuple(args)

        axiom_audit.checkout_volume(
            image=image,
            volume=warm_volume,
            repository_bundle=repository_bundle,
            commit=base_commit,
            runtime="runc",
            docker=_docker,
            runtime_argv=warm_argv,
            seed_file=_seed_file,
        )
        _docker(*warm_argv(
            image, warm_volume, "sh", "-eu", "-c",
            worker_runtime.offline_mathlib_cache_script("/project/dependencies"),
            workdir="/project/repo", runtime="runc",
        ))
        _docker(*warm_argv(
            image, warm_volume, "lake", "build", "--no-build", "Mathlib",
            workdir="/project/repo", runtime="runc",
        ), timeout=120)
        warm = list(warm_argv(
            image, warm_volume, "sh", "-eu", "-c",
            "export LEAN_NUM_THREADS=1; lake build",
            workdir="/project/repo", runtime="runc",
        ))
        warm[warm.index("--memory") + 1] = "6g"
        warm[warm.index("--memory-swap") + 1] = "6g"
        warm_name = f"{warm_volume}-build"
        warm[2:2] = ["--name", warm_name]
        try:
            _docker(*warm, timeout=540)
        finally:
            try:
                _docker("rm", "-f", warm_name)
            except VerifierInfrastructureError as exc:
                if "No such container" not in str(exc):
                    raise
        _docker(*warm_argv(
            image, warm_volume, "sh", "-eu", "-c",
            "export LEAN_NUM_THREADS=1; lake build --no-build",
            workdir="/project/repo", runtime="runc",
        ), timeout=150)
    finally:
        _docker("volume", "rm", "-f", warm_volume)


def _run_bundle(run: dict[str, Any], state: dict[str, Any]) -> bytes:
    evidence = Path(run["evidence_dir"])
    if isinstance(run.get("preparation_manifest"), dict):
        rust, aeneas = _prepared_probe_evidence(run)
    else:
        try:
            rust = (evidence / "probe-rust.json").read_bytes()
            aeneas = (evidence / "probe-aeneas.json").read_bytes()
        except OSError as exc:
            raise VerifierError("clean verifier probe evidence is missing") from exc
    accepted_commit = run["accepted"]["accepted_commit"]
    repository = worker.verification_repository(run, accepted_commit)
    if repository is None:
        raise VerifierError("accepted commit changed before verification")
    return build_bundle(
        {
            "accepted/repository.bundle": repository,
            "evidence/probe-aeneas.json": aeneas,
            "evidence/probe-rust.json": rust,
            "input/autofv.json": _canonical_bytes(run["manifest"]),
            "state/verification.json": _canonical_bytes(state),
        }
    )


def _seed_file(
    image: str,
    volume: str,
    path: str,
    raw: bytes,
    *,
    runtime: str,
    allowed_paths: set[str] | frozenset[str] = frozenset(),
) -> None:
    if path not in {
        "repository.bundle",
        "reference-check.lean",
        "repo/functions.json",
        f"repo/{axiom_audit.REFERENCE_SOURCE}",
        f"repo/{axiom_audit.EXPECTED_SOURCE}",
        f"repo/{axiom_audit.BASELINE_SOURCE}",
        f"repo/{axiom_audit.AUDIT_SOURCE}",
        f"repo/{axiom_audit.AUDIT_LIBRARY}.lean",
        f"repo/{axiom_audit.BASELINE_LIBRARY}.lean",
        "repo/AutoFVCounterexample.lean",
        "repo/AutoFVCounterexampleAudit.lean",
        f"repo/{counterexample.OLEAN_PATH}",
    } | set(allowed_paths):
        raise VerifierError("clean verifier seed path is not allowlisted")
    _docker(
        "run",
        "--rm",
        "-i",
        "--pull",
        "never",
        "--runtime",
        runtime,
        "--read-only",
        "--network",
        "none",
        "--user",
        "0:0",
        "--security-opt",
        "no-new-privileges",
        "--mount",
        f"type=volume,src={volume},dst=/project,volume-nocopy",
        image,
        "sh",
        "-eu",
        "-c",
        "install -d -o 65532 -g 65532 \"$(dirname \"/project/$1\")\"; "
        "cat > \"/project/$1\"; chown 65532:65532 \"/project/$1\"; "
        "chmod 0444 \"/project/$1\"",
        "autofv-seed",
        path,
        input_bytes=raw,
    )


def _archive_sources(raw: bytes, paths: set[str]) -> dict[str, bytes]:
    found: dict[str, bytes] = {}
    try:
        with tarfile.open(fileobj=io.BytesIO(raw), mode="r:*") as archive:
            for member in archive:
                name = member.name.rstrip("/") if member.isdir() else member.name
                if not _safe_path(name) or not (member.isdir() or member.isreg()):
                    raise VerifierError("accepted_tree_unsafe")
                if member.isreg() and member.name in paths:
                    source = archive.extractfile(member)
                    if source is None or member.size > MAX_MEMBER_BYTES:
                        raise VerifierError("accepted_tree_unsafe")
                    found[member.name] = source.read(MAX_MEMBER_BYTES + 1)
    except (tarfile.TarError, OSError) as exc:
        raise VerifierError("accepted_tree_invalid") from exc
    if set(found) != paths:
        raise VerifierError("accepted_tree_scope_missing")
    return found


def _snapshot_hash(raw: bytes) -> str:
    entries = []
    try:
        with tarfile.open(fileobj=io.BytesIO(raw), mode="r:*") as archive:
            for member in archive:
                name = member.name.rstrip("/") if member.isdir() else member.name
                if not _safe_path(name) or not (member.isdir() or member.isreg()):
                    raise VerifierError("snapshot_tree_unsafe")
                path = PurePosixPath(member.name)
                if (
                    member.isdir()
                    or any(part in worker.SKIP_PARTS for part in path.parts)
                    or path.name in worker.SKIP_NAMES
                ):
                    continue
                source = archive.extractfile(member)
                if source is None or member.size > MAX_MEMBER_BYTES:
                    raise VerifierError("snapshot_tree_unsafe")
                content = source.read(MAX_MEMBER_BYTES + 1)
                entries.append(
                    {
                        "path": member.name,
                        "sha256": _sha256(content),
                        "size": len(content),
                    }
                )
    except (tarfile.TarError, OSError) as exc:
        raise VerifierError("snapshot_tree_invalid") from exc
    entries.sort(key=lambda item: item["path"])
    return _sha256(_canonical_bytes(entries))


def _source_audit(
    archive: bytes,
    graph: dict[str, Any],
    claimed_uses: list[dict[str, Any]],
) -> tuple[list[str], bool, list[dict[str, Any]]]:
    paths = set(graph["source_paths"].values())
    sources = _archive_sources(archive, paths)
    holes: list[str] = []
    trust_passed = True
    discovered: dict[tuple[str, str, str], tuple[str, str]] = {}
    for path, raw in sorted(sources.items()):
        text = raw.decode("utf-8", "strict")
        source_sha256 = _sha256(raw)
        for line_number, line in enumerate(text.splitlines(), 1):
            code = line.split("--", 1)[0]
            if re.search(r"\b(?:sorry|sorryAx|admit)\b", code):
                holes.append(f"{path}:{line_number}")
            if re.search(r"^\s*axiom\b|@\[(?:extern|implemented_by)\b", code):
                trust_passed = False
            if re.search(r"\bnative_decide\b", code):
                expression_sha256 = _sha256(code.strip().encode())
                discovered[(path, source_sha256, expression_sha256)] = (
                    path,
                    expression_sha256,
                )
    claimed = {
        (
            item.get("source_path"),
            item.get("source_sha256"),
            item.get("expression_sha256"),
        )
        for item in claimed_uses
        if isinstance(item, dict)
    }
    observed_uses = claimed_uses if claimed == set(discovered) else [{"mismatch": True}]
    return holes, trust_passed, observed_uses


def _reference_program(raw: bytes) -> bytes:
    """Compatibility facade for the controller-owned meaning-check builder."""
    return axiom_audit.reference_program(_strict_json(raw, "verifier_reference"))


def _probe_output(
    image: str,
    volume: str,
    executable: str,
    *arguments: str,
    runtime: str,
) -> bytes:
    return _docker(
        *_runtime_argv(
            image,
            volume,
            "sh",
            "-eu",
            "-c",
            'output="$(mktemp)"; "$@" -o "$output" >&2; cat "$output"',
            "autofv-probe",
            executable,
            *arguments,
            workdir="/project/repo",
            runtime=runtime,
        )
    ).stdout


def _final_statuses(raw: bytes, nodes: list[str]) -> dict[str, str]:
    report = _strict_json(raw, "final_probe_aeneas")
    atoms = report.get("data")
    if not isinstance(atoms, dict):
        return {node: "unknown" for node in nodes}
    accepted = {"verified", "transitively-verified"}
    return {
        node: (
            "accepted"
            if isinstance(atoms.get(node), dict)
            and atoms[node].get("verification-status") in accepted
            else "unknown"
        )
        for node in nodes
    }


def _clean_worker_checks(
    run: dict[str, Any],
    invocation: dict[str, Any],
    members: dict[str, bytes],
    state: dict[str, Any],
    reference_bytes: bytes,
) -> dict[str, Any]:
    state = copy.deepcopy(state)
    permitted_incomplete_accepted = state.pop(
        "_counterexample_incomplete_accepted", []
    )
    lock = run["lock"]
    image = invocation["image_digest"]
    runtime = lock["tools"]["runsc"]["runtime_name"]
    nonce = secrets.token_hex(8)
    volume = f"autofv-verify-{nonce}"
    audit_volume = f"autofv-verify-audit-{nonce}"
    reference = _strict_json(reference_bytes, "verifier_reference")
    expected_axioms = axiom_audit.expected_inventory(state, reference)
    artifacts = axiom_audit.olean_paths(state["graph"])
    created = []
    dependency_volume = (
        f"autofv-verify-dependencies-{nonce}"
        if isinstance(run.get("preparation_manifest"), dict)
        else None
    )

    def runtime_argv(*args, **kwargs):
        return _runtime_argv(
            *args, dependency_volume=dependency_volume, **kwargs
        )

    try:
        for isolated_volume in (audit_volume, volume):
            _docker("volume", "create", isolated_volume)
            created.append(isolated_volume)
        if dependency_volume is not None:
            created.append(dependency_volume)
            _seed_verifier_dependency_cache(
                run, image, dependency_volume,
                members["accepted/repository.bundle"], state["base_commit"],
            )
        baseline_identities = axiom_audit.prepare_auditor(
            image=image,
            volume=audit_volume,
            repository_bundle=members["accepted/repository.bundle"],
            base_commit=state["base_commit"],
            verify_command=list(worker_runtime.trusted_verify_command(run, run["manifest"])),
            expected=expected_axioms,
            state=state,
            reference=reference,
            runtime=runtime,
            docker=_docker,
            runtime_argv=runtime_argv,
            seed_file=_seed_file,
            permitted_incomplete_accepted=permitted_incomplete_accepted,
        )
        axiom_audit.checkout_volume(
            image=image,
            volume=volume,
            repository_bundle=members["accepted/repository.bundle"],
            commit=invocation["accepted_commit"],
            runtime=runtime,
            docker=_docker,
            runtime_argv=runtime_argv,
            seed_file=_seed_file,
        )
        commit = _docker(
            *runtime_argv(
                image,
                volume,
                "git",
                "rev-parse",
                "HEAD",
                workdir="/project/repo",
                runtime=runtime,
            )
        ).stdout.decode().strip()
        archive = _docker(
            *runtime_argv(
                image,
                volume,
                "git",
                "archive",
                "--format=tar",
                "HEAD",
                workdir="/project/repo",
                runtime=runtime,
            )
        ).stdout
        base_archive = _docker(
            *runtime_argv(
                image,
                volume,
                "git",
                "archive",
                "--format=tar",
                state["base_commit"],
                workdir="/project/repo",
                runtime=runtime,
            )
        ).stdout
        changed = _docker(
            *runtime_argv(
                image,
                volume,
                "git",
                "diff",
                "--name-only",
                state["base_commit"],
                "HEAD",
                workdir="/project/repo",
                runtime=runtime,
            )
        ).stdout.decode().splitlines()
        _docker(
            *runtime_argv(
                image,
                volume,
                "sh",
                "-eu",
                "-c",
                "test ! -e .lake/build",
                workdir="/project/repo",
                runtime=runtime,
            )
        )
        _docker(
            *runtime_argv(
                image,
                volume,
                *worker_runtime.trusted_verify_command(run, run["manifest"]),
                workdir="/project/repo",
                runtime=runtime,
            )
        )
        if isinstance(run.get("preparation_manifest"), dict):
            final_rust = members["evidence/probe-rust.json"]
            final_aeneas = members["evidence/probe-aeneas.json"]
        else:
            final_rust = _probe_output(
                image,
                volume,
                "probe-rust",
                "extract",
                "/project/repo",
                "--with-locations",
                "--with-public-api",
                runtime=runtime,
            )
            _seed_file(
                image,
                volume,
                "repo/functions.json",
                worker.probe_bridge(final_rust, run["manifest"]),
                runtime=runtime,
            )
            final_aeneas = _probe_output(
                image,
                volume,
                "probe-aeneas",
                "extract",
                "/project/repo",
                "--with-public-api",
                runtime=runtime,
            )
        final_graph = probes.parse_probe_bytes(
            run["manifest"], final_rust, final_aeneas
        )
        graph_matches = final_graph["graph_sha256"] == state["graph"]["graph_sha256"]

        program = axiom_audit.reference_program(
            reference, allow_empty=state.get("partial_target") is not None
        )
        _seed_file(
            image,
            volume,
            f"repo/{axiom_audit.REFERENCE_SOURCE}",
            program,
            runtime=runtime,
        )
        _docker(
            *runtime_argv(
                image,
                volume,
                "lake",
                "env",
                "lean",
                "-o",
                axiom_audit.REFERENCE_OLEAN,
                axiom_audit.REFERENCE_SOURCE,
                workdir="/project/repo",
                runtime=runtime,
            )
        )
        axiom_inventory = axiom_audit.audit_artifacts(
            image=image,
            witness_volume=volume,
            audit_volume=audit_volume,
            artifacts=artifacts,
            expected=expected_axioms,
            state=state,
            reference=reference,
            baseline_identities=baseline_identities,
            runtime=runtime,
            max_artifact_bytes=MAX_MEMBER_BYTES,
            docker=_docker,
            runtime_argv=runtime_argv,
            seed_file=_seed_file,
            permitted_incomplete_accepted=permitted_incomplete_accepted,
        )
        accepted_native_uses, hidden_native_uses, all_native_uses = (
            axiom_audit.native_use_provenance(axiom_inventory)
        )
        baseline_holes, _, _ = _source_audit(base_archive, state["graph"], [])
        holes, trust_passed, observed_uses = _source_audit(
            archive, state["graph"], state["native_decide_uses"]
        )
        nodes = state["graph"]["selected_nodes"]
        statuses = _final_statuses(final_aeneas, nodes)
        meaning = (
            {}
            if state.get("partial_target") is not None else
            {
                "reference_integrity": True,
                "statement_equivalence": True,
                "non_vacuity": True,
                "broken_implementation_rejected": True,
            }
        )
        return {
            "verifier_worker_id": invocation["verifier_worker_id"],
            "runtime_identity": True,
            "snapshot_sha256": _snapshot_hash(base_archive),
            "accepted_commit": commit,
            "accepted_tree_sha256": _sha256(archive),
            "image_digest": image,
            "fresh_cache": True,
            "clean_build": True,
            "accepted_nodes": nodes if graph_matches else [],
            "status_by_node": statuses,
            "statement_fingerprints": {
                name: record["model_fingerprint"]
                for name, record in state["frozen_contracts"].items()
            },
            "changed_paths": sorted(changed),
            "holes": holes,
            "trust_passed": trust_passed,
            "native_decide_policy_sha256": invocation[
                "native_decide_policy_sha256"
            ],
            "native_decide_uses": all_native_uses,
            "accepted_native_decide_uses": observed_uses,
            "hidden_native_decide_uses": hidden_native_uses,
            "compiler_assumptions": compiler_assumptions(lock),
            "axiom_inventory": axiom_inventory,
            "meaning": meaning,
            "sorry_count_before": len(baseline_holes),
            "sorry_count_after": len(holes),
        }
    finally:
        for isolated_volume in reversed(created):
            try:
                _docker("volume", "rm", isolated_volume)
            except VerifierError:
                pass


def verify_run(
    run: dict[str, Any],
    expected: dict[str, Any],
    verification_state: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Rebuild the exact commit and evaluate it on the dedicated clean worker."""
    started = subprocess.run(("limactl", "start", VERIFIER_VM), capture_output=True)
    if started.returncode:
        detail = _command_detail(started)
        raise VerifierInfrastructureError(
            f"clean verifier failed to start: {detail or VERIFIER_VM}"
        )
    machine_id = _shell("cat", "/etc/machine-id").stdout.decode().strip()
    verifier_worker_id = f"lima:{VERIFIER_VM}:{machine_id}"
    if not machine_id or verifier_worker_id == run.get("agent_worker_id"):
        raise VerifierInfrastructureError("clean verifier worker is not distinct")
    lock = run["lock"]
    if isinstance(run.get("preparation_manifest"), dict):
        _check_quiet_verifier_vm()
    _check_verifier_runtime(lock)
    toolchain_lock_sha256 = _sha256(_canonical_bytes(lock))
    if expected.get("toolchain_lock_sha256") != toolchain_lock_sha256:
        raise VerifierError("clean verifier toolchain_lock_sha256 mismatch")
    state = verification_state or run.get("verification_state")
    if not isinstance(state, dict):
        raise VerifierInfrastructureError("clean verifier state is missing")
    partial_target = state.get("partial_target")
    if partial_target is not None and not isinstance(run.get("preparation_manifest"), dict):
        raise VerifierError("partial verification requires prepared input")
    bundle = _run_bundle(run, state)
    reference_bytes = _trusted_reference(run)
    reference_sha256 = _sha256(reference_bytes)
    if (
        isinstance(run.get("preparation_manifest"), dict)
        and expected.get("reference_sha256") != reference_sha256
    ) or (
        not isinstance(run.get("preparation_manifest"), dict)
        and expected.get("reference_sha256", reference_sha256) != reference_sha256
    ):
        raise VerifierError("clean verifier reference_sha256 mismatch")
    invocation = {
        "schema": "autofv-verifier-invocation/v1",
        "run_id": run["run_id"],
        "invocation_id": expected.get("invocation_id") or secrets.token_hex(16),
        "agent_worker_id": run["agent_worker_id"],
        "verifier_worker_id": verifier_worker_id,
        "snapshot_sha256": expected["snapshot_sha256"],
        "manifest_sha256": expected["manifest_sha256"],
        "probe_rust_sha256": expected["probe_rust_sha256"],
        "probe_aeneas_sha256": expected["probe_aeneas_sha256"],
        "graph_sha256": expected["graph_sha256"],
        "image_digest": expected["image_digest"],
        "control_bundle_sha256": expected["control_bundle_sha256"],
        "native_decide_policy_sha256": expected[
            "native_decide_policy_sha256"
        ],
        "axiom_scope_sha256": axiom_audit.inventory_scope_sha256(
            axiom_audit.expected_inventory(
                state,
                {"leaves": []} if partial_target is not None
                else _strict_json(reference_bytes, "verifier_reference"),
            )
        ),
        "toolchain_lock_sha256": toolchain_lock_sha256,
        "accepted_commit": expected["accepted_commit"],
        "accepted_tree_sha256": expected["accepted_tree_sha256"],
        "bundle_sha256": _sha256(bundle),
        "reference_sha256": reference_sha256,
    }
    if (
        expected.get("axiom_scope_sha256")
        != invocation["axiom_scope_sha256"]
    ):
        raise VerifierError("clean verifier axiom_scope_sha256 mismatch")
    arguments = {
        "reference_bytes": reference_bytes,
        "run_checks": lambda members, state, reference: _clean_worker_checks(
            run, invocation, members, state, reference
        ),
    }
    if partial_target is not None:
        return verify_bundle(
            bundle, invocation, partial_target=partial_target, **arguments
        )
    if isinstance(run.get("preparation_manifest"), dict):
        return terminal_verifier.verify_terminal_bundle(
            bundle,
            invocation,
            preparation_manifest=run["preparation_manifest"],
            confirm_counterexample=lambda certificate, members, _state, obligation: (
                terminal_verifier.confirm_counterexample_certificate(
                    run,
                    invocation,
                    certificate,
                    obligation,
                    members,
                    _state,
                    docker=_docker,
                    runtime_argv=_runtime_argv,
                    seed_file=_seed_file,
                )
            ),
            **arguments,
        )
    return verify_bundle(bundle, invocation, **arguments)


def _validate_legacy_report(
    report: Any,
    run: dict[str, Any],
    expected: dict[str, Any],
    *,
    require_pass: bool = True,
    require_axiom_inventory: bool = False,
    allow_untrusted_axioms: bool = False,
    permitted_untrusted_declarations: frozenset[str] = frozenset(),
) -> dict[str, Any]:
    """Accept only a distinct worker's hash-bound PASS report."""
    if "invocation_id" in expected:
        required = (INVOCATION_FIELDS - {"schema"}) | {
            "schema",
            "checks",
            "failures",
            "native_decide_uses",
            "accepted_native_decide_uses",
            "hidden_native_decide_uses",
            "compiler_assumptions",
            "axiom_inventory",
            "axiom_inventory_sha256",
            "meaning",
            "sorry_count_before",
            "sorry_count_after",
            "evidence_level",
            "verdict",
            "report_sha256",
        }
        if not isinstance(report, dict) or set(report) != required:
            raise VerifierError("clean verifier report fields mismatch")
        _valid_invocation(
            {
                **{field: report[field] for field in INVOCATION_FIELDS - {"schema"}},
                "schema": "autofv-verifier-invocation/v1",
            }
        )
        if report.get("schema") != "autofv-verifier-report/v1":
            raise VerifierError("clean verifier report schema mismatch")
        if (
            report.get("run_id") != run.get("run_id")
            or report.get("agent_worker_id") != run.get("agent_worker_id")
        ):
            raise VerifierError("clean verifier run identity mismatch")
        if (
            not isinstance(report.get("verifier_worker_id"), str)
            or not report["verifier_worker_id"]
            or report["verifier_worker_id"] == report["agent_worker_id"]
        ):
            raise VerifierError("clean verifier worker is not distinct")
        for field, value in expected.items():
            if field != "schema" and report.get(field) != value:
                raise VerifierError(f"clean verifier {field} mismatch")
        failures = report.get("failures")
        checks = report.get("checks")
        verdict = report.get("verdict")
        evidence_level = report.get("evidence_level")
        if (
            not isinstance(failures, list)
            or any(not isinstance(failure, str) or not failure for failure in failures)
            or not isinstance(checks, dict)
            or any(type(value) is not bool for value in checks.values())
            or verdict not in {"PASS", "FAIL"}
            or evidence_level != ("L4" if verdict == "PASS" else "L0")
            or (verdict == "PASS") != (failures == [])
            or (
                require_axiom_inventory
                and set(checks) != verifier_bundle.REPORT_CHECKS
            )
        ):
            raise VerifierError("clean verifier report reduction mismatch")
        pass_invalid = verdict == "PASS" and (
            set(checks) != verifier_bundle.REPORT_CHECKS
            or any(value is not True for value in checks.values())
            or type(report.get("sorry_count_before")) is not int
            or report["sorry_count_before"] < 0
            or report.get("sorry_count_after") != 0
        )
        if pass_invalid or (require_pass and verdict != "PASS"):
            raise VerifierError("clean verifier did not pass")

        def validate_axiom_inventory(*, allow_untrusted: bool) -> None:
            lock = contracts.load_toolchain_lock()
            inventory = report["axiom_inventory"]
            axiom_audit.validate_report_inventory(
                inventory,
                lock=lock,
                compiler_assumptions=report["compiler_assumptions"],
                require_complete=require_axiom_inventory,
                expected_scope_sha256=report["axiom_scope_sha256"],
                expected_identity_sha256=report["axiom_inventory_sha256"],
                accepted_native_decide_uses=report[
                    "accepted_native_decide_uses"
                ],
                hidden_native_decide_uses=report[
                    "hidden_native_decide_uses"
                ],
                required_native_uses=report["native_decide_uses"],
                allow_untrusted_axioms=allow_untrusted,
                permitted_untrusted_declarations=(
                    permitted_untrusted_declarations
                    if allow_untrusted
                    else frozenset()
                ),
            )

        try:
            validate_axiom_inventory(allow_untrusted=False)
        except (KeyError, TypeError, contracts.ContractError, OSError) as strict_exc:
            if not allow_untrusted_axioms:
                raise VerifierError(
                    "clean verifier axiom inventory mismatch"
                ) from strict_exc
            try:
                validate_axiom_inventory(allow_untrusted=True)
            except (KeyError, TypeError, contracts.ContractError, OSError) as exc:
                raise VerifierError(
                    "clean verifier axiom inventory mismatch"
                ) from exc
            if (
                checks.get("kernel_axioms") is not False
                or "axiom_inventory_invalid" not in failures
            ):
                raise VerifierError("clean verifier axiom inventory mismatch")
        body = {key: value for key, value in report.items() if key != "report_sha256"}
        if report.get("report_sha256") != _sha256(_canonical_bytes(body)):
            raise VerifierError("clean verifier report hash mismatch")
        return report

    # Compatibility for pre-bundle unit seams. Real executions pass a full
    # invocation and therefore cannot authorize this reduced report shape.
    required = {
        "schema",
        "run_id",
        "agent_worker_id",
        "verifier_worker_id",
        *expected.keys(),
        "verdict",
        "report_sha256",
    }
    if not isinstance(report, dict) or set(report) != required:
        raise VerifierError("clean verifier report fields mismatch")
    if report["schema"] != "autofv-verifier-report/v1":
        raise VerifierError("clean verifier report schema mismatch")
    if report["run_id"] != run["run_id"] or report["agent_worker_id"] != run["agent_worker_id"]:
        raise VerifierError("clean verifier run identity mismatch")
    if (
        not isinstance(report["verifier_worker_id"], str)
        or not report["verifier_worker_id"]
        or report["verifier_worker_id"] == report["agent_worker_id"]
    ):
        raise VerifierError("clean verifier worker is not distinct")
    for field, value in expected.items():
        if report[field] != value:
            raise VerifierError(f"clean verifier {field} mismatch")
    if report["verdict"] != "PASS":
        raise VerifierError("clean verifier did not pass")
    body = {key: value for key, value in report.items() if key != "report_sha256"}
    if report["report_sha256"] != _sha256(_canonical_bytes(body)):
        raise VerifierError("clean verifier report hash mismatch")
    return report


def validate_partial_report(
    report: Any,
    run: dict[str, Any],
    expected: dict[str, Any],
    target: str,
    state: dict[str, Any],
) -> dict[str, Any]:
    """Authorize only one kernel-checked helper; never upgrade the root or L4."""
    fields = (INVOCATION_FIELDS - {"schema"}) | {
        "schema", "partial_target", "root_status", "checks", "failures",
        "native_decide_uses", "accepted_native_decide_uses",
        "hidden_native_decide_uses", "compiler_assumptions", "axiom_inventory",
        "axiom_inventory_sha256", "meaning", "sorry_count_before",
        "sorry_count_after", "evidence_level", "verdict", "report_sha256",
    }
    if not isinstance(report, dict) or set(report) != fields:
        raise VerifierError("partial verifier report fields mismatch")
    _valid_invocation({
        **{field: report[field] for field in INVOCATION_FIELDS - {"schema"}},
        "schema": "autofv-verifier-invocation/v1",
    })
    accepted = state.get("accepted_nodes")
    graph = state.get("graph", {})
    if (
        report["schema"] != "autofv-verifier-partial-report/v1"
        or report["run_id"] != run.get("run_id")
        or report["agent_worker_id"] != run.get("agent_worker_id")
        or not report["verifier_worker_id"]
        or report["verifier_worker_id"] == report["agent_worker_id"]
        or report["partial_target"] != target
        or state.get("partial_target") != target
        or target in graph.get("frozen_targets", [])
        or not isinstance(accepted, list)
        or any(not isinstance(item, str) for item in accepted)
        or bool(set(accepted) & set(graph.get("frozen_targets", [])))
        or target not in accepted
        or report["root_status"] != "unverified"
        or report["verdict"] != "SCOPED_PASS"
        or report["evidence_level"] != "P1"
        or report["failures"] != []
        or report["meaning"] != {}
        or report["checks"] != {
            name: name != "meaning" for name in verifier_bundle.REPORT_CHECKS
        }
        or any(type(value) is not bool for value in report["checks"].values())
        or type(report["sorry_count_before"]) is not int
        or type(report["sorry_count_after"]) is not int
        or not 0 <= report["sorry_count_after"] <= report["sorry_count_before"]
        or report["compiler_assumptions"] != state.get("compiler_assumptions")
    ):
        raise VerifierError("partial verifier report reduction mismatch")
    for field, value in expected.items():
        if field != "schema" and report.get(field) != value:
            raise VerifierError(f"partial verifier {field} mismatch")
    if report["report_sha256"] != _sha256(_canonical_bytes({
        key: value for key, value in report.items() if key != "report_sha256"
    })):
        raise VerifierError("partial verifier report hash mismatch")
    try:
        audit_reference = {"leaves": []}
        inventory = report["axiom_inventory"]
        scope = axiom_audit.expected_inventory(state, audit_reference)
        if axiom_audit.inventory_scope_sha256(scope) != expected["axiom_scope_sha256"]:
            raise contracts.ContractError("partial verifier scope mismatch")
        closures = {
            item["declaration"]: sorted({item["declaration"], *item["dependencies"]})
            for item in inventory
        }
        skeleton = axiom_audit.expected_inventory(
            state, audit_reference, observed_closures=closures
        )
        lock = contracts.load_toolchain_lock()
        axiom_audit.validate_inventory(
            inventory, skeleton, lock=lock,
            compiler_assumptions=state["compiler_assumptions"],
        )
        axiom_audit.validate_report_inventory(
            inventory, lock=lock,
            compiler_assumptions=report["compiler_assumptions"],
            require_complete=False,
            expected_scope_sha256=expected["axiom_scope_sha256"],
            expected_identity_sha256=report["axiom_inventory_sha256"],
            accepted_native_decide_uses=report["accepted_native_decide_uses"],
            hidden_native_decide_uses=report["hidden_native_decide_uses"],
            required_native_uses=report["native_decide_uses"],
        )
    except (KeyError, TypeError, ValueError, contracts.ContractError, OSError) as exc:
        raise VerifierError("partial verifier axiom inventory mismatch") from exc
    return report


def validate_report(
    report: Any, run: dict[str, Any], expected: dict[str, Any]
) -> dict[str, Any]:
    """Validate a Phase-1 report or its preparation-bound Phase-2 envelope."""
    if isinstance(report, dict) and terminal_verifier.TERMINAL_REPORT_FIELDS <= set(
        report
    ):
        return terminal_verifier.validate_terminal_report(
            report, run, expected, validate_core=_validate_legacy_report
        )
    return _validate_legacy_report(report, run, expected)
