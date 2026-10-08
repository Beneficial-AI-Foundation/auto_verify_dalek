"""Fixed sealed-runtime prerequisite suite and retained-bundle validation."""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import os
import re
import signal
import stat
import sys
import threading
import time
from contextlib import contextmanager
from decimal import Decimal
from pathlib import Path
from typing import Any, Callable

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from autofv import (  # noqa: E402
    candidate_lane,
    graph_scheduler,
    preflight,
    preflight_evidence,
    provider_config,
    provider_receipts,
    result_summary,
    worker_runtime,
)
from autofv.contracts import (  # noqa: E402
    ContractError,
    canonical_json_bytes,
    load_toolchain_lock,
)

RUNNER_SCHEMA = "autofv-sealed-preflight-runner/v1"
RESULT_SCHEMA = "autofv-preflight-result/v1"
MAX_AGE_SECONDS = 300
MAX_HELPER_WALL_SECONDS = 3600
HELPER_HANDOFF_INPUT_SHA256 = hashlib.sha256(b"autofv:same-worker-helper-handoff:v1").hexdigest()
_ALL_CHECKS = (
    *preflight_evidence.DETERMINISTIC_PREFLIGHT_CASES,
    *preflight_evidence.DETERMINISTIC_PREFLIGHT_GATES,
)


def _graph() -> dict[str, Any]:
    return {
        "frozen_targets": ["Top"],
        "selected_nodes": ["Base", "Left", "Right", "Top"],
        "term_dependencies": [
            ["Left", "Base"],
            ["Right", "Base"],
            ["Top", "Left"],
            ["Top", "Right"],
        ],
        "type_dependencies": [],
        "source_paths": {
            "Base": "Proof/Base.lean",
            "Left": "Proof/Shared.lean",
            "Right": "Proof/Shared.lean",
            "Top": "Proof/Top.lean",
            "Spec.Top": "Spec/Top.lean",
        },
        "supplied_specs": {"Top": "Spec.Top"},
    }


def _linear_dependency_chain() -> None:
    graph = _graph()
    assert graph_scheduler._proof_ready_nodes(graph, set()) == ["Base"]
    assert graph_scheduler._proof_ready_nodes(graph, {"Base"}) == ["Left", "Right"]
    assert graph_scheduler._proof_ready_nodes(graph, {"Base", "Left", "Right"}) == ["Top"]


def _shared_helper_convergence() -> None:
    graph = _graph()
    assert graph_scheduler._immediate_consumers(graph, "Base") == ["Left", "Right"]
    assert graph_scheduler._transitive_consumers(graph, "Base") == ["Left", "Right", "Top"]


def _schedule_trace() -> list[str]:
    trace: list[str] = []
    accepted = graph_scheduler._schedule_proofs(
        _graph(),
        lambda node: trace.append(node) or node,
        lambda node, result: node == result,
        max_workers=4,
    )
    assert accepted == {"Base", "Left", "Right", "Top"}
    return trace


def _same_file_serialization() -> None:
    barrier = threading.Barrier(2)
    lock = threading.Lock()
    active = 0
    overlap = False

    def run(node: str) -> str:
        nonlocal active, overlap
        if node not in {"Left", "Right"}:
            return node
        with lock:
            overlap = overlap or active > 0
            active += 1
        try:
            try:
                barrier.wait(timeout=0.25)
            except threading.BrokenBarrierError:
                pass
        finally:
            with lock:
                active -= 1
        return node

    accepted = graph_scheduler._schedule_proofs(
        _graph(), run, lambda node, result: node == result, max_workers=4
    )
    assert accepted == {"Base", "Left", "Right", "Top"}
    assert not overlap


def _immediate_consumer_release() -> None:
    trace = _schedule_trace()
    assert trace.index("Base") < trace.index("Left")
    assert trace.index("Base") < trace.index("Right")
    assert trace.index("Left") < trace.index("Top")
    assert trace.index("Right") < trace.index("Top")


def _cycle_rejection() -> None:
    graph = _graph()
    graph["term_dependencies"].append(["Base", "Top"])
    state = {"graph": graph, "run": {"events": []}}
    try:
        graph_scheduler._validate_scheduling_graph(state)
    except ContractError as exc:
        assert "cycle" in str(exc)
        return
    raise AssertionError("cyclic graph was accepted")


def _stale_binding_reverification() -> None:
    digest = "1" * 64
    assert candidate_lane.candidate_binding_is_current([digest], digest, [digest], digest)
    assert not candidate_lane.candidate_binding_is_current([digest], digest, [digest], "2" * 64)


def _undeclared_dependency_rejected() -> None:
    state = {"graph": _graph(), "run": {"events": []}}
    payload = {
        "root": "Top",
        "lanes": [
            {"declaration": "Base", "source_path": "Proof/Base.lean", "depends_on": []},
            {"declaration": "Left", "source_path": "Proof/Shared.lean", "depends_on": ["Base"]},
            {"declaration": "Right", "source_path": "Proof/Shared.lean", "depends_on": ["Base", "Missing"]},
        ],
        "join": {"consumer": "Top", "requires": ["Left", "Right"]},
    }
    try:
        graph_scheduler._validate_dependency_plan(state, {"payload": payload})
    except ContractError:
        return
    raise AssertionError("undeclared dependency was accepted")


def _candidate_trust_scope_rejected() -> None:
    argv = worker_runtime._candidate_runtime_argv(
        _lock(), "preflight-volume", "lane-001", "true"
    )
    mounts = [argv[index + 1] for index, item in enumerate(argv[:-1]) if item == "--mount"]
    # Only its private worktree and the read-only dependency cache.
    assert mounts == [
        "type=volume,src=preflight-volume,dst=/candidate,"
        "volume-subpath=lanes/lane-001/work,volume-nocopy",
        "type=volume,src=preflight-volume,dst=/dependencies,"
        "volume-subpath=dependencies,volume-nocopy,readonly",
    ]


def _budget_receipt_reconciliation() -> None:
    reduced = result_summary.reduce_accounting(
        {
            "cost_classification": "synthetic_fixture",
            "lock": {"fixed_proxy": {"cost_classification": "synthetic_fixture"}},
        },
        {"receipts": [], "model_exchanges": {}},
    )
    assert reduced["requests"] == 0 and reduced["cost"] == 0
    assert reduced["accounting"]["provider_authenticated"]["requests"] == 0


def _honest_terminal_labels() -> None:
    accounting = {"provider_authenticated": {"requests": 0}}
    summary = result_summary.render_generic_summary(
        {},
        {"target_states": {"Top": {"status": "accepted"}}, "wall_seconds_used": 0},
        {"verdict": "PASS", "checks": {"clean_build": True, "target_closure": True, "holes": False}},
        verifier_bound=True,
        accounting=accounting,
    )
    assert summary["verified_counts"] == {"targets": 0, "declarations": 0, "closure": 0}


def _tool_schema_equality() -> None:
    source = Path("/volume/autofv-control/autofv/agent_lane.py").read_text()
    module = ast.parse(source)
    assignments = [
        node for node in module.body
        if isinstance(node, ast.Assign)
        and any(isinstance(target, ast.Name) and target.id == "_TOOL_SCHEMAS" for target in node.targets)
    ]
    assert len(assignments) == 1
    schemas = ast.literal_eval(assignments[0].value)
    normalized = provider_config._tool_schemas(list(schemas))
    assert len(normalized) == len(schemas) and len({item["function"]["name"] for item in normalized}) == len(schemas)


PROJECT_ROOT = Path("/volume/work/project")
DEPENDENCY_PACKAGES = "/volume/dependencies/packages"


def _source_walk():
    """Walk sealed source; the top-level `.lake` is trusted build and dependency state."""
    for root, directories, files in os.walk(PROJECT_ROOT):
        if Path(root) == PROJECT_ROOT and ".lake" in directories:
            directories.remove(".lake")
        yield root, directories, files


def _tree_has_no_symlinks() -> None:
    lake = PROJECT_ROOT / ".lake"
    packages = lake / "packages"
    if lake.is_symlink() or (
        os.path.lexists(packages)
        and (not packages.is_symlink() or os.readlink(packages) != DEPENDENCY_PACKAGES)
    ):
        raise AssertionError("sealed build state has an unexpected link")
    for root, directories, files in _source_walk():
        for name in (*directories, *files):
            if stat.S_ISLNK(os.lstat(Path(root) / name).st_mode):
                raise AssertionError("sealed source contains a symlink")


def _source_files():
    for root, _directories, files in _source_walk():
        for name in files:
            path = Path(root) / name
            if path.is_file() and not path.is_symlink():
                yield path.read_bytes()


def _secret_scan() -> None:
    for name in provider_config._ENV_NAMES:
        assert name not in os.environ
    pattern = re.compile(
        rb"(?i)(?:api[_-]?key|secret|token|password)\s*[:=]\s*['\"]?[a-z0-9_-]{8,}"
    )
    assert not any(pattern.search(raw) for raw in _source_files())


def _spoiler_scan() -> None:
    markers = (
        b"diamond" + b"-reference",
        b"hidden" + b" reference",
        b"reference." + b"json",
    )
    assert not any(marker in raw.lower() for raw in _source_files() for marker in markers)


def _fixed_egress_path() -> None:
    lock = _lock()
    argv = worker_runtime._runtime_argv(lock, "preflight-volume", "true", network="none")
    assert argv[argv.index("--network") + 1] == "none"
    route = lock["fixed_proxy"]
    assert route["method"] == "POST" and route["path"].startswith("/")


def _provider_identity() -> None:
    route = _lock()["fixed_proxy"]
    assert route["proxy_id"] and route["route_id"]
    assert route["cost_classification"] in {"synthetic_fixture", "provider_authenticated"}


def _candidate_scope() -> None:
    project_probe = Path("/volume/work/project/.autofv-preflight-write-probe")
    try:
        project_probe.write_bytes(b"forbidden")
    except OSError:
        pass
    else:
        project_probe.unlink(missing_ok=True)
        raise AssertionError("sealed source is writable")
    evidence_probe = Path("/volume/evidence/.autofv-preflight-evidence-probe")
    evidence_probe.write_bytes(b"ok")
    evidence_probe.unlink()


def _distinct_terminal_verifier() -> None:
    verifier = _lock()["verifier"]
    assert verifier["separate_from_agent_worker"] is True
    assert verifier["receives_agent_volume_or_cache"] is False
    assert "autofv-verifier" in verifier["identity"]
    assert worker_runtime.AGENT_VM not in verifier["identity"]


def _lock() -> dict[str, Any]:
    return json.loads(Path("/volume/autofv-control/docker/autofv/toolchain-lock.json").read_bytes())


_CHECKS: dict[str, Callable[[], None]] = {
    "linear_dependency_chain": _linear_dependency_chain,
    "shared_helper_convergence": _shared_helper_convergence,
    "same_file_serialization": _same_file_serialization,
    "immediate_consumer_release": _immediate_consumer_release,
    "cycle_rejection": _cycle_rejection,
    "stale_binding_reverification": _stale_binding_reverification,
    "undeclared_dependency_rejected": _undeclared_dependency_rejected,
    "candidate_trust_scope_rejected": _candidate_trust_scope_rejected,
    "budget_receipt_reconciliation": _budget_receipt_reconciliation,
    "honest_terminal_labels": _honest_terminal_labels,
    "tool_schema_equality": _tool_schema_equality,
    "secret_scan": _secret_scan,
    "symlink_scan": _tree_has_no_symlinks,
    "spoiler_scan": _spoiler_scan,
    "fixed_egress_path": _fixed_egress_path,
    "provider_identity": _provider_identity,
    "candidate_scope": _candidate_scope,
    "distinct_terminal_verifier": _distinct_terminal_verifier,
}


def run_fixed_suite(output: str | Path) -> dict[str, Any]:
    """Execute every built-in check; no caller supplies names or outcomes."""
    if tuple(_CHECKS) != _ALL_CHECKS:
        raise RuntimeError("fixed preflight check map mismatch")
    checks = []
    for name, check in _CHECKS.items():
        try:
            check()
        except BaseException as exc:
            checks.append({"name": name, "status": "failed", "detail": type(exc).__name__})
        else:
            checks.append({"name": name, "status": "passed", "detail": "production_path_exercised"})
    body = {"schema": RUNNER_SCHEMA, "checks": checks}
    value = {**body, "runner_sha256": hashlib.sha256(canonical_json_bytes(body)).hexdigest()}
    destination = Path(output)
    temporary = destination.with_name(f".{destination.name}.tmp")
    temporary.write_bytes(canonical_json_bytes(value) + b"\n")
    os.replace(temporary, destination)
    return value


def validate_runner_result(raw: bytes) -> dict[str, Any]:
    try:
        value = json.loads(raw)
    except (UnicodeError, ValueError, json.JSONDecodeError) as exc:
        raise ContractError("sealed preflight runner result is unreadable") from exc
    if raw != canonical_json_bytes(value) + b"\n" or not isinstance(value, dict):
        raise ContractError("sealed preflight runner result is not canonical")
    if set(value) != {"schema", "checks", "runner_sha256"} or value["schema"] != RUNNER_SCHEMA:
        raise ContractError("sealed preflight runner result fields mismatch")
    body = {"schema": value["schema"], "checks": value["checks"]}
    if value["runner_sha256"] != hashlib.sha256(canonical_json_bytes(body)).hexdigest():
        raise ContractError("sealed preflight runner result hash mismatch")
    checks = value["checks"]
    if not isinstance(checks, list) or len(checks) != len(_ALL_CHECKS):
        raise ContractError("sealed preflight runner result is incomplete")
    observed, failed = [], []
    for check in checks:
        if not isinstance(check, dict) or set(check) != {"name", "status", "detail"}:
            raise ContractError("sealed preflight check fields mismatch")
        observed.append(check["name"])
        if check["status"] != "passed" or check["detail"] != "production_path_exercised":
            failed.append(f"{check['name']}:{check['detail']}")
    if tuple(observed) != _ALL_CHECKS:
        raise ContractError("sealed preflight check set mismatch")
    if failed:
        # Name every failure: an attempt must not hide the checks after the first.
        raise ContractError("sealed preflight check failed: " + ",".join(failed))
    return value


def _new_preflight_output(target: Path, output: str | Path) -> Path:
    destination = Path(output).absolute()
    if destination.exists() or destination.is_symlink():
        raise ContractError("preflight output already exists")
    destination = destination.parent.resolve(strict=True) / destination.name
    if destination == target or destination.is_relative_to(target):
        raise ContractError("preflight output must be outside the target")
    return destination


def _write_canonical(path: Path, value: dict[str, Any]) -> None:
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    try:
        with temporary.open("xb") as stream:
            stream.write(canonical_json_bytes(value) + b"\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _scan_secrets(markers: tuple[bytes, ...], *values: bytes) -> str:
    for raw in values:
        if any(marker and marker in raw for marker in markers):
            raise ContractError("provider credential detected in preflight output")
    return hashlib.sha256(b"\0".join(hashlib.sha256(raw).digest() for raw in values)).hexdigest()


def _probe_distinct_verifier(run: dict[str, Any]) -> str:
    from autofv import verifier
    import subprocess

    started = subprocess.run(("limactl", "start", verifier.VERIFIER_VM), capture_output=True)
    if started.returncode:
        raise worker_runtime.WorkerError("preflight verifier failed to start")
    machine_id = verifier._shell("cat", "/etc/machine-id").stdout.decode().strip()
    agent_identity = run.get("agent_worker_id")
    if (
        re.fullmatch(r"[0-9a-f]{32}", machine_id) is None
        or not isinstance(agent_identity, str)
        or re.fullmatch(r"lima:[^:]+:[0-9a-f]{32}", agent_identity) is None
        or machine_id == agent_identity.rsplit(":", 1)[-1]
    ):
        raise worker_runtime.WorkerError("preflight verifier identity is not distinct")
    return f"lima:{verifier.VERIFIER_VM}:{machine_id}"


def configure_prepared_provider(
    run: dict[str, Any], repo: str | Path, *, env_file: str | Path
) -> dict[str, Any]:
    """Configure credentials before the worker freezes its outbound policy."""
    from autofv import agent_lane

    return provider_config.configure_provider(
        run,
        env_path=env_file,
        tool_schemas=list(agent_lane._TOOL_SCHEMAS),
        project_root=Path(repo),
    )


def run_preflight(
    repo: str | Path,
    run_config: str | Path,
    output: str | Path,
    *,
    env_file: str | Path | None = None,
    max_age_seconds: int = MAX_AGE_SECONDS,
    public_rust_root: str | Path | None = None,
    _prepared_run: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Run the fixed suite once in the sealed runsc worker and retain authorization."""
    from autofv import prepare_dalek, provider_service, worker
    from autofv.contracts import (
        load_toolchain_lock,
        validate_native_decide_policy,
        validate_run_config,
        validate_target,
    )

    target, manifest = validate_target(repo)
    prepare_dalek._scan_prepared(target)
    _, config = validate_run_config(run_config)
    if config["schema"] == "autofv-run/v2":
        if _prepared_run is None or not isinstance(_prepared_run.get("preparation_manifest"), dict):
            raise ContractError("FVS preflight requires a provenance-bound prepared run")
        from . import fvs_packet
        fvs_packet.bind_original(config["source_packet"], prepared_root=target,
            preparation=_prepared_run["preparation_manifest"],
            source_paths=[s["path"] for s in config["source_packet"]["sources"] if s["surface"] != "rust"],
            rust_root=Path(public_rust_root) if public_rust_root is not None else None)
        _prepared_run["role_profile"] = config["role_profile"]
        _prepared_run["source_packet_sha256"] = config["source_packet"]["packet_sha256"]
    lock = load_toolchain_lock()
    validate_native_decide_policy(lock)
    destination = _new_preflight_output(target, output)
    destination.mkdir(mode=0o700)
    (destination / "checks").mkdir(mode=0o700)
    run = _prepared_run
    retain_worker = run is not None
    succeeded = False
    try:
        if run is None:
            run = worker.prepare_run(target, manifest, lock)
        elif (
            run.get("lock") != lock
            or run.get("snapshot_sha256") != worker.hash_tree(target)
            or run.get("manifest_sha256")
            != hashlib.sha256(canonical_json_bytes(manifest)).hexdigest()
        ):
            raise ContractError("prepared preflight run identity mismatch")
        # Shared verifier VM: started or reused here, retained for its separate owner.
        run["preflight_verifier_worker_id"] = _probe_distinct_verifier(run)
        if provider_config.provider_binding(run) is None:
            configure_prepared_provider(run, target, env_file=env_file)
        markers = provider_config.secret_markers(run)

        def chmod_project(mode: str) -> None:
            worker_runtime._docker(
                "run",
                "--rm",
                "--pull",
                "never",
                "--runtime",
                lock["tools"]["runsc"]["runtime_name"],
                "--read-only",
                "--network",
                "none",
                "--user",
                "0:0",
                "--security-opt",
                "no-new-privileges",
                "--mount",
                f"type=volume,src={run['volume']},dst=/volume,volume-nocopy",
                lock["image"]["image_digest"],
                "chmod",
                "-R",
                mode,
                "/volume/work/project",
            )

        chmod_project("a-w")
        try:
            completed = worker_runtime._docker(
                *worker_runtime._runtime_argv(
                    lock,
                    run["volume"],
                    "python",
                    "-I",
                    "/volume/autofv-control/autofv/preflight_runner.py",
                    "--output",
                    "/volume/evidence/preflight-checks.json",
                    network="none",
                ),
                check=False,
            )
            _scan_secrets(markers, completed.stdout, completed.stderr)
            collected = worker_runtime._docker(
                *worker_runtime._runtime_argv(
                    lock,
                    run["volume"],
                    "cat",
                    "/volume/evidence/preflight-checks.json",
                    network="none",
                ),
                check=False,
            )
            _scan_secrets(markers, collected.stdout, collected.stderr)
        finally:
            # Lanes add git worktrees and commits under the project after preflight.
            chmod_project("u+w")
        if collected.returncode:
            raise ContractError("sealed preflight result collection failed")
        validate_runner_result(collected.stdout)
        if completed.returncode:
            raise ContractError("sealed preflight runner failed")
        binding = provider_config.provider_binding(run)
        if binding is None:
            raise ContractError("provider binding is unavailable")
        identities = preflight._current_provider_identities(run, binding.public)
        source_head = run["base_commit"]
        groups: dict[str, dict[str, Path]] = {"case": {}, "gate": {}}
        for prefix, names in (
            ("case", preflight_evidence.DETERMINISTIC_PREFLIGHT_CASES),
            ("gate", preflight_evidence.DETERMINISTIC_PREFLIGHT_GATES),
        ):
            for index, name in enumerate(names):
                path = destination / "checks" / f"{prefix}-{index:02d}-{name}.json"
                preflight_evidence.write_check_outcome(
                    path,
                    check_name=name,
                    check_id=f"autofv.preflight_runner::{prefix}_{name}",
                    status="passed",
                    origin="trusted_runner",
                    execution_class="sealed_runtime",
                    applicability="applicable_sealed_runtime",
                    identities=identities,
                    source_head=source_head,
                )
                groups[prefix][name] = path
        completed_at = int(time.time())
        suite_path = destination / "retained-suite.json"
        suite = preflight_evidence.write_retained_suite_result(
            suite_path,
            case_outcomes=groups["case"],
            gate_outcomes=groups["gate"],
            identities=identities,
            source_head=source_head,
            completed_at_unix=completed_at,
        )
        suite_sha = hashlib.sha256(suite_path.read_bytes()).hexdigest()

        def evidence(prefix: str, name: str) -> dict[str, str]:
            path = groups[prefix][name]
            return preflight_evidence.named_check_evidence(
                f"autofv.preflight_runner::{prefix}_{name}",
                path.read_bytes(),
                suite_sha256=suite_sha,
                evidence_kind="sealed_runtime",
                applicability="applicable_sealed_runtime",
            )

        retained = [path.read_bytes() for paths in groups.values() for path in paths.values()]
        zero_secret_scan_sha256 = _scan_secrets(
            markers, completed.stdout, completed.stderr, collected.stdout, *retained
        )
        preflight_path = destination / "deterministic-preflight.json"
        record = preflight.write_deterministic_preflight(
            preflight_path,
            suite_sha256=suite_sha,
            case_evidence={name: evidence("case", name) for name in groups["case"]},
            gate_evidence={name: evidence("gate", name) for name in groups["gate"]},
            identities=identities,
            zero_secret_scan_sha256=zero_secret_scan_sha256,
            source_head=source_head,
            completed_at_unix=completed_at,
        )
        authorization = provider_service.load_preflight_authorization(
            run,
            preflight_path=preflight_path,
            suite_artifact_path=suite_path,
            max_age_seconds=max_age_seconds,
        )
        authorization_path = destination / "provider-authorization.json"
        _write_canonical(authorization_path, authorization)
        authorization_raw = authorization_path.read_bytes()
        all_retained = [
            *retained,
            suite_path.read_bytes(),
            preflight_path.read_bytes(),
            authorization_raw,
        ]
        _scan_secrets(markers, *all_retained)
        result_path = destination / "preflight-result.json"
        result = {
            "schema": RESULT_SCHEMA,
            "status": "passed",
            "artifacts": {
                "suite": str(suite_path.resolve(strict=True)),
                "preflight": str(preflight_path.resolve(strict=True)),
                "authorization": str(authorization_path.resolve(strict=True)),
            },
            "hashes": {
                "suite_sha256": suite_sha,
                "preflight_sha256": record["preflight_sha256"],
                "authorization_sha256": hashlib.sha256(authorization_raw).hexdigest(),
            },
            "identities": identities,
            "source_head": source_head,
            "completed_at_unix": suite["completed_at_unix"],
            "provider_authentication": binding.public["receipt_authentication"],
        }
        _write_canonical(result_path, result)
        _scan_secrets(markers, result_path.read_bytes())
        validate_preflight_bundle(
            result_path,
            expected_source_head=source_head,
            max_age_seconds=max_age_seconds,
        )
        succeeded = True
        return result
    finally:
        cleanup_error = None
        if run is not None and not retain_worker:
            try:
                worker.force_destroy_worker(run)
                run["worker_disposed"] = True
            except BaseException as exc:
                cleanup_error = exc
        if run is not None and (not succeeded or not retain_worker):
            try:
                # Abort erases the binding key the listener registry is indexed by.
                provider_service.release(run)
            except BaseException as exc:
                cleanup_error = cleanup_error or exc
            finally:
                provider_config.abort_configuration(run)
        if not succeeded:
            import shutil
            shutil.rmtree(destination, ignore_errors=True)
        if cleanup_error is not None:
            if succeeded:
                import shutil
                shutil.rmtree(destination, ignore_errors=True)
            raise worker_runtime.WorkerError("preflight worker cleanup failed") from cleanup_error


@contextmanager
def _preflight_deadline(state):
    """Stop active preflight work; retain the existing finalization reserve for cleanup.

    The handler never touches run state. Expiry inside a serialized state commit (charge,
    reservation, wall reduction) is redelivered just after it; transport runs unlocked.
    """
    from .run_state import BudgetExhausted, _charge_wall, _state_lock
    if threading.current_thread() is not threading.main_thread() or signal.getitimer(signal.ITIMER_REAL)[0]:
        raise ContractError("FVS preflight requires a main thread without an active alarm")
    used = _charge_wall(state)
    limit = Decimal(state["config"]["max_wall_seconds"])
    active = limit - used - state["finalization_reserve_seconds"]
    if active <= 0:
        raise ContractError("FVS preflight active-work deadline must be positive")
    previous = signal.getsignal(signal.SIGALRM)
    lock = _state_lock(state)

    def expired(_signum, _frame):
        if lock.held():
            signal.setitimer(signal.ITIMER_REAL, 0.05)
            return
        raise BudgetExhausted("wall_seconds", limit, used + active)

    try:
        signal.signal(signal.SIGALRM, expired)
        signal.setitimer(signal.ITIMER_REAL, float(active))
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)


def _error_detail(exc: BaseException, markers: tuple[bytes, ...]) -> str:
    """Bounded cause chain; scanned in full before truncation, dropped on a credential match."""
    parts, visible_parts, seen = [], [], set()
    visible = True
    while exc is not None and id(exc) not in seen and len(parts) < 4:
        seen.add(id(exc))
        detail = f"{type(exc).__name__}: {exc}"
        parts.append(detail)
        if visible:
            visible_parts.append(detail)
        if exc.__cause__ is None and exc.__suppress_context__:
            visible = False
        exc = exc.__cause__ or exc.__context__
    try:
        _scan_secrets(markers, " <- ".join(parts).encode("utf-8", "replace"))
    except ContractError:
        return "redacted: provider credential marker matched"
    return " <- ".join(visible_parts)[:2000]


def _public_pair_inventory(state, destination):
    """Fresh keyless GETs; advertised support is not authenticated accessibility."""
    import urllib.request
    from . import fvs_profile, model, provider_messages, provider_transport
    root = destination / "public-metadata"
    root.mkdir(mode=0o700)

    def fetch(suffix, name, maximum):
        request = urllib.request.Request("https://openrouter.ai/api/v1/models" + suffix,
            headers={"Accept": "application/json", "User-Agent": "AutoFV-public-metadata-check"})
        timeout = min(20, model._provider_timeout_seconds(state))
        deadline = time.monotonic_ns() + int(timeout * 1_000_000_000)
        # Same proxy-free, redirect-free, absolute-deadline opener as paid requests.
        with provider_transport._open_upstream(request, timeout=timeout,
                                               deadline_monotonic_ns=deadline) as reply:
            if reply.status != 200:
                raise ContractError("FVS public metadata did not return HTTP 200")
            raw = provider_transport._read_upstream(reply, deadline, maximum)
        value = provider_messages.strict_json(raw, "FVS public metadata", allow_floats=True)
        with (root / name).open("xb") as output:
            output.write(raw)
        return value, hashlib.sha256(raw).hexdigest()

    catalog, catalog_sha = fetch("", "models.json", 8 * 1024 * 1024)
    records = {}
    for model_id in (fvs_profile.AUTHOR, fvs_profile.REVIEWER):
        matches = [m for m in catalog["data"] if m["id"] == model_id]
        if len(matches) != 1:
            raise ContractError("FVS exact model missing/duplicated in public catalog")
        advertised = matches[0]
        parameters, efforts = advertised["supported_parameters"], advertised["reasoning"]["supported_efforts"]
        if (not isinstance(parameters, list) or any(not isinstance(x, str) for x in parameters)
            or not isinstance(efforts, list) or any(not isinstance(x, str) for x in efforts)
            or not {"reasoning", "tools", "tool_choice"} <= set(parameters) or "xhigh" not in efforts):
            raise ContractError("FVS model lacks advertised parameters/xhigh")
        endpoint, endpoint_sha = fetch("/" + model_id + "/endpoints",
            hashlib.sha256(model_id.encode()).hexdigest()[:16] + ".json", 4 * 1024 * 1024)
        records[model_id] = {"endpoint_inventory": fvs_profile.public_endpoint_inventory(model_id, endpoint),
            "supported_parameters": advertised["supported_parameters"],
            "supported_efforts": advertised["reasoning"]["supported_efforts"],
            "catalog_sha256": catalog_sha, "endpoint_catalog_sha256": endpoint_sha}
    record = {"schema": "local-fvs-public-inventory/v1", "models": records,
              "profile_sha256": fvs_profile.digest(fvs_profile.profile()),
              "fetched_at_unix": int(time.time()), "authenticated": False, "inference": False}
    _write_canonical(root / "inventory.json", record)
    return record


def run_fvs_preflight(
    repo: str | Path, run_config: str | Path, output: str | Path, *,
    env_file: str | Path, preparation_manifest: str | Path,
    probe_rust_evidence: str | Path, probe_aeneas_evidence: str | Path,
    dependency_cache: str | Path, public_rust_root: str | Path,
    check_model_accessibility: bool = False,
) -> dict[str, Any]:
    """One owned prepared-worker preflight, optionally two bounded accessibility calls.

    Never allocates a scored experiment, selects a model pair or executes returned tools.
    Cleanup uses the existing bounded worker operations; deadline overrun is not success.
    """
    from . import experiment, fvs_packet, fvs_profile, model, prepare_dalek, provider_service, worker
    from .run_state import (_charge_wall, _check_budget, _checkpoint_value,
                           _external_call, _finalization_reserve)
    from .contracts import validate_native_decide_policy, validate_run_config, validate_target

    target, manifest = validate_target(repo)
    prepare_dalek._scan_prepared(target)
    _, config = validate_run_config(run_config)
    if not fvs_profile.enabled(config):
        raise ContractError("prepared FVS preflight requires run/v2")
    if type(check_model_accessibility) is not bool or any(value is None for value in
        (env_file, preparation_manifest, probe_rust_evidence, probe_aeneas_evidence,
         dependency_cache, public_rust_root)):
        raise ContractError("FVS preflight requires complete explicit preparation/provider inputs")
    lock = load_toolchain_lock()
    validate_native_decide_policy(lock)
    destination = _new_preflight_output(target, output)
    state = {"run": {"events": []}, "config": config, "run_round": model.agentproc.run_round,
             "cost": Decimal("0.000000"), "receipts": [], "model_exchanges": {},
             "pending_model_exchanges": {}, "receipt_rejections": [],
             "wall_seconds_used": Decimal("0.000000"), "wall_started_epoch_ns": time.time_ns(),
             "wall_started_monotonic_ns": time.monotonic_ns(),
             "finalization_reserve_seconds": _finalization_reserve(config)}
    run, binding, markers, created, owned = None, None, (), False, False
    calls, reservations, service_digest, release_failed = [], {}, None, False
    journal, journal_failures, failure_metadata, failure_metadata_failures = {}, {}, {}, {}
    phase, error_type, error_detail, cleanup = "prepared_inputs", None, None, "not_created"
    result = {"schema": "autofv-prepared-preflight/v1", "status": "failed", "execution_mode": "full",
              "model_accessibility": "not_requested" if not check_model_accessibility else "failed",
              "provider_model_preflights": {}, "config_sha256": fvs_profile.digest(_checkpoint_value(config)),
              "role_profile_sha256": fvs_profile.digest(fvs_profile.profile()),
              "source_packet_sha256": config["source_packet"]["packet_sha256"],
              "billing": "bounded_reported_cost", "selection_authorized": False,
              "formal_verification_or_review_claim": False}
    try:
        with _preflight_deadline(state):
            prepared, graph, receipt, sources = experiment._load_prepared_inputs(target, manifest,
                preparation_manifest, probe_rust_evidence, probe_aeneas_evidence, dependency_cache,
                execution_mode="full")
            fvs_packet.bind_original(config["source_packet"], prepared_root=target, preparation=prepared,
                source_paths=list(graph["source_paths"].values()), rust_root=Path(public_rust_root))
            _check_budget(state)
            destination.mkdir(mode=0o700)
            owned = True

            def before_worker(preparing):
                nonlocal run, binding, markers, service_digest
                run = preparing
                run.update(role_profile=config["role_profile"],
                    source_packet_sha256=config["source_packet"]["packet_sha256"],
                    preparation_manifest=prepared, prepared_graph_receipt=receipt,
                    graph_sha256=graph["graph_sha256"])
                state["run"] = run
                configure_prepared_provider(run, target, env_file=env_file)
                binding = provider_config.provider_binding(run)
                markers = (*provider_config.secret_markers(run), bytes(binding.client_token))
                service_digest = run["provider_binding_sha256"]
                provider_service.start(run)

            phase = "prepare_worker"
            run = _external_call(state, phase, lambda: worker.prepare_run(target, manifest, lock,
                                                                        before_worker=before_worker))
            created = True
            state["run"] = run
            phase = "dependency_cache"
            run["dependency_cache_receipt"] = _external_call(state, phase, lambda: worker.seed_dependency_cache(
                run, sources["dependency-cache"], receipt["dependency_cache_sha256"]))
            _write_canonical(destination / "prepared-graph.json", receipt)
            phase = "sealed_suite"
            result["sealed_preflight"] = _external_call(state, phase, lambda: authorize_prepared_run(
                run, target, run_config, destination / "sealed", env_file=env_file,
                max_age_seconds=min(MAX_AGE_SECONDS, config["max_wall_seconds"]),
                public_rust_root=public_rust_root))
            # Authorization rereads the config file; a change is rejected, never re-frozen.
            if (fvs_profile.digest(_checkpoint_value(validate_run_config(run_config)[1])) != result["config_sha256"]
                or run.get("role_profile") != config["role_profile"]
                or run.get("source_packet_sha256") != config["source_packet"]["packet_sha256"]):
                raise ContractError("FVS preflight configuration changed during authorization")
            if check_model_accessibility:
                phase = "public_inventory"
                result["public_inventory"] = _external_call(state, phase,
                    lambda: _public_pair_inventory(state, destination))
                phase = "egress"
                _external_call(state, phase, lambda: worker.verify_egress(run))
                messages = [{"role": "system", "content": "This is an accessibility probe, not a proof or review. "
                    "Call submit_candidate with patch='', claimed_status='blocked', "
                    "and evidence=['accessibility probe only']. Do not claim approval."},
                    {"role": "user", "content": "Return that accessibility-probe submission now."}]
                inputs = [result["config_sha256"], fvs_profile.digest(prepared), graph["graph_sha256"]]
                calls = [(model._model_envelope(state, request_id="preflight-accessibility-" + role,
                    role=role, input_hashes=model._message_bound_hashes(inputs, messages), sequence=sequence),
                    messages, "explicit") for sequence, role in enumerate(("scout", "spec_reviewer"), 1)]
                phase = "pair_reservation"
                _check_budget(state)
                model._reserve_provider_calls(state, calls)
                reservations = {key: Decimal(value["reservation_usd"])
                                for key, value in state["pending_model_exchanges"].items()}
                for request, _messages, _kind in calls:
                    phase = "model_accessibility:" + request["role"]
                    response, _ = model._model_request(state, request_id=request["request_id"],
                        role=request["role"], input_hashes=inputs, messages=messages)
                    if (response["kind"] != "tool_call" or response["payload"]["name"] != "submit_candidate"
                        or response["payload"]["arguments"] != {"patch": "", "claimed_status": "blocked",
                                                                  "evidence": ["accessibility probe only"]}):
                        raise ContractError("FVS accessibility probe lacks the requested final submission")
                result["model_accessibility"] = "passed"
            _check_budget(state)
            result["status"] = "passed"
    except (Exception, KeyboardInterrupt) as exc:
        result["status"] = "failed"
        error_type = type(exc).__name__
        # Never finalize into an output directory this invocation did not create.
        if not owned:
            raise
        error_detail = _error_detail(exc, markers)
    finally:
        if run is not None:
            if (created or run.get("worker_created")) and not run.get("worker_disposed"):
                try:
                    worker.force_destroy_worker(run)
                    cleanup = "disposed"
                except BaseException:
                    cleanup = "failed"
            elif run.get("worker_disposed"):
                cleanup = "disposed"
            if binding is not None:
                for request, _messages, _kind in calls:
                    key = request["request_id"]
                    try:
                        path = provider_service._journal_path(run, key)
                        record = provider_service._load(path, binding, request)
                        if record is not None:
                            journal[key] = record
                            if record["status"] == "completed" and key not in state["model_exchanges"]:
                                model._accept_model_exchange(state, request, record["response"], record["receipt"],
                                                             enforce_budget=False, allow_out_of_order=True)
                        elif (key in state["model_exchanges"] or state["pending_model_exchanges"].get(key, {}).get("dispatch_state")
                              in {"dispatched", "ambiguous"}):
                            journal_failures[key] = "missing_dispatched_journal"
                    except Exception:
                        journal_failures[key] = "invalid_signed_journal_or_exchange"
                        continue
                    diagnostic_path = path.with_suffix(".failure")
                    try:
                        if diagnostic_path.exists():
                            diagnostic = provider_service._load_failure_companion(diagnostic_path, binding, request)
                            if record is None or record["status"] != "dispatched" or diagnostic is None:
                                raise ContractError("failure metadata lacks an ambiguous dispatched journal")
                            failure_metadata[key] = diagnostic
                    except Exception:
                        failure_metadata_failures[key] = "invalid_failure_companion"
            try:
                provider_service.release(run)
            except BaseException:
                release_failed = True
        _charge_wall(state)
    service_release = ("failed" if release_failed or (service_digest is not None
                                                      and provider_service.is_running(service_digest))
                       else "not_started" if service_digest is None else "released")
    if (cleanup == "failed" or service_release == "failed"
        or state["wall_seconds_used"] > config["max_wall_seconds"]):
        result["status"] = "failed"
    result.update(phase=phase, error_type=error_type, error_detail=error_detail, cleanup=cleanup,
        service_release=service_release, reported_cost_usd=str(state["cost"]),
        wall_seconds_used=str(state["wall_seconds_used"]))
    if run is not None:
        # The worker run root keeps the signed journal/inventory; the verifier VM is not stopped.
        result.update(run_id=run.get("run_id"), retained_run_root=run.get("run_root"),
            verifier_worker_id=run.get("preflight_verifier_worker_id"),
            verifier_lifecycle="started_or_reused_and_retained"
                if run.get("preflight_verifier_worker_id") else "not_probed")
    pending = state["pending_model_exchanges"]
    # A signal may arrive after reservation commit but before its local summary is copied.
    reservations.update({key: Decimal(item["reservation_usd"]) for key, item in pending.items()})
    if journal_failures:
        result["status"] = "failed"
        result["journal_failures"] = journal_failures
    if failure_metadata_failures:
        result["status"] = "failed"
        result["failure_metadata_failures"] = failure_metadata_failures
    undispatched, liability = {}, {}
    for key, amount in reservations.items():
        record = journal.get(key)
        if key in state["model_exchanges"]:
            continue
        if (record is not None and record["status"] != "reserved"
            or pending.get(key, {}).get("dispatch_state") in {"dispatched", "ambiguous"}
            or key in journal_failures):
            liability[key] = max(amount, Decimal(record["reservation_usd"]) if record else amount)
        elif key in pending:
            undispatched[key] = amount
    result["undispatched_reservation_usd"] = str(sum(undispatched.values(), Decimal("0.000000")))
    result["unresolved_dispatched_liability_usd"] = str(sum(liability.values(), Decimal("0.000000")))
    result["unresolved_reservation_usd"] = str(sum([*undispatched.values(), *liability.values()], Decimal("0.000000")))
    result["reported_cost_usd"] = str(state["cost"])
    if state["cost"] > config["max_cost_usd"]:
        result["status"] = "failed"
    accounting = _checkpoint_value({"receipts": state["receipts"], "pending_model_exchanges": pending,
        "planned_reservations_usd": reservations, "receipt_rejections": state["receipt_rejections"],
        "provider_journal": journal, "journal_failures": journal_failures,
        "provider_failure_metadata": failure_metadata, "failure_metadata_failures": failure_metadata_failures})
    _scan_secrets(markers, canonical_json_bytes(accounting))
    _write_canonical(destination / "accounting.json", accounting)
    if run is not None:
        for model_id, record in dict(run.get("provider_model_preflights", {})).items():
            provider_receipts.validate_preflight_record(record)
            raw = canonical_json_bytes(record)
            _scan_secrets(markers, raw)
            path = destination / ("provider-model-preflight-" + hashlib.sha256(model_id.encode()).hexdigest()[:16] + ".json")
            _write_canonical(path, record)
            result["provider_model_preflights"][model_id] = {"path": str(path),
                "preflight_sha256": record["preflight_sha256"],
                "artifact_sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
    _scan_secrets(markers, canonical_json_bytes(result))
    _write_canonical(destination / "preflight-result.json", result)
    return result


def prepare_helper_handoff(state: dict[str, Any], bundle_path: Path) -> Path:
    """Check the pair on the owned helper worker; keep one clock and receipt ledger."""
    from . import fvs_profile, model, provider_service, worker, worker_proxy
    from .run_state import _check_budget, _checkpoint_value, _external_call

    run, config = state["run"], state["config"]
    if (not fvs_profile.enabled(config) or run.get("fresh_pair_preflight") is not True
        or run.get("execution_mode") != "proof_only"
        or config["max_cost_usd"] > Decimal("10.000000") or config["max_wall_seconds"] > MAX_HELPER_WALL_SECONDS
        or state["cost"] != 0 or state["receipts"] or state["model_exchanges"]
        or state["pending_model_exchanges"] or run.get("provider_model_preflights")
        or run.get("helper_handoff") is not None or run.get("worker_disposed")):
        raise ContractError("helper handoff requires a new prepared FVS run")
    bundle = validate_preflight_bundle(bundle_path, expected_source_head=run["base_commit"])
    binding = provider_config.provider_binding(run)
    if (binding is None or bundle["identities"]["provider_identity_sha256"] != binding.public["binding_sha256"]
        or bundle["provider_authentication"] != binding.public["receipt_authentication"]
        or binding.public["role_profile_sha256"] != fvs_profile.digest(fvs_profile.profile())
        or binding.public["source_packet_sha256"] != config["source_packet"]["packet_sha256"]):
        raise ContractError("helper handoff provider identity mismatch")
    destination = Path(run["evidence_dir"]) / "helper-handoff"
    destination.mkdir(mode=0o700, parents=True, exist_ok=False)
    with _preflight_deadline(state):
        inventory = _external_call(state, "handoff:inventory", lambda: _public_pair_inventory(state, destination))
        _external_call(state, "handoff:egress", lambda: worker.verify_egress(run))
        messages = [{"role": "system", "content": "This is an accessibility probe, not a proof or review. "
            "Call submit_candidate with patch='', claimed_status='blocked', "
            "and evidence=['accessibility probe only']. Do not claim approval."},
            {"role": "user", "content": "Return that accessibility-probe submission now."}]
        # Input hashes are covered by the provider receipt signature; unsigned
        # selection metadata alone must not permit cross-worker reuse.
        inputs = [HELPER_HANDOFF_INPUT_SHA256, fvs_profile.digest(_checkpoint_value(config)), run["graph_sha256"]]
        calls = [(model._model_envelope(state, request_id="preflight-accessibility-" + role,
            role=role, input_hashes=model._message_bound_hashes(inputs, messages), sequence=sequence),
            messages, "explicit") for sequence, role in enumerate(("scout", "spec_reviewer"), 1)]
        planned = sum((worker_proxy.provider_reservation_usd(run, request, messages)
                       for request, messages, _kind in calls), Decimal(0))
        if planned > Decimal("1.000000"):
            raise ContractError("helper accessibility reservation exceeds USD1 sub-limit")
        model._reserve_provider_calls(state, calls)
        for request, _messages, _kind in calls:
            response, _ = model._model_request(state, request_id=request["request_id"],
                role=request["role"], input_hashes=inputs, messages=messages)
            if (response["kind"] != "tool_call" or response["payload"]["name"] != "submit_candidate"
                or response["payload"]["arguments"] != {"patch": "", "claimed_status": "blocked",
                                                         "evidence": ["accessibility probe only"]}):
                raise ContractError("helper accessibility probe lacks the requested final submission")
        _check_budget(state)
        if (state["cost"] > Decimal("1.000000") or state["pending_model_exchanges"]
            or len(state["receipts"]) != 2 or state["receipt_rejections"]):
            raise ContractError("helper accessibility accounting is incomplete")
        evidence, model_paths = {}, {}
        for model_id in (fvs_profile.AUTHOR, fvs_profile.REVIEWER):
            path = Path(run["evidence_dir"]) / ("provider-model-preflight-" + hashlib.sha256(model_id.encode()).hexdigest()[:16] + ".json")
            record = provider_service.validate_pinned_preflight(path, run=run)
            item = inventory["models"][model_id]
            evidence[model_id] = {**{k: item[k] for k in ("endpoint_inventory", "supported_parameters",
                "supported_efforts", "catalog_sha256")}, "provider_preflight": record}
            model_paths[model_id] = {"path": str(path.resolve(strict=True)),
                "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
        ready = {"schema": "autofv-helper-handoff/v1", "status": "passed",
            "run_id": run["run_id"], "binding_sha256": binding.public["binding_sha256"],
            "bundle_path": str(bundle_path.resolve(strict=True)),
            "bundle_sha256": hashlib.sha256(bundle_path.read_bytes()).hexdigest(),
            "model_records": model_paths, "cleanup": "retained_for_immediate_helper",
            "service_release": "retained_for_immediate_helper",
            "accessibility_cost_usd": str(state["cost"]), "planned_upper_usd": str(planned),
            "budget_policy": "accessibility_included_in_shared_run_clock_and_receipts",
            "selection_authorizes_spend": False}
        ready_path = destination / "ready.json"
        _write_canonical(ready_path, ready)
        run["helper_handoff"] = {"path": str(ready_path.resolve(strict=True)),
            "sha256": hashlib.sha256(ready_path.read_bytes()).hexdigest()}
        validate_helper_handoff(run)
        fields = {"model_id", "endpoint", "endpoint_sha256", "parameters", "pricing", "pricing_sha256",
            "tool_schema_sha256", "capability_sha256", "fixed_proxy_sha256", "proxy_id", "route_id",
            "role_profile", "role_profile_sha256", "source_packet_sha256"}
        selection = {"schema": "autofv-retained-model-selection/v2", "status": "selected",
            "selected_at": int(time.time()), "selected_by": "trusted_same_worker_handoff", "decision": "select-model",
            "scope": {"proof_smoke": True, "full_retained_run": True, "provider_request_authorized": False,
                "spend_authorized": False, "push_authorized": False, "dynamic_routing_allowed": False,
                "model_substitution_allowed": False},
            "model": {k: binding.public[k] for k in fields}, "accessibility_evidence": evidence,
            "constraints": {"execution_mode": "proof_only", "freshness_seconds": MAX_AGE_SECONDS},
            "verification": dict(run["helper_handoff"])}
        selection_path = destination / "selection.json"
        _write_canonical(selection_path, selection)
        # A distinct run authorization retains the existing helper wall policy. The
        # original signed 300-second bundle is never overwritten or extended.
        provider_service.load_preflight_authorization(run,
            preflight_path=bundle["artifacts"]["preflight"], suite_artifact_path=bundle["artifacts"]["suite"],
            max_age_seconds=config["max_wall_seconds"])
        return selection_path


def validate_helper_handoff(run: dict[str, Any]) -> dict[str, Any]:
    """Recheck current pair freshness at selection and immediately before first dispatch."""
    from . import fvs_profile, provider_service

    if run.get("fresh_pair_preflight") is not True or run.get("execution_mode") != "proof_only":
        raise ContractError("helper handoff requires its original helper invocation")
    ref = run["helper_handoff"]
    path = Path(ref["path"])
    ready = provider_receipts._read_canonical(path, "helper handoff")
    binding = provider_config.provider_binding(run)
    if (hashlib.sha256(path.read_bytes()).hexdigest() != ref["sha256"] or binding is None
        or ready["schema"] != "autofv-helper-handoff/v1" or ready["status"] != "passed"
        or ready["run_id"] != run["run_id"] or ready["binding_sha256"] != binding.public["binding_sha256"]
        or run.get("worker_disposed") or set(ready["model_records"]) != {fvs_profile.AUTHOR, fvs_profile.REVIEWER}):
        raise ContractError("helper handoff identity mismatch")
    bundle_path = Path(ready["bundle_path"])
    bundle = validate_preflight_bundle(bundle_path, expected_source_head=run["base_commit"])
    if (hashlib.sha256(bundle_path.read_bytes()).hexdigest() != ready["bundle_sha256"]
        or bundle["identities"]["provider_identity_sha256"] != binding.public["binding_sha256"]
        or bundle["provider_authentication"] != binding.public["receipt_authentication"]):
        raise ContractError("helper handoff bundle binding mismatch")
    for model_id, item in ready["model_records"].items():
        record_path = Path(item["path"])
        record = provider_service.validate_pinned_preflight(record_path, run=run)
        if (hashlib.sha256(record_path.read_bytes()).hexdigest() != item["sha256"]
            or record["request"]["model_id"] != model_id
            or HELPER_HANDOFF_INPUT_SHA256 not in record["request"]["input_hashes"]):
            raise ContractError("helper handoff model record mismatch")
    return ready


def authorize_prepared_run(
    run: dict[str, Any],
    repo: str | Path,
    run_config: str | Path,
    output: str | Path,
    *,
    env_file: str | Path,
    max_age_seconds: int,
    public_rust_root: str | Path | None = None,
) -> dict[str, Any]:
    """Authorize provider calls on an already allocated sealed worker."""
    return run_preflight(
        repo,
        run_config,
        output,
        env_file=env_file,
        max_age_seconds=max_age_seconds,
        public_rust_root=public_rust_root,
        _prepared_run=run,
    )


def validate_preflight_bundle(
    path: str | Path,
    *,
    expected_source_head: str | None = None,
    max_age_seconds: int = MAX_AGE_SECONDS,
) -> dict[str, Any]:
    """Reopen and cryptographically validate one pinned pre-provider bundle."""
    result_path, raw = preflight_evidence.read_artifact(path, "preflight result")
    try:
        result = json.loads(raw)
    except (UnicodeError, ValueError, json.JSONDecodeError) as exc:
        raise ContractError("preflight result is unreadable") from exc
    fields = {
        "schema", "status", "artifacts", "hashes", "identities", "source_head",
        "completed_at_unix", "provider_authentication",
    }
    if raw != canonical_json_bytes(result) + b"\n" or not isinstance(result, dict) or set(result) != fields:
        raise ContractError("preflight result fields mismatch")
    if result["schema"] != RESULT_SCHEMA or result["status"] != "passed":
        raise ContractError("preflight result is not green")
    identities = preflight_evidence.validated_identities(result["identities"], "preflight result")
    try:
        current_control = worker_runtime._control_manifest(load_toolchain_lock())[0][
            "bundle_sha256"
        ]
    except (KeyError, OSError, worker_runtime.WorkerError) as exc:
        raise ContractError("current control bundle identity is unavailable") from exc
    if identities["control_bundle_sha256"] != current_control:
        raise ContractError("preflight result control bundle identity mismatch")
    source_head = result["source_head"]
    if expected_source_head is not None and source_head != expected_source_head:
        raise ContractError("preflight result source identity mismatch")
    artifacts = result["artifacts"]
    expected_artifacts = {"suite", "preflight", "authorization"}
    if not isinstance(artifacts, dict) or set(artifacts) != expected_artifacts:
        raise ContractError("preflight result artifact paths mismatch")
    opened = {}
    for name, value in artifacts.items():
        artifact_path = Path(value)
        if not artifact_path.is_absolute() or artifact_path.parent != result_path.parent:
            raise ContractError("preflight result artifact path is not pinned")
        opened[name] = preflight_evidence.read_artifact(artifact_path, f"preflight {name}")
    suite, _, suite_raw = preflight_evidence.validate_retained_suite(
        opened["suite"][0], expected_identities=identities, expected_source_head=source_head
    )
    suite_sha = hashlib.sha256(suite_raw).hexdigest()
    record = preflight.require_deterministic_preflight(
        opened["preflight"][0],
        expected_identities=identities,
        expected_source_head=source_head,
        expected_suite_sha256=suite_sha,
        now_unix=int(time.time()),
        max_age_seconds=max_age_seconds,
        required_applicability="applicable_sealed_runtime",
        required_evidence_kind="sealed_runtime",
    )
    try:
        authorization = json.loads(opened["authorization"][1])
    except (UnicodeError, ValueError, json.JSONDecodeError) as exc:
        raise ContractError("provider authorization is unreadable") from exc
    if opened["authorization"][1] != canonical_json_bytes(authorization) + b"\n":
        raise ContractError("provider authorization is not canonical")
    body = {key: value for key, value in authorization.items() if key != "auth"}
    provider_receipts.verify_signature(
        body, authorization.get("auth"), result["provider_authentication"], "provider preflight authorization"
    )
    hashes = result["hashes"]
    actual_hashes = {
        "suite_sha256": suite_sha,
        "preflight_sha256": record["preflight_sha256"],
        "authorization_sha256": hashlib.sha256(opened["authorization"][1]).hexdigest(),
    }
    if hashes != actual_hashes:
        raise ContractError("preflight result artifact hash mismatch")
    if (
        authorization.get("binding_sha256") != identities["provider_identity_sha256"]
        or authorization.get("source_head") != source_head
        or authorization.get("preflight_sha256") != record["preflight_sha256"]
        or authorization.get("suite_sha256") != suite_sha
        or authorization.get("preflight_path") != str(opened["preflight"][0])
        or authorization.get("suite_artifact_path") != str(opened["suite"][0])
        or authorization.get("max_age_seconds") != max_age_seconds
        or result["completed_at_unix"] != suite["completed_at_unix"]
    ):
        raise ContractError("provider authorization binding mismatch")
    return result


def validate_reconstructed_provider_preflight(
    path: str | Path,
    *,
    bundle_path: str | Path,
    env_file: str | Path | None = None,
) -> dict[str, Any]:
    """Validate a post-call artifact against a freshly reconstructed binding."""
    from autofv import agent_lane, fvs_profile, provider_service
    from autofv.contracts import load_toolchain_lock

    bundle = validate_preflight_bundle(bundle_path)
    authorization_path = Path(bundle["artifacts"]["authorization"])
    authorization = json.loads(authorization_path.read_bytes())
    lock = load_toolchain_lock()
    run = {
        "run_id": authorization["run_id"],
        "lock": lock,
        "fixed_proxy_sha256": hashlib.sha256(
            canonical_json_bytes(lock["fixed_proxy"])
        ).hexdigest(),
    }
    try:
        recorded = provider_receipts.validate_preflight(path)["provider_binding"]
        if (recorded["binding_sha256"] != bundle["identities"]["provider_identity_sha256"]
            or recorded["run_id"] != run["run_id"]):
            raise ContractError("provider preflight binding does not match sealed bundle")
        if bundle["provider_authentication"] != recorded["receipt_authentication"]:
            raise ContractError("provider authorization signer does not match preflight binding")
        if recorded["schema"] == "autofv-provider-binding/v2":
            run.update(role_profile=fvs_profile.PROFILE_ID,
                       source_packet_sha256=recorded["source_packet_sha256"])
        public = provider_config.configure_provider(
            run,
            env_path=env_file,
            tool_schemas=list(agent_lane._TOOL_SCHEMAS),
        )
        if public["binding_sha256"] != bundle["identities"]["provider_identity_sha256"]:
            raise ContractError("reconstructed provider binding does not match preflight bundle")
        value = provider_service.validate_pinned_preflight(path, run=run)
        return {
            "schema": "autofv-pinned-provider-preflight-validation/v1",
            "status": "passed",
            "binding_sha256": public["binding_sha256"],
            "preflight_sha256": value["preflight_sha256"],
        }
    finally:
        provider_config.abort_configuration(run)


def main() -> None:
    parser = argparse.ArgumentParser(prog="preflight_runner")
    parser.add_argument("--output")
    parser.add_argument("--validate-provider")
    parser.add_argument("--bundle")
    parser.add_argument("--env-file")
    args = parser.parse_args()
    if args.validate_provider is not None:
        if args.output is not None or args.bundle is None:
            parser.error("provider validation requires --validate-provider and --bundle")
        result = validate_reconstructed_provider_preflight(
            args.validate_provider,
            bundle_path=args.bundle,
            env_file=args.env_file,
        )
        print(canonical_json_bytes(result).decode())
        return
    if args.output is None or args.bundle is not None or args.env_file is not None:
        parser.error("sealed runner requires --output")
    result = run_fixed_suite(args.output)
    if any(check["status"] != "passed" for check in result["checks"]):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
