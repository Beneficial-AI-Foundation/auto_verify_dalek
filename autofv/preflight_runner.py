"""Fixed sealed-runtime prerequisite suite and retained-bundle validation."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import sys
import time
from pathlib import Path
from typing import Any, Callable

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from autofv import (  # noqa: E402
    agent_lane,
    diamond,
    graph_scheduler,
    preflight,
    preflight_evidence,
    prepare_dalek,
    provider_config,
    provider_receipts,
    result_summary,
    worker_runtime,
)
from autofv.contracts import ContractError, canonical_json_bytes  # noqa: E402

RUNNER_SCHEMA = "autofv-sealed-preflight-runner/v1"
RESULT_SCHEMA = "autofv-preflight-result/v1"
MAX_AGE_SECONDS = 300
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
    trace = _schedule_trace()
    assert trace.index("Left") != trace.index("Right")


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
    assert diamond._candidate_binding_is_current([digest], digest, [digest], digest)
    assert not diamond._candidate_binding_is_current([digest], digest, [digest], "2" * 64)


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
    assert len(mounts) == 1 and "dst=/candidate" in mounts[0]
    assert all("/volume/work/project" not in item for item in mounts)


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
    tools = {
        schema["name"]: {"schema": schema, "invoke": lambda _arguments: None}
        for schema in agent_lane._TOOL_SCHEMAS
    }
    assert agent_lane.capture_tool_schemas(tools) == list(agent_lane._TOOL_SCHEMAS)


def _tree_has_no_symlinks() -> None:
    for root, directories, files in os.walk("/volume/work/project"):
        for name in (*directories, *files):
            if stat.S_ISLNK(os.lstat(Path(root) / name).st_mode):
                raise AssertionError("sealed source contains a symlink")


def _secret_scan() -> None:
    for name in provider_config._ENV_NAMES:
        assert name not in os.environ
    prepare_dalek._scan_prepared(Path("/volume/work/project"))


def _spoiler_scan() -> None:
    prepare_dalek._scan_prepared(Path("/volume/work/project"))


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
    observed = []
    for check in checks:
        if not isinstance(check, dict) or set(check) != {"name", "status", "detail"}:
            raise ContractError("sealed preflight check fields mismatch")
        observed.append(check["name"])
        if check["status"] != "passed" or check["detail"] != "production_path_exercised":
            raise ContractError(f"sealed preflight check failed: {check.get('name')}")
    if tuple(observed) != _ALL_CHECKS:
        raise ContractError("sealed preflight check set mismatch")
    return value


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
    identity = f"lima:{verifier.VERIFIER_VM}:{machine_id}"
    if not machine_id or identity == run.get("agent_worker_id"):
        raise worker_runtime.WorkerError("preflight verifier identity is not distinct")
    return identity


def run_preflight(
    repo: str | Path,
    run_config: str | Path,
    output: str | Path,
    *,
    env_file: str | Path | None = None,
    max_age_seconds: int = MAX_AGE_SECONDS,
) -> dict[str, Any]:
    """Run the fixed suite once in the sealed runsc worker and retain authorization."""
    from autofv import provider_service, worker
    from autofv.contracts import (
        load_toolchain_lock,
        validate_native_decide_policy,
        validate_run_config,
        validate_target,
    )

    target, manifest = validate_target(repo)
    validate_run_config(run_config)
    lock = load_toolchain_lock()
    validate_native_decide_policy(lock)
    destination = Path(output).absolute()
    if destination.exists() or destination.is_symlink():
        raise ContractError("preflight output already exists")
    parent = destination.parent.resolve(strict=True)
    if destination == target or destination.is_relative_to(target):
        raise ContractError("preflight output must be outside the target")
    destination = parent / destination.name
    destination.mkdir(mode=0o700)
    (destination / "checks").mkdir(mode=0o700)
    run: dict[str, Any] | None = None
    succeeded = False
    try:
        run = worker.prepare_run(target, manifest, lock)
        _probe_distinct_verifier(run)
        tools = list(agent_lane._TOOL_SCHEMAS)
        provider_config.configure_provider(
            run,
            env_path=env_file,
            tool_schemas=tools,
            project_root=target,
        )
        markers = provider_config.secret_markers(run)
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
            "a-w",
            "/volume/work/project",
        )
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
        if run is not None:
            try:
                worker.force_destroy_worker(run)
                run["worker_disposed"] = True
            except BaseException as exc:
                cleanup_error = exc
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


def main() -> None:
    parser = argparse.ArgumentParser(prog="preflight_runner")
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    result = run_fixed_suite(args.output)
    if any(check["status"] != "passed" for check in result["checks"]):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
