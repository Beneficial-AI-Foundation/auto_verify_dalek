from __future__ import annotations

import hashlib
import io
import json
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from autofv import worker, worker_artifacts, worker_runtime


_LOCK = {
    "image": {"image_digest": "sha256:" + "1" * 64},
    "tools": {"runsc": {"runtime_name": "runsc-hardened"}},
}
_LANE_ID = "proof-left-001"
_ASSIGNED_PATH = "Proof/Left.lean"


def _git(root: Path, *argv: str, check: bool = True) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        ("git", *argv), cwd=root, check=check, capture_output=True
    )


def _candidate(head: str, patch: str) -> dict[str, object]:
    return {
        "request_id": "candidate-001",
        "assigned_path": _ASSIGNED_PATH,
        "payload": {
            "assigned_path": _ASSIGNED_PATH,
            "base_commit": head,
            "patch": patch,
            "patch_sha256": hashlib.sha256(patch.encode("utf-8")).hexdigest(),
        },
    }


def _lane(run_root: Path) -> dict[str, str]:
    lane_root = run_root / "lanes" / _LANE_ID
    return {
        "schema": "autofv-proof-lane/v1",
        "lane_id": _LANE_ID,
        "request_id": _LANE_ID,
        "node": "probe:Proof.left",
        "base_commit": "a" * 40,
        "assigned_path": _ASSIGNED_PATH,
        "worktree_path": str(lane_root / "work"),
        "cache_path": str(lane_root / "cache"),
        "result_path": str(lane_root / "result" / "candidate.json"),
    }


class CandidateRuntimeBoundaryTests(unittest.TestCase):
    def test_candidate_runtime_argv_mounts_only_private_worktree(self) -> None:
        argv = worker_runtime._candidate_runtime_argv(
            _LOCK, "run-volume", _LANE_ID, "lake", "build"
        )

        self.assertEqual(
            argv,
            (
                "run",
                "--rm",
                "-i",
                "--pull",
                "never",
                "--runtime",
                "runsc-hardened",
                "--read-only",
                "--network",
                "none",
                "--user",
                worker_runtime.AGENT_UID,
                "--workdir",
                "/candidate",
                "--security-opt",
                "no-new-privileges",
                "--cap-drop",
                "ALL",
                "--cgroupns",
                "private",
                "--pids-limit",
                "256",
                "--cpus",
                "2",
                "--memory",
                "2g",
                "--tmpfs",
                "/tmp:rw,noexec,nosuid,nodev,size=64m,mode=1777",
                "--tmpfs",
                "/home/autofv/.cache:rw,noexec,nosuid,nodev,size=64m,mode=1777",
                "--env",
                "CARGO_NET_OFFLINE=true",
                "--mount",
                (
                    "type=volume,src=run-volume,dst=/candidate,"
                    "volume-subpath=lanes/proof-left-001/work,volume-nocopy"
                ),
                "sha256:" + "1" * 64,
                "lake",
                "build",
            ),
        )
        mounts = [argv[index + 1] for index, item in enumerate(argv) if item == "--mount"]
        self.assertEqual(len(mounts), 1)
        self.assertNotIn("dst=/volume", mounts[0])
        self.assertNotIn("/volume/work/project", argv)
        self.assertNotIn("/volume/evidence", argv)

    def test_sealed_check_uses_nonfollowing_lane_guard_before_verify(self) -> None:
        run = {
            "execution_tier": "sealed_runsc",
            "lock": _LOCK,
            "volume": "run-volume",
        }
        lane = {
            "lane_id": _LANE_ID,
            "assigned_path": _ASSIGNED_PATH,
            "worktree_path": f"/volume/lanes/{_LANE_ID}/work",
        }
        completed = subprocess.CompletedProcess(
            args=(), returncode=0, stdout=b"checked\n", stderr=b""
        )

        with mock.patch.object(worker._runtime, "_docker", return_value=completed) as docker:
            diagnostic = worker.check_lane(run, lane, {"verify": ["lake", "build"]})

        self.assertTrue(diagnostic.startswith("sealed_runtime:exit=0:"))
        argv = docker.call_args.args
        self.assertIn("/candidate", argv)
        script = argv[argv.index("-c") + 1]
        self.assertIn("O_NOFOLLOW", script)
        self.assertIn("os.fchdir", script)
        self.assertLess(argv.index(script), argv.index(_ASSIGNED_PATH))
        self.assertEqual(argv[-2:], ("lake", "build"))

    def test_sealed_lane_guard_rejects_root_and_ancestor_symlinks(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp).resolve()
            real_parent = base / "real-parent"
            real_root = real_parent / "work"
            (real_root / "Proof").mkdir(parents=True)
            (real_root / _ASSIGNED_PATH).write_text("source\n", encoding="utf-8")
            root_link = base / "root-link"
            root_link.symlink_to(real_root, target_is_directory=True)
            parent_link = base / "parent-link"
            parent_link.symlink_to(real_parent, target_is_directory=True)

            for label, root in (
                ("root", root_link),
                ("ancestor", parent_link / "work"),
            ):
                argv = worker._sealed_lane_exec(
                    str(root), _ASSIGNED_PATH, sys.executable, "-c", "pass"
                )
                with self.subTest(symlink=label):
                    completed = subprocess.run(
                        (sys.executable, *argv[1:]), capture_output=True
                    )
                    self.assertNotEqual(completed.returncode, 0)

    def test_sealed_lane_guard_detaches_git_authority_before_command(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve() / "work"
            (root / "Proof").mkdir(parents=True)
            (root / _ASSIGNED_PATH).write_text("source\n", encoding="utf-8")
            (root / ".git").write_text(
                "gitdir: /volume/work/project/.git/worktrees/work\n",
                encoding="utf-8",
            )
            argv = worker._sealed_lane_exec(
                str(root),
                _ASSIGNED_PATH,
                sys.executable,
                "-c",
                (
                    "from pathlib import Path; "
                    "assert not Path('.git').exists(); "
                    "assert Path('Proof/Left.lean').read_text() == 'source\\n'"
                ),
                detach_git=True,
            )

            completed = subprocess.run(
                (sys.executable, *argv[1:]), capture_output=True
            )

            self.assertEqual(completed.returncode, 0, completed.stderr.decode())
            self.assertFalse((root / ".git").exists())

    def test_simulation_lane_rejects_symlinked_ancestor_for_read_edit_and_check(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            run_root = Path(tmp) / "run"
            lanes = run_root / "lanes"
            outside = Path(tmp) / "outside" / _LANE_ID
            work = outside / "work"
            (work / "Proof").mkdir(parents=True)
            (work / _ASSIGNED_PATH).write_text("source\n", encoding="utf-8")
            lanes.mkdir(parents=True)
            (lanes / _LANE_ID).symlink_to(outside, target_is_directory=True)
            lane = {
                "lane_id": _LANE_ID,
                "assigned_path": _ASSIGNED_PATH,
                "worktree_path": str(lanes / _LANE_ID / "work"),
            }
            run = {
                "execution_tier": "simulation",
                "run_root": str(run_root),
            }
            patch = (
                f"diff --git a/{_ASSIGNED_PATH} b/{_ASSIGNED_PATH}\n"
                f"--- a/{_ASSIGNED_PATH}\n"
                f"+++ b/{_ASSIGNED_PATH}\n"
                "@@ -1 +1 @@\n"
                "-source\n"
                "+changed\n"
            )
            operations = {
                "read": lambda: worker.read_lane_file(
                    run, lane, _ASSIGNED_PATH, [_ASSIGNED_PATH]
                ),
                "edit": lambda: worker.edit_lane_file(run, lane, patch),
                "check": lambda: worker.check_lane(
                    run, lane, {"verify": ["lake", "build"]}
                ),
            }

            for name, operation in operations.items():
                with self.subTest(operation=name), self.assertRaisesRegex(
                    worker.WorkerError, "symlink"
                ):
                    operation()


class SealedAcceptanceBoundaryTests(unittest.TestCase):
    def test_acceptance_verifies_private_snapshot_before_exact_canonical_import(
        self,
    ) -> None:
        patch = (
            f"diff --git a/{_ASSIGNED_PATH} b/{_ASSIGNED_PATH}\n"
            f"--- a/{_ASSIGNED_PATH}\n"
            f"+++ b/{_ASSIGNED_PATH}\n"
            "@@ -1 +1 @@\n"
            "-source\n"
            "+proved\n"
        )
        candidate = _candidate("a" * 40, patch)
        run = {
            "execution_tier": "sealed_runsc",
            "run_id": "run-acceptance",
            "volume": "run-volume",
            "base_commit": "a" * 40,
            "lock": _LOCK,
            "events": [],
        }
        events: list[tuple[str, tuple[str, ...]]] = []

        def git(_run, *argv, input_bytes=None):
            events.append(("git", argv))
            if argv[:3] == ("archive", "--format=tar", "HEAD"):
                return b"canonical-tree-archive"
            if argv == ("diff", "--cached", "--name-only", "-z"):
                return (_ASSIGNED_PATH + "\0").encode()
            if argv == ("write-tree",):
                return b"e" * 40 + b"\n"
            if argv == ("rev-parse", "HEAD"):
                return b"b" * 40 + b"\n"
            return b""

        def docker(*argv, input_bytes=None, check=True):
            events.append(("docker", argv))
            joined = " ".join(argv)
            if "autofv-candidate-source/v1" in joined:
                stdout = b"d" * 64 + b"\n"
            elif "AUTOFV_EXPECTED_TREE" in joined:
                stdout = b"e" * 40 + b"\n"
            else:
                stdout = b""
            return subprocess.CompletedProcess(argv, 0, stdout, b"")

        with mock.patch.object(worker._runtime, "_git", side_effect=git), mock.patch.object(
            worker._runtime, "_docker", side_effect=docker
        ):
            accepted = worker.accept_candidate(run, candidate, {"verify": ["lake", "build"]})

        verify_indexes = [
            index
            for index, (kind, argv) in enumerate(events)
            if kind == "docker" and argv[-2:] == ("lake", "build")
        ]
        import_indexes = [
            index
            for index, (kind, argv) in enumerate(events)
            if kind == "git" and argv[:2] == ("apply", "-")
        ]
        self.assertEqual(len(verify_indexes), 1)
        self.assertEqual(len(import_indexes), 1)
        self.assertLess(verify_indexes[0], import_indexes[0])
        verify_argv = events[verify_indexes[0]][1]
        mounts = [
            verify_argv[index + 1]
            for index, value in enumerate(verify_argv)
            if value == "--mount"
        ]
        self.assertEqual(len(mounts), 1)
        self.assertIn("dst=/candidate", mounts[0])
        self.assertIn("volume-subpath=lanes/accept-", mounts[0])
        self.assertNotIn("dst=/volume", mounts[0])
        self.assertFalse(
            any(
                kind == "docker"
                and argv[-2:] == ("lake", "build")
                and any("dst=/volume" in value for value in argv)
                for kind, argv in events
            )
        )
        self.assertIn(
            ("git", ("diff", "--cached", "--name-only", "-z")), events
        )
        self.assertIn(("git", ("write-tree",)), events)
        self.assertEqual(accepted["accepted_commit"], "b" * 40)


class ResumeVerificationBoundaryTests(unittest.TestCase):
    @staticmethod
    def _source_archive() -> bytes:
        stream = io.BytesIO()
        raw = b"theorem resumed : True := by trivial\n"
        with tarfile.open(fileobj=stream, mode="w") as archive:
            info = tarfile.TarInfo(_ASSIGNED_PATH)
            info.size = len(raw)
            info.mode = 0o644
            info.uid = info.gid = info.mtime = 0
            archive.addfile(info, io.BytesIO(raw))
        return stream.getvalue()

    def test_resume_build_mounts_only_isolated_source_snapshot(self) -> None:
        run = {
            "execution_tier": "sealed_runsc",
            "run_id": "resume-isolation",
            "volume": "run-volume",
            "lock": _LOCK,
        }
        source = self._source_archive()
        events: list[tuple[str, tuple[str, ...]]] = []

        def git(_run, *argv, input_bytes=None):
            events.append(("git", argv))
            if argv == ("status", "--porcelain"):
                return b""
            if argv == ("rev-parse", "HEAD"):
                return b"a" * 40 + b"\n"
            if argv == ("archive", "--format=tar", "HEAD"):
                return b"accepted-tree"
            raise AssertionError(argv)

        def docker(*argv, input_bytes=None, check=True):
            events.append(("docker", argv))
            joined = " ".join(argv)
            if "autofv-resume-source/v1" in joined:
                stdout = source
            elif "autofv-candidate-source/v1" in joined:
                stdout = b"d" * 64 + b"\n"
            else:
                stdout = b""
            return subprocess.CompletedProcess(argv, 0, stdout, b"")

        with mock.patch.object(
            worker_artifacts, "_owned_worker", return_value={"status": "Running"}
        ), mock.patch.object(worker_artifacts, "_git", side_effect=git), mock.patch.object(
            worker_artifacts, "_docker", side_effect=docker
        ), mock.patch.object(
            worker_runtime, "_docker", side_effect=docker
        ):
            observed = worker.inspect_resume_state(
                run, {"verify": ["lake", "build"]}
            )

        self.assertTrue(observed["valid"])
        builds = [
            argv
            for kind, argv in events
            if kind == "docker" and argv[-2:] == ("lake", "build")
        ]
        self.assertEqual(len(builds), 1)
        mounts = [
            builds[0][index + 1]
            for index, value in enumerate(builds[0])
            if value == "--mount"
        ]
        self.assertEqual(len(mounts), 1)
        self.assertIn("dst=/candidate", mounts[0])
        self.assertIn("volume-subpath=lanes/resume-", mounts[0])
        self.assertNotIn("dst=/volume", mounts[0])
        self.assertGreaterEqual(
            sum(
                "autofv-resume-source/v1" in " ".join(argv)
                for kind, argv in events
                if kind == "docker"
            ),
            2,
        )

    def test_resume_rejects_build_that_changes_isolated_source(self) -> None:
        run = {
            "execution_tier": "sealed_runsc",
            "run_id": "resume-source-mutation",
            "volume": "run-volume",
            "lock": _LOCK,
        }
        source = self._source_archive()
        digests = iter((b"d" * 64 + b"\n", b"e" * 64 + b"\n"))

        def git(_run, *argv, input_bytes=None):
            if argv == ("status", "--porcelain"):
                return b""
            if argv == ("rev-parse", "HEAD"):
                return b"a" * 40 + b"\n"
            if argv == ("archive", "--format=tar", "HEAD"):
                return b"accepted-tree"
            raise AssertionError(argv)

        def docker(*argv, input_bytes=None, check=True):
            joined = " ".join(argv)
            if "autofv-resume-source/v1" in joined:
                stdout = source
            elif "autofv-candidate-source/v1" in joined:
                stdout = next(digests)
            else:
                stdout = b""
            return subprocess.CompletedProcess(argv, 0, stdout, b"")

        with mock.patch.object(
            worker_artifacts, "_owned_worker", return_value={"status": "Running"}
        ), mock.patch.object(worker_artifacts, "_git", side_effect=git), mock.patch.object(
            worker_artifacts, "_docker", side_effect=docker
        ), mock.patch.object(
            worker_runtime, "_docker", side_effect=docker
        ):
            observed = worker.inspect_resume_state(
                run, {"verify": ["lake", "build"]}
            )

        self.assertFalse(observed["valid"])
        self.assertIn("modified", observed["reason"])


class RunRootBoundaryTests(unittest.TestCase):
    def test_prepare_run_canonicalizes_symlinked_mkdtemp_root_immediately(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp).resolve()
            real_parent = base / "real-parent"
            returned = real_parent / "run-root"
            returned.mkdir(parents=True)
            alias = base / "alias"
            alias.symlink_to(real_parent, target_is_directory=True)
            lock = {
                **_LOCK,
                "fixed_proxy": {"cost_classification": "fixture"},
                "native_decide_policy": {"selection": "deny"},
                "native_decide_policy_sha256": "2" * 64,
            }
            failure = worker.WorkerError("stop after root construction")

            with mock.patch.object(
                worker._runtime,
                "_seed_archive",
                return_value=(b"", {"bundle_sha256": "3" * 64}, "4" * 64),
            ), mock.patch.object(
                worker._runtime, "_new_run_id", return_value="run-root-test"
            ), mock.patch.object(
                worker.tempfile, "mkdtemp", return_value=str(alias / "run-root")
            ), mock.patch.object(
                worker._runtime, "_create_worker", side_effect=failure
            ), self.assertRaises(worker.WorkerError) as raised:
                worker.prepare_run(base, {}, lock)

            self.assertEqual(raised.exception.run["run_root"], str(returned))
            self.assertEqual(
                raised.exception.run["evidence_dir"], str(returned / "evidence")
            )

    def test_local_lane_trust_starts_below_canonicalized_temp_root(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp).resolve()
            real_parent = base / "real-parent"
            run_root = real_parent / "run-root"
            alias = base / "alias"
            run_root.mkdir(parents=True)
            alias.symlink_to(real_parent, target_is_directory=True)
            canonical_root = (alias / "run-root").resolve(strict=True)
            lane = _lane(canonical_root)
            source = Path(lane["worktree_path"]) / _ASSIGNED_PATH
            source.parent.mkdir(parents=True)
            source.write_text("source\n", encoding="utf-8")
            run = {
                "execution_tier": "simulation",
                "run_root": str(canonical_root),
            }

            self.assertEqual(
                worker.read_lane_file(run, lane, _ASSIGNED_PATH, [_ASSIGNED_PATH]),
                "source\n",
            )
            below_root = canonical_root / "lanes" / _LANE_ID
            shutil.rmtree(below_root)
            outside = canonical_root / "outside"
            (outside / "work" / "Proof").mkdir(parents=True)
            (outside / "work" / _ASSIGNED_PATH).write_text(
                "hostile\n", encoding="utf-8"
            )
            below_root.symlink_to(outside, target_is_directory=True)
            with self.assertRaisesRegex(worker.WorkerError, "symlink"):
                worker.read_lane_file(run, lane, _ASSIGNED_PATH, [_ASSIGNED_PATH])


class LaneSnapshotTests(unittest.TestCase):
    def _source_tree(self, lane: dict[str, str], *, assigned: str, sibling: str) -> None:
        root = Path(lane["worktree_path"])
        (root / "Proof").mkdir(parents=True, exist_ok=True)
        (root / _ASSIGNED_PATH).write_text(assigned, encoding="utf-8")
        (root / "Proof" / "Sibling.lean").write_text(sibling, encoding="utf-8")
        (root / ".lake").mkdir(exist_ok=True)
        (root / ".lake" / "cache").write_text("non-authority", encoding="utf-8")

    def test_authenticated_snapshot_restores_recreated_lane_source_exactly(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            run_root = Path(tmp).resolve()
            run = {
                "run_id": "run-snapshot",
                "run_root": str(run_root),
                "project_dir": str(run_root / "project"),
                "execution_tier": "simulation",
            }
            lane = _lane(run_root)
            self._source_tree(lane, assigned="edited\n", sibling="base sibling\n")
            receipt = worker.save_lane_snapshot(run, lane)
            shutil.rmtree(run_root / "lanes")

            def recreate(_run, lanes):
                self.assertEqual(lanes, [lane])
                self._source_tree(
                    lane, assigned="base\n", sibling="wrong sibling\n"
                )
                (Path(lane["worktree_path"]) / "Proof" / "extra.lean").write_text(
                    "extra\n", encoding="utf-8"
                )

            with mock.patch.object(worker, "prepare_lanes", side_effect=recreate) as prepare:
                restored = worker.restore_lane_snapshot(
                    run, lane, expected_receipt=receipt
                )

            prepare.assert_called_once()
            root = Path(lane["worktree_path"])
            self.assertEqual((root / _ASSIGNED_PATH).read_text(), "edited\n")
            self.assertEqual(
                (root / "Proof" / "Sibling.lean").read_text(), "base sibling\n"
            )
            self.assertFalse((root / "Proof" / "extra.lean").exists())
            self.assertEqual(restored["snapshot_sha256"], receipt["snapshot_sha256"])

    def test_missing_or_tampered_snapshot_fails_closed_with_live_lane(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            run_root = Path(tmp).resolve()
            run = {
                "run_id": "run-snapshot",
                "run_root": str(run_root),
                "project_dir": str(run_root / "project"),
                "execution_tier": "simulation",
            }
            lane = _lane(run_root)
            self._source_tree(lane, assigned="edited\n", sibling="sibling\n")
            worker.save_lane_snapshot(run, lane)
            record = run_root / "lane-snapshots" / f"{_LANE_ID}.json"
            retained = record.read_bytes()
            record.unlink()
            with self.assertRaisesRegex(worker.WorkerError, "snapshot.*missing"):
                worker.restore_lane_snapshot(run, lane)
            record.write_bytes(retained)
            value = json.loads(retained)
            value["body"]["base_commit"] = "b" * 40
            record.write_text(json.dumps(value), encoding="utf-8")
            with self.assertRaisesRegex(worker.WorkerError, "authentication"):
                worker.restore_lane_snapshot(run, lane)
            record.unlink()
            record.symlink_to(run_root / "lane-snapshots" / f"{_LANE_ID}.tar")
            with self.assertRaisesRegex(worker.WorkerError, "file is invalid"):
                worker.restore_lane_snapshot(run, lane)

    def test_authenticated_older_snapshot_cannot_replace_durable_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            run_root = Path(tmp).resolve()
            run = {
                "run_id": "run-snapshot",
                "run_root": str(run_root),
                "project_dir": str(run_root / "project"),
                "execution_tier": "simulation",
            }
            lane = _lane(run_root)
            self._source_tree(lane, assigned="first\n", sibling="sibling\n")
            first = worker.save_lane_snapshot(run, lane)
            directory = run_root / "lane-snapshots"
            old_record = (directory / f"{_LANE_ID}.json").read_bytes()
            old_archive = (directory / f"{_LANE_ID}.tar").read_bytes()
            (Path(lane["worktree_path"]) / _ASSIGNED_PATH).write_text(
                "second\n", encoding="utf-8"
            )
            current = worker.save_lane_snapshot(run, lane)
            self.assertGreater(current["sequence"], first["sequence"])
            (directory / f"{_LANE_ID}.json").write_bytes(old_record)
            (directory / f"{_LANE_ID}.tar").write_bytes(old_archive)

            with self.assertRaisesRegex(worker.WorkerError, "durable receipt"):
                worker.restore_lane_snapshot(
                    run, lane, expected_receipt=current
                )
            self.assertEqual(
                (Path(lane["worktree_path"]) / _ASSIGNED_PATH).read_text(),
                "second\n",
            )

    def test_snapshot_capture_ignores_read_only_atime_drift(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            run_root = Path(tmp).resolve()
            run = {
                "run_id": "run-atime",
                "run_root": str(run_root),
                "project_dir": str(run_root / "project"),
                "execution_tier": "simulation",
            }
            lane = _lane(run_root)
            self._source_tree(lane, assigned="edited\n", sibling="sibling\n")
            original_lstat = Path.lstat
            calls = 0

            class AtimeDrift:
                def __init__(self, value, atime_ns):
                    self._value = value
                    self.st_atime_ns = atime_ns

                def __getattr__(self, name):
                    return getattr(self._value, name)

                def __eq__(self, other):
                    return (
                        isinstance(other, AtimeDrift)
                        and self._value == other._value
                        and self.st_atime_ns == other.st_atime_ns
                    )

            def lstat_with_atime_drift(path: Path):
                nonlocal calls
                calls += 1
                value = original_lstat(path)
                return AtimeDrift(value, value.st_atime_ns + calls)

            with mock.patch.object(Path, "lstat", new=lstat_with_atime_drift):
                receipt = worker.save_lane_snapshot(run, lane)

            self.assertEqual(receipt["sequence"], 1)


class SimulationAcceptanceRollbackTests(unittest.TestCase):
    def _repository(self, root: Path, *, failing_hook: bool = False) -> str:
        (root / "Proof").mkdir(parents=True)
        (root / _ASSIGNED_PATH).write_text(
            "theorem Candidate : True := by\n  trivial\n", encoding="utf-8"
        )
        (root / "staged.txt").write_text("staged-base\n", encoding="utf-8")
        (root / "unstaged.txt").write_text("unstaged-base\n", encoding="utf-8")
        _git(root, "init", "-q")
        _git(root, "add", "--all")
        _git(
            root,
            "-c",
            "user.name=AutoFV",
            "-c",
            "user.email=autofv@invalid",
            "commit",
            "-q",
            "-m",
            "base",
        )
        (root / "staged.txt").write_text("staged-before\n", encoding="utf-8")
        _git(root, "add", "--", "staged.txt")
        (root / "unstaged.txt").write_text("unstaged-before\n", encoding="utf-8")
        if failing_hook:
            hook = root / ".git" / "hooks" / "pre-commit"
            hook.write_text("#!/bin/sh\nexit 1\n", encoding="utf-8")
            hook.chmod(stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)
        return _git(root, "rev-parse", "HEAD").stdout.decode().strip()

    def _snapshot(self, root: Path) -> dict[str, object]:
        return {
            "head": _git(root, "rev-parse", "HEAD").stdout,
            "status": _git(root, "status", "--porcelain=v2", "-z").stdout,
            "cached": _git(root, "diff", "--cached", "--binary").stdout,
            "worktree": _git(root, "diff", "--binary").stdout,
            "index": (root / ".git" / "index").read_bytes(),
            "files": {
                relative: (root / relative).read_bytes()
                for relative in (_ASSIGNED_PATH, "staged.txt", "unstaged.txt")
            },
        }

    def _assert_snapshot(self, root: Path, expected: dict[str, object]) -> None:
        self.assertEqual((root / ".git" / "index").read_bytes(), expected["index"])
        observed = self._snapshot(root)
        self.assertEqual(
            {key: value for key, value in observed.items() if key != "index"},
            {key: value for key, value in expected.items() if key != "index"},
        )

    def test_static_failure_restores_preexisting_index_and_worktree_exactly(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            head = self._repository(root)
            before = self._snapshot(root)
            patch = (
                f"diff --git a/{_ASSIGNED_PATH} b/{_ASSIGNED_PATH}\n"
                f"--- a/{_ASSIGNED_PATH}\n"
                f"+++ b/{_ASSIGNED_PATH}\n"
                "@@ -1,2 +1,2 @@\n"
                " theorem Candidate : True := by\n"
                "-  trivial\n"
                "+  trivial \n"
            )
            run = {
                "execution_tier": "simulation",
                "project_dir": str(root),
                "base_commit": head,
                "events": [],
            }

            with self.assertRaisesRegex(
                worker.WorkerError, "simulation static candidate check failed"
            ):
                worker.accept_candidate(run, _candidate(head, patch), {})

            self._assert_snapshot(root, before)

    def test_commit_failure_restores_preexisting_index_and_worktree_exactly(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            head = self._repository(root, failing_hook=True)
            before = self._snapshot(root)
            patch = (
                f"diff --git a/{_ASSIGNED_PATH} b/{_ASSIGNED_PATH}\n"
                f"--- a/{_ASSIGNED_PATH}\n"
                f"+++ b/{_ASSIGNED_PATH}\n"
                "@@ -1,2 +1,2 @@\n"
                " theorem Candidate : True := by\n"
                "-  trivial\n"
                "+  exact True.intro\n"
            )
            run = {
                "execution_tier": "simulation",
                "project_dir": str(root),
                "base_commit": head,
                "events": [],
            }

            with self.assertRaisesRegex(
                worker.WorkerError, "simulation candidate commit failed"
            ):
                worker.accept_candidate(run, _candidate(head, patch), {})

            self._assert_snapshot(root, before)

    def test_post_commit_evidence_failure_restores_head_index_and_worktree(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            head = self._repository(root)
            before = self._snapshot(root)
            patch = (
                f"diff --git a/{_ASSIGNED_PATH} b/{_ASSIGNED_PATH}\n"
                f"--- a/{_ASSIGNED_PATH}\n"
                f"+++ b/{_ASSIGNED_PATH}\n"
                "@@ -1,2 +1,2 @@\n"
                " theorem Candidate : True := by\n"
                "-  trivial\n"
                "+  exact True.intro\n"
            )
            run = {
                "execution_tier": "simulation",
                "project_dir": str(root),
                "base_commit": head,
                "events": [],
            }
            real_run = subprocess.run

            def fail_archive(argv, *args, **kwargs):
                if tuple(argv[:3]) == ("git", "archive", "--format=tar"):
                    raise subprocess.CalledProcessError(1, argv)
                return real_run(argv, *args, **kwargs)

            with mock.patch.object(
                worker.subprocess, "run", side_effect=fail_archive
            ), self.assertRaises(subprocess.CalledProcessError):
                worker.accept_candidate(run, _candidate(head, patch), {})

            self._assert_snapshot(root, before)


if __name__ == "__main__":
    unittest.main()
