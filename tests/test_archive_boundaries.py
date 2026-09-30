"""Host checks for worker boundaries: archives, bounded commands and exports."""

import hashlib
import io
import json
import os
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from autofv import results, worker_artifacts, worker_runtime


def _tar(*members: tuple[str, bytes, bytes]) -> bytes:
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w") as archive:
        for name, kind, data in members:
            info = tarfile.TarInfo(name)
            info.type = kind
            if kind == tarfile.REGTYPE:
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))
            else:
                info.linkname = data.decode()
                archive.addfile(info)
    return raw.getvalue()


class SafeTarTests(unittest.TestCase):
    def test_plain_tree_is_accepted(self):
        worker_artifacts._safe_tar(
            _tar(("src", tarfile.DIRTYPE, b""), ("src/a.lean", tarfile.REGTYPE, b"x")), "tree"
        )

    def test_hostile_members_are_rejected(self):
        cases = {
            "hardlink": _tar(("a", tarfile.REGTYPE, b"x"), ("b", tarfile.LNKTYPE, b"a")),
            "symlink": _tar(("a", tarfile.SYMTYPE, b"/etc/passwd"),),
            "parent": _tar(("../a", tarfile.REGTYPE, b"x"),),
            "absolute": _tar(("/a", tarfile.REGTYPE, b"x"),),
            "duplicate": _tar(("a", tarfile.REGTYPE, b"x"), ("a", tarfile.REGTYPE, b"y")),
            "fifo": _tar(("a", tarfile.FIFOTYPE, b""),),
        }
        for name, raw in cases.items():
            with self.subTest(name), self.assertRaisesRegex(
                worker_artifacts.WorkerError, "tree contains an unsafe member"
            ):
                worker_artifacts._safe_tar(raw, "tree")

    def test_truncated_archive_and_forbidden_names_are_rejected(self):
        raw = _tar(("a", tarfile.REGTYPE, b"x" * 4096))
        with self.assertRaisesRegex(worker_artifacts.WorkerError, "not a valid archive"):
            worker_artifacts._safe_tar(raw[:700], "tree")
        with self.assertRaisesRegex(worker_artifacts.WorkerError, "forbidden material"):
            worker_artifacts._safe_tar(
                _tar(("x/diamond-reference/a", tarfile.REGTYPE, b"x")), "tree",
                forbidden=(b"diamond-reference",),
            )


class TrustedVolumeScanTests(unittest.TestCase):
    ROOTS = ("work", "accepted", "autofv-control", "logs", "evidence", "lanes")

    def scan(self, volume: Path) -> dict:
        program = worker_artifacts._VOLUME_SCAN_PROGRAM.replace('"/volume/', f'"{volume}/')
        worker_scan = json.loads(subprocess.run(
            (sys.executable, "-c", program), input=b'{"markers": []}',
            capture_output=True, check=True,
        ).stdout)
        for item in worker_scan["roots"]:
            item["root"] = item["root"].replace(str(volume), "/volume")
        raw = io.BytesIO()
        with tarfile.open(fileobj=raw, mode="w", format=tarfile.GNU_FORMAT) as archive:
            for root in self.ROOTS:
                archive.add(volume / root, arcname=root)
        completed = subprocess.CompletedProcess((), 0, raw.getvalue(), b"")
        with mock.patch.object(worker_artifacts, "_runtime_argv", return_value=()), \
                mock.patch.object(worker_artifacts, "_docker", return_value=completed):
            return worker_artifacts._trusted_worker_volume_scan(
                {"lock": {}, "volume": "run-volume"}, (), worker_scan
            )

    def test_prepared_dependency_links_match_the_in_vm_scan_and_others_fail(self):
        with tempfile.TemporaryDirectory() as tmp:
            volume = Path(tmp).resolve() / "volume"
            for root in self.ROOTS:
                (volume / root).mkdir(parents=True)
            project = volume / "work/project"
            lane = volume / "lanes/lane-1/work"
            for tree, target in ((project, "/volume/dependencies/packages"),
                                 (lane, "/dependencies/packages")):
                (tree / ".lake").mkdir(parents=True)
                (tree / "Main.lean").write_text("def x := 1\n")
                (tree / ".lake/packages").symlink_to(target)

            self.assertTrue(self.scan(volume)["clean"])

            (lane / "escape").symlink_to("/etc")
            with self.assertRaisesRegex(worker_artifacts.WorkerError, "unsafe member"):
                self.scan(volume)


class MaterializeAcceptedTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp()).resolve()
        self.addCleanup(subprocess.run, ("rm", "-rf", str(self.root)))
        source = self.root / "source"
        source.mkdir()
        env = {**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t",
               "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@t"}
        for command in (("init", "-q"), ("add", "."), ("commit", "-qm", "accepted")):
            if command[0] == "add":
                (source / "Proof.lean").write_text("theorem t : True := trivial\n")
            subprocess.run(("git", "-C", str(source), *command), check=True, env=env)
        self.commit = subprocess.run(
            ("git", "-C", str(source), "rev-parse", "HEAD"),
            check=True, capture_output=True, text=True,
        ).stdout.strip()
        self.run_root = self.root / "run"
        (self.run_root / "export/accepted").mkdir(parents=True)
        (self.run_root / "accepted").mkdir()
        (self.run_root / "accepted/input.txt").write_text("snapshot")
        subprocess.run(
            ("git", "-C", str(source), "bundle", "create", "-q",
             str(self.run_root / "export/accepted/repository.bundle"), "HEAD"),
            check=True,
        )

    def _run(self, commit):
        return {"run_root": str(self.run_root), "accepted": {"accepted_commit": commit}}

    def _leftovers(self):
        return sorted(path.name for path in self.run_root.iterdir() if path.name.endswith(".tmp"))

    def test_exact_commit_replaces_input_snapshot(self):
        results.materialize_accepted(self._run(self.commit))
        accepted = self.run_root / "accepted"
        self.assertTrue((accepted / "Proof.lean").is_file())
        self.assertFalse((accepted / "input.txt").exists())
        self.assertEqual(self._leftovers(), [])

    def test_wrong_commit_or_symlinked_bundle_keeps_input(self):
        with self.assertRaisesRegex(results.ResultError, "commit mismatch"):
            results.materialize_accepted(self._run("f" * 40))
        self.assertTrue((self.run_root / "accepted/input.txt").is_file())
        self.assertEqual(self._leftovers(), [])
        bundle = self.run_root / "export/accepted/repository.bundle"
        bundle.rename(self.root / "outside.bundle")
        bundle.symlink_to(self.root / "outside.bundle")
        with self.assertRaisesRegex(results.ResultError, "export is incomplete"):
            results.materialize_accepted(self._run(self.commit))
        self.assertTrue((self.run_root / "accepted/input.txt").is_file())


class WorkerCommandBoundTests(unittest.TestCase):
    def test_worker_commands_get_a_default_deadline_and_output_bound(self):
        seen = {}

        def bounded(argv, input_bytes, timeout, **options):
            seen.update(timeout=timeout, **options)
            return subprocess.CompletedProcess(argv, 0, b"ok", b"")

        with mock.patch.object(worker_runtime, "bounded_run", side_effect=bounded):
            self.assertEqual(worker_runtime._lima("true").stdout, b"ok")
        self.assertEqual(seen["timeout"], worker_runtime.COMMAND_TIMEOUT_SECONDS)
        self.assertIs(seen["error"], worker_runtime.WorkerError)

    def test_timed_out_worker_command_kills_its_process_group(self):
        with tempfile.TemporaryDirectory() as tmp:
            marker = Path(tmp) / "survived"
            with self.assertRaisesRegex(worker_runtime.WorkerError, "agent worker command timed out"):
                worker_runtime.bounded_run(
                    ("sh", "-c", f"(sleep 2; touch {marker}) & sleep 30"), None, 0.5,
                    error=worker_runtime.WorkerError, what="agent worker",
                    limit=worker_runtime.MAX_COMMAND_OUTPUT_BYTES,
                )
            subprocess.run(("sleep", "2.5"))
            self.assertFalse(marker.exists())

    def test_failed_container_run_is_removed_inside_the_vm(self):
        calls = []

        def lima(*argv, **_kwargs):
            calls.append(argv)
            if "run" in argv:
                raise worker_runtime.WorkerError("agent worker command timed out")
            return subprocess.CompletedProcess(argv, 0, b"", b"")

        with mock.patch.object(worker_runtime, "_lima", side_effect=lima):
            with self.assertRaisesRegex(worker_runtime.WorkerError, "timed out"):
                worker_runtime._docker("run", "--rm", "-i", "image", "lake", "build")
        name = calls[0][calls[0].index("--name") + 1]
        self.assertTrue(name.startswith("autofv-worker-cmd-"))
        self.assertEqual(calls[1], ("sudo", "docker", "rm", "-f", name))

    def test_cache_stream_is_bounded(self):
        with tempfile.NamedTemporaryFile() as source, mock.patch.object(
            worker_runtime, "bounded_run",
            return_value=subprocess.CompletedProcess((), 0, b"", b""),
        ) as bounded:
            worker_runtime._lima_stream_file(Path(source.name), "cat")
        self.assertEqual(bounded.call_args.args[2], worker_runtime.COMMAND_TIMEOUT_SECONDS)
        self.assertIsNotNone(bounded.call_args.kwargs["stdin"])


class ExportDiskTests(unittest.TestCase):
    def test_export_refuses_to_start_without_free_disk(self):
        with tempfile.TemporaryDirectory() as tmp:
            run = {"run_root": tmp}
            with mock.patch.object(
                worker_artifacts, "_export_artifacts", return_value={"accepted/tree.tar": b"x" * 10}
            ), mock.patch.object(
                worker_artifacts.shutil, "disk_usage", return_value=mock.Mock(free=5)
            ), mock.patch.object(worker_artifacts, "scan_retained_state") as scan:
                with self.assertRaisesRegex(worker_artifacts.WorkerError, "free disk"):
                    worker_artifacts.export_run(run)
            scan.assert_not_called()
            self.assertFalse((Path(tmp) / "export").exists())


class RestoreExportTests(unittest.TestCase):
    """A disposed run's volume must regain every mount its containers need."""

    def _restore(self, run, seeded=None):
        commands = []

        def docker(*argv, **_kwargs):
            commands.append(argv)
            return subprocess.CompletedProcess(argv, 1 if argv[:2] == ("volume", "inspect") else 0, b"", b"")

        def git(_run, *argv, **_kwargs):
            return {"rev-parse": b"c" * 40 + b"\n", "archive": b"tree"}.get(argv[0], b"")

        artifacts = {name: b"" for name in (
            "accepted/tree.tar", "accepted/repository.bundle",
            "working/changes.patch", "working/untracked.tar")}
        seams = {
            "_load_verified_export": mock.Mock(return_value=({"sequence": 1}, artifacts)),
            "_control_manifest": mock.Mock(return_value=({"bundle_sha256": "b"}, [])),
            "_owned_worker": mock.Mock(return_value=None),
            "_create_worker": mock.Mock(), "_destroy_worker": mock.Mock(),
            "inspect_worker": mock.Mock(return_value={"inventory_sha256": "i", "machine_id": "m"}),
            "claim_worker": mock.Mock(), "_atomic_write": mock.Mock(),
            "inspect_scored_container": mock.Mock(return_value={}),
            "seed_dependency_cache": mock.Mock(return_value=seeded),
            "_docker": docker, "_git": git,
        }
        with mock.patch.multiple(worker_artifacts, **seams):
            worker_artifacts._restore_export(run)
        return commands, seams["seed_dependency_cache"]

    def _run(self, **extra):
        return {"evidence_dir": tempfile.mkdtemp(), "lock": {}, "control_bundle_sha256": "b",
                "run_id": "r", "volume": "v", "image_digest": "sha256:" + "0" * 64,
                "accepted": {"accepted_commit": "c" * 40,
                             "accepted_tree_sha256": hashlib.sha256(b"tree").hexdigest()},
                "events": [], **extra}

    def test_restored_volume_recreates_the_dependencies_mount(self):
        commands, seed = self._restore(self._run())
        script = next(argv[-1] for argv in commands if argv[:1] == ("run",))
        self.assertIn("/volume/dependencies", script.split(" && ")[0])
        self.assertIn("/volume/dependencies", script.split(" && ")[-1])
        seed.assert_not_called()

    def test_prepared_run_reseeds_its_pinned_cache_or_fails_closed(self):
        receipt = {"schema": "autofv-dependency-cache-binding/v1", "sha256": "d" * 64}
        prepared = dict(
            dependency_cache_receipt=receipt,
            prepared_probe_sources={"dependency-cache": "/cache.tar.zst"},
            prepared_graph_receipt={"dependency_cache_sha256": "d" * 64},
        )
        _, seed = self._restore(self._run(**prepared), seeded=receipt)
        seed.assert_called_once_with(mock.ANY, "/cache.tar.zst", "d" * 64)
        with self.assertRaisesRegex(worker_artifacts.WorkerError, "dependency cache identity"):
            self._restore(self._run(**prepared), seeded={**receipt, "sha256": "e" * 64})


if __name__ == "__main__":
    unittest.main()
