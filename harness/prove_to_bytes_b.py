#!/usr/bin/env python3
"""Preview (default) or explicitly run the isolated to_bytes B experiment."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import time
import uuid

import prove_top_spec as harness
import fv_skills

ROOT = Path(harness.REPO)
TARGET = "curve25519_dalek.backend.serial.u64.field.FieldElement51.to_bytes_spec"
PATH = "Curve25519Dalek/Specs/Backend/Serial/U64/Field/FieldElement51/ToBytes.lean"
SKELETON = """import Curve25519Dalek.Funs
import Curve25519Dalek.Math.Basic
import Curve25519Dalek.Aux
import Curve25519Dalek.Specs.Backend.Serial.U64.Field.FieldElement51.Reduce
import Curve25519Dalek.Tactics

open Aeneas Aeneas.Std Result Aeneas.Std.WP

namespace curve25519_dalek.backend.serial.u64.field.FieldElement51

@[progress]
theorem to_bytes_spec (self : backend.serial.u64.field.FieldElement51) :
    to_bytes self ⦃ result =>
    U8x32_as_Nat result ≡ Field51_as_Nat self [MOD p] ∧
    U8x32_as_Nat result < p ⦄ := by
  sorry

end curve25519_dalek.backend.serial.u64.field.FieldElement51
"""



def start_attempt_branch():
    """Give each actual run a unique branch without committing existing work."""
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    branch = f"exp/to-bytes-{stamp}-{uuid.uuid4().hex[:8]}"
    subprocess.run(["git", "switch", "-c", branch], cwd=ROOT, check=True)
    print(f"Branch: {branch}", flush=True)
    return branch


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", action="store_true", help="invoke the model; default only prints the prompt")
    parser.add_argument("--prepare-only", action="store_true", help="prepare an isolated experiment and validate target selection without calling the model")
    parser.add_argument("--model")
    parser.add_argument("--interactive-prompt", action="store_true",
                        help="use the successful interactive debugging workflow adapted for the harness")
    parser.add_argument("--fv-skills", action="store_true",
                        help="use the pinned FVS headless lean-verify skill")
    parser.add_argument("--run-dir", help="new directory for this independent attempt")
    parser.add_argument("--timeout", type=int, default=3600)
    parser.add_argument("--quiet-turns", action="store_true",
                        help="hide live per-turn summaries; preserve full transcripts")
    parser.add_argument("--max-turns", type=int, default=300)
    parser.add_argument("--build-timeout", type=int, default=harness.driver.BUILD_TIMEOUT)
    args = parser.parse_args()
    if args.interactive_prompt:
        prompt_source = "experiments/to_bytes_b/interactive_harness_prompt.txt"
        harness.driver.PROMPT = (ROOT / prompt_source).read_text()
        harness.PROOF_SKETCH = ""
    else:
        prompt_source = "experiments/to_bytes_b/prompt.md"
        strategy = (ROOT / prompt_source).read_text()
        # Preserve the original B prompt, including its auxiliary-lemma rule.
        harness.PROOF_SKETCH = "\n" + strategy
        harness.driver.PROMPT = harness.driver.PROMPT.replace(
            "replace only its `sorry` with a proof.",
            "replace its `sorry` with a proof. You may add and prove auxiliary lemmas in this file.")
    line = SKELETON.splitlines().index("  sorry") + 1
    prompt = harness.driver.PROMPT.format(
        decl="to_bytes_spec", path=PATH, line=line,
        module=harness.driver.path_to_module(PATH)) + harness.PROOF_SKETCH
    skills_manifest = fv_skills.manifest() if args.fv_skills else None
    if args.fv_skills:
        prompt += fv_skills.prompt()
    if args.run and args.prepare_only:
        parser.error("choose either --run or --prepare-only")
    if not args.run and not args.prepare_only:
        print(SKELETON)
        print(prompt)
        return
    if not args.run_dir or (args.run and not args.model):
        parser.error("preparation requires --run-dir; --run also requires --model")
    if min(args.timeout, args.max_turns, args.build_timeout) <= 0:
        parser.error("timeout, build-timeout and max-turns must be positive")
    run_dir = Path(args.run_dir).resolve()
    source = (ROOT / harness.BUNDLE).resolve()
    if run_dir == source or source in run_dir.parents:
        parser.error("run-dir must be outside the source bundle")
    try:
        run_dir.mkdir(parents=True, exist_ok=False)
    except FileExistsError:
        parser.error("run-dir already exists; choose a new directory")
    bundle = run_dir / "bundle"
    bundle.mkdir()
    subprocess.run([
        "rsync", "-a", "--exclude=/.git", "--exclude=/.lake/packages",
        str(ROOT / harness.BUNDLE) + "/", str(bundle) + "/",
    ], check=True)
    (bundle / PATH).write_text(SKELETON)
    manifest_path = bundle / "bundle_manifest.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["kept_theorems"] = {PATH: [TARGET]}
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n")
    (run_dir / "prompt.txt").write_text(prompt)
    branch = start_attempt_branch() if args.run else None
    revision = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT,
                              check=True, capture_output=True, text=True).stdout.strip()
    hashes = {str(p.relative_to(bundle)): hashlib.sha256(p.read_bytes()).hexdigest()
              for p in sorted(bundle.rglob("*.lean")) if ".lake" not in p.relative_to(bundle).parts}
    (run_dir / "experiment.json").write_text(json.dumps({
        "variant": "B-interactive" if args.interactive_prompt else "B",
        "prompt_mode": "interactive" if args.interactive_prompt else "baseline",
        "prompt_source": prompt_source,
        "target": TARGET, "revision": revision, "branch": branch,
        "model": args.model, "rounds": 1, "timeout": args.timeout,
        "max_turns": args.max_turns, "source_sha256": hashes,
        "build_timeout": args.build_timeout,
        "quiet_turns": args.quiet_turns,
        "prompt_sha256": hashlib.sha256(prompt.encode()).hexdigest(),
        "fv_skills": skills_manifest,
    }, indent=2) + "\n")
    # Keep repeated attempts' transcripts separate: driver otherwise names
    # them by target and round, which collide across independent runs.
    harness.LEDGER = str(run_dir / "results.jsonl")
    harness.driver.TRANSCRIPTS = str(run_dir / "transcripts")
    Path(harness.driver.TRANSCRIPTS).mkdir()
    sys.argv = [__file__, "--bundle", str(bundle), "--target", TARGET,
                "--model", args.model or "", "--run-dir", str(run_dir / "run"),
                "--rounds", "1", "--timeout", str(args.timeout),
                "--max-turns", str(args.max_turns),
                "--build-timeout", str(args.build_timeout)]
    if args.quiet_turns:
        sys.argv.append("--quiet-turns")
    if args.prepare_only:
        sys.argv.append("--dry-run")
    if args.fv_skills:
        sys.argv.append("--fv-skills")
    start = time.monotonic()
    status = {"status": "prepared" if args.prepare_only else "finished", "exit_code": 0}
    try:
        harness.main()
    except SystemExit as exc:
        status.update(status="failed", exit_code=exc.code, error=str(exc))
        raise
    except BaseException as exc:
        status.update(status="interrupted" if isinstance(exc, KeyboardInterrupt) else "error",
                      exit_code=1, error=str(exc))
        raise
    finally:
        status["wall_seconds"] = round(time.monotonic() - start, 3)
        (run_dir / "status.json").write_text(json.dumps(status, indent=2) + "\n")


if __name__ == "__main__":
    main()
