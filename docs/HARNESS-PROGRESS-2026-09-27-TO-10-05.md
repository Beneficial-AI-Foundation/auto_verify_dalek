# Harness Improvements: September 27–October 5, 2026

During this period, I made the AI proof workflow easier to follow, check, and resume.

The **harness** is the program that manages an AI working on Lean proofs. It starts the AI, controls which files it can change, runs checks, saves progress, and verifies the final result.

This summary covers changes on the current branch through commit `4302a9a` on October 5.


## 2. Clearer proof instructions

**September 29–30 and October 2**

I updated the instructions to encourage the AI to:

- Compile after meaningful changes and use the errors to guide the next step.
- Simplify slow proof steps instead of just increasing resource limits.

The above two prompts and use Opus instead of Sonnet make AI can prove to_bytes.

- Search for existing lemmas before writing new ones.
- Split large proofs into smaller pieces that fit together.

I also added optional instructions based on interactive proof work and an optional formal-verification skill with reference material.

## 4. More reliable Lean checks

**October 1**

I added `lean_check` to manage compilation. It uses a fixed format to
 reports success, failure, or timeout; extracts useful errors; saves logs; and cleans up its build processes after a timeout or interruption.

## 5. Saved progress and code snapshots

**October 1**

The harness now saves progress notes: the current task, reported results, remaining goals, failed approaches, and next steps. These notes can be passed to a resumed or new session.

It also saves drafts and eligible snapshots of code that passed compilation. Later failures do not erase the last successful snapshot. Source and configuration changes invalidate outdated check results; loading notes does not overwrite current code.


## 6. An optional second opinion when stuck

**October 5**

I added an independent AI reviewer, repeated failures, timeouts, or an exhausted proof budget can trigger a review of the available evidence.

The reviewer can read code and logs and suggest a different specification. It cannot edit code or change acceptance rules. Its advice goes to the prover if rounds remain; otherwise, the report is saved for later.

**Benefit:** A stuck proof can get a fresh diagnosis without giving the reviewer control over the result.

## 7. Reminders after context compression

**October 5**

When a long conversation is compressed, the harness reminds the AI to reread the task, handoff notes, and checking instructions, then reconcile them with current code and logs.

## 8. Clearer target selection and documentation

I checked Lara's script. It seems to be incorrect.

I added a script to identify top-level functions from the Lean dependency graph and clarified how these differ from Rust public APIs. I also added diagrams and documentation for checks, recovery, and diagnosis.

**Benefit:** It is easier to explain which functions we are proving and how the workflow operates.