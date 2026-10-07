"""Serial, durable proof DAG scheduling with fresh Workers and bounded refinement.

Agent reports are proposals, never acceptance evidence. Lean and the existing
scope/statement gates decide acceptance. State and partials live in the run dir;
only a completely verified graph is published to the bundle.
"""
import copy
import hashlib
import json
import os
import re
import subprocess
from pathlib import Path

import agentproc
import driver

REPORT = '''
If a structural obstacle prevents this proof, end your final message with
END_REASON:LIMIT followed by exactly one JSON object on the last line:
{"blocker":{"kind":"needs_split","reason":"...","evidence":"..."}}
  when the proof needs auxiliary lemmas;
{"blocker":{"kind":"needs_stronger_spec","spec":"<internal function>","reason":"...","evidence":"..."}}
  when an already accepted internal specification (listed as available) is
  too weak for this proof: name the function, say exactly which equation or
  bound is missing, and quote the goal that needs it;
{"blocker":{"kind":"invalid_contract","reason":"...","evidence":"..."}}
  when the frozen target statement itself is false.
Ordinary Lean errors should be repaired, not reported as structural blockers.
Do not change existing theorem statements. Do not write a report file.
Without a blocker, do not end your message with a JSON object.
'''
REVISION = '''
A previous specification for this function was accepted and later turned out
to be too weak. It has been removed from the file; write a stronger one.
Request from `{requester}`: {reason}
Evidence: {evidence}
Previous statement(s):
{previous}
The new statement must still hold for the function and must provide what the
requester needs. Callers proved against the old statement are re-proved later.
'''
CONTEXT = '''
Context from earlier work on this target in this run. You are a fresh session;
the workspace contains only accepted, verified work.
{helpers}{history}'''
SORRY_NOTE = ('Your proof depends on declarations that themselves contain `sorry` and are '
              'not frozen Math-layer assumptions: {bad}. The sorry count alone does not '
              'show this. Replace those dependencies with proved lemmas (or prove them '
              'in the target file).')
KINDS = ('needs_split', 'invalid_contract', 'needs_stronger_spec')
NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_']*(?:\.[A-Za-z_][A-Za-z0-9_']*)*\Z")
GIT = ['git', '-c', 'user.name=harness', '-c', 'user.email=harness@localhost']


def fingerprints(modules, work, args):
    """Statement fingerprints of current sources. StmtCanon reads .olean files,
    and a rollback restores sources only, so rebuild first (cheap when fresh)."""
    rc, _, _, output = driver.build_sorry_counts(work, args.build_timeout, include_output=True)
    if rc != 0:
        raise RuntimeError('workspace does not build before fingerprinting: ' + output[-2000:])
    return driver.stmt_fingerprints(modules, work)


def short(fn):
    return fn.removeprefix('probe:').removeprefix('curve25519_dalek.')


def git(work, *argv):
    r = driver.sh(GIT + list(argv), work)
    if r.returncode != 0:
        raise RuntimeError(f"git {argv[0]} failed: {r.stderr[-800:]}")
    return r.stdout.strip()


def commit(work, path, msg):
    """Commit in the slot and return the new HEAD sha."""
    driver.slot_commit(work, path, msg)
    return git(work, 'rev-parse', 'HEAD')


def json_objects(text):
    """Every top-level JSON object in `text`, in order; surrounding prose,
    code fences and trailing lines are ignored."""
    decoder, found, pos = json.JSONDecoder(), [], 0
    while (start := text.find('{', pos)) != -1:
        try:
            value, end = decoder.raw_decode(text, start)
        except ValueError:
            pos = start + 1
            continue
        if isinstance(value, dict):
            found.append(value)
        pos = end
    return found


def object_result(result):
    """The last JSON object in an agent's final message (its report)."""
    objects = json_objects(result.get('result') or '')
    return objects[-1] if objects else {}


def blocker_result(result):
    value = object_result(result or {}).get('blocker')
    if not isinstance(value, dict) or value.get('kind') not in KINDS:
        return None
    keys = ('reason', 'evidence') + (('spec',) if value['kind'] == 'needs_stronger_spec' else ())
    if all(isinstance(value.get(k), str) and value[k].strip() for k in keys):
        return value
    return None


MATH_ASSUMPTIONS = Path(driver.REPO, 'harness', 'frozen', 'math_assumptions.json')


def math_assumptions():
    """Names of the frozen Math-layer sorries (plan.md §4): the only
    declarations through which an accepted proof may depend on sorryAx."""
    return frozenset(a['name'] for a in json.loads(MATH_ASSUMPTIONS.read_text())['assumptions'])


def disallowed_sorries(fp, allowed):
    """Closure members carrying a sorry that are not whitelisted Math
    assumptions. Fails closed: missing evidence counts as disallowed."""
    axioms = fp.get('axioms')
    if not isinstance(axioms, list):
        return ['<no axiom evidence>']
    if 'sorryAx' not in axioms:
        return []
    sources = fp.get('sorry_sources')
    if not isinstance(sources, list) or not sources:
        return ['<no sorry-source evidence>']
    return sorted(s['name'] for s in sources
                  if s['name'] not in allowed or not s['module'].startswith('Curve25519Dalek.Math'))


def is_clean(fp, allowed=frozenset()):
    return fp.get('kind') == 'theorem' and not disallowed_sorries(fp, allowed)


def clean_theorems(fps, names, allowed=frozenset()):
    return bool(names) and all(is_clean(fps.get(n, {}), allowed) for n in names)


def validate_graph(nodes):
    pending, visited = set(nodes), set()
    while pending:
        ready = {key for key in pending if set(nodes[key]['deps']) <= visited}
        if not ready:
            raise ValueError('proof graph has a cycle or unknown dependency')
        visited.update(ready)
        pending -= ready


class Graph:
    def __init__(self, steps):
        self.nodes = {}
        previous = []
        for i, step in enumerate(steps):
            key = f'n{i + 1}'
            self.nodes[key] = dict(step, id=key, deps=previous[:],
                                   status='pending', refinements=0, revisions=0, tries=0)
            previous = [key]
        if any('callers' in s for s in steps):
            callers = {short(n.get('top_fn', n['fn'])): n for n in self.nodes.values()}
            for n in self.nodes.values():
                n['deps'] = []
            for n in self.nodes.values():
                for caller in n.get('callers', []):
                    if caller in callers:
                        callers[caller]['deps'].append(n['id'])
            # Top acceptance requires every planned internal spec, including
            # nodes reached through aliases omitted by the caller mapping.
            self.nodes[previous[0]]['deps'] = list(self.nodes)[:-1]
        self.events = []
        self.commits = []  # ordered slot commits: {sha, kind: accept|split|unsplit, node}
        self.math_assumptions = []
        self.attempts = 0
        self.initial = None
        self.initial_counts = None
        validate_graph(self.nodes)

    def ready(self):
        return next((n for n in self.nodes.values() if n['status'] == 'pending'
                     and all(self.nodes[d]['status'] == 'accepted'
                             for d in n['deps'])), None)

    def upstream(self, key):
        """Transitive dependencies of `key`."""
        found, todo = set(), list(self.nodes[key]['deps'])
        while todo:
            d = todo.pop()
            if d not in found:
                found.add(d)
                todo.extend(self.nodes[d]['deps'])
        return found

    def downstream(self, key):
        """Every node that transitively depends on `key`."""
        return {n['id'] for n in self.nodes.values() if key in self.upstream(n['id'])}

    def spec_for(self, name, requester):
        """The accepted internal spec node named by a Worker's report, if it is
        an upstream dependency of the requesting node; otherwise None."""
        want = short(name)
        up = self.upstream(requester['id'])
        hits = [n for n in self.nodes.values()
                if n['mode'] == 'spec' and n['id'] in up and n['status'] == 'accepted'
                and (short(n['fn']) == want or short(n['fn']).endswith('.' + want))]
        return hits[0] if len(hits) == 1 else None

    def split(self, node, helpers):
        original = node['deps'][:]
        ids = [f"{node['id']}.r{node['refinements'] + 1}.h{i + 1}"
               for i in range(len(helpers))]
        rnd = node['refinements'] + 1
        for i, helper in enumerate(helpers):
            self.nodes[ids[i]] = dict(
                id=ids[i], mode='helper', fn=helper['name'], path=node['path'],
                deps=original + [ids[j] for j in helper['deps']],
                status='pending', refinements=0, tries=0,
                parent=node['id'], round=rnd)
        node.setdefault('split_deps', {})[str(rnd)] = original
        node.setdefault('helpers', []).extend(
            dict(id=ids[i], name=h['name'], type=h.get('type', ''), purpose=h.get('purpose', ''))
            for i, h in enumerate(helpers))
        node['deps'] = ids
        node['status'] = 'pending'
        node['tries'] = 0  # new situation: helpers available
        node['refinements'] += 1
        validate_graph(self.nodes)

    def save(self, run_dir, work):
        paths = {n['path'] for n in self.nodes.values()}
        state = dict(version=1, nodes=self.nodes, events=self.events,
                     commits=self.commits, attempts=self.attempts,
                     math_assumptions=self.math_assumptions,
                     initial=self.initial, initial_counts=self.initial_counts,
                     source_sha256={p: hashlib.sha256(Path(work, p).read_bytes()).hexdigest()
                                    for p in paths})
        tmp = Path(run_dir, 'graph.json.tmp')
        tmp.write_text(json.dumps(state, indent=2) + '\n')
        tmp.replace(Path(run_dir, 'graph.json'))

    @classmethod
    def restore(cls, steps, run_dir, work):
        state = json.loads(Path(run_dir, 'graph.json').read_text())
        graph = cls(steps)
        for key, node in graph.nodes.items():
            saved = state['nodes'].get(key, {})
            if any(saved.get(k) != node[k] for k in ('fn', 'path', 'mode')):
                raise ValueError('initial plan changed since checkpoint')
        for path, digest in state['source_sha256'].items():
            if hashlib.sha256(Path(work, path).read_bytes()).hexdigest() != digest:
                raise ValueError(f'checkpoint source changed: {path}')
        if any(driver.changed_files(work)):
            raise ValueError('checkpoint workspace has uncommitted changes; inspect partials before recovery')
        graph.nodes, graph.events = state['nodes'], state['events']
        graph.commits = state.get('commits', [])
        for c in graph.commits:
            if driver.sh(['git', 'cat-file', '-e', c['sha'] + '^{commit}'], work).returncode != 0:
                raise ValueError(f"checkpoint commit missing from slot: {c['sha']}")
        graph.attempts = state['attempts']
        graph.initial, graph.initial_counts = state['initial'], state['initial_counts']
        validate_graph(graph.nodes)
        for node in graph.nodes.values():
            if node['status'] in ('blocked', 'running'):
                node['status'] = 'pending'
        return graph


def validate_proposal(proposal, source, limit):
    """Only add typed helper placeholders at one exact source anchor."""
    helpers = proposal.get('helpers')
    anchor = proposal.get('before')
    if not isinstance(helpers, list) or not 1 <= len(helpers) <= limit:
        raise ValueError('invalid helper count')
    if not isinstance(anchor, str) or not anchor or source.count(anchor) != 1:
        raise ValueError('before must be a unique, nonempty source substring')
    position = source.index(anchor)
    if position and source[position - 1] != '\n':
        raise ValueError('anchor must begin at a line boundary')
    names = set()
    for i, h in enumerate(helpers):
        if (not isinstance(h, dict) or not isinstance(h.get('name'), str)
                or not NAME.fullmatch(h['name'])):
            raise ValueError('helper needs a fully qualified Lean name')
        if h['name'] in names:
            raise ValueError('duplicate helper name')
        names.add(h['name'])
        if not isinstance(h.get('type'), str) or not h['type'].strip():
            raise ValueError('helper needs a closed Lean type')
        if not isinstance(h.get('purpose'), str) or not h['purpose'].strip():
            raise ValueError('helper needs a purpose in the parent proof')
        deps = h.get('deps')
        if not isinstance(deps, list) or any(type(d) is not int or not 0 <= d < i for d in deps):
            raise ValueError('helper dependencies must point to earlier helpers')
        # Types are expressions, never a channel for arbitrary Lean commands.
        if re.search(r'\b(axiom|theorem|lemma|def|opaque|namespace|end|import|set_option|syntax|macro|elab|sorry|admit)\b|[;@]', h['type']):
            raise ValueError('commands/placeholders are forbidden in helper types')
    insertion = '\n' + ''.join(
        f"theorem _root_.{h['name']} : {h['type']} := by\n  sorry\n\n"
        for h in helpers)
    return source.replace(anchor, insertion + anchor, 1), helpers


def revise(graph, args, spec, requester, report, work, log):
    """Reopen an accepted internal spec that a downstream Worker found too weak.

    The slot is reset to the commit before the spec's acceptance; later commits
    are replayed except the acceptances of the spec and of every node that
    transitively depends on it (their proofs may use the old statement). A
    replayed acceptance that conflicts, or a replay that does not build, falls
    back to replaying split commits only. Any failure restores the slot exactly.
    Returns (reopened node ids, sorry counts after revision); raises ValueError.
    """
    if spec['revisions'] >= args.max_spec_revisions:
        raise ValueError('spec revision budget exhausted')
    idx = next((i for i, c in enumerate(graph.commits)
                if c['kind'] == 'accept' and c['node'] == spec['id']), None)
    if idx is None:
        raise ValueError('no acceptance commit recorded for the spec')
    module = driver.path_to_module(spec['path'])
    fps, _ = fingerprints([module], work, args)
    previous = {t: fps.get(module, {}).get(t, {}).get('pp') for t in spec.get('theorems', [])}
    dropped = graph.downstream(spec['id']) | {spec['id']}
    pre = git(work, 'rev-parse', 'HEAD')
    base = git(work, 'rev-parse', graph.commits[idx]['sha'] + '^')

    def replay(keep_accepts):
        git(work, 'reset', '--hard', base)
        kept, lost = graph.commits[:idx], []
        for c in graph.commits[idx + 1:]:
            if c['kind'] == 'accept' and (c['node'] in dropped or not keep_accepts):
                lost.append(c['node'])
                continue
            r = driver.sh(GIT + ['cherry-pick', '--allow-empty', c['sha']], work)
            if r.returncode != 0:
                driver.sh(['git', 'cherry-pick', '--abort'], work)
                if c['kind'] != 'accept':
                    raise ValueError(f"cannot replay split commit of {c['node']}")
                lost.append(c['node'])
                continue
            kept.append(dict(c, sha=git(work, 'rev-parse', 'HEAD')))
        rc, counts, _, output = driver.build_sorry_counts(work, args.build_timeout, include_output=True)
        if rc != 0:
            raise ValueError('slot does not build after revision: ' + output[-2000:])
        return kept, lost, counts

    try:
        try:
            kept, lost, counts = replay(True)
        except ValueError as first:
            log(f"revision replay with independent acceptances failed ({first}); retrying with splits only")
            kept, lost, counts = replay(False)
    except (ValueError, RuntimeError, subprocess.TimeoutExpired):
        git(work, 'reset', '--hard', pre)
        raise
    graph.commits = kept
    reopened = sorted(dropped | set(lost))
    for key in reopened:
        n = graph.nodes[key]
        n['status'] = 'pending'
        n['tries'] = 0
        n.pop('theorems', None)
    spec['revisions'] += 1
    spec.setdefault('revision_requests', []).append(dict(
        requester=requester['fn'], reason=report['reason'],
        evidence=report['evidence'], previous=previous))
    return reopened, counts


def failure_summary(attempt, outcome, detail, rounds):
    """Short, bounded record of one failed Worker attempt for later prompts."""
    summary = dict(attempt=attempt, outcome=outcome)
    blocker = detail.get('blocker') or {}
    gate = detail.get('gate_detail') or detail  # agent_limit wraps the gate verdict
    if blocker:
        summary['reason'] = blocker['reason'][:400]
        summary['evidence'] = blocker['evidence'][:800]
    elif isinstance(gate.get('reason'), str):
        summary['reason'] = gate['reason'][:400]
    summary['errors'] = [f"{e['file']}:{e['line']}: {e['message'][:300]}"
                         for e in (gate.get('errors') or [])[:3]]
    summary['rounds'] = len(rounds or [])
    return summary


def context_block(graph, node):
    """Helpers added for this node and its earlier failed attempts."""
    helpers = ''.join(
        f"  - {h['name']} : {h['type']}\n      purpose: {h['purpose']}"
        f"  [{graph.nodes.get(h['id'], {}).get('status', 'unknown')}]\n"
        for h in node.get('helpers', []))
    if helpers:
        helpers = ('Helper lemmas added for this proof (already in the file; use '
                   'the accepted ones, do not restate or modify them):\n' + helpers)
    history = ''
    for h in node.get('history', []):
        line = f"  attempt {h['attempt']}: {h['outcome']}"
        if h.get('reason'):
            line += f"; reason: {h['reason']}"
        if h.get('evidence'):
            line += f"\n      evidence: {h['evidence']}"
        for e in h.get('errors', []):
            line += f"\n      error: {e}"
        history += line + '\n'
    if history:
        history = ('Previous attempts on this target (their edits were rolled back; '
                   'do not repeat the same approach blindly):\n' + history)
    return CONTEXT.format(helpers=helpers, history=history) if helpers or history else ''


def revision_block(node):
    requests = node.get('revision_requests') or []
    return ''.join(REVISION.format(
        requester=short(r['requester']), reason=r['reason'], evidence=r['evidence'],
        previous='\n'.join(f"  {t}: {pp or '(statement unavailable)'}"
                           for t, pp in r['previous'].items()) or '  (none recorded)')
        for r in requests)


def placeholder_re(name):
    return re.compile(r"^theorem _root_\." + re.escape(name) +
                      r"\s*:.*?:=\s*by[ \t]*\n\s*sorry[ \t]*\n\n?", re.M | re.S)


def unsplit(graph, args, helper, report, work, before_counts, log):
    """A helper proposed by the Refiner is false: remove that round's unproved
    helper placeholders, restore the parent's dependencies (proved siblings
    stay), and remember the false statement for the next Refiner.
    Returns (removed node ids, sorry counts); raises ValueError, slot unchanged.
    """
    parent = graph.nodes[helper['parent']]
    rnd = helper['round']
    siblings = [n for n in graph.nodes.values()
                if n.get('parent') == parent['id'] and n.get('round') == rnd]
    removed = [n for n in siblings if n['status'] != 'accepted']
    removed_ids = {n['id'] for n in removed}
    for n in graph.nodes.values():
        if n['id'] not in removed_ids and n['id'] != parent['id'] and removed_ids & set(n['deps']):
            raise ValueError(f"{n['id']} depends on a helper being removed")
    path = parent['path']
    module = driver.path_to_module(path)
    old, _ = fingerprints([module], work, args)
    source = Path(work, path).read_text()
    for n in removed:
        source, k = placeholder_re(n['fn']).subn('', source)
        if k != 1:
            raise ValueError(f"placeholder of {n['fn']} not found exactly once")
    try:
        Path(work, path).write_text(source)
        rc, counts, _, output = driver.build_sorry_counts(work, args.build_timeout, include_output=True)
        if rc != 0:
            raise ValueError('slot does not build after removing helpers: ' + output[-2000:])
        new, _ = driver.stmt_fingerprints([module], work)
        gone = set(old.get(module, {})) - set(new.get(module, {}))
        if gone != {n['fn'] for n in removed} or any(driver.stmt_diff(
                {k: v for k, v in old[module].items() if k not in gone}, new[module])):
            raise ValueError('removal changed other statements')
        if counts.get(path, 0) != before_counts.get(path, 0) - len(removed):
            raise ValueError('unexpected sorry count after removal')
        for p in set(counts) | set(before_counts):
            if p != path and counts.get(p, 0) != before_counts.get(p, 0):
                raise ValueError('removal changed another module')
    except (ValueError, RuntimeError, subprocess.TimeoutExpired):
        mod, new_files = driver.changed_files(work)
        driver.rollback(mod, new_files, work)
        raise
    graph.commits.append(dict(sha=commit(work, path, f"DAG unsplit {parent['id']} r{rnd}"),
                              kind='unsplit', node=parent['id']))
    for n in removed:
        del graph.nodes[n['id']]
    kept = [n['id'] for n in siblings if n['id'] not in removed_ids]
    parent['deps'] = parent['split_deps'][str(rnd)] + kept
    false_type = next((h['type'] for h in parent.get('helpers', []) if h['id'] == helper['id']), '')
    parent['helpers'] = [h for h in parent.get('helpers', []) if h['id'] not in removed_ids]
    parent.setdefault('rejected_helpers', []).append(dict(
        name=helper['fn'], type=false_type,
        reason=report['reason'][:400], evidence=report['evidence'][:800]))
    parent.setdefault('history', []).append(dict(
        attempt=graph.attempts, outcome='helper_invalid', rounds=0, errors=[],
        reason=f"proposed helper {helper['fn']} is false: {report['reason'][:300]}"))
    parent['status'] = 'pending'
    parent['tries'] = 0
    validate_graph(graph.nodes)
    return sorted(removed_ids), counts


def refine(graph, args, node, report, task_prompt, failed_source, work, run_dir,
           attempt, env, settings, prefix, before_counts, log):
    """Ask a read-only Refiner for helper statements, verify and insert them.
    Returns the sorry counts after an accepted split, or None."""
    path = node['path']
    module = driver.path_to_module(path)
    log(f"refiner for {node['id']}: {report['reason']}")
    baseline, _ = fingerprints([module], work, args)
    source = Path(work, path).read_text()
    rejected = ''.join(f"  - {h['name']} : {h['type']}\n      why false: {h['reason']}\n"
                       for h in node.get('rejected_helpers', []))
    ref_prompt = f'''You are the proof Refiner. Read the target file {path} and relevant definitions.
Target: {node['fn']}. Blocker: {json.dumps(report)}
Original Worker task:\n{task_prompt}
Failed attempt excerpt (diagnostic only; workspace has been rolled back):
{failed_source}
''' + (f'''Helpers proposed earlier for this target turned out to be FALSE. Do not propose
them again or anything equivalent; check the actual bounds and definitions:
{rejected}''' if rejected else '') + f'''Keep every existing declaration and target statement unchanged. Propose auxiliary
lemmas sufficient to simplify the parent proof. Do not weaken its contract.
End your final message with exactly one JSON object on its last line:
{{"before":"unique exact substring at a line start before the target",
"helpers":[{{"name":"Fully.Qualified.unique_name", "type":"closed Lean proposition, including all forall binders",
"deps":[], "purpose":"how the parent uses it"}}]}}
Helpers appear in this order. deps are zero-based indices of earlier helpers.
They must not depend on the parent or on later/unproved nodes. Use at most
{args.max_helpers_per_split} helpers. Do not edit files. If decomposition is
inappropriate return {{"blocked":"reason"}}.
'''
    ref_session = agentproc.new_session_id()
    # Read-only mount when sandboxed (set up by prove_top_spec); the
    # changed_files check below stays as a second line of defense.
    ref_prefix = getattr(args, 'refiner_prefix', None) or prefix
    status, rc, wall, result, provenance = agentproc.run_round(
        ref_prompt, str(Path(run_dir, f'refiner-{attempt}.jsonl')),
        cwd=work, session_id=ref_session, resume=False, model=args.model,
        max_turns=args.max_turns, deadline_seconds=args.timeout,
        allowed_tools='Read,Grep,Glob', env=env, settings_path=settings,
        sandbox_prefix=ref_prefix, local_checks=False,
        progress_log=(None if getattr(args, 'quiet_turns', False) else
                      lambda message: log(f"[refiner {node['id']}] {message}")))
    ref_event = dict(role='refiner', node=node['id'], session=ref_session,
                     sandbox='read_only' if ref_prefix is not prefix else
                             ('shared_writable' if prefix else 'none'),
                     status=status, wall_seconds=wall, provenance=provenance,
                     cost_usd=(result or {}).get('total_cost_usd'),
                     num_turns=(result or {}).get('num_turns'))
    graph.events.append(ref_event)
    try:
        if status != 'ok' or rc != 0:
            raise ValueError('refiner did not complete')
        if any(driver.changed_files(work)):
            raise ValueError('refiner changed workspace')
        proposal = object_result(result or {})
        ref_event['proposal'] = proposal
        updated, helpers = validate_proposal(proposal, source, min(
            args.max_helpers_per_split, args.max_proof_nodes - len(graph.nodes)))
        Path(work, path).write_text(updated)
        rc, counts, _, output = driver.build_sorry_counts(work, args.build_timeout, include_output=True)
        if rc != 0:
            raise ValueError('helper statements do not elaborate: ' + output[-2000:])
        after, _ = driver.stmt_fingerprints([module], work)
        old, newfps = baseline[module], after[module]
        if any(driver.stmt_diff(old, newfps)):
            raise ValueError('refinement changed existing statements')
        added = set(newfps) - set(old)
        if added != {h['name'] for h in helpers} or any(newfps[n]['kind'] != 'theorem' for n in added):
            raise ValueError('refinement must add exactly the declared helper theorems')
        if counts.get(path, 0) != before_counts.get(path, 0) + len(helpers):
            raise ValueError('unexpected refinement sorry count')
        for p in set(counts) | set(before_counts):
            if p != path and counts.get(p, 0) != before_counts.get(p, 0):
                raise ValueError('refinement changed another module')
        graph.commits.append(dict(sha=commit(work, path, f"DAG split {node['id']}"),
                                  kind='split', node=node['id']))
        graph.split(node, helpers)
        ref_event['outcome'] = 'accepted_decomposition'
        return counts
    except (ValueError, RuntimeError, TimeoutError, subprocess.TimeoutExpired) as error:
        mod, new = driver.changed_files(work)
        driver.rollback(mod, new, work)
        ref_event.update(outcome='rejected_decomposition', error=str(error))
        return None


def run(args, steps, work, run_dir, before_counts, env, settings, prefix,
        step_prompt, done, top_in_plan, log, api):
    graph = (Graph.restore(steps, run_dir, work) if args.resume_dynamic else Graph(steps))
    allowed = math_assumptions()
    graph.math_assumptions = sorted(allowed)
    modules = list(dict.fromkeys(driver.path_to_module(s['path']) for s in steps))
    if graph.initial is None:
        graph.initial, _ = fingerprints(modules, work, args)
        graph.initial_counts = dict(before_counts)
    initial, initial_counts = graph.initial, graph.initial_counts
    for n in graph.nodes.values():
        if n['status'] == 'accepted' and n['mode'] == 'spec':
            done[n['fn'].removeprefix('probe:')] = dict(
                path=n['path'], theorems=n['theorems'], run_id=Path(run_dir).name)
    attempt = graph.attempts
    while (node := graph.ready()) is not None:
        attempt += 1
        if attempt > args.max_node_attempts:
            graph.events.append({'outcome': 'attempt_budget_exhausted'})
            break
        graph.attempts = attempt
        path = node['path']
        module = driver.path_to_module(path)
        baseline, _ = fingerprints([module], work, args)
        local = copy.copy(args)
        local.resume_proof_state = None
        local.gate_mode = 'fill' if node['mode'] == 'helper' else node['mode']
        local.gate_callee = node['fn'].removeprefix('probe:') if node['mode'] == 'spec' else None
        local.gate_pure_callees = {local.gate_callee} if node.get('result') is False else set()

        def validate(outcome, detail, result):
            if outcome == 'accepted':
                fps = detail.get('g1_after', {}).get(module, {})
                names = detail.get('specs', []) if node['mode'] == 'spec' else [node['fn'].removeprefix('probe:')]
                bad = {n: disallowed_sorries(fps.get(n, {}), allowed) for n in names}
                bad = {n: d for n, d in bad.items() if d or fps.get(n, {}).get('kind') != 'theorem'}
                if not names or bad:
                    return 'rejected_sorry_remains', {**detail, 'reason': f'target depends on sorry outside the math assumptions: {bad}',
                        'harness_note': SORRY_NOTE.format(bad=json.dumps(bad))}
                old = baseline.get(module, {})
                for name, fp in fps.items():
                    if name not in old or is_clean(old[name], allowed):
                        if (d := disallowed_sorries(fp, allowed)) and fp.get('kind') == 'theorem':
                            return 'rejected_sorry_remains', {**detail, 'reason': f'new or previously verified declaration uses sorryAx: {name}',
                                'harness_note': SORRY_NOTE.format(bad=json.dumps({name: d}))}
                detail['verified_theorems'] = names
            elif outcome in driver.FEEDBACK:
                report = blocker_result(result)
                if report:
                    return 'structural_blocker', {**detail, 'blocker': report}
            return outcome, detail

        local.round_validator = validate

        def task_prompt(n, i):
            if n['mode'] == 'helper':
                text = (f"Prove ONLY the body of {n['fn']} in {n['path']}. "
                        'Its type and all other declarations are frozen. '
                        'Previously accepted dependencies are in the workspace.\n')
            else:
                text = step_prompt(i, n, done) + revision_block(n)
            return text + context_block(graph, n) + REPORT

        prompt = task_prompt(node, attempt)
        tid = 'dag_' + Path(run_dir).name + '_' + str(attempt)
        node['status'] = 'running'
        node['tries'] = node.get('tries', 0) + 1
        graph.save(run_dir, work)
        log(f"worker {node['id']}: {node['fn']} (fresh session, try {node['tries']})")
        outcome, detail, rounds, sessions = driver.run_rounds(
            prompt, tid, path, before_counts, local, env, settings,
            baseline, work, prefix, log)
        event = dict(node=node['id'], outcome=outcome, sessions=sessions,
                     rounds=rounds, detail=detail)
        graph.events.append(event)
        if outcome == 'accepted':
            node['status'] = 'accepted'
            node['theorems'] = detail['verified_theorems']
            before_counts = detail['counts_after']
            graph.commits.append(dict(sha=commit(work, path, f"DAG accepted {node['id']}"),
                                      kind='accept', node=node['id']))
            if node['mode'] == 'spec':
                done[node['fn'].removeprefix('probe:')] = dict(
                    path=path, theorems=node['theorems'], run_id=Path(run_dir).name)
            graph.save(run_dir, work)
            continue
        node.setdefault('history', []).append(failure_summary(attempt, outcome, detail, rounds))
        event['partial_manifest'] = api.save_partial_snapshot(
            run_dir, attempt, [path], work, {path: [node['fn']]}, rounds=rounds)
        failed_source = Path(work, path).read_text()[-16000:]
        mod, new = driver.changed_files(work)
        driver.rollback(mod, new, work)
        node['status'] = 'blocked'
        graph.save(run_dir, work)
        if agentproc.RECEIVED_SIGNAL is not None:
            break
        report = detail.get('blocker', {})
        kind = report.get('kind') if outcome == 'structural_blocker' else None
        if kind is None and node['tries'] <= args.max_node_retries:
            # Ordinary failure (gate rejection, limit, timeout): one more fresh
            # session with the attempt history; no decomposition yet.
            node['status'] = 'pending'
            event['retry'] = True
            log(f"retry {node['id']} ({node['tries']}/{1 + args.max_node_retries} tries used)")
            graph.save(run_dir, work)
            continue
        if kind == 'needs_stronger_spec':
            spec = graph.spec_for(report['spec'], node)
            rev_event = dict(role='revision', node=node['id'], request=report,
                             spec=spec['id'] if spec else None)
            graph.events.append(rev_event)
            try:
                if spec is None:
                    raise ValueError('spec is not an accepted upstream internal specification of this node')
                log(f"revision of {spec['id']} ({spec['fn']}) requested by {node['id']}: {report['reason']}")
                reopened, before_counts = revise(graph, args, spec, node, report, work, log)
                for key in reopened:
                    if graph.nodes[key]['mode'] == 'spec':
                        done.pop(graph.nodes[key]['fn'].removeprefix('probe:'), None)
                rev_event.update(outcome='accepted_revision', reopened=reopened)
            except (ValueError, RuntimeError, subprocess.TimeoutExpired) as error:
                rev_event.update(outcome='rejected_revision', error=str(error))
            graph.save(run_dir, work)
            continue
        if kind == 'invalid_contract' and node['mode'] == 'helper':
            parent = graph.nodes[node['parent']]
            un_event = dict(role='unsplit', node=node['id'], parent=parent['id'], request=report)
            graph.events.append(un_event)
            try:
                log(f"helper {node['id']} reported false; removing round {node['round']} of {parent['id']}")
                removed, before_counts = unsplit(graph, args, node, report, work, before_counts, log)
                un_event.update(outcome='accepted_unsplit', removed=removed)
            except (ValueError, RuntimeError, subprocess.TimeoutExpired) as error:
                un_event.update(outcome='rejected_unsplit', error=str(error))
                graph.save(run_dir, work)
                continue
            graph.save(run_dir, work)
            last = parent.get('last_blocker')
            if (last and parent['refinements'] < args.max_refinements
                    and len(graph.nodes) < args.max_proof_nodes):
                counts = refine(graph, args, parent, last, task_prompt(parent, attempt),
                                Path(work, parent['path']).read_text()[-16000:], work, run_dir,
                                attempt, env, settings, prefix, before_counts, log)
                if counts is not None:
                    before_counts = counts
            # Otherwise the parent is pending again and gets fresh Worker attempts.
            graph.save(run_dir, work)
            continue
        if (kind != 'needs_split'
                or node['refinements'] >= args.max_refinements
                or len(graph.nodes) >= args.max_proof_nodes):
            # Independent ready nodes may still make progress.
            continue
        node['last_blocker'] = report
        counts = refine(graph, args, node, report, prompt, failed_source, work, run_dir,
                        attempt, env, settings, prefix, before_counts, log)
        if counts is not None:
            before_counts = counts
        graph.save(run_dir, work)
    complete = all(n['status'] == 'accepted' for n in graph.nodes.values())
    if complete:
        batch_callees = {s['fn'].removeprefix('probe:'): s['path'] for s in steps if s['mode'] == 'spec'}
        outcome, detail = driver.gate(
            work, steps[-1]['path'], initial_counts, args.build_timeout, initial,
            g2=False, mode='joint', editable_paths=list(dict.fromkeys(s['path'] for s in steps)),
            callees=batch_callees,
            pure_callees={s['fn'].removeprefix('probe:') for s in steps if s.get('result') is False})
        fps = detail.get('g1_after', {})
        complete = outcome == 'accepted' and all(
            clean_theorems(fps.get(driver.path_to_module(n['path']), {}), n['theorems'], allowed)
            for n in graph.nodes.values())
        graph.events.append(dict(role='final_gate', outcome=outcome, verified=complete))
        if complete:
            paths = list(dict.fromkeys([s['path'] for s in steps] + [api.ROOT_MODULE]))
            api.atomic_publish_joint(args.bundle, work, paths, done)
    graph.save(run_dir, work)
    return complete
