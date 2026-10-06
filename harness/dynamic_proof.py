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
If a structural obstacle prevents this proof, return ONLY one JSON object:
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
KINDS = ('needs_split', 'invalid_contract', 'needs_stronger_spec')
NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_']*(?:\.[A-Za-z_][A-Za-z0-9_']*)*\Z")
GIT = ['git', '-c', 'user.name=harness', '-c', 'user.email=harness@localhost']


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


def object_result(result):
    text = (result.get('result') or '').strip()
    if text.startswith('```json') and text.endswith('```'):
        text = text[7:-3].strip()
    try:
        value = json.loads(text)
        return value if isinstance(value, dict) else {}
    except (ValueError, TypeError):
        return {}


def blocker_result(result):
    value = object_result(result).get('blocker')
    if not isinstance(value, dict) or value.get('kind') not in KINDS:
        return None
    keys = ('reason', 'evidence') + (('spec',) if value['kind'] == 'needs_stronger_spec' else ())
    if all(isinstance(value.get(k), str) and value[k].strip() for k in keys):
        return value
    return None


def clean_theorems(fps, names):
    return bool(names) and all(
        fps.get(n, {}).get('kind') == 'theorem' and
        isinstance(fps[n].get('axioms'), list) and
        'sorryAx' not in fps[n]['axioms'] for n in names)


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
                                   status='pending', refinements=0, revisions=0)
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
        self.commits = []  # ordered slot commits: {sha, kind: accept|split, node}
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
        for i, helper in enumerate(helpers):
            self.nodes[ids[i]] = dict(
                id=ids[i], mode='helper', fn=helper['name'], path=node['path'],
                deps=original + [ids[j] for j in helper['deps']],
                status='pending', refinements=0)
        node['deps'] = ids
        node['status'] = 'pending'
        node['refinements'] += 1
        validate_graph(self.nodes)

    def save(self, run_dir, work):
        paths = {n['path'] for n in self.nodes.values()}
        state = dict(version=1, nodes=self.nodes, events=self.events,
                     commits=self.commits, attempts=self.attempts,
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
    fps, _ = driver.stmt_fingerprints([module], work)
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
        n.pop('theorems', None)
    spec['revisions'] += 1
    spec.setdefault('revision_requests', []).append(dict(
        requester=requester['fn'], reason=report['reason'],
        evidence=report['evidence'], previous=previous))
    return reopened, counts


def revision_block(node):
    requests = node.get('revision_requests') or []
    return ''.join(REVISION.format(
        requester=short(r['requester']), reason=r['reason'], evidence=r['evidence'],
        previous='\n'.join(f"  {t}: {pp or '(statement unavailable)'}"
                           for t, pp in r['previous'].items()) or '  (none recorded)')
        for r in requests)


def run(args, steps, work, run_dir, before_counts, env, settings, prefix,
        step_prompt, done, top_in_plan, log, api):
    graph = (Graph.restore(steps, run_dir, work) if args.resume_dynamic else Graph(steps))
    modules = list(dict.fromkeys(driver.path_to_module(s['path']) for s in steps))
    if graph.initial is None:
        graph.initial, _ = driver.stmt_fingerprints(modules, work)
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
        baseline, _ = driver.stmt_fingerprints([module], work)
        local = copy.copy(args)
        local.resume_proof_state = None
        local.gate_mode = 'fill' if node['mode'] == 'helper' else node['mode']
        local.gate_callee = node['fn'].removeprefix('probe:') if node['mode'] == 'spec' else None
        local.gate_pure_callees = {local.gate_callee} if node.get('result') is False else set()

        def validate(outcome, detail, result):
            if outcome == 'accepted':
                fps = detail.get('g1_after', {}).get(module, {})
                names = detail.get('specs', []) if node['mode'] == 'spec' else [node['fn'].removeprefix('probe:')]
                if not clean_theorems(fps, names):
                    return 'rejected_sorry_remains', {**detail, 'reason': 'target axiom closure contains sorryAx or evidence missing'}
                old = baseline.get(module, {})
                for name, fp in fps.items():
                    if (name not in old or old[name].get('axioms') == [] or
                            isinstance(old[name].get('axioms'), list) and 'sorryAx' not in old[name]['axioms']):
                        if not isinstance(fp.get('axioms'), list) or 'sorryAx' in fp['axioms']:
                            return 'rejected_sorry_remains', {**detail, 'reason': f'new or previously verified declaration uses sorryAx: {name}'}
                detail['verified_theorems'] = names
            elif outcome in driver.FEEDBACK:
                report = blocker_result(result)
                if report:
                    return 'structural_blocker', {**detail, 'blocker': report}
            return outcome, detail

        local.round_validator = validate
        if node['mode'] == 'helper':
            prompt = (f"Prove ONLY the body of {node['fn']} in {path}. "
                      'Its type and all other declarations are frozen. '
                      'Previously accepted dependencies are in the workspace.\n')
        else:
            prompt = step_prompt(attempt, node, done) + revision_block(node)
        prompt += REPORT
        tid = 'dag_' + Path(run_dir).name + '_' + str(attempt)
        node['status'] = 'running'
        graph.save(run_dir, work)
        log(f"worker {node['id']}: {node['fn']} (fresh session)")
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
        if (kind != 'needs_split'
                or node['refinements'] >= args.max_refinements
                or len(graph.nodes) >= args.max_proof_nodes):
            # Independent ready nodes may still make progress.
            continue
        log(f"refiner for {node['id']}: {report['reason']}")
        source = Path(work, path).read_text()
        ref_prompt = f'''You are the proof Refiner. Read the target file {path} and relevant definitions.
Target: {node['fn']}. Blocker: {json.dumps(report)}
Original Worker task:\n{prompt}
Failed attempt excerpt (diagnostic only; workspace has been rolled back):
{failed_source}
Keep every existing declaration and target statement unchanged. Propose auxiliary
lemmas sufficient to simplify the parent proof. Do not weaken its contract.
Return ONLY JSON: {{"before":"unique exact substring at a line start before the target",
"helpers":[{{"name":"Fully.Qualified.unique_name", "type":"closed Lean proposition, including all forall binders",
"deps":[], "purpose":"how the parent uses it"}}]}}
Helpers appear in this order. deps are zero-based indices of earlier helpers.
They must not depend on the parent or on later/unproved nodes. Use at most
{args.max_helpers_per_split} helpers. Do not edit files. If decomposition is
inappropriate return {{"blocked":"reason"}}.
'''
        ref_session = agentproc.new_session_id()
        status, rc, wall, result, provenance = agentproc.run_round(
            ref_prompt, str(Path(run_dir, f'refiner-{attempt}.jsonl')),
            cwd=work, session_id=ref_session, resume=False, model=args.model,
            max_turns=args.max_turns, deadline_seconds=args.timeout,
            allowed_tools='Read,Grep,Glob', env=env, settings_path=settings,
            sandbox_prefix=prefix, local_checks=False)
        ref_event = dict(role='refiner', node=node['id'], session=ref_session,
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
            before_counts = counts
            ref_event['outcome'] = 'accepted_decomposition'
        except (ValueError, RuntimeError, TimeoutError, subprocess.TimeoutExpired) as error:
            mod, new = driver.changed_files(work)
            driver.rollback(mod, new, work)
            ref_event.update(outcome='rejected_decomposition', error=str(error))
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
            clean_theorems(fps.get(driver.path_to_module(n['path']), {}), n['theorems'])
            for n in graph.nodes.values())
        graph.events.append(dict(role='final_gate', outcome=outcome, verified=complete))
        if complete:
            paths = list(dict.fromkeys([s['path'] for s in steps] + [api.ROOT_MODULE]))
            api.atomic_publish_joint(args.bundle, work, paths, done)
    graph.save(run_dir, work)
    return complete
