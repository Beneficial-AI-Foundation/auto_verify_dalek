import assert from 'node:assert/strict';
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { pathToFileURL } from 'node:url';
import { AdmissionJournal } from '../journal.mjs';
import { guardedModels, narrowTools, openRoleHarness } from '../bridge.mjs';
import { qualification, subscriptionCredentials, TOOL_NAMES, SETTINGS, SDK_VERSIONS } from '../policy.mjs';
import { installedSdk } from '../sdk-versions.mjs';
import { grant, model, message, options, context, FixtureStream, runtime, completed } from './helpers.mjs';

function setup(t, upstream = runtime(), g = grant()) {
  const directory = mkdtempSync(join(tmpdir(), 'autofv-pi-fixture-'));
  const journal = new AdmissionJournal(directory, g);
  t.after(() => journal.close());
  const models = guardedModels(upstream, { grant: g, role: 'prover', journal, AssistantMessageEventStream: FixtureStream });
  return { directory, journal, models, upstream, g };
}

test('live profile is disabled until explicit entitlement, new budget, and cancellation approvals', () => {
  const q = qualification(grant({ mode: 'live', serverOutputCap: 16384 }));
  assert.equal(q.callable, false);
  assert.deepEqual(q.blockers, ['live_approval_missing', 'exact_model_entitlement_unvalidated',
    'subscription_server_output_cap_unsupported', 'subscription_cost_unknown', 'upstream_cancellation_not_guaranteed',
    'sealed_isolation_unqualified', 'callback_process_cancellation_unqualified']);
  assert.equal(q.currentFvsEquivalent, false);
  const approved = qualification(grant({ mode: 'live', approvalId: 'synthetic-approval',
    entitlementValidated: true, acceptsUnknownCost: true, acceptsBestEffortCancellation: true,
    isolationEvidenceSha256: 'a'.repeat(64), callbackLifecycleEvidenceSha256: 'b'.repeat(64) }));
  assert.equal(approved.callable, true);
  assert.equal(approved.serverOutputCapEnforced, false);
});

test('real entry refuses unapproved or synthetic runs before importing SDK or reading credentials', async () => {
  const credentialStore = { read() { assert.fail('must not inspect credentials'); } };
  await assert.rejects(openRoleHarness({ grant: grant({ mode: 'live' }), credentialStore }), /live_approval_missing/);
  await assert.rejects(openRoleHarness({ grant: grant(), credentialStore }), /live_entry_requires_live_grant/);
});

test('credential guard rejects missing, API-key, other-provider, and mutation fallback', async () => {
  for (const value of [undefined, { type: 'api_key', key: 'SYNTHETIC_ONLY' }]) {
    const store = subscriptionCredentials({ async modify(id, fn) { await fn(value); return value; } });
    await assert.rejects(store.read('openai'), /subscription_auth_required/);
    await assert.rejects(store.read('openai-codex'), /provider_not_allowed/);
  }
  const oauth = { type: 'oauth', opaqueFixture: 'never-serialize' };
  let stored = oauth;
  const store = subscriptionCredentials({
    async read() { assert.fail('guard must not execute read-time API-key commands'); },
    async list() { return [{ providerId: 'openai', type: stored.type }]; },
    async modify(id, fn) { stored = (await fn(stored)) ?? stored; return stored; },
  });
  assert.equal(await store.read('openai'), oauth);
  assert.deepEqual(await store.list(), [{ providerId: 'openai', type: 'oauth' }]);
  await assert.rejects(store.modify('openai', async () => ({ type: 'api_key' })), /subscription_auth_required/);
  assert.equal(await store.modify('openai', async () => undefined), oauth);
  await assert.rejects(store.delete('openai'), /auth_mutation_not_allowed/);
  stored = undefined;
  await assert.rejects(store.modify('openai', async () => oauth), /subscription_auth_required/);
});

test('credential guard checks post-write result and never returns ambient fallback', async () => {
  const store = subscriptionCredentials({ async modify() { return undefined; } });
  await assert.rejects(store.modify('openai', async () => undefined), /subscription_auth_required/);
});

test('happy synthetic response uses managed runtime once and reports unknown subscription cost', async t => {
  const { models, upstream, journal } = setup(t);
  assert.equal((await models.streamSimple(model, context, options).result()).stopReason, 'stop');
  assert.equal(upstream.calls, 1);
  const report = journal.report();
  assert.equal(report.attempts[0].usage.tokens.output, 3);
  assert.equal(report.attempts[0].usage.tokens.reasoning, 2);
  assert.equal(report.attempts[0].usage.tokens.totalTokens, 13);
  assert.equal(report.attempts[0].usage.costUsd, null);
  assert.equal(report.costUsd, null); assert.equal(report.billingReceipt, null);
  assert.equal(report.attempts[0].usage.observedModel, null);
  assert.doesNotMatch(JSON.stringify(report), /fixture answer|public fixture|"cost":/);
});

test('per-dispatch auth drift fails closed before upstream', async t => {
  const upstream = runtime(); upstream.checkAuth = async () => ({ type: 'api_key' });
  const { models } = setup(t, upstream);
  assert.equal((await models.streamSimple(model, context, options).result()).errorMessage, 'subscription_auth_required');
  assert.equal(upstream.calls, 0);
});

for (const key of ['apiKey', 'env', 'headers', 'onPayload', 'onResponse', 'transformHeaders', 'maxTokens']) {
  test(`caller cannot inject ${key}`, async t => {
    const { models, upstream } = setup(t);
    assert.equal((await models.streamSimple(model, context, { ...options, [key]: 'SYNTHETIC_SECRET' }).result()).errorMessage,
      'unsafe_stream_options');
    assert.equal(upstream.calls, 0);
  });
}

test('models facade rejects credential, alternative model, deferred and image operations', t => {
  const { models } = setup(t);
  for (const method of ['getAuth', 'login', 'logout', 'setRuntimeApiKey', 'stream', 'images', 'fetchDeferred', 'cancelDeferred']) {
    assert.throws(() => models[method](), /models_operation_not_allowed/);
  }
  assert.throws(() => models.getModel('openai-codex', model.id), /model_not_allowed/);
  assert.throws(() => models.getModel('openai', 'other-model'), /model_not_allowed/);
});

for (const [failure, code] of [
  [Object.assign(new Error('SYNTHETIC_PRIVATE_ERROR'), { status: 429 }), 'quota_terminal'],
  [Object.assign(new Error('SYNTHETIC_PRIVATE_ERROR'), { status: 401 }), 'auth_terminal'],
  [new Error('SYNTHETIC_PRIVATE_ERROR'), 'transport_uncertain'],
]) {
  test(`${code} is terminal, redacted, and cannot trigger an automatic resend`, async t => {
    const { models, upstream, journal } = setup(t, runtime(() => { throw failure; }));
    const first = await models.streamSimple(model, context, options).result();
    assert.equal(first.errorMessage, code);
    const second = await models.streamSimple(model, context, { ...options, sessionId: 'new-session' }).result();
    assert.equal(second.errorMessage, 'prior_request_quarantined');
    assert.equal(upstream.calls, 1);
    assert.equal(journal.report().attempts[0].usage, null);
    assert.doesNotMatch(JSON.stringify([first, second, journal.report()]), /SYNTHETIC_PRIVATE_ERROR/);
  });
}

test('normalized quota errors from the SDK stay terminal without retaining provider prose', async t => {
  const { models, upstream } = setup(t, runtime(() => completed(message({ stopReason: 'error',
    errorMessage: 'subscription_sharing_usage_limit_exceeded SYNTHETIC_PRIVATE_ERROR' }))));
  const result = await models.streamSimple(model, context, options).result();
  assert.equal(result.errorMessage, 'quota_terminal');
  assert.equal(upstream.calls, 1);
  assert.doesNotMatch(JSON.stringify(result), /SYNTHETIC_PRIVATE_ERROR/);
});

test('completed identical request is not automatically sent again', async t => {
  const { models, upstream } = setup(t);
  await models.streamSimple(model, context, options).result();
  assert.equal((await models.streamSimple(model, context, options).result()).errorMessage, 'duplicate_request_quarantined');
  assert.equal(upstream.calls, 1);
});

test('completed journal cannot reopen under a fresh provider session, even with valid-shaped live grants', async t => {
  const g = grant({ mode: 'live', approvalId: 'SYNTHETIC_APPROVAL', entitlementValidated: true,
    acceptsUnknownCost: true, acceptsBestEffortCancellation: true,
    isolationEvidenceSha256: 'a'.repeat(64), callbackLifecycleEvidenceSha256: 'b'.repeat(64) });
  const { models, journal } = setup(t, runtime(), g);
  await models.streamSimple(model, context, options).result();
  await assert.rejects(openRoleHarness({ grant: g, journal }), /reopen_requires_reconciliation/);
});

test('crash/reopen preserves original grant and quarantines uncertain in-flight requests', t => {
  const { directory, journal, g } = setup(t);
  journal.begin({ request: 'first' }, Date.now()); journal.close();
  const reopened = new AdmissionJournal(directory, g); t.after(() => reopened.close());
  assert.equal(reopened.grant.startedAtMs, g.startedAtMs);
  assert.throws(() => reopened.begin({ request: 'second' }, Date.now()), /prior_request_quarantined/);
  assert.throws(() => new AdmissionJournal(directory, { ...g, deadlineMs: g.deadlineMs + 1000 }), /original_grant_changed/);
});

test('one-time Harness claim prevents two empty-journal handles and survives reopen', t => {
  const { directory, journal, g } = setup(t);
  const second = new AdmissionJournal(directory, g); t.after(() => second.close());
  journal.claim('prover');
  assert.throws(() => second.claim('prover'), /harness_already_claimed/);
  journal.close();
  const reopened = new AdmissionJournal(directory, g); t.after(() => reopened.close());
  assert.throws(() => reopened.claim('prover'), /harness_already_claimed/);
  assert.equal(reopened.report().claimedRole, 'prover');
});

test('invocation and original deadline cannot be reset by a new session or role', async t => {
  const { models, journal, upstream, g } = setup(t, runtime(), grant({ maxInvocations: 1 }));
  await models.streamSimple(model, context, options).result();
  assert.equal((await models.streamSimple(model, context, { ...options, sessionId: 'new' }).result()).errorMessage, 'invocation_limit');
  assert.equal(upstream.calls, 1);
  assert.throws(() => journal.begin({ request: 'late' }, g.deadlineMs), /deadline_exhausted/);
});

test('deadline aborts locally even if synthetic provider ignores cancellation; no resend', async t => {
  const { models, upstream, journal } = setup(t, runtime(() => new FixtureStream()), grant({ requestTimeoutMs: 25 }));
  // Keep the test process alive while AbortSignal.timeout's unref timer fires.
  const keepAlive = setTimeout(() => {}, 1000); t.after(() => clearTimeout(keepAlive));
  assert.equal((await models.streamSimple(model, context, options).result()).errorMessage, 'request_aborted_uncertain');
  assert.equal(upstream.calls, 1); assert.equal(journal.report().attempts[0].state, 'quarantined');
});

test('synchronous admission delay cannot dispatch after the request deadline', async t => {
  const { journal, g, upstream } = setup(t);
  let clock = Date.now();
  const delayed = { grant: journal.grant,
    begin(...args) { const id = journal.begin(...args); clock += g.requestTimeoutMs; return id; },
    finish: (...args) => journal.finish(...args) };
  const models = guardedModels(upstream, { grant: g, role: 'prover', journal: delayed,
    AssistantMessageEventStream: FixtureStream, now: () => clock });
  assert.equal((await models.streamSimple(model, context, options).result()).errorMessage, 'deadline_exhausted');
  assert.equal(upstream.calls, 0);
  assert.equal(journal.report().attempts[0].state, 'quarantined');
});

test('synchronous provider completion after the deadline cannot be accepted', async t => {
  const g = grant(); let clock = Date.now();
  const upstream = runtime(() => { clock += g.requestTimeoutMs; return completed(); });
  const { journal } = setup(t, upstream, g);
  const models = guardedModels(upstream, { grant: g, role: 'prover', journal,
    AssistantMessageEventStream: FixtureStream, now: () => clock });
  assert.equal((await models.streamSimple(model, context, options).result()).errorMessage, 'deadline_exhausted');
  assert.equal(upstream.calls, 1);
  assert.equal(journal.report().attempts[0].state, 'quarantined');
});

test('observed model substitution is rejected and quarantined', async t => {
  const { models, journal } = setup(t, runtime(() => completed(message({ responseModel: 'different-model' }))));
  assert.equal((await models.streamSimple(model, context, options).result()).errorMessage, 'model_identity_changed');
  assert.equal(journal.report().attempts[0].state, 'quarantined');
});

test('mutable SDK partials and unknown final metadata cannot leak into durable output', async t => {
  const partial = message({ stopReason: 'pending' });
  const source = new FixtureStream();
  source.push({ type: 'start', partial });
  const { models } = setup(t, runtime(() => source));
  const output = models.streamSimple(model, context, options);
  const iterator = output[Symbol.asyncIterator]();
  const start = await iterator.next();
  partial.errorMessage = 'SYNTHETIC_CREDENTIAL_CANARY';
  partial.secretMetadata = 'SYNTHETIC_CREDENTIAL_CANARY';
  const final = message({ secretMetadata: 'SYNTHETIC_CREDENTIAL_CANARY',
    content: [{ type: 'text', text: 'answer', secretMetadata: 'SYNTHETIC_CREDENTIAL_CANARY' }] });
  source.push({ type: 'done', reason: 'stop', message: final }); source.end(final);
  const result = await output.result();
  assert.doesNotMatch(JSON.stringify([start, result]), /SYNTHETIC_CREDENTIAL_CANARY/);
  assert.notEqual(result.content, final.content);
  final.content[0].text = 'MUTATED_AFTER_RETURN';
  assert.equal(result.content[0].text, 'answer');
});

test('tools expose only validated callbacks, no SDK API, no role escalation or delegation', async t => {
  const { journal, g } = setup(t);
  const boundary = { grant: g, journal };
  const seen = [];
  const callbacks = Object.fromEntries(TOOL_NAMES.map(name => [name, (...args) => { seen.push([name, args]); return 'ok'; }]));
  assert.throws(() => narrowTools('prover', { ...callbacks, bash() {} }, boundary), /callback_surface_mismatch/);
  const tools = narrowTools('proof_reviewer', callbacks, boundary);
  assert.deepEqual(tools.map(t => t.name), TOOL_NAMES);
  for (const name of ['edit_assigned', 'check_lean']) {
    assert.match((await tools.find(t => t.name === name).execute({})).output[0].text, /read_only_role/);
  }
  assert.equal(seen.length, 0);
  await tools[0].execute({ path: 'Allowed.lean' }, { models: { secret: 'SYNTHETIC_SECRET' } });
  assert.equal(seen[0][1].length, 2);
  assert.deepEqual(seen[0][1][0], { path: 'Allowed.lean' });
  assert.deepEqual(Object.keys(seen[0][1][1]).sort(), ['deadlineMs', 'signal']);
  assert.ok(tools.every(t => t.replay === 'unsafe' && t.executionMode === 'sequential'));
  assert.equal(SETTINGS.retry.enabled, false); assert.equal(SETTINGS.compaction.enabled, false);
  assert.equal(SETTINGS.stream.maxRetries, 0); assert.equal(SETTINGS.stream.deferred, false);
});

test('callback timeout is quarantined and later callbacks cannot start', async t => {
  const { journal, g } = setup(t);
  const controller = new AbortController();
  let calls = 0;
  const callbacks = Object.fromEntries(TOOL_NAMES.map(name => [name, () => { calls++; return new Promise(() => {}); }]));
  const tools = narrowTools('prover', callbacks, { grant: g, journal, hostSignal: controller.signal });
  const pending = tools[0].execute({ path: 'Allowed.lean' });
  await new Promise(resolve => setImmediate(resolve)); controller.abort();
  assert.equal((await pending).isError, true);
  assert.equal(journal.blocked(), 'controller_callback_uncertain');
  await assert.rejects(tools[1].execute({ query: 'later' }), /prior_request_quarantined/);
  assert.equal(calls, 1);
});

test('callback cannot start after original deadline', async t => {
  const { journal, g } = setup(t);
  const callbacks = Object.fromEntries(TOOL_NAMES.map(name => [name, () => assert.fail('late callback')]));
  const tools = narrowTools('prover', callbacks, { grant: g, journal, now: () => g.deadlineMs });
  await assert.rejects(tools[0].execute({ path: 'Allowed.lean' }), /deadline_exhausted/);
});

test('metadata verifier supports import-only exports and rejects nested pi-ai instances', () => {
  const root = mkdtempSync(join(tmpdir(), 'autofv-pi-metadata-'));
  for (const [name, version] of Object.entries(SDK_VERSIONS)) {
    const directory = join(root, 'node_modules', name); mkdirSync(directory, { recursive: true });
    writeFileSync(join(directory, 'package.json'), JSON.stringify({ name, version, type: 'module', exports: { '.': { import: './index.js' } } }));
    writeFileSync(join(directory, 'index.js'), 'throw new Error("Metadata lookup must not execute package code");');
  }
  const base = pathToFileURL(join(root, 'entry.mjs'));
  assert.deepEqual(installedSdk(base), SDK_VERSIONS);
  const nested = join(root, 'node_modules/@earendil-works/pi-durable/node_modules/@earendil-works/pi-ai');
  mkdirSync(nested, { recursive: true });
  writeFileSync(join(nested, 'package.json'), JSON.stringify({ name: '@earendil-works/pi-ai', version: '1.2.0', main: 'index.js' }));
  writeFileSync(join(nested, 'index.js'), '');
  assert.throws(() => installedSdk(base), /multiple_pi_ai_instances/);
});

test('no private error or callback data is persisted by admission journal', async t => {
  const { directory, models } = setup(t, runtime(() => { throw new Error('SYNTHETIC_CANARY'); }));
  await models.streamSimple(model, context, options).result();
  const bytes = readFileSync(join(directory, 'admissions.sqlite'));
  for (const text of ['SYNTHETIC_CANARY', 'public fixture', 'fixture answer']) assert.equal(bytes.includes(Buffer.from(text)), false);
});
