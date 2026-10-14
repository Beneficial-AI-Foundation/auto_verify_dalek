/** Actual pinned SDKs; synthetic credentials/output only, all fetch calls intercepted. */
import assert from 'node:assert/strict';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { ModelRuntime } from '@earendil-works/pi-coding-agent';
import { AssistantMessageEventStream } from '@earendil-works/pi-ai';
import { MemoryStorage } from '@earendil-works/pi-durable';
import { BACKGROUND_CONTEXT } from '@earendil-works/chord/context';
import { openRoleHarness, guardedModels } from '../bridge.mjs';
import { AdmissionJournal } from '../journal.mjs';
import { installedSdk } from '../sdk-versions.mjs';
import { subscriptionCredentials, SDK_VERSIONS, ROLES, TOOL_NAMES } from '../policy.mjs';
import { grant, message, options, context } from '../test/helpers.mjs';

function fakeStore(credential = { type: 'oauth', access: 'SYNTHETIC_ACCESS_NOT_REAL',
  refresh: 'SYNTHETIC_REFRESH_NOT_REAL', expires: Date.now() + 86400000, clientId: 'SYNTHETIC_CLIENT_ID', scopes: ['api.responses.write'] }) {
  return {
    async read() { return credential; },
    async list() { return [{ providerId: 'openai', type: credential?.type }]; },
    async modify(id, fn) { credential = (await fn(credential)) ?? credential; return credential; },
    async delete() { assert.fail('no auth mutations'); },
  };
}
async function fixture(t, overrides = {}) {
  const credentialStore = fakeStore();
  const managedModelRuntime = await ModelRuntime.create({ credentials: subscriptionCredentials(credentialStore),
    modelsPath: null, refreshOnCreate: false, allowModelNetwork: false });
  const model = managedModelRuntime.getModels('openai').find(m => m.api === 'openai-responses');
  assert.ok(model, 'pinned built-in OpenAI catalog should be available without network');
  const g = grant({ roleModels: Object.fromEntries(ROLES.map(role => [role, model.id])), ...overrides });
  const journal = new AdmissionJournal(mkdtempSync(join(tmpdir(), 'autofv-pi-sdk-')), g);
  t.after(() => journal.close());
  return { credentialStore, managedModelRuntime, model, grant: g, journal };
}

test('installed SDK versions and pi-ai module identity are exact', () => {
  assert.deepEqual(installedSdk(), SDK_VERSIONS);
});

test('real ModelRuntime and Durable execute synthetic subscription role without network', async t => {
  t.mock.method(globalThis, 'fetch', () => assert.fail('unexpected network attempt'));
  const f = await fixture(t, { mode: 'live', approvalId: 'SYNTHETIC_APPROVAL',
    entitlementValidated: true, acceptsUnknownCost: true, acceptsBestEffortCancellation: true,
    isolationEvidenceSha256: 'a'.repeat(64), callbackLifecycleEvidenceSha256: 'b'.repeat(64) });
  let calls = 0;
  t.mock.method(ModelRuntime.prototype, 'streamSimple', function (model, request, streamOptions) {
    calls++;
    assert.equal(streamOptions.maxRetries, 0);
    assert.equal(streamOptions.deferred, false);
    assert.equal(streamOptions.apiKey, undefined);
    assert.equal(streamOptions.headers, undefined);
    assert.equal(request.messages.some(m => JSON.stringify(m).includes('SYNTHETIC_ACCESS_NOT_REAL')), false);
    const answer = message({ model: model.id, api: model.api, provider: model.provider });
    const stream = new AssistantMessageEventStream();
    stream.push({ type: 'done', reason: 'stop', message: answer }); stream.end(answer);
    return stream;
  });
  const harness = await openRoleHarness({ ...f, role: 'prover', context: BACKGROUND_CONTEXT,
    storage: new MemoryStorage(), instructions: 'Synthetic SDK boundary test.',
    callbacks: Object.fromEntries(TOOL_NAMES.map(name => [name, () => 'fixture'])) });
  t.after(() => harness.close());
  assert.equal((await harness.submit('fixture-request', 'Synthetic input.')).status, 'done');
  assert.equal(calls, 1);
  assert.equal(harness.report().attempts[0].state, 'completed');
  assert.equal(harness.report().costUsd, null);
});

test('real managed OAuth dispatch hits only intercepted fetch and stops after subscription quota error', async t => {
  let calls = 0;
  t.mock.method(globalThis, 'fetch', async (url, init) => {
    calls++;
    assert.match(typeof url === 'string' ? url : url.url ?? String(url), /^https:\/\/api\.openai\.com\/v1\/responses$/);
    const body = JSON.parse(init?.body ?? await url.text());
    assert.equal(body.max_output_tokens, undefined);
    return new Response(JSON.stringify({ error: { message: 'SYNTHETIC_ERROR_CANARY',
      code: 'subscription_sharing_usage_limit_exceeded', type: 'insufficient_quota' } }),
    { status: 429, headers: { 'content-type': 'application/json' } });
  });
  const f = await fixture(t);
  const models = guardedModels(f.managedModelRuntime, { ...f, role: 'prover', AssistantMessageEventStream });
  const result = await models.streamSimple(f.model, context, options).result();
  assert.equal(result.errorMessage, 'quota_terminal');
  assert.equal(calls, 1);
  assert.doesNotMatch(JSON.stringify([result, f.journal.report()]), /SYNTHETIC_ERROR_CANARY|SYNTHETIC_ACCESS_NOT_REAL/);
  await models.streamSimple(f.model, context, options).result();
  assert.equal(calls, 1);
});

test('missing credential cannot reach ambient API key through actual managed runtime', async t => {
  t.mock.method(globalThis, 'fetch', () => assert.fail('ambient fallback must not dispatch'));
  const f = await fixture(t);
  const missing = await ModelRuntime.create({ credentials: subscriptionCredentials({
    async read() { return undefined; }, async list() { return []; },
    async modify(id, fn) { await fn(undefined); return undefined; },
  }), modelsPath: null, refreshOnCreate: false, allowModelNetwork: false });
  const models = guardedModels(missing, { ...f, role: 'prover', AssistantMessageEventStream });
  const result = await models.streamSimple(f.model, context, options).result();
  assert.equal(result.stopReason, 'error');
  assert.equal(f.journal.report().attempts.length, 0);
});

test('real Durable rejects extra tool arguments before the controller callback', async t => {
  t.mock.method(globalThis, 'fetch', () => assert.fail('unexpected network attempt'));
  const f = await fixture(t, { mode: 'live', approvalId: 'SYNTHETIC_APPROVAL',
    entitlementValidated: true, acceptsUnknownCost: true, acceptsBestEffortCancellation: true,
    isolationEvidenceSha256: 'a'.repeat(64), callbackLifecycleEvidenceSha256: 'b'.repeat(64) });
  let calls = 0;
  t.mock.method(ModelRuntime.prototype, 'streamSimple', function (model) {
    calls++;
    const answer = message({ model: model.id, api: model.api, provider: model.provider,
      ...(calls === 1 ? { stopReason: 'toolUse', content: [{ type: 'toolCall', id: 'bad-args',
        name: 'read_allowed', arguments: { path: 'Allowed.lean', extra: 'must-be-refused' } }] } : {}) });
    const stream = new AssistantMessageEventStream();
    stream.push({ type: 'done', reason: answer.stopReason, message: answer }); stream.end(answer);
    return stream;
  });
  const harness = await openRoleHarness({ ...f, role: 'prover', context: BACKGROUND_CONTEXT,
    storage: new MemoryStorage(), instructions: 'Synthetic malformed tool test.',
    callbacks: Object.fromEntries(TOOL_NAMES.map(name => [name, () => assert.fail('invalid tool must not invoke callback')])) });
  t.after(() => harness.close());
  assert.equal((await harness.submit('fixture-request', 'Synthetic input.')).status, 'done');
  assert.equal(calls, 2);
});

test('real SDK OAuth refresh failure is terminal and cannot fall back to an API-key request', async t => {
  let refreshes = 0;
  t.mock.method(globalThis, 'fetch', async url => {
    const target = typeof url === 'string' ? url : url.url ?? String(url);
    assert.equal(target, 'https://auth.openai.com/api/accounts/oauth/token');
    refreshes++;
    return new Response(JSON.stringify({ error: 'invalid_grant', error_description: 'SYNTHETIC_REFRESH_ERROR_CANARY' }),
      { status: 400, headers: { 'content-type': 'application/json' } });
  });
  const f = await fixture(t);
  const expired = await ModelRuntime.create({ credentials: subscriptionCredentials(fakeStore({ type: 'oauth',
    access: 'SYNTHETIC_EXPIRED_ACCESS', refresh: 'SYNTHETIC_EXPIRED_REFRESH', expires: 1, clientId: 'SYNTHETIC_CLIENT_ID', scopes: ['api.responses.write'] })),
    modelsPath: null, refreshOnCreate: false, allowModelNetwork: false });
  const models = guardedModels(expired, { ...f, role: 'prover', AssistantMessageEventStream });
  const result = await models.streamSimple(f.model, context, options).result();
  assert.equal(result.stopReason, 'error');
  assert.equal(refreshes, 1);
  assert.equal(f.journal.report().attempts[0].state, 'quarantined');
  assert.doesNotMatch(JSON.stringify([result, f.journal.report()]), /SYNTHETIC_REFRESH_ERROR_CANARY|SYNTHETIC_EXPIRED/);
  await models.streamSimple(f.model, context, options).result();
  assert.equal(refreshes, 1);
});
