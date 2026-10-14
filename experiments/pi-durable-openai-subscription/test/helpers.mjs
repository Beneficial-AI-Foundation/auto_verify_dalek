import { ROLES, PROFILE } from '../policy.mjs';

export function grant(overrides = {}) {
  const now = Date.now();
  return { schema: PROFILE, runId: 'fixture-run', mode: 'synthetic',
    roleModels: Object.fromEntries(ROLES.map(role => [role, 'fixture-openai-model'])),
    startedAtMs: now - 1000, deadlineMs: now + 60000, maxInvocations: 3, requestTimeoutMs: 5000,
    serverOutputCap: null, approvalId: null, acceptsUnknownCost: false,
    acceptsBestEffortCancellation: false, entitlementValidated: false,
    isolationEvidenceSha256: null, callbackLifecycleEvidenceSha256: null, ...overrides };
}
export const model = Object.freeze({ id: 'fixture-openai-model', provider: 'openai', api: 'openai-responses' });
export const options = { maxRetries: 0, deferred: false, transport: 'sse', cacheRetention: 'none', sessionId: 'fixture-session' };
export const context = { messages: [{ role: 'user', content: 'public fixture', timestamp: 1 }] };
export function message(overrides = {}) {
  return { role: 'assistant', content: [{ type: 'text', text: 'fixture answer' }], api: model.api,
    provider: model.provider, model: model.id, stopReason: 'stop', timestamp: 1,
    usage: { input: 10, output: 3, reasoning: 2, cacheRead: 0, cacheWrite: 0, totalTokens: 13,
      cost: { input: 1, output: 1, cacheRead: 0, cacheWrite: 0, total: 2 } }, ...overrides };
}

// Synthetic protocol double; real Pi stream/Harness coverage lives in test-sdk/.
export class FixtureStream {
  #queue = []; #waiters = []; #ended = false; #resolve; #result;
  constructor() { this.#result = new Promise(resolve => { this.#resolve = resolve; }); }
  push(event) {
    const waiter = this.#waiters.shift();
    if (waiter) waiter({ done: false, value: event }); else this.#queue.push(event);
  }
  end(message) {
    this.#ended = true; this.#resolve(message);
    for (const waiter of this.#waiters.splice(0)) waiter({ done: true });
  }
  result() { return this.#result; }
  [Symbol.asyncIterator]() { return this; }
  next() {
    if (this.#queue.length) return Promise.resolve({ done: false, value: this.#queue.shift() });
    if (this.#ended) return Promise.resolve({ done: true });
    return new Promise(resolve => this.#waiters.push(resolve));
  }
}
export function completed(value = message()) {
  const stream = new FixtureStream();
  stream.push({ type: 'done', reason: value.stopReason, message: value }); stream.end(value);
  return stream;
}
export function runtime(reply = () => completed()) {
  let calls = 0;
  return {
    get calls() { return calls; },
    getModel() { return model; },
    getProvider() { return { auth: { oauth: { isSubscription: true } } }; },
    async checkAuth() { return { type: 'oauth', source: 'OAuth' }; },
    streamSimple(...args) { calls++; return reply(...args); },
  };
}
