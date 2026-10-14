/** Public Pi SDK seam. Trusted controller only; not a new launcher or verifier. */
import { readFileSync } from 'node:fs';
import { installedSdk } from './sdk-versions.mjs';
import {
  BoundaryError, SETTINGS, TOOL_NAMES, canonical, digest, failureCode, qualification,
  reject, subscriptionCredentials, validateGrant,
} from './policy.mjs';

const SCHEMAS = JSON.parse(readFileSync(new URL('./tool-schemas.json', import.meta.url), 'utf8'));
const WRITERS = new Set(['specifier', 'prover', 'repair']);
const OPTION_KEYS = new Set(['signal', 'sessionId', 'reasoning', 'maxRetries', 'deferred',
  'cacheRetention', 'transport', 'timeoutMs']);

function usageRecord(message) {
  const u = message.usage;
  const keys = ['input', 'output', 'cacheRead', 'cacheWrite', 'totalTokens'];
  if (!u || keys.some(k => !Number.isSafeInteger(u[k]) || u[k] < 0)
      || (u.reasoning !== undefined && (!Number.isSafeInteger(u.reasoning)
        || u.reasoning < 0 || u.reasoning > u.output))) reject('invalid_usage');
  return {
    tokens: Object.fromEntries([...keys, ...(u.reasoning === undefined ? [] : ['reasoning'])].map(k => [k, u[k]])),
    requestedModel: message.model, observedModel: message.responseModel ?? null,
    provider: message.provider, authMode: 'managed_subscription',
    costUsd: null, costClassification: 'subscription_cost_unknown', billingReceipt: null,
  };
}

function assertMessage(message, model) {
  if (!message || message.provider !== 'openai' || message.model !== model.id
      || message.api !== 'openai-responses'
      || (message.responseModel !== undefined && message.responseModel !== model.id)) reject('model_identity_changed');
  if (message.deferred || message.stopReason === 'deferred') reject('deferred_response_refused');
}

function safeMessage(message) {
  const pick = (value, keys) => Object.fromEntries(keys.filter(k => value[k] !== undefined)
    .map(k => [k, structuredClone(value[k])]));
  const content = message.content.map(block => {
    const keys = {
      text: ['type', 'text', 'textSignature'],
      thinking: ['type', 'thinking', 'thinkingSignature', 'redacted'],
      toolCall: ['type', 'id', 'name', 'arguments'],
    }[block.type];
    if (!keys) reject('unsupported_response_content');
    return pick(block, keys);
  });
  const usage = pick(message.usage, ['input', 'output', 'cacheRead', 'cacheWrite', 'totalTokens', 'reasoning']);
  const costKeys = ['input', 'output', 'cacheRead', 'cacheWrite', 'total'];
  if (!message.usage.cost || costKeys.some(k => !Number.isFinite(message.usage.cost[k]) || message.usage.cost[k] < 0)) {
    reject('invalid_usage');
  }
  usage.cost = pick(message.usage.cost, costKeys); // SDK estimates only; never a subscription billing receipt.
  return { ...pick(message, ['role', 'api', 'provider', 'model', 'responseModel', 'responseId',
    'providerThinkingLevel', 'thinkingLevel', 'stopReason', 'timestamp', 'durationMs']), content, usage };
}

/** SDK protocol placeholders are not usage evidence; journal usage stays null on failure. */
function errorMessage(model, code, now) {
  return { role: 'assistant', content: [], api: 'openai-responses', provider: 'openai',
    model: model.id, timestamp: now, stopReason: 'error', errorMessage: code,
    usage: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, totalTokens: 0,
      cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0 } } };
}

function withAbort(promise, signal) {
  if (signal.aborted) return Promise.reject(new BoundaryError('request_aborted_uncertain'));
  return new Promise((resolve, rejectPromise) => {
    const cancel = () => rejectPromise(new BoundaryError('request_aborted_uncertain'));
    signal.addEventListener('abort', cancel, { once: true });
    Promise.resolve(promise).then(resolve, rejectPromise).finally(() => signal.removeEventListener('abort', cancel));
  });
}

/**
 * Deliberately narrowed runtime Models seam: only getModel and streamSimple work.
 * All other methods deny rather than expose auth, provider mutation, images, or delegation.
 * This must be dynamically verified with the pinned Harness; it is not the full Models API.
 */
export function guardedModels(managedModelRuntime, { grant: value, role, journal, AssistantMessageEventStream, now = Date.now, hostSignal }) {
  const grant = validateGrant(value);
  const q = qualification(grant);
  if (!q.callable) reject(q.blockers[0]);
  if (!Object.hasOwn(grant.roleModels, role) || canonical(journal.grant) !== canonical(grant)) reject('role_or_grant_mismatch');
  const requested = grant.roleModels[role];
  const lookup = (provider, id) => {
    if (provider !== 'openai' || id !== requested) reject('model_not_allowed');
    const model = managedModelRuntime.getModel(provider, id);
    if (!model || model.provider !== provider || model.id !== id || model.api !== 'openai-responses') reject('model_unavailable');
    return model;
  };
  const methods = Object.freeze({
    getModel: lookup,
    streamSimple(model, context, options = {}) {
      const output = new AssistantMessageEventStream();
      // Never let raw SDK/store exceptions cross into Durable documents or reports.
      (async () => {
        let reservation;
        let signal;
        try {
          if (canonical(model) !== canonical(lookup('openai', requested))) reject('model_identity_changed');
          if (Object.keys(options).some(k => !OPTION_KEYS.has(k))
              || typeof options.sessionId !== 'string' || options.sessionId.length > 200
              || options.maxRetries !== 0 || options.deferred !== false
              || options.cacheRetention !== 'none' || options.transport !== 'sse') reject('unsafe_stream_options');
          const requestDeadline = Math.min(grant.deadlineMs, now() + grant.requestTimeoutMs);
          const remaining = requestDeadline - now();
          if (remaining <= 0) reject('deadline_exhausted');
          signal = AbortSignal.any([AbortSignal.timeout(remaining), ...(options.signal ? [options.signal] : []),
            ...(hostSignal ? [hostSignal] : [])]);
          const provider = managedModelRuntime.getProvider('openai');
          if (provider?.auth?.oauth?.isSubscription !== true) reject('subscription_provider_required');
          const auth = await withAbort(managedModelRuntime.checkAuth('openai', { signal }), signal);
          if (auth?.type !== 'oauth') reject('subscription_auth_required');
          // No messages in this journal: only a hash of the exact role/session/context.
          reservation = journal.begin({ role, model: requested, sessionId: options.sessionId,
            contextSha256: digest(context) }, now());
          // Synchronous SQLite/fsync can block timers; recheck the absolute clock.
          if (now() >= requestDeadline || signal.aborted) reject('deadline_exhausted');
          const stream = managedModelRuntime.streamSimple(model, context, {
            signal, sessionId: options.sessionId, reasoning: options.reasoning,
            maxRetries: 0, deferred: false, cacheRetention: 'none', transport: 'sse',
            timeoutMs: requestDeadline - now(),
          });
          const iterator = stream[Symbol.asyncIterator]();
          const empty = errorMessage(model, '', now());
          empty.stopReason = 'pending'; delete empty.errorMessage;
          output.push({ type: 'start', partial: empty });
          while (true) {
            const next = await withAbort(iterator.next(), signal);
            if (next.done) break;
            const event = next.value;
            if (event.type === 'done' || event.type === 'error') continue;
            assertMessage(event.partial, model);
            // Deliberately do not forward shared, mutable SDK partial objects.
            // The SDK can later attach credential-bearing failure diagnostics to them.
          }
          const message = await withAbort(stream.result(), signal);
          assertMessage(message, model);
          if (!['stop', 'toolUse'].includes(message.stopReason)) reject(failureCode(message));
          const usage = usageRecord(message);
          const safe = safeMessage(message);
          if (now() >= requestDeadline || signal.aborted) reject('deadline_exhausted');
          journal.finish(reservation, 'completed', usage);
          reservation = undefined;
          output.push({ type: 'done', reason: safe.stopReason, message: safe });
          output.end(safe);
        } catch (error) {
          let code = failureCode(error);
          if (reservation !== undefined) {
            try { journal.finish(reservation, code); } catch { code = 'journal_completion_uncertain'; }
          }
          const message = errorMessage(model, code, now());
          output.push({ type: 'error', reason: 'error', error: message });
          output.end(message);
        }
      })();
      return output;
    },
  });
  return new Proxy(methods, {
    get(target, key) {
      if (Object.hasOwn(target, key)) return target[key];
      if (key === 'then') return undefined;
      return () => reject('models_operation_not_allowed');
    },
  });
}

export function narrowTools(role, callbacks, { grant: value, journal, hostSignal, now = Date.now }) {
  const grant = validateGrant(value);
  if (canonical(Object.keys(callbacks).sort()) !== canonical([...TOOL_NAMES].sort())
      || Object.values(callbacks).some(fn => typeof fn !== 'function')) reject('callback_surface_mismatch');
  return SCHEMAS.map(({ name, description, input_schema }) => ({
    name, description, parameters: structuredClone(input_schema), replay: 'unsafe',
    executionMode: 'sequential', callers: ['model'], outputLimits: { maxBytes: 16384, retain: 'head' },
    async execute(args, _api, context = {}) {
      if (journal.blocked()) reject('prior_request_quarantined');
      const remaining = grant.deadlineMs - now();
      if (remaining <= 0) reject('deadline_exhausted');
      const signal = AbortSignal.any([AbortSignal.timeout(remaining),
        ...(context.abortSignal ? [context.abortSignal] : []), ...(hostSignal ? [hostSignal] : [])]);
      signal.throwIfAborted();
      if (!WRITERS.has(role) && ['edit_assigned', 'check_lean'].includes(name)) {
        return { output: [{ type: 'text', text: 'read_only_role' }] };
      }
      // Callback must be the existing controller's validated invoke_lane_tool seam.
      // Never pass Durable's api, models, registry, filesystem, or context to it.
      try {
        const result = await withAbort(Promise.resolve().then(() => {
          signal.throwIfAborted();
          if (now() >= grant.deadlineMs) reject('deadline_exhausted');
          return callbacks[name](structuredClone(args), { signal, deadlineMs: grant.deadlineMs });
        }), signal);
        if (now() >= grant.deadlineMs || signal.aborted) reject('deadline_exhausted');
        const text = typeof result === 'string' ? result : canonical(result);
        if (Buffer.byteLength(text) > 16384) reject('callback_output_too_large');
        return { output: [{ type: 'text', text }],
          ...(name === 'submit_candidate' ? { control: { terminate: true } } : {}) };
      } catch {
        journal.quarantine('controller_callback_uncertain');
        return { output: [{ type: 'text', text: 'controller_callback_failed' }], isError: true };
      }
    },
  }));
}

/**
 * Real SDK entry, callable after installation. No CLI/session/extension discovery.
 * The caller owns approved auth/storage paths and OS isolation. Store implementation
 * stays host-side; no unsupported AuthStorage import or token-to-key conversion.
 */
export async function openRoleHarness({ credentialStore, storage, context, grant, role, journal, callbacks, instructions }) {
  grant = validateGrant(grant);
  const q = qualification(grant);
  if (!q.callable) reject(q.blockers[0]);
  if (grant.mode !== 'live') reject('live_entry_requires_live_grant');
  if (Date.now() < grant.startedAtMs || Date.now() >= grant.deadlineMs) reject('deadline_exhausted');
  if (journal.report().attempts.length || journal.blocked()) reject('reopen_requires_reconciliation');
  installedSdk();
  journal.claim(role);
  let timer;
  let harness;
  let cleanupContext;
  try {
    const [{ ModelRuntime }, { Harness, createRegistry }, { AssistantMessageEventStream }, { withoutAbortSignal }] = await Promise.all([
    import('@earendil-works/pi-coding-agent'), import('@earendil-works/pi-durable'), import('@earendil-works/pi-ai'),
    import('@earendil-works/chord/context'),
  ]);
  cleanupContext = withoutAbortSignal(context);
  const deadline = new AbortController();
  timer = setTimeout(() => deadline.abort(), Math.max(0, grant.deadlineMs - Date.now())); timer.unref();
  const hostSignal = AbortSignal.any([deadline.signal, ...(context.abortSignal ? [context.abortSignal] : [])]);
  const managedModelRuntime = await ModelRuntime.create({
    credentials: subscriptionCredentials(credentialStore), modelsPath: null,
    refreshOnCreate: false, allowModelNetwork: false, signal: hostSignal,
  });
  const models = guardedModels(managedModelRuntime, { grant, role, journal, AssistantMessageEventStream, hostSignal });
  const tools = narrowTools(role, callbacks, { grant, journal, hostSignal });
  const extension = { name: 'autofv-scoped-callbacks', tools };
  const registry = createRegistry();
  registry.install(extension);
  harness = await Harness.open(storage, {
    models, registry, settings: { ...SETTINGS, extensions: [extension] },
    // onReport errors may contain arbitrary SDK/store data; never retain them.
    onReport: () => {},
  }, context);
    const state = await harness.inspect(context);
    // Opening is passive. Recovered work requires explicit reconciliation; never resume here.
    if (state.tasks.length || state.submissions.length) reject('recovered_work_requires_reconciliation');
    const conversation = await harness.createConversation({ ownership: { kind: 'ownerless' }, agent: {
      model: { provider: 'openai', modelId: grant.roleModels[role] }, thinkingLevel: 'off',
      extensions: [extension], tools, modelTools: tools, instructions,
    } }, context);
    const cancel = () => {
      try { journal.quarantine('role_cancelled_uncertain'); } catch { /* Existing reservations remain fail-closed. */ }
      void conversation.abort(cleanupContext, { background: true }).catch(() => {});
    };
    hostSignal.addEventListener('abort', cancel, { once: true });
    if (hostSignal.aborted) cancel();
    // Keep raw Harness/Conversation methods (manual compaction, forking, tasks) private.
    return Object.freeze({
      async submit(requestId, content) {
        try {
          if (hostSignal.aborted) reject('role_cancelled_uncertain');
          const submission = await conversation.submit({ type: 'input', requestId, content, whenBusy: 'reject' }, cleanupContext);
          return await withAbort(submission.wait(cleanupContext), hostSignal);
        } catch (error) { throw new BoundaryError(failureCode(error)); }
      },
      async abort() {
        try { deadline.abort(); await conversation.abort(cleanupContext, { background: true }); }
        catch (error) { throw new BoundaryError(failureCode(error)); }
      },
      async close() {
        clearTimeout(timer); hostSignal.removeEventListener('abort', cancel);
        try { await harness.close(cleanupContext); }
        catch (error) { throw new BoundaryError(failureCode(error)); }
      },
      report() { return { qualification: q, ...journal.report() }; },
    });
  } catch (error) {
    clearTimeout(timer);
    try { await harness?.close(cleanupContext); } catch { /* Do not disclose SDK cleanup diagnostics. */ }
    throw new BoundaryError(failureCode(error));
  }
}
