/** Opt-in spike policy. This is not an AutoFV run/v2 or a spending authorization. */
import { createHash } from 'node:crypto';

export const SOURCE_COMMIT = '946bd3c73e2a417e3a2f432b9e0faa59511d062e';
export const SDK_SOURCE = '7d75a0e3eb273dff753d49c066ea29fbe7b3b6f6';
export const PROFILE = 'autofv-pi-openai-only-spike/v1';
export const TOOL_NAMES = Object.freeze([
  'read_allowed', 'search_allowed', 'edit_assigned', 'check_lean', 'submit_candidate',
]);
export const ROLES = Object.freeze([
  'scout', 'dependency_planner', 'specifier', 'spec_reviewer', 'prover',
  'proof_reviewer', 'repair', 'verification_adviser',
]);
export const SDK_VERSIONS = Object.freeze({
  '@earendil-works/chord': '1.2.0',
  '@earendil-works/pi-ai': '1.2.0',
  '@earendil-works/pi-coding-agent': '1.2.0',
  '@earendil-works/pi-durable': '1.2.0',
});
export const SETTINGS = Object.freeze({
  retry: Object.freeze({ enabled: false, maxRetries: 0 }),
  compaction: Object.freeze({ enabled: false, backgroundTokens: 0 }),
  stream: Object.freeze({ maxRetries: 0, deferred: false, cacheRetention: 'none', transport: 'sse' }),
  toolExecution: 'sequential',
});

export class BoundaryError extends Error {
  constructor(code) { super(code); this.name = 'BoundaryError'; this.code = code; }
}
export function reject(code) { throw new BoundaryError(code); }
export function canonical(value) {
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.keys(value).sort().map(k => `${JSON.stringify(k)}:${canonical(value[k])}`).join(',')}}`;
  }
  const text = JSON.stringify(value);
  if (text === undefined) reject('non_json_value');
  return text;
}
export function digest(value) { return createHash('sha256').update(canonical(value)).digest('hex'); }

/** Persist this original grant unchanged; reopen must never mint a fresh clock. */
export function validateGrant(value) {
  const fields = ['schema', 'runId', 'mode', 'roleModels', 'startedAtMs', 'deadlineMs',
    'maxInvocations', 'requestTimeoutMs', 'serverOutputCap', 'approvalId',
    'acceptsUnknownCost', 'acceptsBestEffortCancellation', 'entitlementValidated',
    'isolationEvidenceSha256', 'callbackLifecycleEvidenceSha256'];
  if (!value || canonical(Object.keys(value).sort()) !== canonical(fields.sort())) reject('invalid_grant');
  const g = structuredClone(value);
  if (g.schema !== PROFILE || !['synthetic', 'live'].includes(g.mode)
      || !/^[A-Za-z0-9_-]{1,100}$/.test(g.runId)
      || canonical(Object.keys(g.roleModels).sort()) !== canonical([...ROLES].sort())
      || Object.values(g.roleModels).some(m => typeof m !== 'string' || !/^[a-zA-Z0-9._-]{1,100}$/.test(m))
      || ['startedAtMs', 'deadlineMs', 'maxInvocations', 'requestTimeoutMs'].some(k => !Number.isSafeInteger(g[k]) || g[k] <= 0)
      || g.deadlineMs <= g.startedAtMs || g.maxInvocations > 1000
      || g.deadlineMs - g.startedAtMs > 2147483647
      || g.requestTimeoutMs > g.deadlineMs - g.startedAtMs
      || ![null, 16384].includes(g.serverOutputCap)
      || ![g.acceptsUnknownCost, g.acceptsBestEffortCancellation, g.entitlementValidated].every(v => typeof v === 'boolean')
      || [g.isolationEvidenceSha256, g.callbackLifecycleEvidenceSha256]
        .some(v => v !== null && (typeof v !== 'string' || !/^[a-f0-9]{64}$/.test(v)))
      || !(g.approvalId === null || /^[a-zA-Z0-9_-]{1,100}$/.test(g.approvalId))) reject('invalid_grant');
  return g;
}

export function qualification(value) {
  const g = validateGrant(value);
  const blockers = [];
  if (g.mode === 'live') {
    if (g.approvalId === null) blockers.push('live_approval_missing');
    if (!g.entitlementValidated) blockers.push('exact_model_entitlement_unvalidated');
    if (g.serverOutputCap !== null) blockers.push('subscription_server_output_cap_unsupported');
    if (!g.acceptsUnknownCost) blockers.push('subscription_cost_unknown');
    if (!g.acceptsBestEffortCancellation) blockers.push('upstream_cancellation_not_guaranteed');
    if (g.isolationEvidenceSha256 === null) blockers.push('sealed_isolation_unqualified');
    if (g.callbackLifecycleEvidenceSha256 === null) blockers.push('callback_process_cancellation_unqualified');
  }
  return {
    profile: PROFILE, mode: g.mode, callable: blockers.length === 0, blockers,
    sourceCommit: SOURCE_COMMIT, sdkSource: SDK_SOURCE, sdkVersions: SDK_VERSIONS,
    authMode: 'managed_openai_subscription_only', roleModels: g.roleModels,
    currentFvsEquivalent: false, serverOutputCapEnforced: false,
    enforcement: ['original_deadline', 'invocation_limit', 'abort_signal', 'uncertain_request_quarantine'],
    limitations: ['abort_does_not_prove_upstream_stop', 'subscription_cost_unknown',
      'no_billing_receipt', 'no_live_isolation_or_success_evidence'],
  };
}

/** Only inspect the public type tag. Never copy, serialize, or export token fields. */
export function subscriptionCredentials(store) {
  const checked = (credential) => {
    if (credential?.type !== 'oauth') reject('subscription_auth_required');
    return credential;
  };
  const provider = id => { if (id !== 'openai') reject('provider_not_allowed'); };
  return Object.freeze({
    async read(id, options) {
      provider(id);
      // Some stores resolve command-backed API keys in read() before returning
      // their type. Inspect the raw credential under the public mutation lock;
      // undefined leaves it unchanged and cannot execute that read-time command.
      return checked(await store.modify(id, async current => { checked(current); return undefined; }, options));
    },
    async list(options) {
      const entries = await store.list(options);
      if (entries.length !== 1 || entries[0].providerId !== 'openai' || entries[0].type !== 'oauth') {
        reject('subscription_auth_required');
      }
      return [{ providerId: 'openai', type: 'oauth' }];
    },
    async modify(id, fn, options) {
      provider(id);
      return checked(await store.modify(id, async current => {
        checked(current);
        const next = await fn(current);
        if (next !== undefined) checked(next);
        return next;
      }, options));
    },
    async delete() { reject('auth_mutation_not_allowed'); },
  });
}

/** Do not persist provider error text, causes, headers, credentials, or request objects. */
export function failureCode(error) {
  if (error instanceof BoundaryError) return error.code;
  const status = error?.status ?? error?.statusCode;
  const message = typeof error?.errorMessage === 'string' ? error.errorMessage.slice(0, 8192) : '';
  if (status === 429 || error?.code === 'insufficient_quota'
      || /subscription_sharing_usage_limit_exceeded|insufficient_quota|rate_limit_exceeded/.test(message)) {
    return 'quota_terminal';
  }
  if ([401, 403].includes(status) || ['auth', 'oauth'].includes(error?.code)) return 'auth_terminal';
  return 'transport_uncertain';
}
