/** Private, canonical newline-delimited IPC. No caller-selected executable code. */
import { createHash } from 'node:crypto';
export const PROTOCOL = 'autofv-pi-ipc/v1';
export const MAX_FRAME_BYTES = 2 * 1024 * 1024;
export const MAX_CONTINUATION_BYTES = 256 * 1024;
export class BoundaryError extends Error {
  constructor(code) { super(code); this.code = code; }
}
export function reject(code) { throw new BoundaryError(code); }
export function exact(value, required, optional = []) {
  if (!value || Array.isArray(value) || Object.getPrototypeOf(value) !== Object.prototype
      || required.some(k => !Object.hasOwn(value, k))
      || Object.keys(value).some(k => !required.includes(k) && !optional.includes(k))) reject('invalid_shape');
  return value;
}
export function bounded(value, depth = 0, budget = {n: 0}) {
  if (depth > 24 || ++budget.n > 32768) reject('structure_limit');
  if (value === null || typeof value === 'boolean') return;
  if (typeof value === 'string') {
    if (Buffer.byteLength(value) > MAX_FRAME_BYTES || /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/u.test(value)) reject('invalid_string');
    return;
  }
  if (typeof value === 'number' && Number.isSafeInteger(value)) return;
  if (Array.isArray(value)) { for (const v of value) bounded(v, depth + 1, budget); return; }
  if (value && Object.getPrototypeOf(value) === Object.prototype) {
    for (const [k, v] of Object.entries(value)) { bounded(k, depth + 1, budget); bounded(v, depth + 1, budget); }
    return;
  }
  reject('invalid_json');
}
export function canonical(value) {
  bounded(value);
  const sort = v => Array.isArray(v) ? v.map(sort) : v && typeof v === 'object'
    ? Object.fromEntries(Object.keys(v).sort().map(k => [k, sort(v[k])])) : v;
  return JSON.stringify(sort(value));
}
export function digest(value) { return createHash('sha256').update(canonical(value)).digest('hex'); }
export function parseFrame(raw) {
  if (!Buffer.isBuffer(raw) || raw.length > MAX_FRAME_BYTES) reject('frame_limit');
  let text, value;
  try { text = new TextDecoder('utf-8', {fatal: true}).decode(raw); value = JSON.parse(text); }
  catch { reject('invalid_json'); }
  // Canonical input rejects duplicate keys, invalid escapes, and float aliases.
  if (canonical(value) !== text) reject('noncanonical_json');
  if (value.v !== 1 || !['hello', 'generate_one', 'cancel', 'close'].includes(value.op)) reject('invalid_protocol');
  const fields = value.op === 'generate_one' ? ['v', 'op', 'payload'] : value.op === 'cancel'
    ? ['v', 'op', 'request_id', 'sequence'] : ['v', 'op'];
  exact(value, fields);
  return value;
}
export function encodeFrame(value) {
  const text = canonical(value);
  if (Buffer.byteLength(text) > MAX_FRAME_BYTES) reject('frame_limit');
  return text + '\n';
}
export function identifier(value, max = 200) {
  if (typeof value !== 'string' || !value.length || value.length > max || !/^[A-Za-z0-9._:-]+$/.test(value)) reject('invalid_identity');
  return value;
}
export function sha(value) { if (typeof value !== 'string' || !/^[a-f0-9]{64}$/.test(value)) reject('invalid_digest'); return value; }
export function requestIdentity(value) {
  exact(value, ['run_id', 'conversation_id', 'request_id', 'sequence', 'role', 'model_id', 'history_sha256', 'profile_sha256']);
  for (const k of ['run_id', 'conversation_id', 'request_id', 'role', 'model_id']) identifier(value[k]);
  for (const k of ['history_sha256', 'profile_sha256']) sha(value[k]);
  if (!Number.isSafeInteger(value.sequence) || value.sequence < 1) reject('invalid_sequence');
  if (!['scout','dependency_planner','specifier','spec_reviewer','prover','proof_reviewer','repair','verification_adviser'].includes(value.role)) reject('invalid_role');
  return value;
}
export function failureCode(error) {
  if (error instanceof BoundaryError) return error.code;
  const message = typeof error?.errorMessage === 'string' ? error.errorMessage.slice(0, 8192) : '';
  if (error?.status === 429 || /subscription_sharing_usage_limit_exceeded|insufficient_quota|rate_limit_exceeded/.test(message)) return 'quota_terminal';
  if (['auth','oauth'].includes(error?.code) || [401,403].includes(error?.status)) return 'auth_terminal';
  return 'transport_uncertain';
}
