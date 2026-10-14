/** App-owned dedicated CredentialStore. Never reads Pi/CLI auth files or logs values.
 * Provisioning is separate and requires authorization. The binding names that
 * provisioned store lineage; it is not a provider attestation of account identity.
 */
import { constants } from 'node:fs';
import { open, lstat, rename, unlink } from 'node:fs/promises';
import { dirname, isAbsolute, join } from 'node:path';
import { randomUUID, randomBytes, generateKeyPairSync, createPrivateKey, createPublicKey, sign, verify } from 'node:crypto';
import { canonical, digest, exact, reject, sha } from './protocol.mjs';
const MAX_STORE_BYTES = 65536;
const STORE_SCHEMA = 'autofv-pi-managed-store/v2';
const KEY_NAME = 'store-signing-key.pem';
function oauth(value) {
  if (!value || value.type !== 'oauth') reject('subscription_auth_required');
  if (!['access','refresh','clientId'].every(k => typeof value[k] === 'string' && value[k].length > 0)
      || !Number.isFinite(value.expires) || !Array.isArray(value.scopes)
      || value.scopes.some(v => typeof v !== 'string')) reject('invalid_managed_credential');
  return value;
}
export function subscriptionCredentials(store) {
  const check = credential => {
    if (credential?.type !== 'oauth') reject('subscription_auth_required');
    return credential;
  };
  const provider = id => { if (id !== 'openai') reject('provider_not_allowed'); };
  return Object.freeze({
    async read(id, options) {
      provider(id);
      return check(await store.modify(id, async current => { check(current); return undefined; }, options));
    },
    async list(options) {
      const entries = await store.list(options);
      if (entries.length !== 1 || entries[0].providerId !== 'openai' || entries[0].type !== 'oauth') reject('subscription_auth_required');
      return [{providerId:'openai',type:'oauth'}];
    },
    async modify(id, fn, options) {
      provider(id);
      return check(await store.modify(id, async current => {
        check(current); const next = await fn(current); if (next !== undefined) check(next); return next;
      }, options));
    },
    async delete() { reject('auth_mutation_not_allowed'); },
  });
}
async function privatePath(path, directory = false) {
  const s = await lstat(path);
  if (s.isSymbolicLink() || (directory ? !s.isDirectory() : !s.isFile()) || s.uid !== process.getuid()
      || (s.mode & 0o077) !== 0) reject('unsafe_managed_store');
  return s;
}
export function openManagedStore(path, accountBinding) {
  if (!isAbsolute(path)) reject('unsafe_managed_store'); sha(accountBinding);
  let priorDigest = null;
  let serial = Promise.resolve();
  async function locked(fn, options = {}) {
    if (options.signal?.aborted) reject('request_aborted_uncertain');
    await privatePath(dirname(path), true);
    let lock;
    try { lock = await open(path + '.lock', constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY | constants.O_NOFOLLOW, 0o600); }
    catch { reject('managed_store_locked'); }
    let temporary;
    try {
      await privatePath(path);
      const handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
      let raw;
      try { if ((await handle.stat()).size > MAX_STORE_BYTES) reject('unsafe_managed_store'); raw = await handle.readFile('utf8'); }
      finally { await handle.close(); }
      let envelope; try { envelope = JSON.parse(raw); } catch { reject('invalid_managed_store'); }
      validateEnvelope(envelope,accountBinding);
      if (priorDigest !== null && digest(envelope) !== priorDigest) reject('managed_account_changed');
      const current = oauth(envelope.credential);
      priorDigest = digest(envelope);
      const next = await fn(structuredClone(current));
      if (next !== undefined) {
        oauth(next);
        // Only the SDK's locked refresh may mutate this store during a run.
        if (next.clientId !== current.clientId || canonical([...new Set(next.scopes)].sort()) !== canonical([...new Set(current.scopes)].sort())) reject('managed_account_changed');
        envelope.credential = next;
        const keyPath = join(dirname(path),KEY_NAME);
        const privateKey = createPrivateKey(await readPrivateFile(keyPath,16384));
        if (createPublicKey(privateKey).export({type:'spki',format:'pem'}) !== envelope.public_key) reject('managed_account_changed');
        envelope.signature = sign(null,Buffer.from(canonical(unsignedEnvelope(envelope))),privateKey).toString('base64');
        validateEnvelope(envelope,accountBinding);
        const bytes = canonical(envelope) + '\n';
        if (Buffer.byteLength(bytes) > MAX_STORE_BYTES) reject('invalid_managed_store');
        temporary = join(dirname(path), '.credential-' + randomUUID());
        const out = await open(temporary, constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY | constants.O_NOFOLLOW, 0o600);
        try { await out.writeFile(bytes); await out.sync(); } finally { await out.close(); }
        await rename(temporary,path); temporary = null;
        const dir = await open(dirname(path), constants.O_RDONLY); try { await dir.sync(); } finally { await dir.close(); }
        priorDigest = digest(envelope);
      }
      return structuredClone(envelope.credential);
    } finally {
      if (temporary) await unlink(temporary).catch(() => {});
      await lock.close(); await unlink(path + '.lock');
    }
  }
  const modify = (id, fn, options) => {
    if (id !== 'openai') reject('provider_not_allowed');
    const result = serial.then(() => locked(fn,options)); serial = result.catch(() => {}); return result;
  };
  return Object.freeze({modify,
    read: (id, options) => modify(id,async () => undefined,options),
    async list(options) { await modify('openai',async () => undefined,options); return [{providerId:'openai',type:'oauth'}]; },
    async delete() { reject('auth_mutation_not_allowed'); },
  });
}

function unsignedEnvelope(envelope) {
  const {signature,...unsigned} = envelope; return unsigned;
}
function validateEnvelope(envelope,accountBinding) {
  exact(envelope,['schema','account_binding_sha256','public_key','lineage','credential','signature']);
  if (envelope.schema !== STORE_SCHEMA || envelope.account_binding_sha256 !== accountBinding
      || typeof envelope.public_key !== 'string' || typeof envelope.signature !== 'string'
      || !/^[a-f0-9]{64}$/.test(envelope.lineage)
      || digest({public_key:envelope.public_key,lineage:envelope.lineage}) !== accountBinding) reject('managed_account_changed');
  let key, signature;
  try { key = createPublicKey(envelope.public_key); signature = Buffer.from(envelope.signature,'base64'); }
  catch { reject('managed_account_changed'); }
  if (key.asymmetricKeyType !== 'ed25519' || signature.length !== 64 || signature.toString('base64') !== envelope.signature
      || !verify(null,Buffer.from(canonical(unsignedEnvelope(envelope))),key,signature)) reject('managed_account_changed');
}
async function readPrivateFile(path,limit = MAX_STORE_BYTES) {
  await privatePath(path);
  const handle = await open(path,constants.O_RDONLY|constants.O_NOFOLLOW);
  try { if ((await handle.stat()).size > limit) reject('unsafe_managed_store'); return await handle.readFile('utf8'); }
  finally { await handle.close(); }
}
/** Node-only provisioning primitive. Caller already owns a freshly created private directory. */
export async function initializeManagedStore(path,credential) {
  if (!isAbsolute(path)) reject('unsafe_managed_store');
  await privatePath(dirname(path),true); oauth(credential);
  const {privateKey,publicKey} = generateKeyPairSync('ed25519');
  const public_key = publicKey.export({type:'spki',format:'pem'});
  const lineage = randomBytes(32).toString('hex');
  const account_binding_sha256 = digest({public_key,lineage});
  const unsigned = {schema:STORE_SCHEMA,account_binding_sha256,public_key,lineage,credential};
  const envelope = {...unsigned,signature:sign(null,Buffer.from(canonical(unsigned)),privateKey).toString('base64')};
  const encoded = canonical(envelope)+'\n';
  if (Buffer.byteLength(encoded) > MAX_STORE_BYTES) reject('invalid_managed_store');
  const keyPath = join(dirname(path),KEY_NAME);
  const key = await open(keyPath,constants.O_CREAT|constants.O_EXCL|constants.O_WRONLY|constants.O_NOFOLLOW,0o600);
  try { await key.writeFile(privateKey.export({type:'pkcs8',format:'pem'})); await key.sync(); }
  finally { await key.close(); }
  const out = await open(path,constants.O_CREAT|constants.O_EXCL|constants.O_WRONLY|constants.O_NOFOLLOW,0o600);
  try { await out.writeFile(encoded); await out.sync(); }
  finally { await out.close(); }
  const directory = await open(dirname(path),'r');try { await directory.sync(); }finally { await directory.close(); }
  return {account_binding_sha256,store_path:path};
}
