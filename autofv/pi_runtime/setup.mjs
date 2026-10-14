/** Explicit, human-operated local provisioning only. No model generation. */
import { mkdir, open, lstat } from 'node:fs/promises';
import { isAbsolute, join } from 'node:path';
import { createInterface } from 'node:readline/promises';
import { randomUUID } from 'node:crypto';
import { pathToFileURL } from 'node:url';
import { canonical, failureCode, reject } from './protocol.mjs';
import { installedSdk } from './sdk-versions.mjs';
import { guardedFetch } from './network.mjs';
import { initializeManagedStore } from './managed-store.mjs';

export async function provision(directory, {login, interaction, deviceId = randomUUID()} = {}) {
  if (!isAbsolute(directory)) reject('setup_path_not_absolute');
  if (!login) installedSdk();
  // Existing directories/stores are never overwritten or adopted implicitly.
  await mkdir(directory,{mode:0o700});
  const s = await lstat(directory);
  if (!s.isDirectory() || s.isSymbolicLink() || s.uid !== process.getuid() || (s.mode & 0o077)) reject('unsafe_managed_store');
  let credential;
  const memory = {read:async () => credential,list:async () => credential ? [{providerId:'openai',type:'oauth'}] : [],
    async modify(id,fn) { if (id !== 'openai') reject('provider_not_allowed'); credential = (await fn(credential)) ?? credential; return credential; },
    async delete() { reject('auth_mutation_not_allowed'); }};
  if (!login) {
    globalThis.fetch = guardedFetch(globalThis.fetch.bind(globalThis));
    const {ModelRuntime} = await import('@earendil-works/pi-coding-agent');
    const runtime = await ModelRuntime.create({credentials:memory,modelsPath:null,refreshOnCreate:false,allowModelNetwork:false});
    login = (events,options) => runtime.login('openai','oauth',events,options);
  }
  const selected = await login(interaction,{getDeviceId:() => deviceId,agentName:'AutoFV dedicated subscription transport'});
  if (!selected || selected.type !== 'oauth' || typeof selected.clientId !== 'string' || !Array.isArray(selected.scopes)) reject('subscription_auth_required');
  const path = join(directory,'credential.json');
  const {account_binding_sha256} = await initializeManagedStore(path,selected);
  const metadata = {schema:'autofv-pi-provisioning/v1',store_path:path,account_binding_sha256,device_id:deviceId,
    account_identity:'human-selected-login; not independently reported by SDK',entitlement_validated:false,model_dispatched:false};
  const meta = await open(join(directory,'provisioning.json'),'wx',0o600);
  try { await meta.writeFile(canonical(metadata)+'\n'); await meta.sync(); } finally { await meta.close(); }
  const dir = await open(directory,'r'); try { await dir.sync(); } finally { await dir.close(); }
  return metadata;
}
async function main() {
  if (process.argv.length !== 4 || process.argv[2] !== '--new-store') reject('invalid_startup');
  if (!process.stdin.isTTY || !process.stdout.isTTY) reject('interactive_setup_required');
  const rl = createInterface({input:process.stdin,output:process.stdout});
  const abort = new AbortController(); process.once('SIGINT',() => abort.abort());
  try {
    process.stdout.write('This starts a separate ChatGPT sign-in and saves OAuth credentials in a NEW dedicated local store. It makes no model request. Choose the intended account in the browser.\n');
    const answer = await rl.question('Type SIGN IN to continue: ');
    if (answer !== 'SIGN IN') reject('setup_cancelled');
    const metadata = await provision(process.argv[3],{interaction:{signal:abort.signal,
      async prompt(event) {
        if (!['manual_code','text'].includes(event.type)) reject('unsupported_auth_prompt');
        return rl.question(event.message+' ',{signal:event.signal ?? abort.signal});
      },
      notify(event) {
        if (event.type === 'auth_url') process.stdout.write('Open this official sign-in URL in your browser:\n'+event.url+'\n');
        else if (event.type === 'progress') process.stdout.write('Completing the sign-in...\n');
      },
    }});
    process.stdout.write('Dedicated store created. Provisioning metadata (no credentials):\n'+JSON.stringify(metadata,null,2)+'\n');
  } finally { rl.close(); }
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch(error => { process.stderr.write('Setup stopped: '+failureCode(error)+'\n'); process.exitCode = 1; });
}
