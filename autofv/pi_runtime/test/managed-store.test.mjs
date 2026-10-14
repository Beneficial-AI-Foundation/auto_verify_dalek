import assert from 'node:assert/strict';
import { test } from 'node:test';
import { mkdtemp, writeFile, readFile, chmod, symlink, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { openManagedStore, subscriptionCredentials, initializeManagedStore } from '../managed-store.mjs';
import { provision } from '../setup.mjs';
const credential=()=>({type:'oauth',access:'SYNTHETIC_ACCESS',refresh:'SYNTHETIC_REFRESH',expires:Date.now()+86400000,clientId:'SYNTHETIC_CLIENT',scopes:['api.responses.write']});
async function fixture(t) {
  const dir=await mkdtemp(join(tmpdir(),'pi-store-test-'));t.after(()=>rm(dir,{recursive:true,force:true}));
  const path=join(dir,'credential.json');
  const {account_binding_sha256:binding}=await initializeManagedStore(path,credential());
  const value=JSON.parse(await readFile(path,'utf8'));return {dir,path,value,binding};
}
test('dedicated store reads under lock, persists SDK refresh, never exports metadata secrets',async t=>{
  const f=await fixture(t),store=subscriptionCredentials(openManagedStore(f.path,f.binding));
  assert.deepEqual(await store.list(),[{providerId:'openai',type:'oauth'}]);
  await store.modify('openai',async c=>({...c,access:'SYNTHETIC_REFRESHED',refresh:'SYNTHETIC_ROTATED'}));
  assert.equal((await store.read('openai')).access,'SYNTHETIC_REFRESHED');
  assert.equal(JSON.parse(await readFile(f.path,'utf8')).credential.refresh,'SYNTHETIC_ROTATED');
});
test('store rejects external replacement and different provisioned binding',async t=>{
  const f=await fixture(t),store=openManagedStore(f.path,f.binding);await store.read('openai');
  f.value.credential.access='REPLACEMENT_ACCOUNT';await writeFile(f.path,JSON.stringify(f.value));
  await assert.rejects(store.read('openai'),/managed_account_changed/);
  await assert.rejects(openManagedStore(f.path,'b'.repeat(64)).read('openai'),/managed_account_changed/);
});
test('store rejects command keys, client replacement, insecure permissions, symlinks and locks',async t=>{
  const f=await fixture(t),store=openManagedStore(f.path,f.binding);
  await assert.rejects(store.modify('openai',async c=>({...c,clientId:'OTHER'})),/managed_account_changed/);
  await chmod(f.path,0o644);await assert.rejects(store.read('openai'),/unsafe_managed_store/);
  await chmod(f.path,0o600);const link=join(f.dir,'link.json');await symlink(f.path,link);await assert.rejects(openManagedStore(link,f.binding).read('openai'),/unsafe_managed_store/);
  await writeFile(f.path+'.lock','',{mode:0o600});await assert.rejects(store.read('openai'),/managed_store_locked/);
});
test('user-operated provisioning public login seam persists only into new dedicated store',async t=>{
  const base=await mkdtemp(join(tmpdir(),'pi-setup-test-'));t.after(()=>rm(base,{recursive:true,force:true}));
  const directory=join(base,'new-store');let calls=0;
  const metadata=await provision(directory,{interaction:{},deviceId:'fixture-device',login:async(interaction,options)=>{calls++;assert.equal(options.getDeviceId(),'fixture-device');return credential();}});
  assert.equal(calls,1);assert.equal(metadata.model_dispatched,false);assert.equal(metadata.entitlement_validated,false);
  assert.doesNotMatch(JSON.stringify(metadata),/SYNTHETIC_ACCESS|SYNTHETIC_REFRESH/);
  assert.equal((await openManagedStore(metadata.store_path,metadata.account_binding_sha256).read('openai')).type,'oauth');
  await assert.rejects(provision(directory,{interaction:{},login:()=>assert.fail('overwrite login')}));
});

test('signed credential tamper remains rejected after process/store restart',async t=>{
  const f=await fixture(t);
  await openManagedStore(f.path,f.binding).read('openai');
  f.value.credential.clientId='REPLACEMENT_ACCOUNT';f.value.credential.access='REPLACED_ACCESS';
  await writeFile(f.path,JSON.stringify(f.value));
  await assert.rejects(openManagedStore(f.path,f.binding).read('openai'),/managed_account_changed/);
});
test('valid signed refresh reopens and unsigned v1 cannot be adopted',async t=>{
  const f=await fixture(t);
  await openManagedStore(f.path,f.binding).modify('openai',async c=>({...c,access:'ROTATED',refresh:'ROTATED_REFRESH'}));
  assert.equal((await openManagedStore(f.path,f.binding).read('openai')).access,'ROTATED');
  await writeFile(f.path,JSON.stringify({schema:'autofv-pi-managed-store/v1',account_binding_sha256:f.binding,credential:credential()}));
  await assert.rejects(openManagedStore(f.path,f.binding).read('openai'));
});

test('refresh scope order may change but permission additions/removals cannot',async t=>{
  const base=await mkdtemp(join(tmpdir(),'pi-scope-test-'));t.after(()=>rm(base,{recursive:true,force:true}));
  const path=join(base,'credential.json');
  const {account_binding_sha256:binding}=await initializeManagedStore(path,{...credential(),scopes:['resource.invoke','chatgpt.tokens.use.direct']});
  const store=openManagedStore(path,binding);
  await store.modify('openai',async c=>({...c,scopes:[...c.scopes].reverse(),access:'ROTATED'}));
  assert.equal((await openManagedStore(path,binding).read('openai')).access,'ROTATED');
  await assert.rejects(store.modify('openai',async c=>({...c,scopes:[...c.scopes,'unexpected.permission']})),/managed_account_changed/);
});
