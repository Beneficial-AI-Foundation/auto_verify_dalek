/** Actual pinned SDK, intercepted HTTP only, synthetic auth. No live model. */
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { ModelRuntime } from '@earendil-works/pi-coding-agent';
import { generateOne } from '../generation.mjs';
import { subscriptionCredentials } from '../managed-store.mjs';
import { installedSdk, SDK_VERSIONS } from '../sdk-versions.mjs';
import { guardedFetch } from '../network.mjs';
import { payload, nextPayload, sseResponse } from '../test/helpers.mjs';
function store(value={type:'oauth',access:'SYNTHETIC_ACCESS',refresh:'SYNTHETIC_REFRESH',expires:Date.now()+86400000,clientId:'SYNTHETIC_CLIENT',scopes:['api.responses.write']}) {
  return {async read(){assert.fail('raw read');},async list(){return value ? [{providerId:'openai',type:value.type}] : [];},async modify(id,fn){value=(await fn(value))??value;return value;},async delete(){assert.fail('delete');}};
}
const runtime = credentials => ModelRuntime.create({credentials:subscriptionCredentials(credentials),modelsPath:null,refreshOnCreate:false,allowModelNetwork:false});
const signal=()=>new AbortController().signal;
test('installed metadata exact and single pi-ai module identity',()=>assert.deepEqual(installedSdk(),SDK_VERSIONS));
test('real typed SDK request is required xhigh, no server cap or retries, native continuation exact',async t=>{
  const bodies=[];
  t.mock.method(globalThis,'fetch',guardedFetch(async (input,init)=>{
    const body=JSON.parse(init?.body ?? await input.text());bodies.push(body);
    assert.equal(body.reasoning.effort,'xhigh');assert.equal(body.tool_choice,'required');
    assert.equal(body.max_output_tokens,undefined);assert.equal(body.previous_response_id,undefined);assert.equal(body.store,false);
    assert.equal(body.tools.length,5);assert.equal(body.stream,true);
    return sseResponse();
  }));
  const rt=await runtime(store()), p=payload(); const result=await generateOne(rt,p,signal());
  assert.equal(result.observed_model,'gpt-6.1-sol');assert.equal(result.observed_effort,'xhigh');assert.equal(result.usage.input,7);
  await generateOne(rt,nextPayload(p,result),signal());assert.equal(bodies.length,2);
  const native=bodies[1].input;
  assert.deepEqual(native.find(i=>i.type==='reasoning'),{id:'rs_1',type:'reasoning',summary:[],encrypted_content:'PRIVATE_ENCRYPTED'});
  assert.equal(native.find(i=>i.type==='message'&&i.role==='assistant').phase,'commentary');
  assert.equal(native.find(i=>i.type==='function_call').call_id,'call_1');
  assert.equal(native.find(i=>i.type==='function_call').id,'fc_1');
  assert.equal(native.find(i=>i.type==='function_call_output').call_id,'call_1');
  assert.doesNotMatch(JSON.stringify(bodies),/SYNTHETIC_ACCESS|SYNTHETIC_REFRESH/);
});
test('actual SDK multiple tool calls and missing usage cannot become completed responses',async t=>{
  for (const options of [{extraCalls:true},{missingUsage:true},{model:'wrong-model'}]) {
    t.mock.method(globalThis,'fetch',async()=>sseResponse(options));
    await assert.rejects(generateOne(await runtime(store()),payload(),signal()));
  }
});
test('quota failure makes one intercepted HTTP attempt without raw error propagation',async t=>{
  let calls=0;t.mock.method(globalThis,'fetch',async()=>{calls++;return new Response(JSON.stringify({error:{message:'PRIVATE_QUOTA_CANARY',code:'subscription_sharing_usage_limit_exceeded'}}),{status:429,headers:{'content-type':'application/json'}});});
  await assert.rejects(generateOne(await runtime(store()),payload(),signal()));assert.equal(calls,1);
});
test('actual runtime missing credential cannot fall back to ambient key',async t=>{
  t.mock.method(globalThis,'fetch',()=>assert.fail('network fallback'));
  const prior=process.env.OPENAI_API_KEY;process.env.OPENAI_API_KEY='SYNTHETIC_FORBIDDEN_KEY';
  try {await assert.rejects(generateOne(await runtime(store(null)),payload(),signal()));}
  finally {if(prior===undefined)delete process.env.OPENAI_API_KEY;else process.env.OPENAI_API_KEY=prior;}
});
test('actual expired OAuth only refreshes approved endpoint once and never dispatches',async t=>{
  let calls=0;t.mock.method(globalThis,'fetch',guardedFetch(async input=>{calls++;assert.equal(String(input),'https://auth.openai.com/api/accounts/oauth/token');return new Response('{"error":"invalid_grant"}',{status:400,headers:{'content-type':'application/json'}});}));
  const expired={type:'oauth',access:'SYNTHETIC_EXPIRED',refresh:'SYNTHETIC_REFRESH',expires:1,clientId:'SYNTHETIC_CLIENT',scopes:['api.responses.write']};
  await assert.rejects(generateOne(await runtime(store(expired)),payload(),signal()));assert.equal(calls,1);
});
test('actual SDK refresh uses production dedicated store and persists rotation before generation',async t=>{
  const {mkdtemp,writeFile,readFile,rm}=await import('node:fs/promises');
  const {tmpdir}=await import('node:os');const {join}=await import('node:path');
  const {openManagedStore,initializeManagedStore}=await import('../managed-store.mjs');
  const directory=await mkdtemp(join(tmpdir(),'pi-sdk-refresh-'));t.after(()=>rm(directory,{recursive:true,force:true}));
  const path=join(directory,'credential.json');
  const {account_binding_sha256:binding}=await initializeManagedStore(path,{type:'oauth',access:'SYNTHETIC_EXPIRED',refresh:'SYNTHETIC_REFRESH',expires:1,clientId:'SYNTHETIC_CLIENT',scopes:['chatgpt.tokens.use.direct']});
  const targets=[];
  t.mock.method(globalThis,'fetch',guardedFetch(async(input,init)=>{
    const target=typeof input==='string'?input:input.url;targets.push(target);
    if(target==='https://auth.openai.com/api/accounts/oauth/token') return new Response(JSON.stringify({access_token:'SYNTHETIC_ROTATED_ACCESS',refresh_token:'SYNTHETIC_ROTATED_REFRESH',scope:'chatgpt.tokens.use.direct',expires_in:3600}),{status:200,headers:{'content-type':'application/json'}});
    return sseResponse();
  }));
  const result=await generateOne(await runtime(openManagedStore(path,binding)),payload(),signal());
  assert.deepEqual(targets,['https://auth.openai.com/api/accounts/oauth/token','https://api.openai.com/v1/responses']);
  assert.equal(JSON.parse(await readFile(path,'utf8')).credential.refresh,'SYNTHETIC_ROTATED_REFRESH');
  assert.doesNotMatch(JSON.stringify(result),/SYNTHETIC_ROTATED|SYNTHETIC_EXPIRED|SYNTHETIC_REFRESH/);
});
test('SDK lookup cannot use dependencies from parent/outside dedicated runtime directory',()=>{
  assert.throws(()=>installedSdk(new URL('../test/no-local-node-modules.mjs',import.meta.url).href),/sdk_not_installed/);
});
