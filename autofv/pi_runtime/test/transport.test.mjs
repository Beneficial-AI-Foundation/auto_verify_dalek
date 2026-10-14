import assert from 'node:assert/strict';
import { test } from 'node:test';
import { PassThrough } from 'node:stream';
import { canonical, digest, encodeFrame, parseFrame, MAX_FRAME_BYTES } from '../protocol.mjs';
import { generateOne, validatePayload } from '../generation.mjs';
import { restoreHistory, projectContinuation, validateContinuation } from '../continuation.mjs';
import { subscriptionCredentials } from '../managed-store.mjs';
import { guardedFetch } from '../network.mjs';
import { serve } from '../transport.mjs';
import { SDK_VERSIONS } from '../sdk-versions.mjs';
import { payload, terminal, fakeRuntime, nextPayload } from './helpers.mjs';
const signal = () => new AbortController().signal;

test('canonical strict frames reject duplicates, extra fields, float aliases, invalid UTF-8 and oversize', () => {
  assert.deepEqual(parseFrame(Buffer.from(canonical({v:1,op:'hello'}))),{v:1,op:'hello'});
  for (const raw of ['{"op":"hello","v":1,"v":1}','{"op":"hello","v":1.0}','{"extra":1,"op":"hello","v":1}']) assert.throws(()=>parseFrame(Buffer.from(raw)));
  assert.throws(()=>parseFrame(Buffer.from([255])));
  assert.throws(()=>parseFrame(Buffer.alloc(MAX_FRAME_BYTES+1)));
  assert.throws(()=>canonical({n:Infinity}));
});
test('one typed generation retains native reasoning/phase/ID only in host continuation', async () => {
  const first = payload(), runtime = fakeRuntime();
  const result = await generateOne(runtime,first,signal());
  assert.equal(runtime.calls,1);
  assert.deepEqual(result.usage,{input:7,output:8,cacheRead:2,cacheWrite:3,totalTokens:20,reasoning:5});
  assert.equal(result.continuation.native.tool_call_id,'call_1|fc_1');
  assert.doesNotMatch(JSON.stringify(result),/PRIVATE_SUMMARY/);
  const next = nextPayload(first,result), restored = validatePayload(next);
  assert.equal(restored.messages[1].content[0].thinking,'');
  assert.equal(restored.messages[1].content[0].thinkingSignature,result.continuation.native.content[0].thinkingSignature);
  assert.equal(restored.messages[1].content[1].textSignature,result.continuation.native.content[1].textSignature);
  assert.equal(restored.messages[2].toolCallId,'call_1|fc_1');
});
test('multiple calls, extra tool arguments and arbitrary native state are refused', async () => {
  const m = terminal(); m.content.push(m.content.at(-1));
  await assert.rejects(generateOne(fakeRuntime(m),payload(),signal()),/multiple_or_missing/);
  const bad = terminal(); bad.content.at(-1).arguments.extra = true;
  assert.throws(()=>projectContinuation(bad,payload().request),/invalid_shape/);
  const r = projectContinuation(terminal(),payload().request);
  r.native.content[0].thinkingSignature = JSON.stringify({id:'fc_evil',type:'function_call',summary:[]});
  assert.throws(()=>validateContinuation(r),/invalid_continuation/);
});
test('reject missing continuation, drifted history, unpaired tool results and extra prior records', async () => {
  const p=payload(), r=await generateOne(fakeRuntime(),p,signal());
  const n=nextPayload(p,r);
  for (const mutate of [v=>v.continuations=[],v=>v.messages[3].tool_call_id='other',v=>v.messages.pop(),v=>v.messages[0].content='changed',v=>v.continuations.push(v.continuations[0])]) {
    const bad=structuredClone(n); mutate(bad); bad.request.history_sha256=digest(bad.messages);
    assert.throws(()=>validatePayload(bad));
  }
});
test('exact xhigh required profile rejects unsafe options/model mapping and unsupported roles', async () => {
  for (const field of ['apiKey','headers','fetch','onPayload','maxTokens']) {const p=payload();p.profile[field]='bad';assert.throws(()=>validatePayload(p));}
  const p=payload(); p.profile.effort='high'; assert.throws(()=>validatePayload(p));
  const r=fakeRuntime();const lookup=r.getModel;r.getModel=()=>({...lookup(),thinkingLevelMap:{xhigh:'high'}});
  await assert.rejects(generateOne(r,payload(),signal()),/unsupported_model_profile/); assert.equal(r.calls,0);
  for (const role of ['scout','dependency_planner','verification_adviser']) {const x=payload();x.request.role=role;assert.ok(validatePayload(x));}
});
test('OAuth-only guard uses locked read, refuses missing, API-key and other providers', async () => {
  for (const current of [undefined,{type:'api_key',key:'!echo hostile'}]) {
    const store=subscriptionCredentials({read(){assert.fail('raw read called');},async modify(id,fn){return (await fn(current))??current;}});
    await assert.rejects(store.read('openai'),/subscription_auth_required/);
    await assert.rejects(store.read('other'),/provider_not_allowed/);
  }
});
test('fetch egress restricts destinations and methods, disables redirects', async () => {
  let calls=0; const fetch=guardedFetch(async (url,init)=>{calls++;assert.equal(init.redirect,'error');return new Response('{}');});
  await fetch('https://api.openai.com/v1/responses',{method:'POST'});
  for (const url of ['https://evil.example/','https://api.openai.com/v1/models','https://api.openai.com/v1/responses?token=secret']) await assert.rejects(fetch(url,{method:'POST'}),/egress_refused/);
  await assert.rejects(fetch('https://api.openai.com/v1/responses'),/egress_refused/);assert.equal(calls,1);
});
test('IPC burns one-use IDs, quarantines, requires hello, supports close', async () => {
  const input=new PassThrough(), output=new PassThrough();let raw='';output.on('data',c=>raw+=c);
  const runtime=fakeRuntime();const server=serve({input,output,createRuntime:async()=>runtime,sdk:SDK_VERSIONS});
  input.write(encodeFrame({v:1,op:'hello'})); input.write(encodeFrame({v:1,op:'generate_one',payload:payload()}));
  await new Promise(r=>setTimeout(r,20));
  input.write(encodeFrame({v:1,op:'generate_one',payload:payload()}));await new Promise(r=>setTimeout(r,20));
  const frames=raw.trim().split('\n').map(JSON.parse);assert.equal(frames[0].op,'hello');assert.equal(frames[1].op,'result');assert.equal(frames[2].code,'duplicate_request');assert.equal(runtime.calls,1);
  input.write(encodeFrame({v:1,op:'close'}));server.close();
});
test('malformed stdout input cannot inject trace or start runtime', async () => {
  const input=new PassThrough(), output=new PassThrough();let raw='';output.on('data',c=>raw+=c);
  serve({input,output,createRuntime:()=>assert.fail('runtime initialized'),sdk:SDK_VERSIONS});
  input.write('NOT JSON\n');await new Promise(r=>setTimeout(r,10));assert.equal(JSON.parse(raw).code,'invalid_json');
});
test('raw provider stream bounds unknown SSE bytes before SDK parsing',async()=>{
  const {MAX_PROVIDER_WIRE_BYTES}=await import('../network.mjs');
  let cancelled=false;
  const fetch=guardedFetch(async()=>new Response(new ReadableStream({
    start(controller){controller.enqueue(new Uint8Array(MAX_PROVIDER_WIRE_BYTES));controller.enqueue(new Uint8Array(1));},
    cancel(){cancelled=true;},
  }),{headers:{'content-type':'text/event-stream'}}));
  const response=await fetch('https://api.openai.com/v1/responses',{method:'POST'});
  await assert.rejects(response.text(),/provider_wire_limit/);assert.equal(cancelled,true);
  const headerFetch=guardedFetch(async()=>new Response('x',{headers:{'content-length':String(MAX_PROVIDER_WIRE_BYTES+1)}}));
  await assert.rejects(headerFetch('https://api.openai.com/v1/responses',{method:'POST'}),/provider_wire_limit/);
});
