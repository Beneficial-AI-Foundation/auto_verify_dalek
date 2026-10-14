/** Fixed offline qualification. Actual SDK, synthetic credentials, intercepted fetch. */
import { writeFileSync } from 'node:fs';
import { serve } from './transport.mjs';
import { SDK_VERSIONS } from './sdk-versions.mjs';
import { guardedFetch } from './network.mjs';
import { canonical, reject } from './protocol.mjs';
import { subscriptionCredentials } from './managed-store.mjs';

const marker = process.argv[2];
if (process.argv.length !== 3 || !marker?.startsWith('/')) reject('invalid_startup');
let underlyingCalls = 0;
const guarded = guardedFetch(async () => { underlyingCalls++; throw new Error('network must remain unused'); });
let rejected = 0;
for (const [url, method] of [
  ['https://example.invalid/', 'POST'],
  ['https://api.openai.com/v1/models', 'GET'],
  ['https://api.openai.com/v1/responses?other=1', 'POST'],
  ['https://api.openai.com/v1/responses', 'GET'],
  ['http://api.openai.com/v1/responses', 'POST'],
  ['https://api.openai.com/v1/responses/other', 'POST'],
]) {
  try { await guarded(url, {method}); } catch { rejected++; }
}
if (rejected !== 6 || underlyingCalls !== 0) reject('qualification_policy_failed');
// Exercise the exact pinned public SDK with synthetic OAuth and an intercepted
// fetch before the cancellation canary blocks. No real credentials/network.
let interceptedRequests = 0;
globalThis.fetch = guardedFetch(async (input, init) => {
  interceptedRequests++;
  const body = JSON.parse(init?.body ?? await input.text());
  if (body.model !== 'gpt-6.1-sol' || body.reasoning?.effort !== 'xhigh'
      || body.tool_choice !== 'required' || body.stream !== true || body.store !== false
      || body.max_output_tokens !== undefined || body.previous_response_id !== undefined
      || body.tools?.length !== 5) reject('qualification_policy_failed');
  const item = {type:'function_call',id:'fc_qualification',call_id:'call_qualification',
    name:'check_lean',arguments:'{}',status:'completed'};
  const events = [
    {type:'response.created',response:{id:'resp_qualification'}},
    {type:'response.output_item.added',output_index:0,item},
    {type:'response.output_item.done',output_index:0,item},
    {type:'response.completed',response:{id:'resp_qualification',model:'gpt-6.1-sol',
      status:'completed',reasoning:{effort:'xhigh'},output:[item],
      usage:{input_tokens:1,output_tokens:1,total_tokens:2}}},
  ];
  return new Response(events.map(event => 'event: '+event.type+'\ndata: '+JSON.stringify(event)+'\n\n').join('')
    +'data: [DONE]\n\n', {status:200,headers:{'content-type':'text/event-stream'}});
});
let credential = {type:'oauth',access:'SYNTHETIC_QUALIFICATION_ACCESS',refresh:'SYNTHETIC_QUALIFICATION_REFRESH',
  clientId:'SYNTHETIC_QUALIFICATION_CLIENT',scopes:['api.responses.write'],expires:Date.now()+86400000};
const store = {async read() {reject('qualification_policy_failed');},
  async list() {return [{providerId:'openai',type:'oauth'}];},
  async modify(_id, fn) {credential=(await fn(credential)) ?? credential; return credential;},
  async delete() {reject('qualification_policy_failed');}};
const {ModelRuntime} = await import('@earendil-works/pi-coding-agent');
const actual = await ModelRuntime.create({credentials:subscriptionCredentials(store),modelsPath:null,
  refreshOnCreate:false,allowModelNetwork:false});
// The real transport receives a valid generation frame. Its callback is a
// deliberately uncooperative local canary so the supervisor must kill/reap it.
const runtime = {
  getModel(provider, id) {
    return {provider, id, api:'openai-responses', baseUrl:'https://api.openai.com/v1',
      reasoning:true, thinkingLevelMap:{xhigh:'xhigh'}};
  },
  stream(_model, context, options) {
    const stream = actual.stream(actual.getModel('openai', 'gpt-6.1-sol'),context,options);
    return {async *[Symbol.asyncIterator]() {
    for await (const _event of stream) {}
    const result = await stream.result();
    if (result.stopReason !== 'toolUse' || interceptedRequests !== 1) reject('qualification_policy_failed');
    writeFileSync(marker, canonical({schema:'autofv-pi-cancellation-canary/v1',
      callback_entered:true, sdk_model_requests:0, denied_fetch_routes:rejected,
      underlying_fetch_calls:underlyingCalls, intercepted_sdk_requests:interceptedRequests, retry_count:options.maxRetries})+'\n',
      {flag:'wx', mode:0o600});
    await new Promise(() => {}); }, result() {return new Promise(() => {});}};
  },
};
serve({sdk:SDK_VERSIONS, createRuntime:async () => runtime});
