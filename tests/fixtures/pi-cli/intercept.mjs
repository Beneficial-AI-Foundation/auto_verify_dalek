/** Test-only wire fixture. No model/runtime/encoder/decoder is replaced. */
import fs from 'node:fs';
import net from 'node:net';
import tls from 'node:tls';
import http from 'node:http';
import https from 'node:https';
import dns from 'node:dns';
import dgram from 'node:dgram';
import http2 from 'node:http2';
import { syncBuiltinESMExports } from 'node:module';
const fixture = JSON.parse(fs.readFileSync(process.env.AUTOFV_TEST_FIXTURE, 'utf8'));
for (const key of ['OPENAI_API_KEY','NODE_OPTIONS','HTTP_PROXY','HTTPS_PROXY','NODE_PATH']) {
  if (process.env[key] !== undefined) throw new Error('ambient credential or injection reached child');
}
const denied = () => { throw new Error('test denies every real child socket'); };
net.Socket.prototype.connect = denied;
net.connect = net.createConnection = tls.connect = http.request = http.get = https.request = https.get = denied;
dns.lookup = dns.resolve = dns.resolve4 = dns.resolve6 = denied;
for (const key of ['lookup','resolve','resolve4','resolve6']) dns.promises[key] = denied;
dgram.Socket.prototype.send = dgram.Socket.prototype.bind = http2.connect = denied;
globalThis.WebSocket = class { constructor() { denied(); } };
syncBuiltinESMExports();
let count = 0;
globalThis.fetch = async (input, init = {}) => {
  const url = typeof input === 'string' ? input : input.url;
  if (url !== 'https://api.openai.com/v1/responses') throw new Error('test unexpected network destination');
  if (new Headers(init.headers).get('authorization') !== 'Bearer SYNTHETIC_ACCESS') throw new Error('test subscription auth mismatch');
  const body = JSON.parse(init.body);
  if (body.model !== 'gpt-6.1-sol' || body.reasoning.effort !== 'xhigh' || body.tool_choice !== 'required') throw new Error('test policy mismatch');
  if (body.max_output_tokens !== undefined || body.previous_response_id !== undefined) throw new Error('test unexpected provider options');
  const turn = ++count;
  const action = fixture.actions[turn - 1];
  if (!action) throw new Error('test unexpected generation');
  fs.appendFileSync(fixture.requests, JSON.stringify({url, body}) + '\n');
  // Ignore abort deliberately: the actual supervisor must kill/reap this process.
  if (fixture.hang) return await new Promise(() => {});
  const items = [
    {type:'reasoning',id:`rs_${turn}`,summary:[],encrypted_content:`PRIVATE_CLI_ENCRYPTED_${turn}`},
    {type:'message',id:`msg_${turn}`,role:'assistant',phase:'commentary',status:'completed',content:[{type:'output_text',text:'Synthetic candidate step.',annotations:[]}]},
    {type:'function_call',id:`fc_${turn}`,call_id:`call_${turn}`,name:action.name,arguments:JSON.stringify(action.arguments),status:'completed'},
  ];
  const events = [{type:'response.created',response:{id:`resp_cli_${turn}`}}];
  for (const [i,item] of items.entries()) {
    events.push({type:'response.output_item.added',output_index:i,item});
    if (item.type === 'message') events.push({type:'response.output_text.delta',output_index:i,content_index:0,delta:'Synthetic candidate step.'});
    events.push({type:'response.output_item.done',output_index:i,item});
  }
  events.push({type:'response.completed',response:{id:`resp_cli_${turn}`,model:body.model,status:'completed',reasoning:{effort:'xhigh'},output:items,
    ...(fixture.missing_usage ? {} : {usage:{input_tokens:12,output_tokens:8,total_tokens:20,input_tokens_details:{cached_tokens:2},output_tokens_details:{reasoning_tokens:5}}})}});
  return new Response(events.map(event=>'event: '+event.type+'\ndata: '+JSON.stringify(event)+'\n\n').join('')+'data: [DONE]\n\n',
    {status:200,headers:{'content-type':'text/event-stream'}});
};
