import { readFileSync } from 'node:fs';
import { digest } from '../protocol.mjs';
export const SCHEMAS = JSON.parse(readFileSync(new URL('../tool-schemas.json',import.meta.url)));
export function payload(overrides = {}) {
  const messages = [{role:'system',content:'Synthetic system.'},{role:'user',content:'Synthetic task.'}];
  return {request:{run_id:'fixture-run',conversation_id:'c'.repeat(64),request_id:'lane-cccccccccccccccc-001',sequence:1,role:'prover',model_id:'gpt-6.1-sol',history_sha256:digest(messages),profile_sha256:'a'.repeat(64)},
    profile:{provider:'openai',api:'openai-responses',model_id:'gpt-6.1-sol',effort:'xhigh',tool_choice:'required'},
    messages,continuations:[],admission:{deadline_ms:Date.now()+30000,sequence:1,request_id:'lane-cccccccccccccccc-001'},
    tools:SCHEMAS.map(s=>({type:'function',function:{name:s.name,description:s.description,parameters:s.input_schema}})),...overrides};
}
export function terminal(overrides = {}) {
  return {role:'assistant',api:'openai-responses',provider:'openai',model:'gpt-6.1-sol',responseId:'resp_fixture',
    content:[{type:'thinking',thinking:'PRIVATE_SUMMARY',thinkingSignature:JSON.stringify({id:'rs_1',type:'reasoning',summary:[],encrypted_content:'PRIVATE_ENCRYPTED'})},
      {type:'text',text:'Checking.',textSignature:JSON.stringify({v:1,id:'msg_1',phase:'commentary'})},
      {type:'toolCall',id:'call_1|fc_1',name:'check_lean',arguments:{}}],
    usage:{input:7,output:8,cacheRead:2,cacheWrite:3,totalTokens:20,reasoning:5,cost:{input:0,output:0,cacheRead:0,cacheWrite:0,total:0}},stopReason:'toolUse',timestamp:0,...overrides};
}
export function nextPayload(first,result) {
  const p = payload();
  p.messages = [...first.messages,{role:'assistant',content:'',tool_calls:[{id:first.request.request_id+'-tool',type:'function',function:{name:result.tool_call.name,arguments:JSON.stringify(result.tool_call.arguments)}}]},
    {role:'tool',tool_call_id:first.request.request_id+'-tool',content:'Synthetic diagnostic complete.'}];
  p.request = {...first.request,request_id:'lane-cccccccccccccccc-002',sequence:2,history_sha256:digest(p.messages)};
  p.admission = {...p.admission,sequence:2,request_id:p.request.request_id};
  p.continuations = [result.continuation];
  return p;
}
export function fakeRuntime(message = terminal()) {
  let calls = 0;
  return {get calls(){return calls;},getModel(){return {id:'gpt-6.1-sol',api:'openai-responses',provider:'openai',baseUrl:'https://api.openai.com/v1',reasoning:true,thinkingLevelMap:{xhigh:'xhigh'}};},
    stream(model,context,options) {
      calls++;
      options.onProviderStreamEvent({type:'response.completed',response:{model:model.id,reasoning:{effort:'xhigh'},usage:{input_tokens:12,output_tokens:8,total_tokens:20}}});
      return {async *[Symbol.asyncIterator](){yield {type:'done',message};},async result(){return message;}};
    }};
}
export function sseResponse({extraCalls = false, missingUsage = false, model = 'gpt-6.1-sol'} = {}) {
  const items = [
    {type:'reasoning',id:'rs_1',summary:[],encrypted_content:'PRIVATE_ENCRYPTED'},
    {type:'message',id:'msg_1',role:'assistant',phase:'commentary',status:'completed',content:[{type:'output_text',text:'Checking.',annotations:[]}]},
    {type:'function_call',id:'fc_1',call_id:'call_1',name:'check_lean',arguments:'{}',status:'completed'},
  ];
  if (extraCalls) items.push({...items[2],id:'fc_2',call_id:'call_2'});
  const events = [{type:'response.created',response:{id:'resp_fixture'}}];
  for (const [i,item] of items.entries()) {
    events.push({type:'response.output_item.added',output_index:i,item});
    if (item.type === 'message') events.push({type:'response.output_text.delta',output_index:i,content_index:0,delta:'Checking.'});
    events.push({type:'response.output_item.done',output_index:i,item});
  }
  events.push({type:'response.completed',response:{id:'resp_fixture',model,status:'completed',reasoning:{effort:'xhigh'},output:items,
    ...(missingUsage ? {} : {usage:{input_tokens:12,output_tokens:8,total_tokens:20,input_tokens_details:{cached_tokens:2,cache_write_tokens:3},output_tokens_details:{reasoning_tokens:5}}})}});
  return new Response(events.map(event=>'event: '+event.type+'\ndata: '+JSON.stringify(event)+'\n\n').join('')+'data: [DONE]\n\n',{status:200,headers:{'content-type':'text/event-stream'}});
}
