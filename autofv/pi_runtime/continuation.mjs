/** Opaque provider state stays on the trusted host; Python history owns actions. */
import { readFileSync } from 'node:fs';
import { canonical, digest, exact, identifier, MAX_CONTINUATION_BYTES, reject, requestIdentity } from './protocol.mjs';
const SCHEMAS = JSON.parse(readFileSync(new URL('./tool-schemas.json', import.meta.url), 'utf8'));
export function toolSchemas(tools) {
  if (!Array.isArray(tools) || tools.length !== SCHEMAS.length) reject('tool_schema_mismatch');
  const expected = SCHEMAS.map(s => ({type:'function',function:{name:s.name,description:s.description,parameters:s.input_schema}}));
  const byName = values => [...values].sort((a,b) => String(a?.function?.name).localeCompare(String(b?.function?.name)));
  if (canonical(byName(tools)) !== canonical(byName(expected))) reject('tool_schema_mismatch');
  return SCHEMAS.map(s => ({name:s.name,description:s.description,parameters:structuredClone(s.input_schema)}));
}
export function validateToolCall(call) {
  exact(call, ['name','arguments']);
  const schema = SCHEMAS.find(s => s.name === call.name)?.input_schema;
  if (!schema) reject('tool_not_allowed');
  const required = schema.required ?? [];
  exact(call.arguments, required, Object.keys(schema.properties).filter(k => !required.includes(k)));
  for (const [key,value] of Object.entries(call.arguments)) {
    const property = schema.properties[key], type = property.type;
    if (type === 'string' ? typeof value !== 'string' : type === 'integer' ? !Number.isSafeInteger(value) : type === 'boolean' ? typeof value !== 'boolean' : type === 'array' ? !Array.isArray(value) || value.length > property.maxItems || value.some(v => typeof v !== 'string') : true) reject('invalid_tool_arguments');
    if (property.enum && !property.enum.includes(value)) reject('invalid_tool_arguments');
  }
  return call;
}
export function validateContinuation(record) {
  exact(record, ['schema','request','canonical_tool_id','tool_call','native']);
  if (record.schema !== 'autofv-pi-continuation/v1' || Buffer.byteLength(canonical(record)) > MAX_CONTINUATION_BYTES) reject('invalid_continuation');
  requestIdentity(record.request);
  if (record.canonical_tool_id !== record.request.request_id + '-tool') reject('continuation_identity_mismatch');
  validateToolCall(record.tool_call);
  exact(record.native, ['tool_call_id','content','response_id']);
  if (typeof record.native.tool_call_id !== 'string' || record.native.tool_call_id.length > 512 || !/^[A-Za-z0-9._:-]+(?:\|[A-Za-z0-9._:-]+)?$/.test(record.native.tool_call_id)) reject('invalid_continuation');
  if (record.native.response_id !== null) identifier(record.native.response_id, 512);
  if (!Array.isArray(record.native.content) || record.native.content.length > 32) reject('invalid_continuation');
  let calls = 0;
  for (const block of record.native.content) {
    if (block.type === 'toolCall') { exact(block,['type']); calls++; }
    else if (block.type === 'thinking') {
      exact(block,['type','thinkingSignature'],['redacted']);
      if (typeof block.thinkingSignature !== 'string' || !block.thinkingSignature.length || ('redacted' in block && typeof block.redacted !== 'boolean')) reject('invalid_continuation');
      validateThinkingSignature(block.thinkingSignature);
    } else if (block.type === 'text') {
      exact(block,['type','text'],['textSignature']);
      if (typeof block.text !== 'string' || ('textSignature' in block && typeof block.textSignature !== 'string')) reject('invalid_continuation');
    } else reject('invalid_continuation');
  }
  if (calls !== 1) reject('invalid_continuation');
  return record;
}
function restoredAssistant(record) {
  return {role:'assistant',api:'openai-responses',provider:'openai',model:record.request.model_id,
    content:record.native.content.map(b => b.type === 'toolCall'
      ? {type:'toolCall',id:record.native.tool_call_id,...structuredClone(record.tool_call)}
      : b.type === 'thinking' ? {...b,thinking:''} : {...b}),
    ...(record.native.response_id === null ? {} : {responseId:record.native.response_id}),
    stopReason:'toolUse',timestamp:0,
    usage:{input:0,output:0,cacheRead:0,cacheWrite:0,totalTokens:0,cost:{input:0,output:0,cacheRead:0,cacheWrite:0,total:0}}};
}
export function restoreHistory(messages, records, request) {
  requestIdentity(request);
  if (!Array.isArray(messages) || messages.length < 2 || messages.length > 128 || messages[0]?.role !== 'system'
      || !Array.isArray(records) || records.length > 63 || digest(messages) !== request.history_sha256) reject('history_mismatch');
  const byId = new Map();
  let lastSequence = 0;
  for (const value of records) {
    const r = validateContinuation(value);
    for (const key of ['run_id','conversation_id','role','model_id','profile_sha256']) if (r.request[key] !== request[key]) reject('continuation_identity_mismatch');
    if (byId.has(r.canonical_tool_id) || r.request.sequence <= lastSequence || r.request.sequence >= request.sequence) reject('continuation_sequence_mismatch');
    lastSequence = r.request.sequence;
    byId.set(r.canonical_tool_id,r);
  }
  const result = []; let pending = null; let users = 0; let used = 0;
  for (let index = 0; index < messages.length; index++) {
    const m = messages[index];
    if (pending && m.role !== 'tool') reject('unpaired_tool_call');
    if (m.role === 'system' || m.role === 'user') {
      exact(m,['role','content']);
      if (typeof m.content !== 'string' || !m.content || (m.role === 'system' && index !== 0)) reject('invalid_history');
      if (m.role === 'user') { users++; result.push({role:'user',content:m.content,timestamp:0}); }
    } else if (m.role === 'assistant') {
      exact(m,['role','content','tool_calls']);
      if (![null,''].includes(m.content) || !Array.isArray(m.tool_calls) || m.tool_calls.length !== 1) reject('invalid_history');
      const call = exact(m.tool_calls[0],['id','type','function']);
      const fn = exact(call.function,['name','arguments']);
      if (call.type !== 'function' || typeof fn.arguments !== 'string') reject('invalid_history');
      let args; try { args = JSON.parse(fn.arguments); } catch { reject('invalid_tool_arguments'); }
      if (canonical(args) !== fn.arguments) reject('noncanonical_tool_arguments');
      const record = byId.get(call.id);
      if (!record || record.request.history_sha256 !== digest(messages.slice(0,index))
          || canonical(record.tool_call) !== canonical({name:fn.name,arguments:args})) reject('continuation_history_mismatch');
      result.push(restoredAssistant(record)); pending = record; byId.delete(call.id); used++;
    } else if (m.role === 'tool') {
      exact(m,['role','tool_call_id','content']);
      if (!pending || m.tool_call_id !== pending.canonical_tool_id || typeof m.content !== 'string' || !m.content) reject('unpaired_tool_result');
      result.push({role:'toolResult',toolCallId:pending.native.tool_call_id,toolName:pending.tool_call.name,
        content:[{type:'text',text:m.content}],isError:false,timestamp:0}); pending = null;
    } else reject('invalid_history');
  }
  if (pending || !users || used !== records.length) reject('unpaired_history');
  return {systemPrompt:messages[0].content,messages:result};
}
export function projectContinuation(message, request) {
  const calls = message.content.filter(b => b.type === 'toolCall');
  if (calls.length !== 1) reject('multiple_or_missing_tool_calls');
  const tool = calls[0]; if (tool.namespace !== undefined || tool.thoughtSignature !== undefined) reject('unsupported_response_content'); validateToolCall({name:tool.name,arguments:tool.arguments});
  const content = message.content.map(b => {
    if (b.type === 'toolCall') return {type:'toolCall'};
    if (b.type === 'text') return {type:'text',text:b.text,...(b.textSignature === undefined ? {} : {textSignature:b.textSignature})};
    if (b.type === 'thinking' && typeof b.thinkingSignature === 'string' && b.thinkingSignature.length) return {
      type:'thinking',thinkingSignature:b.thinkingSignature,...(b.redacted === undefined ? {} : {redacted:b.redacted})};
    reject('unsupported_response_content');
  });
  return validateContinuation({schema:'autofv-pi-continuation/v1',request:structuredClone(request),
    canonical_tool_id:request.request_id + '-tool',tool_call:{name:tool.name,arguments:structuredClone(tool.arguments)},
    native:{tool_call_id:tool.id,content,response_id:message.responseId ?? null}});
}

export function validateThinkingSignature(signature) {
  let item; try { item = JSON.parse(signature); } catch { reject('invalid_continuation'); }
  exact(item,['id','type','summary'],['encrypted_content','status']);
  if (item.type !== 'reasoning' || typeof item.id !== 'string' || !Array.isArray(item.summary)) reject('invalid_continuation');
  for (const part of item.summary) {
    exact(part,['type','text']);
    if (part.type !== 'summary_text' || typeof part.text !== 'string') reject('invalid_continuation');
  }
  if (item.encrypted_content !== undefined && item.encrypted_content !== null && typeof item.encrypted_content !== 'string') reject('invalid_continuation');
  if (item.status !== undefined && !['completed','in_progress','incomplete'].includes(item.status)) reject('invalid_continuation');
}
