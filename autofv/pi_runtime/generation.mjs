/** One public ModelRuntime.stream call per controller admission. No role loop. */
import { canonical, exact, reject, requestIdentity, MAX_FRAME_BYTES } from './protocol.mjs';
import { projectContinuation, restoreHistory, toolSchemas } from './continuation.mjs';
export function validatePayload(payload, now = Date.now()) {
  exact(payload,['request','messages','profile','continuations','admission','tools']);
  const r = requestIdentity(payload.request), p = exact(payload.profile,['provider','api','model_id','effort','tool_choice']);
  if (p.provider !== 'openai' || p.api !== 'openai-responses' || p.model_id !== r.model_id
      || p.effort !== 'xhigh' || p.tool_choice !== 'required') reject('profile_mismatch');
  const a = exact(payload.admission,['deadline_ms','sequence','request_id']);
  if (a.request_id !== r.request_id || a.sequence !== r.sequence || !Number.isSafeInteger(a.deadline_ms)
      || a.deadline_ms <= now) reject('invalid_admission');
  const context = restoreHistory(payload.messages,payload.continuations,r);
  context.tools = toolSchemas(payload.tools);
  return context;
}
export function projectUsage(value) {
  exact(value,['input','output','cacheRead','cacheWrite','totalTokens'],['reasoning','cost']);
  const keys = ['input','output','cacheRead','cacheWrite','totalTokens',...(value.reasoning === undefined ? [] : ['reasoning'])];
  if (keys.some(k => !Number.isSafeInteger(value[k]) || value[k] < 0)
      || value.totalTokens !== value.input + value.output + value.cacheRead + value.cacheWrite
      || (value.reasoning ?? 0) > value.output) reject('invalid_usage');
  return Object.fromEntries(keys.map(k => [k,value[k]]));
}
export async function generateOne(runtime, payload, signal) {
  const context = validatePayload(payload);
  const model = runtime.getModel('openai',payload.profile.model_id);
  if (!model || model.api !== 'openai-responses' || model.provider !== 'openai' || model.id !== payload.profile.model_id
      || model.baseUrl !== 'https://api.openai.com/v1' || model.reasoning !== true
      || model.thinkingLevelMap?.xhigh !== 'xhigh'
      || model.headers && Object.keys(model.headers).length || model.samplingParams && Object.keys(model.samplingParams).length
      || model.samplingParamsByThinkingLevel && Object.keys(model.samplingParamsByThinkingLevel).length) reject('unsupported_model_profile');
  const timeoutMs = payload.admission.deadline_ms - Date.now();
  if (timeoutMs <= 0 || signal.aborted) reject('request_aborted_uncertain');
  let terminalUsage = false, observedModel = null, observedEffort = null, responseId = null;
  /** @type {import('@earendil-works/pi-ai').ModelsApiStreamOptions<'openai-responses'>} */
  const options = {reasoningEffort:'xhigh',toolChoice:'required',maxRetries:0,cacheRetention:'none',
    transport:'sse',signal,timeoutMs,env:{},
    onProviderStreamEvent(event) {
      if (event?.type === 'response.created') {
        if (responseId !== null && responseId !== event.response?.id) reject('response_identity_mismatch');
        responseId = event.response?.id ?? null;
      }
      if (event && ['response.completed','response.incomplete'].includes(event.type)) {
        const u = event.response?.usage;
        const counts = [u?.input_tokens,u?.output_tokens,u?.total_tokens];
        terminalUsage = !!u && counts.every(n => Number.isSafeInteger(n) && n >= 0)
          && u.total_tokens === u.input_tokens + u.output_tokens;
        if (!terminalUsage) reject('missing_usage');
        for (const value of [u.input_tokens_details?.cached_tokens ?? 0,u.input_tokens_details?.cache_write_tokens ?? 0,u.output_tokens_details?.reasoning_tokens ?? 0]) {
          if (!Number.isSafeInteger(value) || value < 0) reject('invalid_usage');
        }
        if ((u.input_tokens_details?.cached_tokens ?? 0) + (u.input_tokens_details?.cache_write_tokens ?? 0) > u.input_tokens
          || (u.output_tokens_details?.reasoning_tokens ?? 0) > u.output_tokens) reject('invalid_usage');
        if (responseId !== null && event.response?.id !== responseId) reject('response_identity_mismatch');
        observedModel = event.response?.model ?? null;
        observedEffort = event.response?.reasoning?.effort ?? null;
      }
    }};
  const stream = runtime.stream(model,context,options);
  let streamedBytes = 0;
  for await (const event of stream) {
    if (typeof event.delta === 'string') streamedBytes += Buffer.byteLength(event.delta);
    if (streamedBytes > MAX_FRAME_BYTES || (event.partial?.content && Buffer.byteLength(canonical(event.partial.content)) > MAX_FRAME_BYTES)) reject('stream_limit');
  }
  const message = await stream.result();
  if (signal.aborted) reject('request_aborted_uncertain');
  if (message.stopReason === 'error' || message.stopReason === 'aborted') throw message;
  if (message.role !== 'assistant' || message.api !== model.api || message.provider !== model.provider || message.model !== model.id
      || (message.responseModel !== undefined && message.responseModel !== model.id) || message.deferred || message.stopReason !== 'toolUse'
      || (message.providerThinkingLevel !== undefined && message.providerThinkingLevel !== 'xhigh')) reject('response_profile_mismatch');
  if (!terminalUsage) reject('missing_usage');
  if ((observedModel !== null && observedModel !== model.id) || (observedEffort !== null && observedEffort !== 'xhigh')) reject('response_profile_mismatch');
  const continuation = projectContinuation(message,payload.request);
  return {request_id:payload.request.request_id,sequence:payload.request.sequence,tool_call:continuation.tool_call,
    usage:projectUsage(message.usage),provider_response_id:message.responseId ?? null,
    observed_model:observedModel ?? message.responseModel ?? null,requested_effort:'xhigh',observed_effort:observedEffort ?? message.providerThinkingLevel ?? null,continuation};
}
