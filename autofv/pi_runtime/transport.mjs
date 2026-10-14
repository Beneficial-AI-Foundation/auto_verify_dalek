/** Fixed trusted-host entry. No tools, CLI session, Durable Harness or auth setup. */
import { pathToFileURL } from 'node:url';
import { encodeFrame, failureCode, parseFrame, PROTOCOL, MAX_FRAME_BYTES, reject } from './protocol.mjs';
import { installedSdk } from './sdk-versions.mjs';
import { openManagedStore, subscriptionCredentials } from './managed-store.mjs';
import { generateOne, validatePayload } from './generation.mjs';
import { guardedFetch } from './network.mjs';

export function serve({input = process.stdin, output = process.stdout, createRuntime, sdk = installedSdk(), onClose = () => {}}) {
  let pending = Buffer.alloc(0), greeted = false, active = null, closed = false, failed = false, runtime;
  const usedIds = new Set(), usedSequences = new Set();
  const send = frame => { if (!closed) output.write(encodeFrame(frame)); };
  const error = (code, request = null) => send({v:1,op:'error',code,request_id:request?.request_id ?? null,sequence:request?.sequence ?? null});
  function fail(code, request = null) { failed = true; active?.abort.abort(); error(code,request); }
  async function handle(frame) {
    if (frame.op === 'hello') {
      if (greeted || failed) reject('invalid_protocol');
      greeted = true; send({v:1,op:'hello',protocol:PROTOCOL,packages:sdk}); return;
    }
    if (!greeted) reject('hello_required');
    if (frame.op === 'close') {
      active?.abort.abort(); failed = true;
      send({v:1,op:'closed'}); closed = true; input.pause(); onClose(); return;
    }
    if (frame.op === 'cancel') {
      if (!active || active.request.request_id !== frame.request_id || active.request.sequence !== frame.sequence) reject('cancel_identity_mismatch');
      failed = true; active.abort.abort(); return;
    }
    if (failed) reject('process_quarantined');
    if (active) reject('generation_already_active');
    validatePayload(frame.payload);
    const request = frame.payload.request;
    if (usedIds.has(request.request_id) || usedSequences.has(request.sequence) || usedIds.size >= 4096) reject('duplicate_request');
    // Burn admission before runtime creation/auth. Failed or uncertain requests are never reissued.
    usedIds.add(request.request_id); usedSequences.add(request.sequence);
    const abort = new AbortController(); active = {abort,request};
    const timer = setTimeout(() => { failed = true; abort.abort(); },Math.max(1,frame.payload.admission.deadline_ms-Date.now()));
    try {
      runtime ??= await createRuntime();
      const result = await generateOne(runtime,frame.payload,abort.signal);
      if (failed || abort.signal.aborted) reject('request_aborted_uncertain');
      send({v:1,op:'result',request_id:request.request_id,sequence:request.sequence,result});
    } catch (cause) { fail(failureCode(cause),request); }
    finally { clearTimeout(timer); active = null; }
  }
  input.on('data', chunk => {
    if (closed) return;
    // Bound incomplete frames before allocating a combined buffer.
    if (pending.length + chunk.length > MAX_FRAME_BYTES + 1) { fail('frame_limit'); input.pause(); return; }
    pending = Buffer.concat([pending,chunk]);
    while (!closed) {
      const end = pending.indexOf(10); if (end < 0) break;
      const raw = pending.subarray(0,end); pending = pending.subarray(end+1);
      let frame; try { frame = parseFrame(raw); } catch (cause) { fail(failureCode(cause)); input.pause(); break; }
      handle(frame).catch(cause => fail(failureCode(cause)));
    }
  });
  input.on('end', () => { active?.abort.abort(); closed = true; onClose(); });
  input.on('error', () => { active?.abort.abort(); closed = true; onClose(); });
  return {close() { active?.abort.abort(); closed = true; input.pause(); }};
}
async function main() {
  if (process.argv.length === 3 && process.argv[2] === '--diagnostic') {
    process.stdout.write(JSON.stringify({protocol:PROTOCOL,packages:installedSdk()}) + '\n'); return;
  }
  if (process.argv.length !== 4) reject('invalid_startup');
  const store = openManagedStore(process.argv[2],process.argv[3]);
  // Imports happen only after fetch is restricted. The host still owes sealed egress evidence.
  globalThis.fetch = guardedFetch(globalThis.fetch.bind(globalThis));
  for (const method of ['log','info','warn','error','debug','trace']) console[method] = () => {};
  serve({createRuntime:async () => {
    const { ModelRuntime } = await import('@earendil-works/pi-coding-agent');
    return ModelRuntime.create({credentials:subscriptionCredentials(store),modelsPath:null,refreshOnCreate:false,allowModelNetwork:false});
  },onClose:() => { process.exitCode = 0; }});
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch(cause => { process.stdout.write(encodeFrame({v:1,op:'error',request_id:null,sequence:null,code:failureCode(cause)})); process.exitCode = 1; });
}
