/** Defense in depth for the SDK fetch seam, not an OS egress qualification. */
import { reject } from './protocol.mjs';
export const MAX_PROVIDER_WIRE_BYTES = 4 * 1024 * 1024;
const ALLOWED = new Set(['https://api.openai.com/v1/responses','https://auth.openai.com/api/accounts/oauth/token']);
export function guardedFetch(fetchImpl) {
  return async (input, init = {}) => {
    let url; try { url = new URL(typeof input === 'string' || input instanceof URL ? input : input.url); }
    catch { reject('egress_refused'); }
    const method = (init.method ?? (input instanceof Request ? input.method : 'GET')).toUpperCase();
    if (!ALLOWED.has(url.href) || url.username || url.password || method !== 'POST') reject('egress_refused');
    const response = await fetchImpl(input,{...init,redirect:'error'});
    if (response.redirected || (response.url && response.url !== url.href)) reject('egress_refused');
    const length = response.headers.get('content-length');
    if (length !== null && (!/^[0-9]+$/.test(length) || Number(length) > MAX_PROVIDER_WIRE_BYTES)) {
      await response.body?.cancel(); reject('provider_wire_limit');
    }
    if (!response.body) return response;
    const reader = response.body.getReader(); let received = 0;
    const body = new ReadableStream({
      async pull(controller) {
        try {
          const part = await reader.read();
          if (part.done) { controller.close(); return; }
          received += part.value.byteLength;
          if (received > MAX_PROVIDER_WIRE_BYTES) { await reader.cancel(); reject('provider_wire_limit'); }
          controller.enqueue(part.value);
        } catch (error) { controller.error(error); }
      },
      async cancel(reason) { await reader.cancel(reason); },
    });
    return new Response(body,{status:response.status,statusText:response.statusText,headers:response.headers});
  };
}
