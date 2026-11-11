// Agent-only WebAuthn provider adapter. This is not a browser's native authenticator.
import { createInterface } from 'node:readline';

export async function attachHushPasskeys(context) {
  const queue = [];
  const lines = createInterface({ input: process.stdin });
  lines.on('line', line => {
    const pending = queue.shift();
    if (!pending) return;
    try {
      const value = JSON.parse(line);
      if (!value.ok) pending.reject(new Error('Hush passkey request refused'));
      else pending.resolve(value.credential);
    } catch { pending.reject(new Error('Invalid Hush protocol response')); }
  });
  lines.on('close', () => { for (const item of queue.splice(0)) item.reject(new Error('Hush session closed')); });
  await context.exposeBinding('__hushPasskey', async ({frame}, request) => {
    if (frame.parentFrame()) throw new Error('Hush does not authorize subframes');
    const origin = new URL(frame.url()).origin;
    return new Promise((resolve, reject) => {
      queue.push({resolve, reject});
      process.stdout.write(JSON.stringify({ ...request, origin }) + '\n');
    });
  });
  await context.addInitScript(() => {
    const from64 = value => Uint8Array.from(atob(value.replaceAll('-', '+').replaceAll('_', '/')), c => c.charCodeAt(0)).buffer;
    const serialize = value => {
      if (value instanceof ArrayBuffer || ArrayBuffer.isView(value)) {
        const bytes = value instanceof ArrayBuffer ? new Uint8Array(value) : new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
        return btoa(String.fromCharCode(...bytes)).replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '');
      }
      if (Array.isArray(value)) return value.map(serialize);
      if (value && typeof value === 'object') return Object.fromEntries(Object.entries(value).map(([k,v]) => [k,serialize(v)]));
      return value;
    };
    const decodeExtensions = value => {
      const result = structuredClone(value);
      if (result.prf?.results) for (const key of ['first','second']) if (result.prf.results[key]) result.prf.results[key] = from64(result.prf.results[key]);
      return result;
    };
    const invoke = async (op, options) => {
      if (!options?.publicKey) throw new DOMException('Only public-key credentials are supported', 'NotSupportedError');
      if (options.signal?.aborted) throw new DOMException('Cancelled', 'AbortError');
      const publicKey = serialize(options.publicKey);
      if (op === 'create') publicKey.rp = {...publicKey.rp, id:publicKey.rp.id || location.hostname};
      else publicKey.rpId ||= location.hostname;
      let receipt;
      try { receipt = await globalThis.__hushPasskey({op, publicKey}); }
      catch { throw new DOMException('Hush passkey request refused', 'NotAllowedError'); }
      if (options.signal?.aborted) throw new DOMException('Cancelled', 'AbortError');
      const response = {};
      for (const key of ['clientDataJSON','attestationObject','authenticatorData','signature','userHandle']) {
        if (receipt.response[key] != null) response[key] = from64(receipt.response[key]);
      }
      if (op === 'create') {
        response.getAuthenticatorData = () => from64(receipt.response.authenticatorData);
        response.getPublicKey = () => from64(receipt.response.publicKey);
        response.getPublicKeyAlgorithm = () => receipt.response.publicKeyAlgorithm;
        response.getTransports = () => [...receipt.response.transports];
      }
      return {id:receipt.id, rawId:from64(receipt.rawId), type:'public-key', authenticatorAttachment:receipt.authenticatorAttachment,
        response, getClientExtensionResults:() => decodeExtensions(receipt.clientExtensionResults), toJSON:() => structuredClone(receipt)};
    };
    Object.defineProperty(navigator.credentials, 'create', {value: options => invoke('create',options)});
    Object.defineProperty(navigator.credentials, 'get', {value: options => invoke('get',options)});
    // Do not advertise a native platform authenticator: this adapter is scoped to this context.
  });
  return {close:() => lines.close()};
}
