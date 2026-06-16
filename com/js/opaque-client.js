// web/js/opaque-client.js
// OPAQUE register + login ceremonies driven over HTTP, client side.
// Ported from poc/poc.mjs + server/test/auth.test.mjs. The passphrase NEVER
// leaves the device — OPAQUE proves knowledge of it without revealing it.
//
// Import note: bare specifier '@cloudflare/opaque-ts'. Resolves from node_modules
// in Node; in the browser it is mapped via the importmap in com.html (vendored for
// real deployment, served with SRI).
import {
  getOpaqueConfig, OpaqueID, OpaqueClient,
  RegistrationResponse, KE2,
} from '@cloudflare/opaque-ts';

export const cfg = getOpaqueConfig(OpaqueID.OPAQUE_P256);
// The OPAQUE server identity MUST match the server's configured serverId.
export const DEFAULT_SERVER_ID = 'com.degeofroy.com';

// Portable base64 (no Node Buffer dependency, so this module runs in the browser too).
function bytesToB64(bytes) {
  let bin = '';
  const u = bytes instanceof Uint8Array ? bytes : Uint8Array.from(bytes);
  for (let i = 0; i < u.length; i++) bin += String.fromCharCode(u[i]);
  // btoa exists in browsers; Node 16+ exposes it globally too.
  return btoa(bin);
}
function b64ToNums(b64) {
  const bin = atob(b64);
  const out = new Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
const ser = (x) => bytesToB64(x.serialize());
const toB64 = (bytes) => bytesToB64(bytes);
const fromB64ToNums = (b64) => b64ToNums(b64);
const unwrap = (x, where) => { if (x instanceof Error) throw new Error(`${where}: ${x.message}`); return x; };

async function postJson(fetchImpl, base, path, body) {
  const res = await fetchImpl(`${base}${path}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  });
  const text = await res.text();
  let json;
  try { json = text ? JSON.parse(text) : {}; } catch { json = { _raw: text }; }
  if (!res.ok) {
    throw new Error(`${path} -> ${res.status}: ${JSON.stringify(json)}`);
  }
  return json;
}

// register(passphrase, nickname, base, fetchImpl)
// Runs registerInit -> /register/start -> registerFinish, then returns the
// { record(base64), exportKey } the caller needs to upload key material via
// /register/finish (the caller supplies the identity public/wrapped-private keys).
export async function register(passphrase, nickname, base, fetchImpl = globalThis.fetch, serverId = DEFAULT_SERVER_ID) {
  const client = new OpaqueClient(cfg);
  const req = unwrap(await client.registerInit(passphrase), 'client.registerInit');
  const { response } = await postJson(fetchImpl, base, '/api/opaque/register/start', {
    nickname, request: ser(req),
  });
  const resp = RegistrationResponse.deserialize(cfg, fromB64ToNums(response));
  const fin = unwrap(await client.registerFinish(resp, serverId, nickname), 'client.registerFinish');
  return {
    record: toB64(fin.record.serialize()),
    exportKey: Uint8Array.from(fin.export_key),
  };
}

// Finalise registration by uploading the OPAQUE record + identity key material.
export async function registerFinishUpload(nickname, { record, publicKey, wrappedPrivateKey }, base, fetchImpl = globalThis.fetch) {
  return postJson(fetchImpl, base, '/api/opaque/register/finish', {
    nickname,
    record,
    public_key: toB64(publicKey),
    wrapped_private_key: toB64(wrappedPrivateKey),
  });
}

// login(passphrase, nickname, base, fetchImpl)
// Runs authInit -> /login/start -> authFinish -> /login/finish. Legit users send
// honeypot:''. Returns { token, exportKey }.
export async function login(passphrase, nickname, base, fetchImpl = globalThis.fetch, serverId = DEFAULT_SERVER_ID) {
  const client = new OpaqueClient(cfg);
  const ke1 = unwrap(await client.authInit(passphrase), 'client.authInit');
  const { ke2: ke2B64 } = await postJson(fetchImpl, base, '/api/opaque/login/start', {
    nickname, honeypot: '', ke1: ser(ke1),
  });
  const ke2 = KE2.deserialize(cfg, fromB64ToNums(ke2B64));
  const finC = unwrap(await client.authFinish(ke2, serverId, nickname, serverId), 'client.authFinish');
  const { token } = await postJson(fetchImpl, base, '/api/opaque/login/finish', {
    nickname, ke3: ser(finC.ke3),
  });
  return { token, exportKey: Uint8Array.from(finC.export_key) };
}
