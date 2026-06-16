// web/js/api.js
// Thin HTTP/WS client for the COM server. The bearer token lives ONLY in memory
// (module-scoped) and is NEVER persisted — no localStorage, no cookies, no IndexedDB.
// `base` (server origin) and `fetchImpl` are injectable so this is testable in Node.

let token = null;

// Base URL resolution order (browser):
//   1. window.COM_API_BASE  (set before app.js loads, e.g. in a deploy-env script)
//   2. <meta name="com-api-base" content="...">  (set in com.html for a specific deploy target)
//   3. '' (same-origin, works for local dev and GitHub Pages with proxy)
// In tests the base is injected via setBase().
let base = (function () {
  if (typeof window !== 'undefined') {
    if (window.COM_API_BASE) return window.COM_API_BASE;
    const meta = document.querySelector('meta[name="com-api-base"]');
    if (meta && meta.content) return meta.content;
  }
  return '';
})();

let fetchImpl = (...a) => globalThis.fetch(...a);

export function setToken(t) { token = t; }
export function getToken() { return token; }
export function setBase(b) { base = b; }
export function getBase() { return base; }
export function setFetch(f) { fetchImpl = f; }

function authHeaders(extra = {}) {
  return token ? { authorization: `Bearer ${token}`, ...extra } : { ...extra };
}

async function jsonOrThrow(res, where) {
  const text = await res.text();
  let body;
  try { body = text ? JSON.parse(text) : {}; } catch { body = { _raw: text }; }
  if (!res.ok) throw new Error(`${where} -> ${res.status}: ${JSON.stringify(body)}`);
  return body;
}

export async function getMe() {
  const res = await fetchImpl(`${base}/api/me`, { headers: authHeaders() });
  return jsonOrThrow(res, 'GET /api/me');
}

export async function getKeys() {
  const res = await fetchImpl(`${base}/api/keys`, { headers: authHeaders() });
  return jsonOrThrow(res, 'GET /api/keys');
}

export async function listMessages(cid, after = 0) {
  const res = await fetchImpl(`${base}/api/conversations/${cid}/messages?after=${after}`, {
    headers: authHeaders(),
  });
  return jsonOrThrow(res, 'GET messages');
}

// payload: { client_msg_id, kind, nonce, ciphertext, attachment_id? }
export async function send(cid, payload) {
  const res = await fetchImpl(`${base}/api/conversations/${cid}/messages`, {
    method: 'POST',
    headers: authHeaders({ 'content-type': 'application/json' }),
    body: JSON.stringify(payload),
  });
  return jsonOrThrow(res, 'POST message');
}

// ── onboarding / admin orchestration ────────────────────────────────────────
// All use the in-memory bearer token + injectable base, like the rest of api.js.

export async function adminListUsers() {
  const res = await fetchImpl(`${base}/api/admin/users`, { headers: authHeaders() });
  return jsonOrThrow(res, 'GET /api/admin/users');
}

export async function adminCreateUser(nickname, display_name) {
  const res = await fetchImpl(`${base}/api/admin/users`, {
    method: 'POST',
    headers: authHeaders({ 'content-type': 'application/json' }),
    body: JSON.stringify({ nickname, display_name }),
  });
  return jsonOrThrow(res, 'POST /api/admin/users');
}

export async function adminSetAdmin(userId, isAdmin) {
  const res = await fetchImpl(`${base}/api/admin/users/${userId}/admin`, {
    method: 'POST',
    headers: authHeaders({ 'content-type': 'application/json' }),
    body: JSON.stringify({ is_admin: isAdmin }),
  });
  return jsonOrThrow(res, `POST /api/admin/users/${userId}/admin`);
}

export async function adminCreateConversation(title, memberIds) {
  const res = await fetchImpl(`${base}/api/admin/conversations`, {
    method: 'POST',
    headers: authHeaders({ 'content-type': 'application/json' }),
    body: JSON.stringify({ title, member_ids: memberIds }),
  });
  return jsonOrThrow(res, 'POST /api/admin/conversations');
}

export async function adminAddMember(cid, userId) {
  const res = await fetchImpl(`${base}/api/admin/conversations/${cid}/members`, {
    method: 'POST',
    headers: authHeaders({ 'content-type': 'application/json' }),
    body: JSON.stringify({ user_id: userId }),
  });
  return jsonOrThrow(res, 'POST add member');
}

// ── universal (any user) room management ─────────────────────────────────────

// List ALL users (roster for picking invitees). Minimal fields per shapeMember.
export async function listUsers() {
  const res = await fetchImpl(`${base}/api/users`, { headers: authHeaders() });
  return jsonOrThrow(res, 'GET /api/users');
}

// Create a group room as ANY user (the creator becomes a member).
export async function createConversation(title, memberIds) {
  const res = await fetchImpl(`${base}/api/conversations`, {
    method: 'POST',
    headers: authHeaders({ 'content-type': 'application/json' }),
    body: JSON.stringify({ title, member_ids: memberIds }),
  });
  return jsonOrThrow(res, 'POST /api/conversations');
}

// Invite a member to a room (caller must be a member of cid).
export async function addRoomMember(cid, userId) {
  const res = await fetchImpl(`${base}/api/conversations/${cid}/members`, {
    method: 'POST',
    headers: authHeaders({ 'content-type': 'application/json' }),
    body: JSON.stringify({ user_id: userId }),
  });
  return jsonOrThrow(res, 'POST room member');
}

export async function getMembers(cid) {
  const res = await fetchImpl(`${base}/api/conversations/${cid}/members`, { headers: authHeaders() });
  return jsonOrThrow(res, 'GET members');
}

export async function createDirect(userId) {
  const res = await fetchImpl(`${base}/api/conversations/direct`, {
    method: 'POST',
    headers: authHeaders({ 'content-type': 'application/json' }),
    body: JSON.stringify({ user_id: userId }),
  });
  return jsonOrThrow(res, 'POST direct');
}

// grants: [{ user_id, sealed(base64) }]
export async function grantKeys(cid, grants) {
  const res = await fetchImpl(`${base}/api/conversations/${cid}/keys`, {
    method: 'POST',
    headers: authHeaders({ 'content-type': 'application/json' }),
    body: JSON.stringify({ grants }),
  });
  return jsonOrThrow(res, 'POST keys');
}

export async function markRead(cid, lastReadMessageId) {
  const res = await fetchImpl(`${base}/api/conversations/${cid}/read`, {
    method: 'POST',
    headers: authHeaders({ 'content-type': 'application/json' }),
    body: JSON.stringify({ last_read_message_id: lastReadMessageId }),
  });
  return jsonOrThrow(res, 'POST read');
}

// upload(cid, { nonce(base64), contentType, bytes(Uint8Array) }) -> { attachment_id }
// Uses FormData (browser + Node 18+). The blob carries ONLY ciphertext bytes.
export async function upload(cid, { nonce, contentType, bytes }) {
  const form = new FormData();
  form.append('nonce', nonce);
  form.append('content_type', contentType);
  const blob = new Blob([bytes], { type: 'application/octet-stream' });
  form.append('blob', blob, 'blob.bin');
  const res = await fetchImpl(`${base}/api/upload?conversation_id=${cid}`, {
    method: 'POST',
    headers: authHeaders(), // do NOT set content-type; let fetch add the multipart boundary.
    body: form,
  });
  return jsonOrThrow(res, 'POST upload');
}

export function fileUrl(aid) {
  return `${base}/api/files/${aid}`;
}

export async function deleteConversation(cid) {
  const res = await fetchImpl(`${base}/api/conversations/${cid}`, {
    method: 'DELETE',
    headers: authHeaders(),
  });
  return jsonOrThrow(res, `DELETE /api/conversations/${cid}`);
}

// downloadFile(aid) -> { bytes(Uint8Array), nonce(base64 from X-Nonce header) }
export async function downloadFile(aid) {
  const res = await fetchImpl(fileUrl(aid), { headers: authHeaders() });
  if (!res.ok) throw new Error(`GET file -> ${res.status}`);
  const nonce = res.headers.get('x-nonce');
  const buf = new Uint8Array(await res.arrayBuffer());
  return { bytes: buf, nonce };
}

// openWS(onMessage, { WebSocketImpl, wsBase }) -> the live socket.
// wsBase lets tests point at ws://127.0.0.1:PORT; in the browser we derive it
// from the page origin. Token rides the query string (server reads it there).
export function openWS(onMessage, { WebSocketImpl, wsBase } = {}) {
  const WS = WebSocketImpl || globalThis.WebSocket;
  let origin = wsBase;
  if (!origin) {
    if (base) origin = base.replace(/^http/, 'ws');
    else origin = `${location.origin.replace(/^http/, 'ws')}`;
  }
  const sock = new WS(`${origin}/ws?token=${encodeURIComponent(token)}`);
  sock.addEventListener?.('message', (ev) => {
    try { onMessage(JSON.parse(ev.data)); } catch { /* ignore non-JSON frames */ }
  });
  // Node 'ws' fallback (no addEventListener): also wire .on if present.
  if (!sock.addEventListener && sock.on) {
    sock.on('message', (data) => { try { onMessage(JSON.parse(data.toString())); } catch {} });
  }
  return sock;
}
