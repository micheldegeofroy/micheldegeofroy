// web/js/client-core.js
// The UI-agnostic engine. A `Session` ties OPAQUE login + key unwrap + E2E
// crypto + the REST/WS API together. ALL secrets (export key, private key,
// group keys) live ONLY in memory on this instance — nothing is persisted.
// This is the module the Node integration test drives directly.
import * as sodium from './sodium-helpers.js';
import * as opaque from './opaque-client.js';
import * as api from './api.js';

// Derive the OPAQUE nickname from a passphrase: the LAST whitespace token.
// (Mirrors the poc passphrases like "... the blue chair ann" -> "ann".)
export function nicknameFromPassphrase(passphrase) {
  const parts = normalizePassphrase(passphrase).split(/\s+/);
  return parts[parts.length - 1];
}

// Normalize a passphrase so it is identical across devices/keyboards. Phones
// auto-capitalize sentences and autocorrect words; without this, the same
// passphrase typed on a phone vs a laptop yields different bytes and OPAQUE
// (which needs an exact match) rejects it. Applied IDENTICALLY on register and
// login: Unicode NFKC, trim, lowercase, collapse internal whitespace.
export function normalizePassphrase(passphrase) {
  return String(passphrase).normalize('NFKC').trim().toLowerCase().replace(/\s+/g, ' ');
}

export class Session {
  constructor({ base = '', fetchImpl, WebSocketImpl, wsBase } = {}) {
    this.base = base;
    this.fetchImpl = fetchImpl || ((...a) => globalThis.fetch(...a));
    this.WebSocketImpl = WebSocketImpl;
    this.wsBase = wsBase;
    // In-memory secrets — cleared by destroy().
    this.token = null;
    this.nickname = null;
    this.me = null;
    this.privateKey = null;
    this.publicKey = null;
    this.convKeys = new Map(); // conversation_id -> GROUP_KEY (Uint8Array)
    this.ws = null;
    // Point the shared api module at our base/fetch.
    api.setBase(base);
    if (fetchImpl) api.setFetch(this.fetchImpl);
  }

  // registerFlow(passphrase) — full client self-registration for a user whose
  // USER ROW already exists (seeded by an admin or seed-admin). Runs:
  //   1. OPAQUE register (start → finish) — establishes the OPAQUE record on the server.
  //   2. Generate an X25519 identity keypair via sodium.
  //   3. Wrap the private key under the OPAQUE export_key (secretbox, in-memory only).
  //   4. Upload record + public_key + wrapped_private_key via /api/opaque/register/finish.
  //   5. Auto-login immediately (loginFlow) so the caller lands in the chat.
  // Returns the same `me` object loginFlow returns.
  // Nothing is persisted — all key material lives only in memory.
  async registerFlow(passphrase, base = this.base) {
    await sodium.ready();
    this.base = base;
    api.setBase(base);
    if (this.fetchImpl) api.setFetch(this.fetchImpl);

    const norm = normalizePassphrase(passphrase);
    const nickname = nicknameFromPassphrase(norm);

    // Step 1: OPAQUE registration ceremony (uses the NORMALIZED passphrase).
    const { record, exportKey } = await opaque.register(norm, nickname, base, this.fetchImpl);

    // Step 2+3: generate identity keypair and wrap the private key.
    const id = sodium.newIdentityKeypair();
    const wrappedPrivateKey = sodium.wrapPrivateKey(id.privateKey, exportKey);

    // Step 4: upload OPAQUE record + identity keys.
    await opaque.registerFinishUpload(
      nickname,
      { record, publicKey: id.publicKey, wrappedPrivateKey },
      base,
      this.fetchImpl,
    );

    // Step 5: auto-login so the session is fully established.
    return this.loginFlow(passphrase, base);
  }

  // loginFlow(passphrase) — full client login: OPAQUE -> token -> unwrap private
  // key -> open every sealed conversation GROUP_KEY. Holds them in memory.
  async loginFlow(passphrase, base = this.base) {
    await sodium.ready();
    this.base = base;
    api.setBase(base);
    if (this.fetchImpl) api.setFetch(this.fetchImpl);

    const norm = normalizePassphrase(passphrase);
    this.nickname = nicknameFromPassphrase(norm);
    const { token, exportKey } = await opaque.login(norm, this.nickname, base, this.fetchImpl);
    this.token = token;
    api.setToken(token);

    const keys = await api.getKeys();
    if (!keys.wrapped_private_key) throw new Error('no wrapped_private_key for user');
    this.privateKey = sodium.unwrapPrivateKey(sodium.fromB64(keys.wrapped_private_key), exportKey);
    this.publicKey = sodium.publicFromPrivate(this.privateKey);

    this.convKeys.clear();
    for (const ck of keys.conversation_keys || []) {
      const groupKey = sodium.openGroupKey(sodium.fromB64(ck.sealed), this.publicKey, this.privateKey);
      this.convKeys.set(ck.conversation_id, groupKey);
    }
    // exportKey is no longer needed beyond this point — drop the reference.
    this.me = await api.getMe();
    return this.me;
  }

  // Re-bind the shared api module to THIS session's token/base/fetch before any
  // API call. In the browser there is one active session, but multiple Session
  // instances (tests, multi-account) share the api singleton — this guarantees
  // each call uses the right credentials regardless of which session logged in last.
  _use() {
    api.setBase(this.base);
    if (this.fetchImpl) api.setFetch(this.fetchImpl);
    api.setToken(this.token);
  }

  groupKey(cid) {
    const k = this.convKeys.get(Number(cid)) || this.convKeys.get(cid);
    if (!k) throw new Error(`no group key for conversation ${cid}`);
    return k;
  }

  // sendText(cid, text) — encrypt under the conversation GROUP_KEY, POST ciphertext.
  async sendText(cid, text) {
    this._use();
    const { nonce, ciphertext } = sodium.encryptMessage(text, this.groupKey(cid));
    const clientMsgId = (globalThis.crypto?.randomUUID?.())
      || `${Date.now()}-${Math.random().toString(36).slice(2)}`;
    return api.send(cid, { client_msg_id: clientMsgId, kind: 'text', nonce, ciphertext });
  }

  // decryptIncoming(msgRow) — msgRow = { conversation_id?, nonce, ciphertext, ... }.
  // For text rows returns the plaintext string. cidHint covers WS rows where the
  // conversation_id is on the frame.
  decryptIncoming(msgRow, cidHint) {
    const cid = msgRow.conversation_id ?? cidHint;
    return sodium.decryptMessage(msgRow.nonce, msgRow.ciphertext, this.groupKey(cid));
  }

  // loadConversation(cid) — fetch + decrypt all text messages. Non-text rows are
  // returned with text:null so callers can fetch/render attachments separately.
  async loadConversation(cid, after = 0) {
    this._use();
    const rows = await api.listMessages(cid, after);
    return rows.map((m) => ({
      ...m,
      text: m.kind === 'text' ? this.decryptIncoming(m, cid) : null,
    }));
  }

  // ── onboarding orchestration ────────────────────────────────────────────
  // These create conversations + group keys through REAL endpoints and store
  // newly-minted keys in the SAME in-memory convKeys map login uses, so the
  // session can encrypt/decrypt immediately without a re-login.

  // Store a freshly-created key under cid in the in-memory map (number-keyed).
  _holdKey(cid, key) {
    this.convKeys.set(Number(cid), key);
  }

  // Seal `key` to each member that HAS a public_key (is registered).
  // Returns { grants:[{user_id, sealed(b64)}], pending:[ids without a pubkey] }.
  _sealForMembers(members, key) {
    const grants = [];
    const pending = [];
    for (const m of members) {
      if (m.public_key) {
        const sealed = sodium.sealGroupKeyTo(key, sodium.fromB64(m.public_key));
        grants.push({ user_id: m.id, sealed: sodium.toB64(sealed) });
      } else {
        pending.push(m.id);
      }
    }
    return { grants, pending };
  }

  // adminCreateUser(nickname, displayName) — admin creates an unregistered user
  // row (they self-register later). Returns { id }.
  async adminCreateUser(nickname, displayName) {
    this._use();
    return api.adminCreateUser(nickname, displayName);
  }

  // adminListUsers() — admin view of all users incl. pubkey + registered flags.
  async adminListUsers() {
    this._use();
    return api.adminListUsers();
  }

  // setUserAdmin(userId, isAdmin) — promote or demote another user's admin status.
  // The server blocks self-change and non-admins.
  async setUserAdmin(userId, isAdmin) {
    if (!this.me?.is_admin) throw new Error('admin only');
    this._use();
    return api.adminSetAdmin(userId, isAdmin);
  }

  // createGroup(title, memberIds) — admin flow. Creates the conversation, mints a
  // fresh GROUP_KEY, seals it to every registered member, grants over HTTP, and
  // holds the key locally. Unregistered members are returned as `pending`.
  async createGroup(title, memberIds) {
    await sodium.ready();
    this._use();
    const { conversation_id, members } = await api.adminCreateConversation(title, memberIds);
    const GROUP_KEY = sodium.newGroupKey();
    const { grants, pending } = this._sealForMembers(members, GROUP_KEY);
    let granted = 0;
    if (grants.length) ({ granted } = await api.grantKeys(conversation_id, grants));
    this._holdKey(conversation_id, GROUP_KEY);
    return { conversationId: conversation_id, granted, pending };
  }

  // listUsers() — roster of ALL users (id, nickname, display_name, public_key,
  // registered) so ANY user can pick invitees. No private fields.
  async listUsers() {
    this._use();
    return api.listUsers();
  }

  // getMembers(cid) — members + pubkeys of a conversation I belong to.
  async getMembers(cid) {
    this._use();
    return api.getMembers(cid);
  }

  // createRoom(title, memberIds) — UNIVERSAL flow (any user). Mirrors createGroup
  // but via the non-admin POST /api/conversations endpoint: create the room (the
  // creator is auto-added), mint a fresh GROUP_KEY, seal it to every registered
  // member, grant over HTTP, and hold the key locally. Unregistered members come
  // back as `pending` (grant them once they register, via grantPending).
  async createRoom(title, memberIds) {
    await sodium.ready();
    this._use();
    const { conversation_id, members } = await api.createConversation(title, memberIds);
    const GROUP_KEY = sodium.newGroupKey();
    const { grants, pending } = this._sealForMembers(members, GROUP_KEY);
    let granted = 0;
    if (grants.length) ({ granted } = await api.grantKeys(conversation_id, grants));
    this._holdKey(conversation_id, GROUP_KEY);
    return { conversationId: conversation_id, granted, pending };
  }

  // addToRoom(cid, userId) — UNIVERSAL flow (any MEMBER). Invites the user via the
  // non-admin POST /api/conversations/:cid/members endpoint, then seals the HELD
  // room key to their pubkey and grants it. Unregistered invitees (no pubkey) come
  // back as pending — grant them via grantPending once they register.
  async addToRoom(cid, userId) {
    await sodium.ready();
    this._use();
    const key = this.groupKey(cid); // throws if we don't hold the key
    const { member } = await api.addRoomMember(cid, userId);
    if (!member.public_key) {
      return { granted: 0, pending: [member.id] };
    }
    const sealed = sodium.sealGroupKeyTo(key, sodium.fromB64(member.public_key));
    const { granted } = await api.grantKeys(cid, [{ user_id: member.id, sealed: sodium.toB64(sealed) }]);
    return { granted, pending: [] };
  }

  // addToGroup(cid, userId) — admin adds a member, then seals the HELD group key
  // to that member's pubkey and grants it. If the member is not yet registered
  // (no pubkey) they are returned as pending — call grantPending once they are.
  async addToGroup(cid, userId) {
    await sodium.ready();
    this._use();
    const key = this.groupKey(cid); // throws if we don't hold the key
    const { member } = await api.adminAddMember(cid, userId);
    if (!member.public_key) {
      return { granted: 0, pending: [member.id] };
    }
    const sealed = sodium.sealGroupKeyTo(key, sodium.fromB64(member.public_key));
    const { granted } = await api.grantKeys(cid, [{ user_id: member.id, sealed: sodium.toB64(sealed) }]);
    return { granted, pending: [] };
  }

  // grantPending(cid, memberIds) — re-seal the held group key to members that
  // have since registered. Fetches fresh pubkeys, seals, grants. Members still
  // lacking a pubkey are returned as pending.
  async grantPending(cid, memberIds) {
    await sodium.ready();
    this._use();
    const key = this.groupKey(cid);
    const ids = new Set(memberIds.map(Number));
    const members = (await api.getMembers(cid)).filter((m) => ids.has(Number(m.id)));
    const { grants, pending } = this._sealForMembers(members, key);
    let granted = 0;
    if (grants.length) ({ granted } = await api.grantKeys(cid, grants));
    return { granted, pending };
  }

  // startDirect(userId) — open (or fetch) a peer DM, mint a DM_KEY, seal it to
  // BOTH members, grant, and hold it locally. Returns the conversation id.
  async startDirect(userId) {
    await sodium.ready();
    this._use();
    const { conversation_id, members } = await api.createDirect(userId);
    // If we already hold a key for this DM (re-opened), reuse it.
    if (this.convKeys.has(Number(conversation_id))) return conversation_id;
    const DM_KEY = sodium.newGroupKey();
    const { grants } = this._sealForMembers(members, DM_KEY);
    if (grants.length) await api.grantKeys(conversation_id, grants);
    this._holdKey(conversation_id, DM_KEY);
    return conversation_id;
  }

  // encryptFile(cid, bytes) -> { nonce(base64), ciphertext(Uint8Array) }
  encryptFile(cid, bytes) {
    return sodium.encryptBytes(bytes, this.groupKey(cid));
  }
  // decryptFile(cid, ciphertextBytes, nonceB64) -> Uint8Array plaintext bytes.
  decryptFile(cid, ciphertextBytes, nonceB64) {
    return sodium.decryptBytes(ciphertextBytes, nonceB64, this.groupKey(cid));
  }

  // Convenience: encrypt + upload a file, returning { attachment_id, nonce }.
  async uploadFile(cid, bytes, contentType = 'application/octet-stream') {
    this._use();
    const { nonce, ciphertext } = this.encryptFile(cid, bytes);
    const { attachment_id } = await api.upload(cid, { nonce, contentType, bytes: ciphertext });
    return { attachment_id, nonce };
  }
  // Convenience: download + decrypt a file by attachment id.
  async downloadFile(cid, aid) {
    this._use();
    const { bytes, nonce } = await api.downloadFile(aid);
    return this.decryptFile(cid, bytes, nonce);
  }

  // editText(cid, mid, newText) — re-encrypt locally, PATCH to server.
  async editText(cid, mid, newText) {
    this._use();
    const { nonce, ciphertext } = sodium.encryptMessage(newText, this.groupKey(cid));
    return api.editMessage(cid, mid, { nonce, ciphertext });
  }

  // deleteMessage(cid, mid) — soft-delete on server.
  async deleteMessage(cid, mid) {
    this._use();
    return api.deleteMessage(cid, mid);
  }

  async markRead(cid, lastReadMessageId) { this._use(); return api.markRead(cid, lastReadMessageId); }

  async deleteRoom(cid) {
    this._use();
    const r = await api.deleteConversation(cid);
    this.convKeys.delete(Number(cid));
    return r;
  }

  openWS(onMessage) {
    this.ws = api.openWS(onMessage, { WebSocketImpl: this.WebSocketImpl, wsBase: this.wsBase });
    return this.ws;
  }

  // Wipe all in-memory secrets. Call on logout / beforeunload.
  destroy() {
    const zero = (u) => { if (u && u.fill) u.fill(0); };
    zero(this.privateKey);
    zero(this.publicKey);
    for (const k of this.convKeys.values()) zero(k);
    this.convKeys.clear();
    this.privateKey = null;
    this.publicKey = null;
    this.token = null;
    this.me = null;
    api.setToken(null);
    try { this.ws?.close?.(); } catch { /* ignore */ }
    this.ws = null;
  }
}
