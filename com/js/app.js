// web/js/app.js — wires the UI-agnostic client-core engine to the DOM.
// NO localStorage / IndexedDB / cookies for any secret or content. Secrets live
// only on the in-memory Session and are wiped on logout / beforeunload.
import { Session } from './client-core.js';
import * as api from './api.js';
import * as sodiumHelpers from './sodium-helpers.js';

const $ = (id) => document.getElementById(id);

// Show/hide the password in clear text (module scripts run after DOM is parsed).
$('showPw')?.addEventListener('change', (e) => {
  $('passphrase').type = e.target.checked ? 'text' : 'password';
});

// Resolve API base using the same priority order as api.js:
//   1. window.COM_API_BASE  (set before app.js loads, e.g. in a deploy-env script)
//   2. <meta name="com-api-base" content="...">  (set in com.html for a specific deploy)
//   3. '' (same-origin — works for local dev and same-origin deployments)
const API_BASE = (() => {
  if (typeof window !== 'undefined') {
    if (window.COM_API_BASE) return window.COM_API_BASE;
    const meta = document.querySelector('meta[name="com-api-base"]');
    if (meta && meta.content) return meta.content;
  }
  return '';
})();

let session = null;
let activeCid = null;
let ws = null;
let wsBackoff = 1000;
const objectUrls = []; // track for revocation

// ── login ──────────────────────────────────────────────────────────────────
$('loginForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  $('loginError').textContent = '';
  const passphrase = $('passphrase').value;
  const honeypot = $('username').value;

  // Honeypot: legit users leave it empty. If filled, refuse locally; the real
  // tripwire is server-side (it logs/alerts on any honeypot value at login).
  if (honeypot.trim()) {
    $('loginError').textContent = 'Sign-in failed.';
    return;
  }

  $('loginBtn').disabled = true;
  try {
    session = new Session({ base: API_BASE });
    const me = await session.loginFlow(passphrase, API_BASE);
    $('passphrase').value = ''; // clear the secret from the DOM immediately
    enterChat(me);
  } catch (err) {
    $('loginError').textContent = 'Sign-in failed. Check your passphrase.';
    session?.destroy();
    session = null;
  } finally {
    $('loginBtn').disabled = false;
  }
});

// ── register (first-time setup) ───────────────────────────────────────────
// A user row must already exist (seeded by admin). This registers the OPAQUE
// credential + uploads the identity keypair, then auto-logs in.
$('registerBtn').addEventListener('click', async () => {
  $('loginError').textContent = '';
  const passphrase = $('passphrase').value;
  const honeypot = $('username').value;

  if (honeypot.trim()) {
    $('loginError').textContent = 'Sign-in failed.';
    return;
  }
  if (!passphrase) {
    $('loginError').textContent = 'Enter your passphrase first.';
    return;
  }

  $('registerBtn').disabled = true;
  $('loginBtn').disabled = true;
  $('loginError').textContent = 'Setting up your account…';
  try {
    session = new Session({ base: API_BASE });
    const me = await session.registerFlow(passphrase, API_BASE);
    $('passphrase').value = ''; // clear the secret from the DOM immediately
    $('loginError').textContent = '';
    enterChat(me);
  } catch (err) {
    $('loginError').textContent = 'Registration failed. Check your passphrase or ask your admin.';
    session?.destroy();
    session = null;
  } finally {
    $('registerBtn').disabled = false;
    $('loginBtn').disabled = false;
  }
});

function enterChat(me) {
  $('loginView').hidden = true;
  $('chatView').hidden = false;
  $('who').hidden = false;
  $('who').textContent = me.display_name || me.nickname;
  $('logoutBtn').hidden = false;
  renderConvList(me.conversations || []);
  const first = (me.conversations || [])[0];
  if (first) {
    selectConversation(first.id);
    // Land on the conversation list on phones; the first thread is preloaded
    // behind it and a tap (or the wide-screen layout) reveals it.
    showList();
  }
  connectWS();
  refreshOnboardingPanels().catch(() => {});
}

// ── onboarding panels (DM picker for all; admin panel for admins) ────────────
// `pendingByGroup` tracks unregistered members per group so the admin can grant
// them once they register. It lives only in memory, like everything else.
const pendingByGroup = new Map(); // cid -> Set(userId)

function setNote(id, text, cls = '') {
  const el = $(id);
  if (!el) return;
  el.textContent = text || '';
  el.className = 'panel-note' + (cls ? ' ' + cls : '');
}

async function refreshOnboardingPanels() {
  if (!session?.me) return;
  const isAdmin = !!session.me.is_admin;
  $('adminPanel').hidden = !isAdmin;

  // Everyone gets a "new DM" picker. Admins see the full user list (with pubkeys);
  // non-admins can only DM people they already share a conversation with is not
  // possible to enumerate, so we fall back to nickname entry. For the family use
  // case the picker is admin-fed; non-admins simply pick from people they know.
  let users = [];
  if (isAdmin) {
    try { users = await session.adminListUsers(); } catch { users = []; }
  }
  const me = session.me;
  const others = users.filter((u) => u.id !== me.id);

  // DM picker — list everyone except me (admins) or hide if we can't enumerate.
  const dmPicker = $('dmPicker');
  if (isAdmin) {
    $('dmPanel').hidden = false;
    dmPicker.innerHTML = '';
    for (const u of others) {
      const o = document.createElement('option');
      o.value = String(u.id);
      o.textContent = `${u.display_name || u.nickname}`;
      dmPicker.appendChild(o);
    }
  } else {
    // Non-admins keep the DM picker visible but it stays empty unless we have a
    // roster; in the family model the admin sets up conversations, so this is fine.
    $('dmPanel').hidden = others.length === 0;
  }

  if (!isAdmin) return;

  // Admin: user list with registered status.
  const ul = $('userList');
  ul.innerHTML = '';
  for (const u of users) {
    const li = document.createElement('li');
    li.textContent = `${u.display_name || u.nickname} `;
    const small = document.createElement('span');
    small.style.color = 'var(--muted)';
    small.style.fontSize = '.75rem';
    small.textContent = `@${u.nickname}`;
    li.appendChild(small);
    if (u.is_admin) li.appendChild(tag('admin', 'adm'));
    li.appendChild(u.registered ? tag('registered', 'reg') : tag('pending', 'unreg'));
    ul.appendChild(li);
  }

  // Group-creation member checkboxes (only registered, non-me users).
  const gm = $('groupMembers');
  gm.innerHTML = '';
  for (const u of others.filter((x) => x.registered)) {
    const label = document.createElement('label');
    const cb = document.createElement('input');
    cb.type = 'checkbox';
    cb.value = String(u.id);
    label.appendChild(cb);
    label.appendChild(document.createTextNode(u.display_name || u.nickname));
    gm.appendChild(label);
  }

  // Add-member selects: groups I'm in + all other users.
  const groups = (me.conversations || []).filter((c) => c.kind === 'group');
  fillSelect($('addMemberGroup'), groups.map((g) => ({ value: g.id, text: g.title || `group ${g.id}` })));
  fillSelect($('addMemberUser'), others.map((u) => ({ value: u.id, text: u.display_name || u.nickname })));

  renderPendingList(users);
}

function tag(text, cls) {
  const s = document.createElement('span');
  s.className = 'tag ' + cls;
  s.textContent = text;
  return s;
}
function fillSelect(sel, items) {
  sel.innerHTML = '';
  for (const it of items) {
    const o = document.createElement('option');
    o.value = String(it.value);
    o.textContent = it.text;
    sel.appendChild(o);
  }
}

function renderPendingList(users) {
  const list = $('pendingList');
  list.innerHTML = '';
  const byId = new Map(users.map((u) => [u.id, u]));
  for (const [cid, set] of pendingByGroup) {
    for (const uid of set) {
      const u = byId.get(uid);
      const li = document.createElement('li');
      const label = u ? (u.display_name || u.nickname) : `user ${uid}`;
      const ready = u && u.registered;
      li.textContent = `${label} — ${ready ? 'registered' : 'not registered yet'} (group ${cid})`;
      const btn = document.createElement('button');
      btn.type = 'button';
      btn.textContent = 'Grant';
      btn.disabled = !ready;
      btn.addEventListener('click', () => grantOnePending(cid, uid));
      li.appendChild(btn);
      list.appendChild(li);
    }
  }
}

async function grantOnePending(cid, uid) {
  try {
    const res = await session.grantPending(cid, [uid]);
    if (!res.pending.length) {
      const set = pendingByGroup.get(cid);
      if (set) { set.delete(uid); if (!set.size) pendingByGroup.delete(cid); }
    }
    setNote('adminMsg', `Granted access to ${res.granted} member(s).`, 'ok');
    await refreshOnboardingPanels();
  } catch {
    setNote('adminMsg', 'Grant failed.', 'err');
  }
}

function wireOnboardingForms() {
  $('dmStartBtn')?.addEventListener('click', async () => {
    const sel = $('dmPicker');
    const uid = Number(sel.value);
    if (!uid) return;
    try {
      const cid = await session.startDirect(uid);
      setNote('dmMsg', 'Direct chat ready.', 'ok');
      session.me = await api.getMe();
      renderConvList(session.me.conversations || []);
      selectConversation(cid);
    } catch {
      setNote('dmMsg', 'Could not start chat.', 'err');
    }
  });

  $('createUserForm')?.addEventListener('submit', async (e) => {
    e.preventDefault();
    const nickname = $('newNick').value.trim();
    const display = $('newDisplay').value.trim();
    if (!nickname || !display) return;
    try {
      await session.adminCreateUser(nickname, display);
      $('newNick').value = ''; $('newDisplay').value = '';
      setNote('adminMsg', `Created ${nickname}. They can now register.`, 'ok');
      await refreshOnboardingPanels();
    } catch {
      setNote('adminMsg', 'Could not create user.', 'err');
    }
  });

  $('createGroupForm')?.addEventListener('submit', async (e) => {
    e.preventDefault();
    const title = $('groupTitle').value.trim();
    const ids = Array.from($('groupMembers').querySelectorAll('input:checked')).map((c) => Number(c.value));
    if (!title) return;
    try {
      const { conversationId, granted, pending } = await session.createGroup(title, ids);
      $('groupTitle').value = '';
      if (pending.length) {
        pendingByGroup.set(conversationId, new Set(pending));
        setNote('pendingNote', `${pending.length} member(s) not registered yet — grant them once they register.`, 'err');
      } else {
        setNote('pendingNote', `Group created. Keyed ${granted} member(s).`, 'ok');
      }
      session.me = await api.getMe();
      renderConvList(session.me.conversations || []);
      await refreshOnboardingPanels();
    } catch {
      setNote('pendingNote', 'Could not create group.', 'err');
    }
  });

  $('addMemberForm')?.addEventListener('submit', async (e) => {
    e.preventDefault();
    const cid = Number($('addMemberGroup').value);
    const uid = Number($('addMemberUser').value);
    if (!cid || !uid) return;
    try {
      const res = await session.addToGroup(cid, uid);
      if (res.pending.length) {
        const set = pendingByGroup.get(cid) || new Set();
        for (const p of res.pending) set.add(p);
        pendingByGroup.set(cid, set);
        setNote('adminMsg', 'Added, but member not registered yet — grant after they register.', 'err');
      } else {
        setNote('adminMsg', 'Member added and keyed.', 'ok');
      }
      await refreshOnboardingPanels();
    } catch {
      setNote('adminMsg', 'Could not add member.', 'err');
    }
  });
}
wireOnboardingForms();

function renderConvList(convs) {
  const el = $('convList');
  el.innerHTML = '';
  for (const c of convs) {
    const b = document.createElement('button');
    b.className = 'conv' + (c.id === activeCid ? ' active' : '');
    b.textContent = c.title || c.kind;
    if (c.unread) {
      const badge = document.createElement('span');
      badge.className = 'badge';
      badge.textContent = String(c.unread);
      b.appendChild(badge);
    }
    b.addEventListener('click', () => selectConversation(c.id));
    el.appendChild(b);
  }
}

// ── mobile single-panel navigation ───────────────────────────────────────────
// On phones the sidebar (list) and thread occupy the full width one at a time.
// Adding `show-thread` slides the thread in; the back button clears it.
// On wide screens (>=820px) CSS keeps both panes visible and the back button hidden.
function showThread() {
  $('chatView').classList.add('show-thread');
  $('backBtn').hidden = false;
}
function showList() {
  $('chatView').classList.remove('show-thread');
  $('backBtn').hidden = true;
}
$('backBtn')?.addEventListener('click', showList);

// ── conversation rendering ───────────────────────────────────────────────────
async function selectConversation(cid) {
  activeCid = cid;
  showThread();
  $('messages').innerHTML = '';
  try {
    const rows = await session.loadConversation(cid);
    for (const m of rows) await renderMessage(m);
    scrollToBottom();
    const lastId = rows.length ? rows[rows.length - 1].id : 0;
    if (lastId) session.markRead(cid, lastId).catch(() => {});
  } catch (err) {
    appendSystem('Could not load this conversation.');
  }
}

async function renderMessage(m) {
  const wrap = document.createElement('div');
  const mine = session.me && m.sender_id === session.me.id;
  wrap.className = 'msg' + (mine ? ' mine' : '');

  if (m.kind === 'text') {
    wrap.textContent = m.text != null ? m.text : safeDecrypt(m);
  } else if (m.attachment_id) {
    wrap.appendChild(await renderAttachment(m));
  } else {
    wrap.textContent = '[unsupported message]';
  }
  $('messages').appendChild(wrap);
}

function safeDecrypt(m) {
  try { return session.decryptIncoming(m, activeCid); }
  catch { return '[unable to decrypt]'; }
}

async function renderAttachment(m) {
  const holder = document.createElement('div');
  holder.className = 'attachment';
  holder.textContent = 'Loading attachment…';
  try {
    const bytes = await session.downloadFile(m.conversation_id ?? activeCid, m.attachment_id);
    const blob = new Blob([bytes]);
    const url = URL.createObjectURL(blob);
    objectUrls.push(url);
    holder.innerHTML = '';
    if (m.kind === 'image') {
      const img = document.createElement('img');
      img.src = url;
      img.alt = 'attachment';
      holder.appendChild(img);
    } else {
      const a = document.createElement('a');
      a.href = url;
      a.download = 'attachment';
      a.textContent = 'Download attachment';
      holder.appendChild(a);
    }
  } catch {
    holder.textContent = '[attachment unavailable]';
  }
  return holder;
}

// ── sending text ─────────────────────────────────────────────────────────────
$('composer').addEventListener('submit', async (e) => {
  e.preventDefault();
  const text = $('msgInput').value.trim();
  if (!text || activeCid == null) return;
  $('msgInput').value = '';
  try {
    await session.sendText(activeCid, text);
    // Optimistic render (server does not echo our own sends back to us over WS).
    await renderMessage({ kind: 'text', text, sender_id: session.me.id });
    scrollToBottom();
  } catch {
    appendSystem('Message failed to send.');
  }
});

// ── sending an encrypted file attachment ─────────────────────────────────────
$('fileInput').addEventListener('change', async (e) => {
  const file = e.target.files?.[0];
  if (!file || activeCid == null) return;
  try {
    const bytes = new Uint8Array(await file.arrayBuffer());
    const { attachment_id } = await session.uploadFile(activeCid, bytes, file.type || 'application/octet-stream');
    const kind = (file.type || '').startsWith('image/') ? 'image' : 'video';
    // The attachment is referenced by a message carrying an encrypted caption marker.
    const { nonce, ciphertext } = sodiumHelpers.encryptMessage(' ', session.groupKey(activeCid));
    const clientMsgId = (crypto.randomUUID?.() || `${Date.now()}-${Math.random()}`);
    await api.send(activeCid, { client_msg_id: clientMsgId, kind, nonce, ciphertext, attachment_id });
    await renderMessage({ kind, attachment_id, conversation_id: activeCid, sender_id: session.me.id });
    scrollToBottom();
  } catch {
    appendSystem('Attachment failed to send.');
  } finally {
    e.target.value = '';
  }
});

// ── WebSocket live updates + reconnect with backoff ──────────────────────────
function connectWS() {
  if (!session) return;
  ws = session.openWS(async (frame) => {
    if (frame.type !== 'message') return;
    if (frame.conversation_id === activeCid) {
      await renderMessage({
        id: frame.id, kind: frame.kind, sender_id: frame.sender_id,
        nonce: frame.nonce, ciphertext: frame.ciphertext,
        attachment_id: frame.attachment_id, conversation_id: frame.conversation_id,
        text: frame.kind === 'text' ? safeDecrypt(frame) : undefined,
      });
      scrollToBottom();
      if (frame.id) session.markRead(activeCid, frame.id).catch(() => {});
    } else {
      // Refresh the conversation list to bump the unread badge.
      session.me = await api.getMe();
      renderConvList(session.me.conversations || []);
    }
  });
  wsBackoff = 1000;
  const onClose = () => {
    if (!session) return; // logged out
    setTimeout(connectWS, wsBackoff);
    wsBackoff = Math.min(wsBackoff * 2, 30000);
  };
  ws.addEventListener?.('close', onClose);
  ws.addEventListener?.('error', () => { try { ws.close(); } catch {} });
}

// ── logout / cleanup ─────────────────────────────────────────────────────────
$('logoutBtn').addEventListener('click', lock);
function lock() {
  for (const u of objectUrls) URL.revokeObjectURL(u);
  objectUrls.length = 0;
  session?.destroy();
  session = null;
  ws = null;
  activeCid = null;
  $('chatView').hidden = true;
  $('chatView').classList.remove('show-thread');
  $('backBtn').hidden = true;
  $('loginView').hidden = false;
  $('who').hidden = true;
  $('logoutBtn').hidden = true;
  $('messages').innerHTML = '';
  $('convList').innerHTML = '';
  pendingByGroup.clear();
  $('adminPanel').hidden = true;
  $('userList').innerHTML = '';
  $('pendingList').innerHTML = '';
  setNote('adminMsg', ''); setNote('pendingNote', ''); setNote('dmMsg', '');
}

// Clear in-memory secrets when the tab is closed/hidden.
window.addEventListener('beforeunload', () => { session?.destroy(); });

// ── helpers ──────────────────────────────────────────────────────────────────
function scrollToBottom() {
  const m = $('messages');
  m.scrollTop = m.scrollHeight;
}
function appendSystem(text) {
  const d = document.createElement('div');
  d.className = 'msg system';
  d.textContent = text;
  $('messages').appendChild(d);
}
