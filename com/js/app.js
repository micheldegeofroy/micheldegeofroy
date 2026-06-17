// web/js/app.js — wires the UI-agnostic client-core engine to the DOM.
// NO localStorage / IndexedDB / cookies for any secret or content. Secrets live
// only on the in-memory Session and are wiped on logout / beforeunload.
import { Session } from './client-core.js';
import * as api from './api.js';
import * as sodiumHelpers from './sodium-helpers.js';
import { CallController } from './call.js';

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
let activePeerId = null;     // the other member's id when a direct conv is active
let activePeerName = null;
let ws = null;
let wsBackoff = 1000;
const objectUrls = []; // track for revocation
let call = null;
let callTimer = null, callStart = 0;

// ── sign in ──────────────────────────────────────────────────────────────────
// ONE action: signInFlow sets up a first-time account (admin pre-created it) OR
// logs in a returning user, deciding automatically. No separate "register" step.
$('loginForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  $('loginError').textContent = '';
  const passphrase = $('passphrase').value;
  const honeypot = $('username').value;

  // Honeypot: legit users leave it empty. If filled, refuse locally; the real
  // tripwire is server-side (it alerts on any honeypot value on either path).
  if (honeypot.trim()) {
    $('loginError').textContent = 'Sign-in failed.';
    return;
  }
  if (!passphrase) {
    $('loginError').textContent = 'Enter your passphrase.';
    return;
  }

  $('loginBtn').disabled = true;
  try {
    session = new Session({ base: API_BASE });
    const me = await session.signInFlow(passphrase, honeypot, API_BASE);
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

function enterChat(me) {
  session.me = me;
  $('loginView').hidden = true;
  $('chatView').hidden = false;
  $('who').hidden = false;
  $('who').textContent = me.display_name || me.nickname;
  $('logoutBtn').hidden = false;
  renderConvList();
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
  const me = session.me;

  // EVERY user gets the roster (GET /api/users — minimal public fields) so they
  // can pick people for a new DM, a new room, or to add to the active room.
  let roster = [];
  try { roster = await session.listUsers(); } catch { roster = []; }
  const others = roster.filter((u) => u.id !== me.id);

  // (Direct chats are started by tapping a person in the unified sidebar list;
  // the old DM picker panel was removed.)

  // New-room member checklist — registered, non-me users. Available to ALL users.
  const rm = $('roomMembers');
  rm.innerHTML = '';
  for (const u of others.filter((x) => x.registered)) {
    const label = document.createElement('label');
    const cb = document.createElement('input');
    cb.type = 'checkbox';
    cb.value = String(u.id);
    label.appendChild(cb);
    label.appendChild(document.createTextNode(u.display_name || u.nickname));
    rm.appendChild(label);
  }

  // Refresh the per-room "Add people" affordance for the active room.
  renderAddPeople(roster);

  if (!isAdmin) return;

  // From here down: ADMIN-ONLY panel. Use the admin roster (with is_admin flags).
  let users = [];
  try { users = await session.adminListUsers(); } catch { users = []; }

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
    // Admin toggle via clickable chip. You can't change your OWN admin status.
    const isSelf = u.id === session.me.id;
    if (u.is_admin) {
      const adm = tag('admin', 'adm');
      if (!isSelf) {
        adm.classList.add('clickable');
        adm.title = 'Click to remove admin';
        adm.addEventListener('click', () => toggleAdmin(u.id, false));
      }
      li.appendChild(adm);
    } else if (!isSelf) {
      const mk = tag('make admin', 'mkadm clickable');
      mk.title = 'Click to make admin';
      mk.addEventListener('click', () => toggleAdmin(u.id, true));
      li.appendChild(mk);
    }
    li.appendChild(u.registered ? tag('registered', 'reg') : tag('pending', 'unreg'));

    // Suspend / restore + permanent delete (never for yourself).
    if (!isSelf) {
      if (u.is_active) {
        const s = tag('suspend', 'suspend clickable');
        s.title = 'Block this user from signing in';
        s.addEventListener('click', () => toggleActive(u.id, false));
        li.appendChild(s);
      } else {
        li.appendChild(tag('suspended', 'unreg'));
        const r = tag('restore', 'mkadm clickable');
        r.title = 'Allow this user to sign in again';
        r.addEventListener('click', () => toggleActive(u.id, true));
        li.appendChild(r);
      }
      // Permanent delete — inline two-tap (no popup), auto-disarms after 3.5s.
      const del = tag('delete', 'del clickable');
      del.title = 'Permanently delete this user and shred everything they sent';
      let armed = false, disarm = null;
      del.addEventListener('click', () => {
        if (!armed) {
          armed = true;
          del.textContent = 'tap to confirm';
          del.classList.add('armed');
          clearTimeout(disarm);
          disarm = setTimeout(() => { armed = false; del.textContent = 'delete'; del.classList.remove('armed'); }, 3500);
          return;
        }
        clearTimeout(disarm);
        deleteUser(u.id);
      });
      li.appendChild(del);
    }

    ul.appendChild(li);
  }

  // (Adding people to a room is done from inside the room via "Add people";
  // the admin "Add a member to a group" form was removed.)

  renderPendingList(users);
}

async function toggleAdmin(id, makeAdmin) {
  try {
    await session.setUserAdmin(id, makeAdmin);
    await refreshOnboardingPanels();
  } catch {
    setNote('adminMsg', 'Could not change admin.', 'err');
  }
}

async function toggleActive(id, active) {
  try {
    await session.setUserActive(id, active);
    setNote('adminMsg', active ? 'User restored.' : 'User suspended.', 'ok');
    await refreshOnboardingPanels();
    session.me = await api.getMe();
    renderConvList();
  } catch {
    setNote('adminMsg', active ? 'Could not restore user.' : 'Could not suspend user.', 'err');
  }
}

async function deleteUser(id) {
  try {
    await session.deleteUser(id);
    setNote('adminMsg', 'User permanently deleted.', 'ok');
    await refreshOnboardingPanels();
    session.me = await api.getMe();
    renderConvList();
  } catch {
    setNote('adminMsg', 'Could not delete user.', 'err');
  }
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

// ── per-room "Add people" affordance (ANY member of the active room) ─────────
// Shows the panel only when the active conversation is a GROUP room I belong to,
// and lists registered users who are NOT already members. `roster` is the public
// GET /api/users list. We compute existing members from session.me.conversations
// + the active room's member list (fetched lazily).
let addPeopleMembers = new Set(); // member ids of the active room (lazy)

async function renderAddPeople(roster) {
  const panel = $('addPeoplePanel');
  if (!panel) return;
  const conv = (session.me?.conversations || []).find((c) => c.id === activeCid);
  // Only for group rooms (DMs are 1:1 and not extendable here).
  if (!conv || conv.kind !== 'group') {
    panel.hidden = true;
    return;
  }
  panel.hidden = false;

  // Fetch the current members of the active room (members-only endpoint; we are
  // a member). Fall back to an empty set if it fails.
  try {
    const members = await session.getMembers(activeCid);
    addPeopleMembers = new Set(members.map((m) => Number(m.id)));
  } catch {
    addPeopleMembers = new Set();
  }

  const me = session.me;
  const candidates = roster.filter(
    (u) => u.id !== me.id && u.registered && !addPeopleMembers.has(Number(u.id)),
  );

  const list = $('addPeopleList');
  list.innerHTML = '';
  if (!candidates.length) {
    const note = document.createElement('p');
    note.className = 'panel-note';
    note.textContent = 'Everyone is already in this room.';
    list.appendChild(note);
    return;
  }
  for (const u of candidates) {
    const row = document.createElement('label');
    row.appendChild(document.createTextNode(u.display_name || u.nickname));
    const btn = document.createElement('button');
    btn.type = 'button';
    btn.textContent = 'Add';
    btn.addEventListener('click', () => addPersonToRoom(activeCid, u.id));
    row.appendChild(btn);
    list.appendChild(row);
  }
}

async function addPersonToRoom(cid, uid) {
  try {
    const res = await session.addToRoom(cid, uid);
    if (res.pending.length) {
      const set = pendingByGroup.get(cid) || new Set();
      for (const p of res.pending) set.add(p);
      pendingByGroup.set(cid, set);
      setNote('addPeopleMsg', 'Added — they will get access once they finish setup.', 'err');
    } else {
      setNote('addPeopleMsg', 'Added and given access.', 'ok');
    }
    await refreshOnboardingPanels();
  } catch {
    setNote('addPeopleMsg', 'Could not add this person.', 'err');
  }
}

function wireOnboardingForms() {
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

  // Universal "New room" form — available to EVERY user.
  $('createRoomForm')?.addEventListener('submit', async (e) => {
    e.preventDefault();
    const title = $('roomTitle').value.trim();
    const ids = Array.from($('roomMembers').querySelectorAll('input:checked')).map((c) => Number(c.value));
    if (!title) return;
    try {
      const { conversationId, granted, pending } = await session.createRoom(title, ids);
      $('roomTitle').value = '';
      if (pending.length) {
        pendingByGroup.set(conversationId, new Set(pending));
        setNote('roomMsg', `Room created. ${pending.length} invitee(s) still need to finish setup.`, 'err');
      } else {
        setNote('roomMsg', `Room created. Gave access to ${granted} member(s).`, 'ok');
      }
      session.me = await api.getMe();
      renderConvList();
      $('roomPanel').open = false;
      selectConversation(conversationId);
      await refreshOnboardingPanels();
    } catch {
      setNote('roomMsg', 'Could not create room.', 'err');
    }
  });

}
wireOnboardingForms();

// The sidebar is a UNIFIED list: every family member (registered contact) plus
// every room. Clicking a person opens — or starts, if none exists yet — the
// 1-to-1 direct chat with them; clicking a room opens the room. This is async
// because it needs the roster (GET /api/users); the last roster is cached so a
// transient fetch failure keeps the list populated.
let rosterCache = [];
async function renderConvList() {
  const el = $('convList');
  if (!el || !session?.me) return;
  const convs = session.me.conversations || [];
  const meId = session.me.id;

  // Map existing direct conversations by the other member's id.
  const dmByPeer = new Map();
  for (const c of convs) {
    if (c.kind === 'direct' && c.peer_id != null) dmByPeer.set(Number(c.peer_id), c);
  }
  const rooms = convs.filter((c) => c.kind === 'group');

  try { rosterCache = await session.listUsers(); } catch { /* keep last roster */ }
  const contacts = rosterCache.filter((u) => u.id !== meId && u.registered);

  el.innerHTML = '';

  // People — open or start the direct chat.
  for (const u of contacts) {
    const dm = dmByPeer.get(Number(u.id));
    const b = document.createElement('button');
    b.className = 'conv' + (dm && dm.id === activeCid ? ' active' : '');
    b.textContent = u.display_name || u.nickname;
    if (dm && dm.unread) appendBadge(b, dm.unread);
    b.addEventListener('click', () => openContact(u, dm));
    el.appendChild(b);
  }

  // Rooms — open the room.
  for (const c of rooms) {
    const b = document.createElement('button');
    b.className = 'conv' + (c.id === activeCid ? ' active' : '');
    b.textContent = c.title || `room ${c.id}`;
    if (c.unread) appendBadge(b, c.unread);
    b.addEventListener('click', () => selectConversation(c.id));
    el.appendChild(b);
  }
}

function appendBadge(b, n) {
  const badge = document.createElement('span');
  badge.className = 'badge';
  badge.textContent = String(n);
  b.appendChild(badge);
}

// Open the direct chat with a contact: reuse the existing DM if there is one,
// otherwise mint it (startDirect is idempotent server-side) and select it.
async function openContact(user, existingDm) {
  if (existingDm) { selectConversation(existingDm.id); showThread(); return; }
  try {
    const cid = await session.startDirect(user.id);
    session.me = await api.getMe();
    await renderConvList();
    selectConversation(cid);
    showThread();
  } catch {
    showToast('Could not open chat');
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

// ── delete room (inline two-tap confirm, no popup) ───────────────────────────
let roomDelArmed = false, roomDelTimer = null;
function resetRoomDelete() {
  roomDelArmed = false;
  clearTimeout(roomDelTimer);
  const btn = $('deleteRoomBtn');
  if (btn) { btn.textContent = 'Delete room'; btn.classList.remove('armed'); }
}
$('deleteRoomBtn')?.addEventListener('click', async () => {
  const btn = $('deleteRoomBtn');
  if (!roomDelArmed) {
    roomDelArmed = true;
    btn.textContent = 'Tap again to delete for everyone';
    btn.classList.add('armed');
    clearTimeout(roomDelTimer);
    roomDelTimer = setTimeout(resetRoomDelete, 3500);
    return;
  }
  resetRoomDelete();
  const cid = activeCid;
  if (cid == null) return;
  try {
    await session.deleteRoom(cid);
    session.me = await api.getMe();
    renderConvList();
    activeCid = null;
    $('deleteRoomBar').hidden = true;
    $('addPeoplePanel').hidden = true;
    $('messages').innerHTML = '';
    showList();
    // Select first remaining conversation if any.
    const first = (session.me.conversations || [])[0];
    if (first) selectConversation(first.id);
  } catch {
    appendSystem('Could not delete this room. Try again.');
  }
});

// ── conversation rendering ───────────────────────────────────────────────────
async function selectConversation(cid) {
  activeCid = cid;
  showThread();
  $('messages').innerHTML = '';
  // Show the delete room button for the active conversation.
  $('deleteRoomBar').hidden = false;
  // The Call button appears only for 1-to-1 direct conversations.
  const conv = (session.me?.conversations || []).find((c) => c.id === cid);
  activePeerId = (conv && conv.kind === 'direct') ? conv.peer_id : null;
  activePeerName = conv?.peer || null;
  $('callBar').hidden = activePeerId == null;
  // Refresh the per-room "Add people" affordance for the now-active room.
  setNote('addPeopleMsg', '');
  $('addPeoplePanel').open = false;
  refreshAddPeopleForActive().catch(() => {});
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

// Re-fetch the roster and re-render the "Add people" panel for the active room.
async function refreshAddPeopleForActive() {
  if (!session?.me) return;
  let roster = [];
  try { roster = await session.listUsers(); } catch { roster = []; }
  await renderAddPeople(roster);
}

// ── message action menu ───────────────────────────────────────────────────────
// Shows a small "..." button on hover (desktop) and triggers on long-press (mobile).
// Actions: Copy (text), Download (attachment), Edit (own text), Delete (own or admin).

let openMenu = null; // currently visible menu element

function closeOpenMenu() {
  if (openMenu) { openMenu.remove(); openMenu = null; }
}
document.addEventListener('click', closeOpenMenu);

function showToast(text) {
  let t = document.querySelector('.msg-toast');
  if (!t) {
    t = document.createElement('div');
    t.className = 'msg-toast';
    document.body.appendChild(t);
  }
  t.textContent = text;
  t.classList.add('msg-toast--show');
  clearTimeout(t._timer);
  t._timer = setTimeout(() => t.classList.remove('msg-toast--show'), 1800);
}

function buildMsgMenu(m, wrap, mine) {
  const isAdmin = !!session.me?.is_admin;
  const kind = m.kind || 'text';

  const btn = document.createElement('button');
  btn.className = 'msg-menu-btn';
  btn.setAttribute('aria-label', 'Message actions');
  btn.textContent = '⋯'; // horizontal ellipsis

  btn.addEventListener('click', (e) => {
    e.stopPropagation();
    closeOpenMenu();

    const menu = document.createElement('div');
    menu.className = 'msg-actions';
    openMenu = menu;

    // Copy — text messages.
    if (kind === 'text') {
      const copyItem = menuItem('Copy', async () => {
        const text = wrap.querySelector('.msg-text')?.textContent || '';
        try {
          await navigator.clipboard.writeText(text);
          showToast('Copied');
        } catch {
          showToast('Copy failed');
        }
      });
      menu.appendChild(copyItem);
    }

    // Download — attachment messages.
    if (m.attachment_id) {
      const attHolder = wrap.querySelector('.attachment');
      const dlItem = menuItem('Download', async () => {
        try {
          const cid = Number(attHolder?.dataset?.cid || activeCid);
          const aid = m.attachment_id;
          const filename = attHolder?.dataset?.filename || 'attachment';
          const bytes = await session.downloadFile(cid, aid);
          const blob = new Blob([bytes]);
          const url = URL.createObjectURL(blob);
          const a = document.createElement('a');
          a.href = url;
          a.download = filename;
          document.body.appendChild(a);
          a.click();
          document.body.removeChild(a);
          setTimeout(() => URL.revokeObjectURL(url), 5000);
        } catch {
          showToast('Download failed');
        }
      });
      menu.appendChild(dlItem);
    }

    // Edit — only own text messages that have an id (not unsent optimistic).
    if (mine && kind === 'text' && m.id) {
      const editItem = menuItem('Edit', () => {
        const textEl = wrap.querySelector('.msg-text');
        const current = textEl?.textContent || '';
        const input = document.createElement('input');
        input.type = 'text';
        input.className = 'msg-edit-input';
        input.value = current;

        const saveBtn = document.createElement('button');
        saveBtn.className = 'msg-edit-save';
        saveBtn.textContent = 'Save';

        const cancelBtn = document.createElement('button');
        cancelBtn.className = 'msg-edit-cancel';
        cancelBtn.textContent = 'Cancel';

        const editRow = document.createElement('div');
        editRow.className = 'msg-edit-row';
        editRow.appendChild(input);
        editRow.appendChild(saveBtn);
        editRow.appendChild(cancelBtn);

        // Replace text with edit row.
        textEl.replaceWith(editRow);
        input.focus();
        input.select();

        const cancelEdit = () => {
          editRow.replaceWith(textEl);
        };

        cancelBtn.addEventListener('click', cancelEdit);
        saveBtn.addEventListener('click', async () => {
          const newText = input.value.trim();
          if (!newText || newText === current) { cancelEdit(); return; }
          try {
            const { edited_at } = await session.editText(activeCid, m.id, newText);
            // Restore text node with updated content.
            textEl.textContent = newText;
            editRow.replaceWith(textEl);
            m.text = newText;
            // Update/add edited marker.
            let edMark = wrap.querySelector('.msg-edited');
            if (!edMark) {
              edMark = document.createElement('span');
              edMark.className = 'msg-edited';
              edMark.textContent = ' edited';
              wrap.insertBefore(edMark, btn);
            }
          } catch {
            showToast('Edit failed');
            cancelEdit();
          }
        });
        input.addEventListener('keydown', (ev) => {
          if (ev.key === 'Enter') saveBtn.click();
          if (ev.key === 'Escape') cancelEdit();
        });
      });
      menu.appendChild(editItem);
    }

    // Delete — own messages or admin for any. Inline two-tap confirm (no popup):
    // first tap arms it, second tap deletes; tapping elsewhere closes the menu.
    if (mine || isAdmin) {
      const delItem = document.createElement('button');
      delItem.className = 'msg-action msg-action--danger';
      delItem.textContent = 'Delete';
      let armed = false;
      delItem.addEventListener('click', async (e) => {
        e.stopPropagation();
        if (!armed) { armed = true; delItem.textContent = 'Tap again to delete'; return; }
        closeOpenMenu();
        try {
          await session.deleteMessage(activeCid, m.id);
          wrap.remove();
        } catch {
          showToast('Delete failed');
        }
      });
      menu.appendChild(delItem);
    }

    if (!menu.children.length) return; // nothing to show

    // Position the menu near the button.
    const rect = btn.getBoundingClientRect();
    menu.style.position = 'fixed';
    menu.style.top = `${rect.bottom + 4}px`;
    menu.style.left = `${Math.min(rect.left, window.innerWidth - 160)}px`;
    document.body.appendChild(menu);
  });

  // Long-press on mobile.
  let pressTimer = null;
  wrap.addEventListener('touchstart', (e) => {
    pressTimer = setTimeout(() => { btn.click(); }, 450);
  }, { passive: true });
  wrap.addEventListener('touchend', () => clearTimeout(pressTimer));
  wrap.addEventListener('touchmove', () => clearTimeout(pressTimer));

  return btn;
}

function menuItem(label, onClick) {
  const el = document.createElement('button');
  el.className = 'msg-action';
  el.textContent = label;
  el.addEventListener('click', (e) => {
    e.stopPropagation();
    closeOpenMenu();
    onClick();
  });
  return el;
}

async function renderMessage(m) {
  const wrap = document.createElement('div');
  const mine = session.me && m.sender_id === session.me.id;
  wrap.className = 'msg' + (mine ? ' mine' : '');
  if (m.id) wrap.dataset.mid = String(m.id);
  wrap.dataset.senderId = String(m.sender_id);
  wrap.dataset.kind = m.kind || 'text';

  if (m.kind === 'text') {
    const textNode = document.createElement('span');
    textNode.className = 'msg-text';
    textNode.textContent = m.text != null ? m.text : safeDecrypt(m);
    wrap.appendChild(textNode);
    if (m.edited_at) {
      const ed = document.createElement('span');
      ed.className = 'msg-edited';
      ed.textContent = ' edited';
      wrap.appendChild(ed);
    }
  } else if (m.attachment_id) {
    wrap.appendChild(await renderAttachment(m));
  } else {
    const span = document.createElement('span');
    span.className = 'msg-text';
    span.textContent = '[unsupported message]';
    wrap.appendChild(span);
  }

  // Action affordance.
  wrap.appendChild(buildMsgMenu(m, wrap, mine));
  $('messages').appendChild(wrap);
}

function safeDecrypt(m) {
  try { return session.decryptIncoming(m, activeCid); }
  catch { return '[unable to decrypt]'; }
}

// Decrypt the filename stored as the message body (set during file send).
// Falls back gracefully for old messages that have a blank body.
function decryptFilename(m) {
  try {
    const cid = m.conversation_id ?? activeCid;
    const name = session.decryptIncoming(m, cid);
    if (name && name.trim() && name.trim() !== ' ') return name.trim();
  } catch { /* ignore */ }
  // Fallback: derive a name from content_type if available.
  if (m.content_type) {
    const ext = m.content_type.split('/')[1] || 'bin';
    return `attachment.${ext}`;
  }
  return 'attachment';
}

async function renderAttachment(m) {
  const holder = document.createElement('div');
  holder.className = 'attachment';
  holder.textContent = 'Loading attachment…';
  // Store filename on element for the Download action.
  const filename = decryptFilename(m);
  holder.dataset.filename = filename;
  try {
    const cid = m.conversation_id ?? activeCid;
    const bytes = await session.downloadFile(cid, m.attachment_id);
    const blob = new Blob([bytes]);
    const url = URL.createObjectURL(blob);
    objectUrls.push(url);
    holder.innerHTML = '';
    holder.dataset.filename = filename; // re-set after innerHTML wipe
    holder.dataset.attachmentId = String(m.attachment_id);
    holder.dataset.cid = String(cid);
    if (m.kind === 'image') {
      const img = document.createElement('img');
      img.src = url;
      img.alt = filename;
      holder.appendChild(img);
    } else if (m.kind === 'audio') {
      const audio = document.createElement('audio');
      audio.controls = true;
      audio.preload = 'metadata';
      audio.src = url;
      audio.className = 'voice';
      holder.appendChild(audio);
    } else {
      const a = document.createElement('a');
      a.href = url;
      a.download = filename;
      a.textContent = `Download ${filename}`;
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
    const { id } = await session.sendText(activeCid, text);
    // Optimistic render (server does not echo our own sends back to us over WS).
    await renderMessage({ id, kind: 'text', text, sender_id: session.me.id });
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
    // Encrypt the original filename as the message body so receivers can name the download.
    const { nonce, ciphertext } = sodiumHelpers.encryptMessage(file.name || ' ', session.groupKey(activeCid));
    const clientMsgId = (crypto.randomUUID?.() || `${Date.now()}-${Math.random()}`);
    await api.send(activeCid, { client_msg_id: clientMsgId, kind, nonce, ciphertext, attachment_id });
    await renderMessage({ kind, attachment_id, conversation_id: activeCid, sender_id: session.me.id, nonce, ciphertext });
    scrollToBottom();
  } catch {
    appendSystem('Attachment failed to send.');
  } finally {
    e.target.value = '';
  }
});

// ── push-to-talk voice messages ──────────────────────────────────────────────
// Hold the Talk button to record; release to send the audio as an encrypted
// attachment (kind 'audio') through the SAME blind upload pipeline as files.
let recorder = null, recStream = null, recChunks = [], recording = false, pressActive = false, recStartTs = 0;

function setTalkRecording(on) {
  const btn = $('talkBtn');
  if (btn) btn.classList.toggle('recording', on);
}

async function startRecording() {
  if (recording || activeCid == null) return;
  if (!navigator.mediaDevices?.getUserMedia || typeof MediaRecorder === 'undefined') {
    appendSystem('Voice messages are not supported on this browser.');
    return;
  }
  pressActive = true;
  try {
    const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
    if (!pressActive) { stream.getTracks().forEach((t) => t.stop()); return; } // released during prompt
    recStream = stream;
    recChunks = [];
    recorder = new MediaRecorder(stream);
    recorder.ondataavailable = (ev) => { if (ev.data && ev.data.size) recChunks.push(ev.data); };
    recorder.onstop = onRecordingStop;
    recorder.start();
    recording = true;
    recStartTs = Date.now();
    setTalkRecording(true);
  } catch {
    pressActive = false;
    appendSystem('Microphone unavailable — check permissions.');
  }
}

function stopRecording() {
  pressActive = false;
  if (recording && recorder && recorder.state !== 'inactive') recorder.stop(); // triggers onstop
  setTalkRecording(false);
}

async function onRecordingStop() {
  recording = false;
  const stream = recStream; recStream = null;
  const chunks = recChunks; recChunks = [];
  const rec = recorder; recorder = null;
  if (stream) stream.getTracks().forEach((t) => t.stop());
  const durationMs = Date.now() - recStartTs;
  const type = (rec && rec.mimeType) || 'audio/webm';
  const blob = new Blob(chunks, { type });
  if (blob.size === 0 || durationMs < 400) return; // accidental tap / empty — ignore
  const cid = activeCid;
  if (cid == null) return;
  try {
    const bytes = new Uint8Array(await blob.arrayBuffer());
    const { attachment_id } = await session.uploadFile(cid, bytes, type);
    const ext = type.includes('ogg') ? 'ogg' : (type.includes('mp4') || type.includes('mpeg')) ? 'm4a' : 'webm';
    const name = `voice-message.${ext}`;
    const { nonce, ciphertext } = sodiumHelpers.encryptMessage(name, session.groupKey(cid));
    const clientMsgId = (crypto.randomUUID?.() || `${Date.now()}-${Math.random()}`);
    await api.send(cid, { client_msg_id: clientMsgId, kind: 'audio', nonce, ciphertext, attachment_id });
    await renderMessage({ kind: 'audio', attachment_id, conversation_id: cid, sender_id: session.me.id, nonce, ciphertext });
    scrollToBottom();
  } catch {
    appendSystem('Voice message failed to send.');
  }
}

(() => {
  const btn = $('talkBtn');
  if (!btn) return;
  btn.addEventListener('pointerdown', (e) => { e.preventDefault(); startRecording(); });
  btn.addEventListener('pointerup', (e) => { e.preventDefault(); stopRecording(); });
  btn.addEventListener('pointerleave', () => { if (recording || pressActive) stopRecording(); });
  btn.addEventListener('pointercancel', () => stopRecording());
  btn.addEventListener('contextmenu', (e) => e.preventDefault()); // suppress long-press menu on mobile
})();

// ── voice calls (WebRTC) ─────────────────────────────────────────────────────
function ensureCall() {
  if (call) return call;
  call = new CallController({
    signal: {
      offer: (to, sdp, id) => session.callOffer(to, sdp, id),
      answer: (to, sdp, id) => session.callAnswer(to, sdp, id),
      ice: (to, c, id) => session.callIce(to, c, id),
      hangup: (to, id) => session.callHangup(to, id),
      reject: (to, id) => session.callReject(to, id),
      iceConfig: () => session.iceConfig(),
    },
    onState: renderCallState,
    onRemoteStream: (stream) => { const a = $('remoteAudio'); if (a) a.srcObject = stream; },
  });
  return call;
}

function renderCallState(state, ctl) {
  const incoming = $('incomingCall'), bar = $('inCallBar');
  if (state === 'ringing') {
    $('incomingName').textContent = ctl.peerName || 'Someone';
    incoming.hidden = false; bar.hidden = true;
  } else if (state === 'calling' || state === 'connecting' || state === 'connected') {
    incoming.hidden = true; bar.hidden = false;
    $('inCallName').textContent = ctl.peerName || 'Call';
    if (state === 'connected') {
      startCallTimer();
    } else {
      stopCallTimer();
      $('inCallStatus').textContent = state === 'calling' ? 'Calling…' : 'Connecting…';
    }
  } else { // idle / ended
    incoming.hidden = true; bar.hidden = true;
    stopCallTimer();
    const a = $('remoteAudio'); if (a) a.srcObject = null;
    $('callMuteBtn').textContent = 'Mute';
  }
}

function startCallTimer() {
  callStart = Date.now();
  const tick = () => {
    const s = Math.max(0, Math.floor((Date.now() - callStart) / 1000));
    $('inCallStatus').textContent = `${String(Math.floor(s / 60)).padStart(2, '0')}:${String(s % 60).padStart(2, '0')}`;
  };
  tick();
  clearInterval(callTimer);
  callTimer = setInterval(tick, 1000);
}
function stopCallTimer() { clearInterval(callTimer); callTimer = null; }

$('callBtn')?.addEventListener('click', () => {
  if (activePeerId == null) return;
  ensureCall().startCall(activePeerId, activePeerName).catch((err) => {
    appendSystem(/409/.test(String(err?.message)) ? 'They are not online right now.' : 'Could not start call.');
  });
});
$('callAcceptBtn')?.addEventListener('click', () => ensureCall().accept().catch(() => appendSystem('Could not answer the call.')));
$('callDeclineBtn')?.addEventListener('click', () => ensureCall().reject());
$('callHangupBtn')?.addEventListener('click', () => ensureCall().hangup(true));
$('callMuteBtn')?.addEventListener('click', () => {
  const muted = ensureCall().toggleMute();
  $('callMuteBtn').textContent = muted ? 'Unmute' : 'Mute';
});

// ── WebSocket live updates + reconnect with backoff ──────────────────────────
function connectWS() {
  if (!session) return;
  ws = session.openWS(async (frame) => {
    if (frame.type === 'message') {
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
        renderConvList();
      }
    } else if (frame.type === 'message_edited' && frame.conversation_id === activeCid) {
      const bubble = document.querySelector(`.msg[data-mid="${frame.id}"]`);
      if (bubble) {
        const textEl = bubble.querySelector('.msg-text');
        if (textEl) {
          try {
            const newText = sodiumHelpers.decryptMessage(frame.nonce, frame.ciphertext, session.groupKey(activeCid));
            textEl.textContent = newText;
          } catch { /* skip if key unavailable */ }
        }
        let edMark = bubble.querySelector('.msg-edited');
        if (!edMark) {
          edMark = document.createElement('span');
          edMark.className = 'msg-edited';
          edMark.textContent = ' edited';
          const menuBtn = bubble.querySelector('.msg-menu-btn');
          bubble.insertBefore(edMark, menuBtn || null);
        }
      }
    } else if (frame.type === 'message_deleted' && frame.conversation_id === activeCid) {
      document.querySelector(`.msg[data-mid="${frame.id}"]`)?.remove();
    } else if (frame.type === 'call-offer') {
      ensureCall().incoming(frame);
    } else if (frame.type === 'call-answer') {
      ensureCall().onAnswer(frame).catch(() => {});
    } else if (frame.type === 'call-ice') {
      ensureCall().onIce(frame).catch(() => {});
    } else if (frame.type === 'call-hangup') {
      ensureCall().remoteEnded();
    } else if (frame.type === 'call-reject') {
      ensureCall().remoteEnded();
      appendSystem('Call declined.');
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
  try { call?.hangup(false); } catch { /* ignore */ }
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
  addPeopleMembers = new Set();
  $('adminPanel').hidden = true;
  $('roomPanel').open = false;
  $('addPeoplePanel').hidden = true;
  $('deleteRoomBar').hidden = true;
  $('roomMembers').innerHTML = '';
  $('addPeopleList').innerHTML = '';
  $('userList').innerHTML = '';
  $('pendingList').innerHTML = '';
  setNote('adminMsg', '');
  setNote('roomMsg', ''); setNote('addPeopleMsg', '');
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
