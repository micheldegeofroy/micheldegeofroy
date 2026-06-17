// web/js/call.js — 1-to-1 WebRTC voice call controller.
//
// Owns a single RTCPeerConnection at a time. Media (audio) is peer-to-peer and
// DTLS-SRTP encrypted end to end; the server only relays SDP + ICE via `signal`.
// `signal` is a set of bound send functions (offer/answer/ice/hangup/reject/
// iceConfig) supplied by the session. State is surfaced through onState so the UI
// can render ringing / calling / in-call. States:
//   idle -> calling   -> connecting -> connected -> idle   (caller)
//   idle -> ringing   -> connecting -> connected -> idle   (callee)
export class CallController {
  constructor({ signal, onState, onRemoteStream }) {
    this.signal = signal;
    this.onState = onState || (() => {});
    this.onRemoteStream = onRemoteStream || (() => {});
    this._reset();
  }

  _reset() {
    this.pc = null;
    this.local = null;
    this.peerId = null;
    this.peerName = null;
    this.callId = null;
    this.role = null;
    this.pendingIce = [];
    this.remoteSet = false;
    this._offer = null;
    this.state = 'idle';
  }

  _set(state) { this.state = state; this.onState(state, this); }

  isBusy() { return this.state !== 'idle'; }

  async _newPc() {
    let iceServers = [];
    try { ({ iceServers = [] } = await this.signal.iceConfig()); } catch { /* host/srflx only */ }
    const pc = new RTCPeerConnection({ iceServers });
    pc.onicecandidate = (e) => {
      if (e.candidate && this.peerId != null) {
        this.signal.ice(this.peerId, e.candidate.toJSON(), this.callId).catch(() => {});
      }
    };
    pc.ontrack = (e) => { if (e.streams && e.streams[0]) this.onRemoteStream(e.streams[0]); };
    pc.onconnectionstatechange = () => {
      const s = pc.connectionState;
      if (s === 'connected') this._set('connected');
      else if (s === 'failed' || s === 'disconnected' || s === 'closed') this.hangup(false);
    };
    this.pc = pc;
    return pc;
  }

  async _addMic() {
    this.local = await navigator.mediaDevices.getUserMedia({ audio: true });
    for (const t of this.local.getTracks()) this.pc.addTrack(t, this.local);
  }

  // ── outgoing ──────────────────────────────────────────────────────────────
  async startCall(peerId, peerName) {
    if (this.isBusy()) return;
    this.role = 'caller';
    this.peerId = peerId;
    this.peerName = peerName || null;
    this.callId = (globalThis.crypto?.randomUUID?.()) || `${Date.now()}-${Math.random()}`;
    this._set('calling');
    try {
      await this._newPc();
      await this._addMic();
      const offer = await this.pc.createOffer({ offerToReceiveAudio: true });
      await this.pc.setLocalDescription(offer);
      await this.signal.offer(peerId, offer, this.callId); // throws on 409 unavailable
    } catch (err) {
      this.hangup(false);
      throw err;
    }
  }

  // ── incoming ──────────────────────────────────────────────────────────────
  // Show ringing. If already busy, auto-reject so the caller isn't left hanging.
  incoming(frame) {
    if (this.isBusy()) { this.signal.reject(frame.from, frame.call_id).catch(() => {}); return; }
    this.role = 'callee';
    this.peerId = frame.from;
    this.peerName = frame.from_name || null;
    this.callId = frame.call_id;
    this._offer = frame.sdp;
    this._set('ringing');
  }

  async accept() {
    if (this.state !== 'ringing') return;
    this._set('connecting');
    try {
      await this._newPc();
      await this.pc.setRemoteDescription(this._offer);
      this.remoteSet = true;
      await this._drainIce();
      await this._addMic();
      const answer = await this.pc.createAnswer();
      await this.pc.setLocalDescription(answer);
      await this.signal.answer(this.peerId, answer, this.callId);
    } catch (err) {
      this.hangup(true);
      throw err;
    }
  }

  // ── signaling callbacks ─────────────────────────────────────────────────────
  async onAnswer(frame) {
    if (this.role !== 'caller' || !this.pc || frame.call_id !== this.callId) return;
    this._set('connecting');
    await this.pc.setRemoteDescription(frame.sdp);
    this.remoteSet = true;
    await this._drainIce();
  }

  async onIce(frame) {
    if (frame.call_id !== this.callId) return;
    const c = frame.candidate;
    if (!this.pc || !this.remoteSet) { this.pendingIce.push(c); return; }
    try { await this.pc.addIceCandidate(c); } catch { /* ignore bad candidate */ }
  }

  async _drainIce() {
    for (const c of this.pendingIce.splice(0)) {
      try { await this.pc.addIceCandidate(c); } catch { /* ignore */ }
    }
  }

  // Peer hung up or rejected.
  remoteEnded() {
    if (this.state === 'idle') return;
    this._teardown();
    this._set('ended');
    this._set('idle');
  }

  // Decline a ringing call.
  reject() {
    if (this.peerId != null) this.signal.reject(this.peerId, this.callId).catch(() => {});
    this._teardown();
    this._set('idle');
  }

  // End the call. notify=true tells the peer.
  hangup(notify = true) {
    if (this.state === 'idle') return;
    if (notify && this.peerId != null) this.signal.hangup(this.peerId, this.callId).catch(() => {});
    this._teardown();
    this._set('idle');
  }

  // Toggle local mic. Returns the new muted state (true = muted).
  toggleMute() {
    const tracks = this.local ? this.local.getAudioTracks() : [];
    if (!tracks.length) return false;
    const newEnabled = !tracks[0].enabled;
    for (const t of tracks) t.enabled = newEnabled;
    return !newEnabled;
  }

  _teardown() {
    try { this.pc?.close(); } catch { /* ignore */ }
    if (this.local) for (const t of this.local.getTracks()) t.stop();
    this._reset();
  }
}
