'use strict';

/*
 * Concord client.
 *
 * Encryption model:
 *  - A room passphrase is stretched with PBKDF2 into an AES-256-GCM key,
 *    entirely client-side. The server never sees the passphrase or key.
 *  - Every chat message, control message (voice presence) and WebRTC
 *    signaling payload (SDP/ICE) is sealed with that key before it is sent.
 *    Because signaling is sealed, the server cannot tamper with SDP
 *    fingerprints, so the DTLS-SRTP media encryption is end-to-end too.
 *  - Voice/video flow peer-to-peer (mesh); the server only relays ciphertext.
 */

const $ = sel => document.querySelector(sel);
const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();

// ---------- inline SVG icons ----------
// Static, trusted markup only — never interpolate user data into these
// strings (they are parsed as HTML).

const ICONS = {
  warn: '<svg class="ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>',
  speaker: '<svg class="ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polygon points="11 5 6 9 2 9 2 15 6 15 11 19 11 5"/><path d="M15.54 8.46a5 5 0 0 1 0 7.07"/><path d="M19.07 4.93a10 10 0 0 1 0 14.14"/></svg>',
  cursor: '<svg class="ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="m3 3 7.07 16.97 2.51-7.39 7.39-2.51L3 3z"/></svg>',
  maximize: '<svg class="ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="15 3 21 3 21 9"/><polyline points="9 21 3 21 3 15"/><line x1="21" y1="3" x2="14" y2="10"/><line x1="3" y1="21" x2="10" y2="14"/></svg>',
  minimize: '<svg class="ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="4 14 10 14 10 20"/><polyline points="20 10 14 10 14 4"/><line x1="14" y1="10" x2="21" y2="3"/><line x1="3" y1="21" x2="10" y2="14"/></svg>',
  speakerOff: '<svg class="ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polygon points="11 5 6 9 2 9 2 15 6 15 11 19 11 5"/><line x1="23" y1="9" x2="17" y2="15"/><line x1="17" y1="9" x2="23" y2="15"/></svg>'
};

function svgIcon(name) {
  const tpl = document.createElement('template');
  tpl.innerHTML = ICONS[name];
  return tpl.content.firstElementChild;
}

// ---------- base64 helpers (chunked to avoid stack limits) ----------

function toB64(bytes) {
  let s = '';
  const CHUNK = 0x8000;
  for (let i = 0; i < bytes.length; i += CHUNK) {
    s += String.fromCharCode.apply(null, bytes.subarray(i, i + CHUNK));
  }
  return btoa(s);
}

function fromB64(str) {
  const bin = atob(str);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}

// ---------- crypto ----------

async function deriveRoomKey(passphrase, roomName) {
  const material = await crypto.subtle.importKey(
    'raw', textEncoder.encode(passphrase), 'PBKDF2', false, ['deriveKey']
  );
  return crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: textEncoder.encode('concord/v1/' + roomName),
      iterations: 310000,
      hash: 'SHA-256'
    },
    material,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

async function seal(obj) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    roomKey,
    textEncoder.encode(JSON.stringify(obj))
  );
  const out = new Uint8Array(iv.length + ct.byteLength);
  out.set(iv);
  out.set(new Uint8Array(ct), iv.length);
  return toB64(out);
}

async function unseal(str) {
  const buf = fromB64(str);
  const iv = buf.subarray(0, 12);
  const ct = buf.subarray(12);
  const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, roomKey, ct);
  return JSON.parse(textDecoder.decode(pt));
}

// ---------- state ----------

let ws = null;
let myId = null;
let myName = '';
let roomName = '';
let roomKey = null;
let iceServers = [{ urls: 'stun:stun.l.google.com:19302' }];

const peers = new Map(); // id -> { name, inVoice, ping, awaitingPong }
const pcs = new Map();   // id -> { pc, polite, makingOffer, ignoreOffer, pending }

// Latency probes. Peers answer one shared broadcast over the E2E channel, so
// a peer's figure is the full relay round trip (us -> server -> peer -> back).
// Our own row shows the plain websocket round trip to the server. A probe
// that goes unanswered for a whole cycle blanks the stale figure.
const PING_INTERVAL = 5000;
let pingTimer = null;
let pingSeq = 0;
let selfProbe = null; // { n, t } outstanding server echo
let selfPing = null;  // ms to server, null = unknown
let peerProbe = null; // { n, t } outstanding E2E broadcast probe

let inVoice = false;
let micStream = null;
let micMuted = false;
let videoStream = null;  // camera or screen, one at a time
let videoKind = null;    // 'cam' | 'screen' | null

// Screen-share quality presets. WebRTC defaults cap screen share at roughly
// 2.5 Mbps / 5 fps, which looks terrible; these raise the ceiling far above
// that, which a LAN or Tailscale link handles easily.
// Widths that pair with each offered height at 16:9. The capture path caps by
// width and keeps the source's own aspect ratio, so a 16:10 monitor comes out
// slightly taller than the nominal label.
const RES_WIDTH = { 360: 640, 480: 854, 720: 1280, 1080: 1920 };

// The picked resolution and frame rate are a ceiling; with auto on, a weak
// link is allowed to run below them.
let shareHeight = Number(localStorage.getItem('concord-res')) || 1080;
let shareFps = Number(localStorage.getItem('concord-fps')) || 60;
let shareAuto = localStorage.getItem('concord-auto') !== '0';

// Rungs in bitrate order. Auto walks this ladder, never above the ceiling.
const QUALITY_LADDER = [
  { height: 360, fps: 30 },
  { height: 480, fps: 30 },
  { height: 720, fps: 30 },
  { height: 720, fps: 60 },
  { height: 1080, fps: 30 },
  { height: 1080, fps: 60 }
];
let autoRung = null; // set once auto has moved off the ceiling

function tierBitrate(height, fps) {
  return Math.min(
    16_000_000,
    Math.max(800_000, Math.round(RES_WIDTH[height] * height * fps * 0.08))
  );
}

// Builds the settings every part of the pipeline needs from the two choices.
function shareQuality() {
  let height = RES_WIDTH[shareHeight] ? shareHeight : 1080;
  let fps = shareFps === 30 ? 30 : 60;
  if (shareAuto && autoRung !== null) {
    const rung = QUALITY_LADDER[autoRung];
    height = Math.min(height, rung.height);
    fps = Math.min(fps, rung.fps);
  }
  const width = RES_WIDTH[height];
  const maxBitrate = tierBitrate(height, fps);
  return {
    label: `${height}p${fps}`,
    constraints: {
      frameRate: { ideal: fps, max: fps },
      width: { ideal: width },
      height: { ideal: height }
    },
    // At 30 fps the point is readable text; at 60 it is smooth motion.
    hint: fps === 30 ? 'detail' : 'motion',
    maxBitrate,
    maxFramerate: fps,
    degradation: fps === 30 ? 'maintain-resolution' : 'maintain-framerate'
  };
}

// Remote control state.
const controllers = new Set();   // peers ALLOWED to control this machine
let controlling = null;          // peer whose screen we are currently driving
const ctlChannels = new Map();   // peerId -> RTCDataChannel
const isDesktopApp = !!(window.__TAURI__ && window.__TAURI__.core);

// ---------- websocket / protocol ----------

// Accepts "host", "host:port", "ws://...", "wss://...", "http(s)://..."
// and returns { wsUrl, httpBase }.
function parseServer(input) {
  let s = input.trim();
  if (!/^[a-z]+:\/\//i.test(s)) s = 'ws://' + s;
  const u = new URL(s);
  const secure = u.protocol === 'wss:' || u.protocol === 'https:';
  const wsProto = secure ? 'wss:' : 'ws:';
  const httpProto = secure ? 'https:' : 'http:';
  const base = u.pathname.replace(/\/+$/, '');
  return {
    wsUrl: `${wsProto}//${u.host}${base}/ws`,
    httpBase: `${httpProto}//${u.host}${base}`
  };
}

async function connect(server, name, room, passphrase) {
  roomKey = await deriveRoomKey(passphrase, room);
  const { wsUrl, httpBase } = parseServer(server);

  try {
    const cfg = await fetch(httpBase + '/config.json').then(r => r.json());
    if (Array.isArray(cfg.iceServers) && cfg.iceServers.length) iceServers = cfg.iceServers;
  } catch { /* keep default STUN */ }

  ws = new WebSocket(wsUrl);

  ws.onopen = () => {
    ws.send(JSON.stringify({ type: 'join', room, name }));
  };

  ws.onmessage = async ev => {
    let msg;
    try { msg = JSON.parse(ev.data); } catch { return; }

    switch (msg.type) {
      case 'welcome': {
        myId = msg.id;
        for (const p of msg.peers) peers.set(p.id, { name: p.name, inVoice: false });
        enterApp();
        break;
      }
      case 'peer-join': {
        peers.set(msg.id, { name: msg.name, inVoice: false });
        renderRoster();
        addSystemMessage(`${msg.name} joined`);
        // Re-announce our voice presence so the newcomer learns it.
        if (inVoice) sendE2E({ kind: 'voice', on: true });
        // Same for a running watch-together: the starter tells the
        // newcomer what is playing and how far in.
        if (activity?.mine) {
          sendE2E({ kind: 'activity', act: 'start', video: activity.video, t: ytTime() });
        }
        break;
      }
      case 'peer-leave': {
        const p = peers.get(msg.id);
        if (p) addSystemMessage(`${p.name} left`);
        peers.delete(msg.id);
        closePeer(msg.id);
        removeTile(msg.id);
        renderRoster();
        break;
      }
      case 'chat': {
        let payload;
        try { payload = await unseal(msg.data); }
        catch {
          addSystemMessage('received a message that could not be decrypted (different passphrase?)', true);
          return;
        }
        handleE2E(msg.from, payload);
        break;
      }
      case 'signal': {
        let payload;
        try { payload = await unseal(msg.data); } catch { return; }
        handleSignal(msg.from, payload);
        break;
      }
      case 'pong': {
        if (selfProbe && msg.n === selfProbe.n) {
          selfPing = Math.round(performance.now() - selfProbe.t);
          selfProbe = null;
          renderRoster();
        }
        break;
      }
    }
  };

  ws.onclose = () => {
    clearInterval(pingTimer);
    pingTimer = null;
    if (!myId) {
      showJoinError('Could not connect to server.');
      return;
    }
    addSystemMessage('Disconnected from server. Reload the page to rejoin.');
    $('#chat-input').disabled = true;
  };
}

function sendRaw(msg) {
  if (ws && ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify(msg));
}

async function sendE2E(payload) {
  sendRaw({ type: 'chat', data: await seal(payload) });
}

async function sendSignal(to, payload) {
  sendRaw({ type: 'signal', to, data: await seal(payload) });
}

function handleE2E(from, payload) {
  const peer = peers.get(from);
  switch (payload.kind) {
    case 'msg':
      addChatMessage(payload.name || peer?.name || '?', payload.text, payload.ts, false);
      break;
    case 'voice': {
      if (!peer) return;
      peer.inVoice = !!payload.on;
      renderRoster();
      if (peer.inVoice) ensureTile(from);
      else removeTile(from);
      if (peer.inVoice && inVoice) ensurePeer(from);
      if (!peer.inVoice) closePeer(from);
      break;
    }
    // Which of a peer's audio streams carries their shared system audio, so
    // it can be given its own volume rather than being mixed into their voice.
    case 'share-audio': {
      if (!peer) return;
      peer.shareAudioId = payload.on ? payload.id : null;
      classifyPeerAudio(from);
      applyPeerAudio(from);
      if (userMenuFor === from) syncUserMenu();
      break;
    }
    // Latency probe: everyone answers the shared broadcast; the reply is
    // addressed back to the prober.
    case 'ping':
      sendE2E({ kind: 'pong', to: from, n: payload.n });
      break;
    case 'pong':
      if (payload.to !== myId || !peer) return;
      if (!peerProbe || payload.n !== peerProbe.n) return;
      peer.ping = Math.round(performance.now() - peerProbe.t);
      peer.awaitingPong = false;
      renderRoster();
      break;
    // Remote-control handshake. Addressed messages carry `to` because the
    // relay broadcasts these blobs to the whole room.
    case 'control-request':
      if (payload.to === myId && videoKind === 'screen') requestFromPeer(from);
      break;
    case 'control-grant':
      if (payload.to === myId) startControlling(from);
      break;
    case 'control-deny':
      if (payload.to === myId) addSystemMessage(`${peer?.name || 'Peer'} declined the control request.`);
      break;
    case 'activity':
      handleActivityMessage(from, payload);
      break;
  }
}

// ---------- WebRTC (perfect negotiation, mesh) ----------

function ensurePeer(peerId) {
  let st = pcs.get(peerId);
  if (st) return st;

  const pc = new RTCPeerConnection({ iceServers });
  st = { pc, polite: myId > peerId, makingOffer: false, ignoreOffer: false, pending: [] };
  pcs.set(peerId, st);

  for (const track of micStream.getTracks()) pc.addTrack(track, micStream);
  // A peer joining mid-share still needs the shared audio, and needs to be
  // told which stream it is.
  if (shareAudio) {
    pc.addTrack(shareAudio.track, shareAudio.stream);
    sendE2E({ kind: 'share-audio', id: shareAudio.stream.id, on: true });
  }
  if (videoStream) {
    for (const track of videoStream.getTracks()) {
      tuneVideoSender(pc.addTrack(track, videoStream));
    }
    preferVideoCodec(pc);
  }

  // Remote-control channel. The impolite side creates it so exactly one
  // channel exists per link; the polite side picks it up via ondatachannel.
  if (!st.polite) {
    attachCtlChannel(peerId, pc.createDataChannel('ctl', { ordered: true }));
  }
  pc.ondatachannel = ({ channel }) => {
    if (channel.label === 'ctl') attachCtlChannel(peerId, channel);
  };

  pc.onnegotiationneeded = async () => {
    try {
      st.makingOffer = true;
      await pc.setLocalDescription();
      sendSignal(peerId, { description: pc.localDescription });
    } catch (e) {
      console.warn('negotiation failed', e);
    } finally {
      st.makingOffer = false;
    }
  };

  pc.onicecandidate = ({ candidate }) => {
    if (candidate) sendSignal(peerId, { candidate });
  };

  pc.ontrack = ({ track, streams }) => {
    const stream = streams[0] || new MediaStream([track]);
    if (track.kind === 'audio') {
      // A peer sends two audio streams while sharing: their microphone and
      // their machine's output. They get separate volume controls, so each
      // stream is kept and classified by id (see classifyPeerAudio).
      const el = document.createElement('audio');
      el.id = 'audio-' + peerId + '-' + stream.id;
      el.autoplay = true;
      document.body.appendChild(el);
      el.srcObject = stream;
      el.play().catch(showAudioUnlock);
      routePeerAudio(peerId, el, stream);
      track.addEventListener('ended', () => dropPeerStream(peerId, stream.id));
    } else {
      setTileStream(peerId, stream);
      track.addEventListener('mute', () => clearTileStream(peerId));
      track.addEventListener('unmute', () => setTileStream(peerId, stream));
      track.addEventListener('ended', () => clearTileStream(peerId));
    }
  };

  pc.onconnectionstatechange = () => {
    if (pc.connectionState === 'failed' || pc.connectionState === 'closed') {
      closePeer(peerId);
      // Simple retry: if both sides are still in voice, rebuild the link.
      setTimeout(() => {
        if (inVoice && peers.get(peerId)?.inVoice) ensurePeer(peerId);
      }, 2000);
    }
  };

  return st;
}

async function handleSignal(from, payload) {
  if (!inVoice) return;
  const st = ensurePeer(from);
  const { pc } = st;

  try {
    if (payload.description) {
      const desc = payload.description;
      const collision = desc.type === 'offer' && (st.makingOffer || pc.signalingState !== 'stable');
      st.ignoreOffer = !st.polite && collision;
      if (st.ignoreOffer) return;

      await pc.setRemoteDescription(desc);
      for (const c of st.pending.splice(0)) {
        await pc.addIceCandidate(c).catch(() => {});
      }
      if (desc.type === 'offer') {
        await pc.setLocalDescription();
        sendSignal(from, { description: pc.localDescription });
      }
    } else if (payload.candidate) {
      if (!pc.remoteDescription) {
        st.pending.push(payload.candidate);
      } else {
        await pc.addIceCandidate(payload.candidate).catch(e => {
          if (!st.ignoreOffer) console.warn('addIceCandidate', e);
        });
      }
    }
  } catch (e) {
    console.warn('signal handling failed', e);
  }
}

function closePeer(peerId) {
  const st = pcs.get(peerId);
  if (st) {
    st.pc.close();
    pcs.delete(peerId);
  }
  ctlChannels.delete(peerId);
  controllers.delete(peerId);
  if (controlling === peerId) stopControlling();
  const pa = peerAudio.get(peerId);
  if (pa) {
    try { pa.src?.disconnect(); } catch { /* already gone */ }
    try { pa.gain?.disconnect(); } catch { /* already gone */ }
    peerAudio.delete(peerId);
  }
  document.getElementById('audio-' + peerId)?.remove();
  clearTileStream(peerId);
}

// ---------- encoder tuning ----------

// Raise the sender's bitrate/framerate ceiling well above the WebRTC defaults.
async function tuneVideoSender(sender) {
  if (!sender || sender.track?.kind !== 'video') return;
  const q = shareQuality();
  try {
    const params = sender.getParameters();
    if (!params.encodings || !params.encodings.length) params.encodings = [{}];
    params.encodings[0].maxBitrate = q.maxBitrate;
    params.encodings[0].maxFramerate = q.maxFramerate;
    params.encodings[0].scaleResolutionDownBy = 1;
    params.degradationPreference = q.degradation;
    await sender.setParameters(params);
  } catch (e) {
    console.warn('could not tune sender', e);
  }
}

// Prefer VP9 (much better than VP8 on screen content at a given bitrate),
// then H.264 for hardware encoding, before falling back to whatever is left.
function preferVideoCodec(pc) {
  if (!RTCRtpSender.getCapabilities) return;
  const caps = RTCRtpSender.getCapabilities('video');
  if (!caps) return;
  const rank = c => {
    const m = c.mimeType.toLowerCase();
    if (m === 'video/vp9') return 0;
    if (m === 'video/h264') return 1;
    if (m === 'video/vp8') return 2;
    return 3;
  };
  const ordered = [...caps.codecs].sort((a, b) => rank(a) - rank(b));
  for (const t of pc.getTransceivers()) {
    if (t.sender?.track?.kind === 'video' || t.receiver?.track?.kind === 'video') {
      try { t.setCodecPreferences(ordered); } catch { /* unsupported: ignore */ }
    }
  }
}

// Re-apply presets to every active sender (used when quality mode changes).
function retuneAllSenders() {
  for (const st of pcs.values()) {
    for (const sender of st.pc.getSenders()) tuneVideoSender(sender);
  }
  const track = videoStream?.getVideoTracks()[0];
  if (track) {
    const q = shareQuality();
    track.contentHint = q.hint;
    // Native capture tracks have no constraints to apply; only real device
    // tracks do, so a rejection here is expected and harmless.
    track.applyConstraints?.(q.constraints).catch(() => {});
  }
}

// ---------- voice ----------

async function joinVoice() {
  try {
    micStream = await navigator.mediaDevices.getUserMedia({
      audio: { echoCancellation: true, noiseSuppression: true, autoGainControl: true }
    });
  } catch {
    addSystemMessage('microphone access denied — cannot join voice', true);
    return;
  }
  // Create/resume the context inside this click so autoplay policy
  // cannot leave the per-peer gain graph suspended and silent.
  try { getAudioCtx(); } catch { /* element fallback still works */ }

  inVoice = true;
  micMuted = false;
  sendE2E({ kind: 'voice', on: true });
  ensureTile('me');
  for (const [id, p] of peers) {
    if (p.inVoice) ensurePeer(id);
  }
  updateVoiceUI();
  renderRoster();
}

function leaveVoice() {
  sendE2E({ kind: 'voice', on: false });
  stopVideo();
  for (const id of [...pcs.keys()]) closePeer(id);
  micStream?.getTracks().forEach(t => t.stop());
  micStream = null;
  inVoice = false;
  micMuted = false;
  removeTile('me');
  updateVoiceUI();
  renderRoster();
}

function toggleMute() {
  micMuted = !micMuted;
  micStream?.getAudioTracks().forEach(t => { t.enabled = !micMuted; });
  updateVoiceUI();
}

// ---------- video / screen share ----------

async function startVideo(kind, source) {
  stopVideo(); // one source at a time (also clears shareSource)
  shareSource = source || null;
  const q = shareQuality();
  try {
    if (kind === 'screen' && shareSource && isDesktopApp) {
      // Rust captures the picked source directly. getDisplayMedia is avoided
      // on purpose: every WebView2 route through it drags in Chromium's own
      // permission prompt and "sharing your screen" bar, and the launch flags
      // that suppress them either pick the wrong source or fall back to a
      // slow capturer.
      try {
        videoStream = await startHwCapture(shareSource, q);
      } catch (e) {
        // No WebCodecs, no hardware encoder, or a source the Graphics Capture
        // API refuses: fall back to the GDI + JPEG path.
        addSystemMessage('hardware capture unavailable (' + (e.message || e) + ') — using slower path', true);
        videoStream = await startNativeCapture(shareSource, q);
      }
    } else if (kind === 'screen') {
      videoStream = await navigator.mediaDevices.getDisplayMedia({
        video: q.constraints,
        audio: false
      });
    } else {
      videoStream = await navigator.mediaDevices.getUserMedia({
        video: { width: { ideal: 1280 }, height: { ideal: 720 }, frameRate: { ideal: 30 } }
      });
    }
  } catch (e) {
    if (kind === 'screen') addSystemMessage('screen share unavailable: ' + (e.message || e), true);
    return; // user cancelled the picker
  }
  videoKind = kind;

  const track = videoStream.getVideoTracks()[0];
  // Tells the encoder whether to sacrifice sharpness for frame rate or vice versa.
  track.contentHint = kind === 'screen' ? q.hint : 'motion';
  track.onended = () => stopVideo(); // browser "Stop sharing" button

  for (const st of pcs.values()) {
    tuneVideoSender(st.pc.addTrack(track, videoStream));
    preferVideoCodec(st.pc);
  }
  setTileStream('me', videoStream, kind === 'cam');
  if (kind === 'screen') {
    startAutoQuality();
    // System audio rides along with a screen share; a camera has none.
    if (isDesktopApp && !shareAudio) {
      startShareAudio().catch(e =>
        addSystemMessage('system audio unavailable: ' + (e.message || e), true)
      );
    }
  }
  updateVoiceUI();
}

function stopVideo() {
  if (!videoStream) return;
  stopAutoQuality();
  stopShareAudio();
  stopHwCapture();
  stopNativeCapture();
  // Sharing has ended, so any control grant tied to it dies with it.
  revokeAllControl();
  for (const st of pcs.values()) {
    for (const sender of st.pc.getSenders()) {
      if (sender.track && sender.track.kind === 'video') st.pc.removeTrack(sender);
    }
  }
  videoStream.getTracks().forEach(t => t.stop());
  videoStream = null;
  videoKind = null;
  shareSource = null;
  clearTileStream('me');
  updateVoiceUI();
}

// ---------- screen-share source picker ----------
//
// Desktop app only: the Rust side enumerates monitors and windows with
// thumbnails, and the picker renders in our own UI instead of WebView2's
// stock share dialog. After the pick, Rust captures that source directly
// (GDI + JPEG frames pulled over IPC onto a canvas), so getDisplayMedia —
// and its second system dialog — is never involved.

let pickedSource = null; // selection inside the open picker
let shareSource = null;  // source confirmed for the current share

async function openSharePicker() {
  if (!isDesktopApp) {
    startVideo('screen'); // browsers only have the stock picker
    return;
  }
  pickedSource = null;
  $('#picker-share').disabled = true;
  $('#picker').hidden = false;
  await loadCaptureSources();
}

function closeSharePicker() {
  $('#picker').hidden = true;
}

async function loadCaptureSources() {
  const monitors = $('#picker-monitors');
  const windowsGrid = $('#picker-windows');
  monitors.textContent = 'capturing previews…';
  windowsGrid.textContent = '';

  let sources;
  try {
    sources = await window.__TAURI__.core.invoke('list_capture_sources');
  } catch (e) {
    monitors.textContent = 'could not list sources: ' + e;
    return;
  }
  // Ignore a stale response if the picker was closed while enumerating.
  if ($('#picker').hidden) return;

  monitors.textContent = '';
  windowsGrid.textContent = '';
  for (const s of sources) {
    const tile = document.createElement('button');
    tile.type = 'button';
    tile.className = 'src-tile';
    const img = document.createElement('img');
    img.className = 'src-thumb';
    img.src = s.thumb; // JPEG data URL rendered by our own Rust side
    img.alt = '';
    const label = document.createElement('span');
    label.className = 'src-label';
    label.textContent = s.name; // window titles are untrusted text — never HTML
    label.title = s.name;
    tile.append(img, label);
    tile.addEventListener('click', () => {
      $('#picker').querySelectorAll('.src-tile.selected')
        .forEach(t => t.classList.remove('selected'));
      tile.classList.add('selected');
      pickedSource = s;
      $('#picker-share').disabled = false;
    });
    (s.kind === 'monitor' ? monitors : windowsGrid).appendChild(tile);
  }
  if (!windowsGrid.children.length) windowsGrid.textContent = 'no shareable windows';
}

// ---------- shared system audio ----------
//
// Rust captures what this machine is playing and hands over float PCM; an
// audio worklet turns it back into a MediaStreamTrack, which rides the same
// peer connections as a second audio stream. Peers announce the stream id so
// the far side can tell shared audio from a microphone and give each its own
// volume.

let shareAudio = null; // { ctx, node, stream, track, live }

async function startShareAudio() {
  const invoke = window.__TAURI__.core.invoke;
  const info = await invoke('start_share_audio');
  const ctx = new AudioContext({ sampleRate: info.sample_rate });
  await ctx.audioWorklet.addModule('pcm-worklet.js');
  const node = new AudioWorkletNode(ctx, 'pcm-player', {
    numberOfInputs: 0,
    numberOfOutputs: 1,
    outputChannelCount: [info.channels]
  });
  const dest = ctx.createMediaStreamDestination();
  node.connect(dest);
  // Deliberately not connected to ctx.destination: this machine is already
  // playing the sound out loud.

  const track = dest.stream.getAudioTracks()[0];
  const stream = new MediaStream([track]);
  shareAudio = { ctx, node, stream, track, live: true };

  for (const st of pcs.values()) st.pc.addTrack(track, stream);
  sendE2E({ kind: 'share-audio', id: stream.id, on: true });

  if (!info.excludes_own_audio) {
    addSystemMessage(
      'sharing system audio device-wide — this machine cannot exclude the call itself, so others may hear an echo',
      true
    );
  }

  (async () => {
    while (shareAudio?.live) {
      let buf;
      try { buf = await invoke('next_audio_chunk'); } catch { break; }
      if (!shareAudio?.live) return;
      if (!buf || !buf.byteLength) break;
      const pcm = new Float32Array(buf instanceof ArrayBuffer ? buf : buf.buffer);
      node.port.postMessage(pcm, [pcm.buffer]);
    }
    if (shareAudio?.live) stopShareAudio();
  })();

  return track;
}

function stopShareAudio() {
  if (!shareAudio) return;
  const { ctx, track, live } = shareAudio;
  shareAudio.live = false;
  shareAudio = null;
  if (live) sendE2E({ kind: 'share-audio', on: false });
  for (const st of pcs.values()) {
    for (const sender of st.pc.getSenders()) {
      if (sender.track === track) st.pc.removeTrack(sender);
    }
  }
  track.stop();
  ctx.close().catch(() => {});
  if (isDesktopApp) window.__TAURI__.core.invoke('stop_share_audio').catch(() => {});
}

// ---------- hardware capture bridge ----------
//
// Rust captures with Windows.Graphics.Capture and encodes H.264 on the GPU;
// we pull the encoded chunks and decode them with WebCodecs, which is also
// hardware. Frames never become JPEGs and never round-trip through a canvas
// decode, so a 1080p60 share stays cheap on both sides.

let hwCaptureStop = null; // set while a hardware capture is running

// Somewhere to put decoded VideoFrames that a peer connection can read.
// Newer Chromium exposes VideoTrackGenerator; older builds have
// MediaStreamTrackGenerator; a canvas works everywhere but costs a copy.
function createFrameSink(width, height, fps) {
  if (typeof VideoTrackGenerator === 'function') {
    const gen = new VideoTrackGenerator();
    const writer = gen.writable.getWriter();
    return {
      stream: new MediaStream([gen.track]),
      write: frame => writer.write(frame).catch(() => frame.close())
    };
  }
  if (typeof MediaStreamTrackGenerator === 'function') {
    const gen = new MediaStreamTrackGenerator({ kind: 'video' });
    const writer = gen.writable.getWriter();
    return {
      stream: new MediaStream([gen]),
      write: frame => writer.write(frame).catch(() => frame.close())
    };
  }
  const canvas = document.createElement('canvas');
  canvas.width = width;
  canvas.height = height;
  const ctx = canvas.getContext('2d', { desynchronized: true });
  return {
    stream: canvas.captureStream(fps),
    write: frame => {
      ctx.drawImage(frame, 0, 0);
      frame.close();
    }
  };
}

async function startHwCapture(source, q) {
  if (typeof VideoDecoder !== 'function') throw new Error('WebCodecs unavailable');
  const invoke = window.__TAURI__.core.invoke;
  const fps = q.maxFramerate;
  const { width, height, codec } = await invoke('start_hw_capture', {
    id: source.id,
    maxW: Math.min(q.constraints.width.ideal, 1920),
    fps,
    bitrate: q.maxBitrate,
    // The picker already measured the source, so capture can start without
    // waiting for a first frame to learn its size.
    srcW: source.width,
    srcH: source.height
  });

  const sink = createFrameSink(width, height, fps);
  let live = true;
  let frames = 0;

  const decoder = new VideoDecoder({
    output: frame => {
      if (!live) { frame.close(); return; }
      frames++;
      sink.write(frame);
    },
    error: e => {
      console.warn('decoder error', e);
      if (live) stopVideo();
    }
  });
  decoder.configure({ codec, optimizeForLatency: true });

  hwCaptureStop = () => {
    live = false;
    hwCaptureStop = null;
    if (decoder.state !== 'closed') decoder.close();
    invoke('stop_hw_capture').catch(() => {});
  };

  // Per-stage report: whichever number is low is the stage to fix.
  const t0 = performance.now();
  setTimeout(async () => {
    if (!live) return;
    const secs = (performance.now() - t0) / 1000;
    let s = null;
    try { s = await invoke('hw_stats'); } catch { /* report what we have */ }
    const parts = [`${width}x${height} hardware`, `decoded ${Math.round(frames / secs)} fps`];
    if (s) {
      parts.push(
        `captured ${Math.round(s.captured / secs)} fps`,
        `encoded ${Math.round(s.encoded / secs)} fps`,
        `convert ${s.convert_ms.toFixed(1)} ms`,
        `encode ${s.encode_ms.toFixed(1)} ms`
      );
    }
    addSystemMessage('Screen share: ' + parts.join(' | '));
    invoke('hw_log', { line: 'report: ' + parts.join(' | ') }).catch(() => {});
  }, 5000);

  (async () => {
    let started = false;
    let pulls = 0;
    let waited = 0;
    while (live) {
      let buf;
      const pullStart = performance.now();
      try { buf = await invoke('next_hw_chunk'); } catch { break; }
      waited += performance.now() - pullStart;
      pulls++;
      if (!live) return;
      if (!buf || buf.byteLength < 14) break; // source closed or encoder died
      const bytes = buf instanceof ArrayBuffer ? new Uint8Array(buf) : new Uint8Array(buf.buffer);
      const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);

      // One pull carries every frame that was queued: [len][flags][ts][data]...
      let off = 0;
      while (off + 4 <= bytes.byteLength) {
        const len = view.getUint32(off, true);
        off += 4;
        if (len < 9 || off + len > bytes.byteLength) break;
        const key = view.getUint8(off) === 1;
        const timestamp = Number(view.getBigInt64(off + 1, true));
        // A decoder cannot start mid-GOP; wait for the first keyframe.
        if (started || key) {
          started = true;
          try {
            decoder.decode(new EncodedVideoChunk({
              type: key ? 'key' : 'delta',
              timestamp,
              data: bytes.subarray(off + 9, off + len)
            }));
          } catch (e) {
            invoke('hw_log', { line: 'decode failed: ' + (e.message || e) }).catch(() => {});
            return stopVideo();
          }
        }
        off += len;
      }
      if (pulls % 60 === 0) {
        invoke('hw_log', {
          line: `js: ${pulls} pulls, mean wait ${(waited / pulls).toFixed(1)}ms, decoded ${frames}`
        }).catch(() => {});
      }
    }
    if (live) stopVideo();
  })();

  return sink.stream;
}

function stopHwCapture() {
  if (hwCaptureStop) hwCaptureStop();
}

// ---------- native capture bridge (fallback) ----------
//
// GDI grab plus JPEG per frame, decoded in the webview. Slower than the
// hardware path, but works when WebCodecs or a hardware encoder is missing.

let nativeCaptureStop = null; // set while a native capture is running

async function startNativeCapture(source, q) {
  const invoke = window.__TAURI__.core.invoke;
  const fps = q.maxFramerate;
  const { width, height } = await invoke('start_native_capture', {
    id: source.id,
    // Encoding cost scales with pixels, so the native path caps at 1080p-wide
    // even when the preset asks for more.
    maxW: Math.min(q.constraints.width.ideal, 1920),
    fps
  });

  const canvas = document.createElement('canvas');
  canvas.width = width;
  canvas.height = height;
  const ctx = canvas.getContext('2d', { desynchronized: true });
  const stream = canvas.captureStream(fps);

  let live = true;
  nativeCaptureStop = () => {
    live = false;
    nativeCaptureStop = null;
    invoke('stop_native_capture').catch(() => {});
  };

  // One-shot measurement so a slow share is diagnosable without a profiler.
  let frames = 0;
  const t0 = performance.now();
  setTimeout(() => {
    if (live) {
      addSystemMessage(
        `Screen share: ${Math.round(frames / ((performance.now() - t0) / 1000))} fps at ${width}x${height}`
      );
    }
  }, 5000);

  (async () => {
    while (live) {
      let buf;
      try { buf = await invoke('next_frame'); } catch { break; }
      if (!live) return;
      if (!buf || !buf.byteLength) break; // source closed or capture died
      try {
        const bmp = await createImageBitmap(new Blob([buf], { type: 'image/jpeg' }));
        ctx.drawImage(bmp, 0, 0);
        bmp.close();
        frames++;
      } catch { /* skip a bad frame */ }
    }
    // Source vanished (window closed): end the share like a browser
    // "Stop sharing" would.
    if (live) stopVideo();
  })();

  return stream;
}

function stopNativeCapture() {
  if (nativeCaptureStop) nativeCaptureStop();
}

// ---------- remote control ----------
//
// Input events travel over a WebRTC data channel: peer-to-peer and
// DTLS-encrypted, so they never reach the relay server. Control is OFF by
// default and requires an explicit click by the person sharing their screen.
// Any grant is revoked when sharing stops, the peer disconnects, or the
// host presses the panic key (Ctrl+Alt+Break).

function attachCtlChannel(peerId, channel) {
  ctlChannels.set(peerId, channel);
  channel.onmessage = ev => {
    let m;
    try { m = JSON.parse(ev.data); } catch { return; }
    if (m.t === 'input') {
      // Only obey input from a peer this machine explicitly authorised.
      if (!controllers.has(peerId) || !isDesktopApp) return;
      window.__TAURI__.core.invoke('inject_input', { ev: m.ev }).catch(() => {});
    } else if (m.t === 'control-revoked' && controlling === peerId) {
      stopControlling();
      addSystemMessage(`${peers.get(peerId)?.name || 'peer'} ended your remote control session`);
    }
  };
  channel.onclose = () => {
    ctlChannels.delete(peerId);
    if (controlling === peerId) stopControlling();
  };
}

function sendCtl(peerId, obj) {
  const ch = ctlChannels.get(peerId);
  if (ch && ch.readyState === 'open') ch.send(JSON.stringify(obj));
}

// --- host side (the person sharing) ---

function requestFromPeer(peerId) {
  const name = peers.get(peerId)?.name || 'A peer';
  if (!isDesktopApp) {
    sendE2E({ kind: 'control-deny', to: peerId });
    return;
  }
  showConsentPrompt(name, allow => {
    if (allow) {
      controllers.add(peerId);
      sendE2E({ kind: 'control-grant', to: peerId });
      addSystemMessage(`${name} can now control your screen. Press Ctrl+Alt+Break to revoke.`, true);
      updateControlBanner();
    } else {
      sendE2E({ kind: 'control-deny', to: peerId });
    }
  });
}

function revokeAllControl() {
  if (!controllers.size) return;
  for (const id of controllers) sendCtl(id, { t: 'control-revoked' });
  controllers.clear();
  addSystemMessage('Remote control revoked.');
  updateControlBanner();
}

// --- viewer side (the person driving) ---

function startControlling(peerId) {
  controlling = peerId;
  const tile = document.getElementById('tile-' + peerId);
  tile?.classList.add('controlling');
  addSystemMessage(`Controlling ${peers.get(peerId)?.name || 'peer'} — click the video to send input, press Esc to stop.`);
  updateControlBanner();
}

function stopControlling() {
  if (controlling) document.getElementById('tile-' + controlling)?.classList.remove('controlling');
  controlling = null;
  updateControlBanner();
}

// Translate a pointer event on the video element into normalised 0..1
// coordinates within the shared picture, accounting for letterboxing.
function tileCoords(video, e) {
  const r = video.getBoundingClientRect();
  const vw = video.videoWidth || r.width;
  const vh = video.videoHeight || r.height;
  const scale = Math.min(r.width / vw, r.height / vh);
  const dw = vw * scale;
  const dh = vh * scale;
  const ox = (r.width - dw) / 2;
  const oy = (r.height - dh) / 2;
  const x = (e.clientX - r.left - ox) / dw;
  const y = (e.clientY - r.top - oy) / dh;
  return { x: Math.min(Math.max(x, 0), 1), y: Math.min(Math.max(y, 0), 1) };
}

function bindControlInput(peerId, tile) {
  const video = tile.querySelector('video');
  const active = () => controlling === peerId;
  const send = ev => sendCtl(peerId, { t: 'input', ev });

  video.addEventListener('mousemove', e => {
    if (!active()) return;
    send({ t: 'Move', ...tileCoords(video, e) });
  });
  video.addEventListener('mousedown', e => {
    if (!active()) return;
    e.preventDefault();
    send({ t: 'Down', ...tileCoords(video, e), button: e.button });
  });
  video.addEventListener('mouseup', e => {
    if (!active()) return;
    e.preventDefault();
    send({ t: 'Up', ...tileCoords(video, e), button: e.button });
  });
  video.addEventListener('contextmenu', e => { if (active()) e.preventDefault(); });
  video.addEventListener('wheel', e => {
    if (!active()) return;
    e.preventDefault();
    send({ t: 'Wheel', dy: e.deltaY });
  }, { passive: false });
}

// Keyboard is captured window-wide while controlling, so modifiers and
// shortcuts reach the remote machine instead of this window.
window.addEventListener('keydown', e => {
  if (!controlling) return;
  if (e.key === 'Escape') { stopControlling(); return; }
  e.preventDefault();
  sendCtl(controlling, { t: 'input', ev: { t: 'Key', code: e.code, key: e.key, down: true } });
});
window.addEventListener('keyup', e => {
  if (!controlling) return;
  e.preventDefault();
  sendCtl(controlling, { t: 'input', ev: { t: 'Key', code: e.code, key: e.key, down: false } });
});
// Panic key for the host: kill every control grant immediately.
window.addEventListener('keydown', e => {
  if (e.ctrlKey && e.altKey && (e.key === 'Pause' || e.code === 'Pause')) revokeAllControl();
});

// ---------- activities: YouTube watch together ----------
//
// A shared player in the stage. Whoever starts it broadcasts the video id
// over the sealed E2E channel; every client embeds its own YouTube player
// and play/pause/seek commands are relayed the same way, so the server
// still sees only ciphertext. The video itself streams from YouTube on
// each machine — the one deliberate, user-initiated external contact in
// the client (the IFrame API script loads lazily, only when an activity
// starts, and the join prompt discloses it).

let activity = null;    // { video, mine } — mine: this client started it
let ytPlayer = null;
let ytApplyUntil = 0;   // ignore player events we caused by applying a remote command
let ytApiPromise = null;

const YT_ID = /^[\w-]{11}$/;

function parseYouTubeId(input) {
  const s = input.trim();
  if (YT_ID.test(s)) return s;
  let u;
  try { u = new URL(s); } catch { return null; }
  const host = u.hostname.replace(/^(www|m|music)\./, '');
  if (host === 'youtu.be') {
    const id = u.pathname.split('/')[1] || '';
    return YT_ID.test(id) ? id : null;
  }
  if (host === 'youtube.com' || host === 'youtube-nocookie.com') {
    const v = u.searchParams.get('v');
    if (v && YT_ID.test(v)) return v;
    const m = u.pathname.match(/^\/(?:embed|shorts|live|v)\/([\w-]{11})(?:$|\/)/);
    if (m) return m[1];
  }
  return null;
}

function loadYouTubeAPI() {
  if (window.YT && window.YT.Player) return Promise.resolve();
  if (ytApiPromise) return ytApiPromise;
  ytApiPromise = new Promise((resolve, reject) => {
    window.onYouTubeIframeAPIReady = resolve;
    const s = document.createElement('script');
    s.src = 'https://www.youtube.com/iframe_api';
    s.onerror = () => {
      ytApiPromise = null;
      s.remove();
      reject(new Error('could not reach YouTube'));
    };
    document.head.appendChild(s);
  });
  return ytApiPromise;
}

function ytTime() {
  try { return ytPlayer ? ytPlayer.getCurrentTime() : 0; } catch { return 0; }
}

// The activity renders as a tile in the call grid, exactly like a
// participant: it shares the grid, can be focused full-stage, and joins
// the filmstrip when someone else is focused.
//
// Crucially, the YouTube iframe does NOT live inside the tile. Moving an
// iframe in the DOM reloads it, and focusing reparents tiles between the
// grid and the focus stage — the video would restart on every layout
// change. So the tile is an empty placeholder that only does layout, and
// the player sits in an overlay layer that a rAF loop keeps glued to the
// placeholder's rectangle. Built dynamically because the label carries a
// peer-supplied name (textContent only).

let activityLayerRaf = 0;

function ensureActivityTile(label) {
  const grid = $('#video-grid');
  let tile = document.getElementById('tile-activity');
  if (!tile) {
    tile = document.createElement('div');
    tile.id = 'tile-activity';
    tile.className = 'video-tile activity';
    grid.appendChild(tile);
  }

  let layer = document.getElementById('activity-layer');
  if (!layer) {
    layer = document.createElement('div');
    layer.id = 'activity-layer';

    const frame = document.createElement('div');
    frame.id = 'activity-frame';

    const tag = document.createElement('span');
    tag.className = 'tile-label';

    const acts = document.createElement('div');
    acts.className = 'tile-acts';

    // The iframe swallows clicks, so focusing happens via this button
    // instead of the usual click-anywhere-on-the-tile.
    const expand = document.createElement('button');
    expand.className = 'tile-act-btn';
    expand.title = 'Toggle full stage';
    const icMax = svgIcon('maximize');
    icMax.classList.add('ic-max');
    const icMin = svgIcon('minimize');
    icMin.classList.add('ic-min');
    expand.append(icMax, icMin);
    expand.onclick = () => setFocus(focusedTile === 'activity' ? null : 'activity');

    const end = document.createElement('button');
    end.className = 'tile-act-btn';
    end.title = 'End the activity for everyone';
    end.append(document.createTextNode('End'));
    end.onclick = () => {
      sendE2E({ kind: 'activity', act: 'end' });
      addSystemMessage('You ended watch together.');
      endActivityLocal();
    };

    acts.append(expand, end);
    layer.append(frame, tag, acts);
    $('#app').appendChild(layer);
    startActivityLayerSync(tile, layer);
  }
  layer.querySelector('.tile-label').textContent = label;
  updateStage();
  return tile;
}

// Keeps the player overlay pinned to the placeholder tile. Polling a rect
// per frame is cheap and catches everything at once: focus reparenting,
// grid reflow, window resizes and the chat drawer's slide animation.
function startActivityLayerSync(tile, layer) {
  let last = '';
  const step = () => {
    if (!layer.isConnected) { activityLayerRaf = 0; return; }
    const app = $('#app').getBoundingClientRect();
    const r = tile.getBoundingClientRect();
    const key = `${r.left},${r.top},${r.width},${r.height}`;
    if (key !== last) {
      last = key;
      layer.style.left = (r.left - app.left) + 'px';
      layer.style.top = (r.top - app.top) + 'px';
      layer.style.width = r.width + 'px';
      layer.style.height = r.height + 'px';
    }
    layer.classList.toggle('focused', focusedTile === 'activity');
    activityLayerRaf = requestAnimationFrame(step);
  };
  cancelAnimationFrame(activityLayerRaf);
  activityLayerRaf = requestAnimationFrame(step);
}

async function startActivity(video, t, mine, byName) {
  if (activity && activity.video === video) return; // already showing this video
  destroyActivity();
  activity = { video, mine };
  ensureActivityTile(mine ? 'YouTube — started by you' : `YouTube — started by ${byName}`);

  try { await loadYouTubeAPI(); }
  catch (e) {
    addSystemMessage('watch together failed: ' + e.message, true);
    endActivityLocal();
    return;
  }
  if (!activity || activity.video !== video) return; // ended while the API loaded

  const target = document.createElement('div');
  $('#activity-frame').replaceChildren(target);
  ytApplyUntil = performance.now() + 2000; // initial buffer/autoplay events are not user actions
  ytPlayer = new YT.Player(target, {
    videoId: video,
    playerVars: { start: Math.max(0, Math.floor(t || 0)), rel: 0 },
    events: { onStateChange: onYtStateChange }
  });
}

// Player events echo back as sync commands — unless we are inside the
// window where the change was caused by a peer's command, not this user.
function onYtStateChange(e) {
  if (!activity || !ytPlayer) return;
  if (performance.now() < ytApplyUntil) return;
  if (e.data === YT.PlayerState.PLAYING) {
    sendE2E({ kind: 'activity', act: 'play', video: activity.video, t: ytTime() });
  } else if (e.data === YT.PlayerState.PAUSED) {
    sendE2E({ kind: 'activity', act: 'pause', video: activity.video, t: ytTime() });
  }
}

function applyActivityCommand(act, t) {
  if (!ytPlayer || typeof ytPlayer.getPlayerState !== 'function') return;
  ytApplyUntil = performance.now() + 1200;
  try {
    if (typeof t === 'number' && Math.abs(ytTime() - t) > 1.5) ytPlayer.seekTo(t, true);
    if (act === 'play') ytPlayer.playVideo();
    else ytPlayer.pauseVideo();
  } catch { /* player not ready yet — the next command will land */ }
}

function destroyActivity() {
  if (ytPlayer) {
    try { ytPlayer.destroy(); } catch { /* already gone */ }
    ytPlayer = null;
  }
  document.getElementById('activity-frame')?.replaceChildren();
}

function endActivityLocal() {
  activity = null;
  destroyActivity();
  cancelAnimationFrame(activityLayerRaf);
  activityLayerRaf = 0;
  document.getElementById('activity-layer')?.remove();
  removeTile('activity'); // also drops focus if the tile was full-stage
}

function handleActivityMessage(from, payload) {
  const who = peers.get(from)?.name || 'A peer';
  switch (payload.act) {
    case 'start':
      if (!YT_ID.test(String(payload.video))) return;
      if (activity && activity.video === payload.video) return; // re-announce for a newcomer
      addSystemMessage(`${who} started YouTube watch together`);
      startActivity(payload.video, payload.t, false, who);
      break;
    case 'play':
    case 'pause':
      if (activity && activity.video === payload.video) applyActivityCommand(payload.act, payload.t);
      break;
    case 'end':
      if (activity) {
        addSystemMessage(`${who} ended watch together`);
        endActivityLocal();
      }
      break;
  }
}

function closeActivitiesMenu() {
  $('#activities-menu').hidden = true;
  $('#btn-activities').classList.remove('open');
}

// ---------- call tiles ----------
//
// Discord-style: every voice participant owns a tile for the whole call.
// Without video the tile shows an avatar; a camera or screen share fills
// it. Clicking a tile focuses it full-stage and the rest collapse into a
// strip; clicking again (or Esc) returns to the grid.

let focusedTile = null; // peer id or 'me'

const tileName = id => (id === 'me' ? myName + ' (you)' : peers.get(id)?.name || '?');

function ensureTile(id) {
  const grid = $('#video-grid');
  let tile = document.getElementById('tile-' + id);
  if (!tile) {
    tile = document.createElement('div');
    tile.id = 'tile-' + id;
    tile.className = 'video-tile';

    const avatar = document.createElement('div');
    avatar.className = 'tile-avatar';
    const initial = document.createElement('span');
    initial.className = 'tile-initial';
    avatar.append(initial);

    const video = document.createElement('video');
    video.autoplay = true;
    video.muted = true; // audio goes through separate <audio> elements
    video.playsInline = true;

    const tag = document.createElement('span');
    tag.className = 'tile-label';
    tile.append(avatar, video, tag);

    if (id !== 'me') {
      const ctl = document.createElement('button');
      ctl.className = 'tile-ctl';
      ctl.append(svgIcon('cursor'), document.createTextNode(' Control'));
      ctl.title = 'Ask this peer for control of their screen';
      ctl.onclick = () => {
        if (controlling === id) stopControlling();
        else sendE2E({ kind: 'control-request', to: id });
      };
      tile.append(ctl);
      bindControlInput(id, tile);
      tile.addEventListener('contextmenu', e => {
        if (controlling === id) return; // right-click is remote input while driving
        e.preventDefault();
        openUserMenu(id, e.clientX, e.clientY);
      });
    }

    tile.addEventListener('click', e => {
      if (e.target.closest('.tile-ctl')) return;
      if (controlling === id) return; // clicks are remote input while driving
      setFocus(focusedTile === id ? null : id);
    });

    grid.appendChild(tile);
  }
  const name = tileName(id);
  tile.querySelector('.tile-label').textContent = name;
  const initial = tile.querySelector('.tile-initial');
  initial.textContent = (name[0] || '?').toUpperCase();
  initial.style.background = nameColor(name);
  updateStage();
  return tile;
}

function setTileStream(id, stream, mirror) {
  const tile = ensureTile(id);
  tile.querySelector('video').srcObject = stream;
  tile.classList.add('has-video');
  tile.classList.toggle('mirror', !!mirror);
}

function clearTileStream(id) {
  const tile = document.getElementById('tile-' + id);
  if (!tile) return;
  tile.querySelector('video').srcObject = null;
  tile.classList.remove('has-video', 'mirror');
}

function removeTile(id) {
  if (focusedTile === id) setFocus(null);
  document.getElementById('tile-' + id)?.remove();
  updateStage();
}

// The tile moves between the grid and the focus stage. A <video> keeps its
// srcObject across the move but playback can pause, so nudge it.
function setFocus(id) {
  if (focusedTile) {
    const cur = document.getElementById('tile-' + focusedTile);
    if (cur) {
      cur.classList.remove('focused');
      $('#video-grid').appendChild(cur);
      cur.querySelector('video')?.play().catch(() => {}); // activity tile has no <video>
    }
  }
  focusedTile = null;
  const tile = id && document.getElementById('tile-' + id);
  if (tile) {
    focusedTile = id;
    tile.classList.add('focused');
    $('#focus-stage').appendChild(tile);
    tile.querySelector('video')?.play().catch(() => {});
  }
  updateStage();
}

function updateStage() {
  const grid = $('#video-grid');
  $('#focus-stage').hidden = !focusedTile;
  grid.classList.toggle('strip', !!focusedTile);
  grid.hidden = !grid.children.length;
  $('#stage-empty').hidden = !!(grid.children.length || focusedTile);
}

window.addEventListener('keydown', e => {
  if (e.key === 'Escape' && focusedTile && !controlling
      && $('#picker').hidden && $('#activity-modal').hidden) setFocus(null);
});

// ---------- chat drawer ----------

let chatOpen = localStorage.getItem('concord-chat-open') !== '0';
let unreadCount = 0;

function applyChatState() {
  $('#chat-drawer').classList.toggle('closed', !chatOpen);
  $('#btn-chat').classList.toggle('open', chatOpen);
}

function setChatOpen(open) {
  chatOpen = open;
  localStorage.setItem('concord-chat-open', open ? '1' : '0');
  applyChatState();
  if (open) {
    unreadCount = 0;
    $('#chat-unread').hidden = true;
    const wrap = $('#messages');
    wrap.scrollTop = wrap.scrollHeight;
    // preventScroll: the input is still off-screen mid-animation, and a
    // plain focus() would horizontally scroll the whole app to reach it,
    // shoving the sidebar out of view.
    if (!$('#chat-input').disabled) $('#chat-input').focus({ preventScroll: true });
  }
  // Undo any focus-scroll that already happened.
  $('#app').scrollLeft = 0;
  document.documentElement.scrollLeft = 0;
}

function bumpUnread() {
  if (chatOpen) return;
  unreadCount++;
  const badge = $('#chat-unread');
  badge.textContent = unreadCount > 99 ? '99+' : unreadCount;
  badge.hidden = false;
}

// ---------- chat UI ----------

function nameColor(name) {
  let h = 0;
  for (let i = 0; i < name.length; i++) h = (h * 31 + name.charCodeAt(i)) >>> 0;
  // Dark enough to read on the paper background and white bubbles.
  return `hsl(${h % 360} 42% 36%)`;
}

function addChatMessage(name, text, ts, self) {
  const wrap = $('#messages');
  const el = document.createElement('div');
  el.className = 'message' + (self ? ' self' : '');

  const head = document.createElement('div');
  head.className = 'msg-head';
  const author = document.createElement('span');
  author.className = 'msg-author';
  author.textContent = name;
  author.style.color = nameColor(name);
  const time = document.createElement('span');
  time.className = 'msg-time';
  time.textContent = new Date(ts || Date.now()).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  head.append(author, time);

  const body = document.createElement('div');
  body.className = 'msg-body';
  body.textContent = text;

  el.append(head, body);
  wrap.appendChild(el);
  wrap.scrollTop = wrap.scrollHeight;
  if (!self) bumpUnread();
}

function addSystemMessage(text, warn) {
  const wrap = $('#messages');
  const el = document.createElement('div');
  el.className = 'message system' + (warn ? ' warn' : '');
  // Icon and text are appended separately so `text` stays a text node
  // (it can contain peer-supplied names — never feed it to innerHTML).
  if (warn) el.append(svgIcon('warn'));
  el.append(document.createTextNode(text));
  wrap.appendChild(el);
  wrap.scrollTop = wrap.scrollHeight;
}

// ---------- latency probes ----------

function startPingLoop() {
  if (pingTimer) return;
  pingTimer = setInterval(sendPings, PING_INTERVAL);
  sendPings();
}

function sendPings() {
  if (!ws || ws.readyState !== WebSocket.OPEN) return;
  if (selfProbe) selfPing = null; // last echo never came back
  selfProbe = { n: ++pingSeq, t: performance.now() };
  sendRaw({ type: 'ping', n: selfProbe.n });
  if (peers.size) {
    for (const p of peers.values()) {
      if (p.awaitingPong) p.ping = null; // last probe never answered
      p.awaitingPong = true;
    }
    peerProbe = { n: ++pingSeq, t: performance.now() };
    sendE2E({ kind: 'ping', n: peerProbe.n });
  }
  renderRoster();
}

// ---------- per-peer audio: local mute + volume up to 200% ----------
//
// An <audio> element's volume caps at 100%, so each peer's stream is
// routed through a Web Audio gain node instead. Chromium quirk: remote
// WebRTC audio stays silent in a Web Audio graph unless the stream is
// ALSO attached to a playing media element — so the element keeps
// playing, but muted, and the audible path is the gain graph. Mute and
// volume are purely local: nothing is sent to peers or the server.

let audioCtx = null;
// peerId -> { mic, share, streams: Map<streamId, { el, src, kind }> }
// `mic` and `share` are gain nodes; a peer's screen-share audio arrives as its
// own stream so it can be balanced against their voice independently.
const peerAudio = new Map();

function getAudioCtx() {
  if (!audioCtx) audioCtx = new AudioContext();
  if (audioCtx.state === 'suspended') audioCtx.resume().catch(() => {});
  return audioCtx;
}

function peerAudioEntry(peerId) {
  let pa = peerAudio.get(peerId);
  if (!pa) {
    pa = { streams: new Map() };
    peerAudio.set(peerId, pa);
  }
  return pa;
}

function routePeerAudio(peerId, el, stream) {
  const pa = peerAudioEntry(peerId);
  const existing = pa.streams.get(stream.id);
  if (existing?.src) { try { existing.src.disconnect(); } catch { /* stale */ } }
  const entry = { el, src: null };
  pa.streams.set(stream.id, entry);
  try {
    const ctx = getAudioCtx();
    if (!pa.mic) {
      pa.mic = ctx.createGain();
      pa.mic.connect(ctx.destination);
      pa.share = ctx.createGain();
      pa.share.connect(ctx.destination);
    }
    entry.src = ctx.createMediaStreamSource(stream);
    el.muted = true; // output comes from the gain graph, not the element
    if (ctx.state === 'suspended') showAudioUnlock();
  } catch { /* no Web Audio: element fallback, volume caps at 100% */ }
  classifyPeerAudio(peerId);
  applyPeerAudio(peerId);
}

function dropPeerStream(peerId, streamId) {
  const pa = peerAudio.get(peerId);
  const entry = pa?.streams.get(streamId);
  if (!entry) return;
  try { entry.src?.disconnect(); } catch { /* already gone */ }
  entry.el?.remove();
  pa.streams.delete(streamId);
}

// Connects each of a peer's audio streams to the right gain node. The peer
// announces which stream id carries their shared audio, and that message can
// arrive either side of the track itself, so this runs on both events.
function classifyPeerAudio(peerId) {
  const pa = peerAudio.get(peerId);
  const p = peers.get(peerId);
  if (!pa || !pa.mic) return;
  for (const [id, entry] of pa.streams) {
    if (!entry.src) continue;
    try { entry.src.disconnect(); } catch { /* not connected yet */ }
    entry.kind = id === p?.shareAudioId ? 'share' : 'mic';
    entry.src.connect(entry.kind === 'share' ? pa.share : pa.mic);
  }
}

function applyPeerAudio(peerId) {
  const p = peers.get(peerId);
  const pa = peerAudio.get(peerId);
  if (!p || !pa) return;
  const micVol = p.muted ? 0 : (p.volume ?? 1);
  const shareVol = p.muted ? 0 : (p.streamVolume ?? 1);
  if (pa.mic) {
    pa.mic.gain.value = micVol;
    pa.share.gain.value = shareVol;
  } else {
    // Fallback path without Web Audio: one element, mic volume only.
    for (const entry of pa.streams.values()) {
      if (!entry.el) continue;
      entry.el.muted = !!p.muted;
      entry.el.volume = Math.min(1, micVol);
    }
  }
}

function peerHasShareAudio(peerId) {
  const pa = peerAudio.get(peerId);
  return !!pa && [...pa.streams.values()].some(e => e.kind === 'share');
}

// ---------- per-user context menu (right-click a member) ----------

let userMenuFor = null; // peer id the open menu points at

function openUserMenu(id, x, y) {
  const p = peers.get(id);
  if (!p) return;
  userMenuFor = id;
  $('#user-menu-name').textContent = p.name;
  syncUserMenu();
  const menu = $('#user-menu');
  menu.hidden = false;
  // Clamp to the viewport once the size is measurable.
  const r = menu.getBoundingClientRect();
  menu.style.left = Math.max(8, Math.min(x, innerWidth - r.width - 8)) + 'px';
  menu.style.top = Math.max(8, Math.min(y, innerHeight - r.height - 8)) + 'px';
}

function closeUserMenu() {
  userMenuFor = null;
  $('#user-menu').hidden = true;
}

function syncUserMenu() {
  const p = peers.get(userMenuFor);
  if (!p) return;
  const vol = Math.round((p.volume ?? 1) * 100);
  $('#user-menu-vol').value = vol;
  $('#user-menu-volval').textContent = vol + '%';

  // The stream slider only exists while that peer is sharing audio.
  const hasStream = peerHasShareAudio(userMenuFor);
  $('#user-menu-streamrow').hidden = !hasStream;
  if (hasStream) {
    const sv = Math.round((p.streamVolume ?? 1) * 100);
    $('#user-menu-streamvol').value = sv;
    $('#user-menu-streamval').textContent = sv + '%';
  }
  const btn = $('#user-menu-mute');
  btn.replaceChildren(
    svgIcon(p.muted ? 'speaker' : 'speakerOff'),
    document.createTextNode(p.muted ? ' Unmute' : ' Mute')
  );
}

// ---------- roster / misc UI ----------

function renderRoster() {
  if (userMenuFor != null && !peers.has(userMenuFor)) closeUserMenu();
  const ul = $('#user-list');
  ul.innerHTML = '';
  const entries = [[myId, { name: myName + ' (you)', inVoice, ping: selfPing }], ...peers.entries()];
  $('#user-count').textContent = `Members — ${entries.length}`;
  for (const [id, p] of entries) {
    const li = document.createElement('li');
    const dot = document.createElement('span');
    dot.className = 'dot';
    const nm = document.createElement('span');
    nm.textContent = p.name;
    li.append(dot, nm);
    if (id !== myId) {
      // Local audio settings; a captured typed id avoids Map key
      // mismatches that a data attribute would introduce.
      li.addEventListener('contextmenu', e => {
        e.preventDefault();
        openUserMenu(id, e.clientX, e.clientY);
      });
      if (p.muted || (p.volume ?? 1) !== 1) {
        const t = document.createElement('span');
        t.className = 'vol-tag';
        if (p.muted) t.append(svgIcon('speakerOff'));
        else t.textContent = Math.round((p.volume ?? 1) * 100) + '%';
        li.append(t);
      }
    }
    if (p.ping != null) {
      const pg = document.createElement('span');
      pg.className = 'ping';
      pg.textContent = `${p.ping} ms`;
      li.append(pg);
    }
    if (p.inVoice) {
      const v = document.createElement('span');
      v.className = 'in-voice';
      v.append(svgIcon('speaker'));
      li.append(v);
    }
    ul.appendChild(li);
  }
}

function updateVoiceUI() {
  // Sidebar shows "Start voice" only while out of the call;
  // in-call controls live in the floating bar over the stage.
  $('#btn-voice').hidden = inVoice;
  $('#call-bar').hidden = !inVoice;

  const btnMute = $('#btn-mute');
  btnMute.classList.toggle('off', micMuted);
  btnMute.title = micMuted ? 'Unmute microphone' : 'Mute microphone';

  const btnCam = $('#btn-cam');
  btnCam.classList.toggle('on', videoKind === 'cam');
  btnCam.title = videoKind === 'cam' ? 'Stop camera' : 'Share camera';

  const btnScreen = $('#btn-screen');
  btnScreen.classList.toggle('on', videoKind === 'screen');
  btnScreen.title = videoKind === 'screen' ? 'Stop sharing' : 'Share screen';

  $('#voice-status').hidden = !inVoice;
}

function showAudioUnlock() {
  $('#audio-unlock').hidden = false;
}

// Consent gate: nothing grants control except a deliberate click here.
function showConsentPrompt(name, done) {
  const box = $('#consent');
  $('#consent-text').textContent =
    `${name} is asking to control your screen — full mouse and keyboard access to this computer.`;
  box.hidden = false;
  const finish = allow => {
    box.hidden = true;
    $('#consent-allow').onclick = null;
    $('#consent-deny').onclick = null;
    done(allow);
  };
  $('#consent-allow').onclick = () => finish(true);
  $('#consent-deny').onclick = () => finish(false);
}

function updateControlBanner() {
  const banner = $('#control-banner');
  if (controllers.size) {
    const names = [...controllers].map(id => peers.get(id)?.name || '?').join(', ');
    banner.replaceChildren(
      svgIcon('warn'),
      document.createTextNode(` ${names} is controlling your computer — click here (or Ctrl+Alt+Break) to revoke`)
    );
    banner.className = 'granting';
    banner.hidden = false;
  } else if (controlling) {
    banner.replaceChildren(
      svgIcon('cursor'),
      document.createTextNode(` Controlling ${peers.get(controlling)?.name || 'peer'} — press Esc to stop`)
    );
    banner.className = 'driving';
    banner.hidden = false;
  } else {
    banner.hidden = true;
  }
}

function enterApp() {
  $('#join-modal').hidden = true;
  $('#app').hidden = false;
  $('#room-name').textContent = roomName;
  $('#channel-name').textContent = roomName;
  $('#me-name').textContent = myName;
  $('#chat-input').disabled = false;
  $('#chat-input').placeholder = `Write to #${roomName}. Only members can read it.`;
  if (chatOpen) $('#chat-input').focus({ preventScroll: true });
  renderRoster();
  startPingLoop();
  addSystemMessage(`Joined #${roomName} — messages, voice and video are end-to-end encrypted.`);
}

function showJoinError(text) {
  const el = $('#join-error');
  el.textContent = text;
  el.hidden = false;
  $('#join-btn').disabled = false;
  $('#join-btn').textContent = 'Join room';
}

// ---------- wiring ----------

$('#join-form').addEventListener('submit', async e => {
  e.preventDefault();
  const server = $('#join-server').value.trim();
  const name = $('#join-name').value.trim();
  const room = $('#join-room').value.trim();
  const pass = $('#join-pass').value;
  if (!server || !name || !room || !pass) return;

  $('#join-btn').disabled = true;
  $('#join-btn').textContent = 'Deriving key…';
  $('#join-error').hidden = true;

  myName = name;
  roomName = room;
  localStorage.setItem('concord-server', server);
  localStorage.setItem('concord-name', name);
  localStorage.setItem('concord-room', room);

  try {
    await connect(server, name, room, pass);
  } catch (err) {
    console.error(err);
    showJoinError('Failed to join: ' + err.message);
  }
});

$('#chat-form').addEventListener('submit', e => {
  e.preventDefault();
  const input = $('#chat-input');
  const text = input.value.trim();
  if (!text) return;
  input.value = '';
  const ts = Date.now();
  sendE2E({ kind: 'msg', name: myName, text, ts });
  addChatMessage(myName, text, ts, true);
});

$('#btn-chat').addEventListener('click', () => setChatOpen(!chatOpen));
$('#chat-close').addEventListener('click', () => setChatOpen(false));
applyChatState();

$('#btn-voice').addEventListener('click', joinVoice);
$('#btn-leave').addEventListener('click', leaveVoice);
$('#btn-mute').addEventListener('click', toggleMute);
$('#btn-cam').addEventListener('click', () => (videoKind === 'cam' ? stopVideo() : startVideo('cam')));
$('#btn-screen').addEventListener('click', () => (videoKind === 'screen' ? stopVideo() : openSharePicker()));

$('#btn-activities').addEventListener('click', e => {
  e.stopPropagation();
  const menu = $('#activities-menu');
  menu.hidden = !menu.hidden;
  $('#btn-activities').classList.toggle('open', !menu.hidden);
});
document.addEventListener('click', e => {
  if (!$('#activities-menu').hidden && !e.target.closest('#activities-wrap')) closeActivitiesMenu();
});

$('#act-youtube').addEventListener('click', () => {
  closeActivitiesMenu();
  $('#activity-error').hidden = true;
  $('#activity-url').value = '';
  $('#activity-modal').hidden = false;
  $('#activity-url').focus();
});

$('#activity-cancel').addEventListener('click', () => { $('#activity-modal').hidden = true; });

$('#activity-form').addEventListener('submit', e => {
  e.preventDefault();
  const id = parseYouTubeId($('#activity-url').value);
  if (!id) {
    const el = $('#activity-error');
    el.textContent = 'That does not look like a YouTube link or video ID.';
    el.hidden = false;
    return;
  }
  $('#activity-modal').hidden = true;
  sendE2E({ kind: 'activity', act: 'start', video: id });
  addSystemMessage('You started YouTube watch together.');
  startActivity(id, 0, true);
});

window.addEventListener('keydown', e => {
  if (e.key !== 'Escape') return;
  if (!$('#activity-modal').hidden) $('#activity-modal').hidden = true;
  else if (!$('#user-menu').hidden) closeUserMenu();
  else closeActivitiesMenu();
});

document.addEventListener('click', e => {
  if (!$('#user-menu').hidden && !e.target.closest('#user-menu')) closeUserMenu();
});

$('#user-menu-mute').addEventListener('click', () => {
  const p = peers.get(userMenuFor);
  if (!p) return;
  p.muted = !p.muted;
  applyPeerAudio(userMenuFor);
  syncUserMenu();
  renderRoster();
});

$('#user-menu-vol').addEventListener('input', e => {
  const p = peers.get(userMenuFor);
  if (!p) return;
  p.volume = e.target.value / 100;
  $('#user-menu-volval').textContent = e.target.value + '%';
  applyPeerAudio(userMenuFor);
});
// Roster redraw only when the drag ends — it rebuilds the list.
$('#user-menu-vol').addEventListener('change', renderRoster);

$('#user-menu-streamvol').addEventListener('input', e => {
  const p = peers.get(userMenuFor);
  if (!p) return;
  p.streamVolume = e.target.value / 100;
  $('#user-menu-streamval').textContent = e.target.value + '%';
  applyPeerAudio(userMenuFor);
});

$('#picker-cancel').addEventListener('click', closeSharePicker);
$('#picker-refresh').addEventListener('click', loadCaptureSources);
$('#picker-share').addEventListener('click', () => {
  if (!pickedSource) return;
  closeSharePicker();
  startVideo('screen', pickedSource);
});
window.addEventListener('keydown', e => {
  if (e.key === 'Escape' && !$('#picker').hidden) closeSharePicker();
});

$('#audio-unlock').addEventListener('click', () => {
  document.querySelectorAll('audio').forEach(a => a.play().catch(() => {}));
  if (audioCtx) audioCtx.resume().catch(() => {});
  $('#audio-unlock').hidden = true;
});

$('#control-banner').addEventListener('click', () => {
  if (controllers.size) revokeAllControl();
  else stopControlling();
});

// ---------- stream quality menu ----------
//
// Lives on the share button rather than the sidebar: the settings only matter
// while sharing, and that is where the hand already is.

// Resolution and frame rate are fixed when capture starts, so changing either
// mid-share restarts it on the same source.
function applyShareQuality(note) {
  retuneAllSenders();
  renderShareMenu();
  addSystemMessage(note || `Share quality: ${shareQuality().label}`);
  if (videoKind === 'screen' && shareSource) startVideo('screen', shareSource);
}

function optionRow(label, selected, onPick) {
  const row = document.createElement('button');
  row.type = 'button';
  row.className = 'opt-row' + (selected ? ' selected' : '');
  row.setAttribute('role', 'radio');
  row.setAttribute('aria-checked', selected ? 'true' : 'false');
  const text = document.createElement('span');
  text.textContent = label;
  const dot = document.createElement('span');
  dot.className = 'opt-dot';
  row.append(text, dot);
  row.addEventListener('click', onPick);
  return row;
}

// ---------- adaptive quality ----------
//
// WebRTC already drops bitrate on a weak link, but it cannot lower what we
// capture, so a struggling peer just gets a soft, smeared 1080p. Watching the
// congestion controller's own bandwidth estimate and re-capturing at a lower
// rung keeps the picture sharp instead.

const AUTO_INTERVAL = 4000;
const AUTO_COOLDOWN = 12000; // each change restarts capture, so change rarely
let autoTimer = null;
let autoLastChange = 0;
let autoPending = null; // a rung must be wanted twice in a row to take effect

async function measureUplink() {
  let available = Infinity;
  let limited = false;
  for (const st of pcs.values()) {
    let stats;
    try { stats = await st.pc.getStats(); } catch { continue; }
    stats.forEach(r => {
      if (r.type === 'candidate-pair' && r.nominated && r.availableOutgoingBitrate) {
        available = Math.min(available, r.availableOutgoingBitrate);
      }
      // The encoder itself reports when bandwidth is what is holding it back.
      if (r.type === 'outbound-rtp' && r.kind === 'video' && r.qualityLimitationReason === 'bandwidth') {
        limited = true;
      }
    });
  }
  return { available, limited };
}

// Highest rung that fits the measured headroom, capped by the user's choice.
function pickRung(available) {
  const ceiling = QUALITY_LADDER.findIndex(
    r => r.height === (RES_WIDTH[shareHeight] ? shareHeight : 1080) && r.fps === (shareFps === 30 ? 30 : 60)
  );
  const top = ceiling === -1 ? QUALITY_LADDER.length - 1 : ceiling;
  for (let i = top; i >= 0; i--) {
    const r = QUALITY_LADDER[i];
    // Leave a fifth of the link spare so the estimate has room to breathe.
    if (tierBitrate(r.height, r.fps) * 1.2 <= available) return i;
  }
  return 0;
}

async function checkUplink() {
  if (!shareAuto || videoKind !== 'screen' || !pcs.size) return;
  const { available, limited } = await measureUplink();
  if (!isFinite(available)) return; // no estimate yet

  let want = pickRung(available);
  // A limited encoder means the estimate is already optimistic; step down.
  if (limited && autoRung !== null && want >= autoRung) want = Math.max(0, autoRung - 1);

  if (want === autoRung || (autoRung === null && want === QUALITY_LADDER.length - 1)) {
    autoPending = null;
    return;
  }
  if (autoPending !== want) {
    autoPending = want;
    return; // wait for a second reading before disrupting the share
  }
  if (Date.now() - autoLastChange < AUTO_COOLDOWN) return;

  autoPending = null;
  autoLastChange = Date.now();
  const previous = shareQuality().label;
  autoRung = want;
  const q = shareQuality();
  applyShareQuality(
    `Connection ${Math.round(available / 1000)} kbps — share ${
      q.label === previous ? 'held at' : 'adjusted to'
    } ${q.label}`
  );
}

function startAutoQuality() {
  stopAutoQuality();
  autoTimer = setInterval(checkUplink, AUTO_INTERVAL);
}

function stopAutoQuality() {
  if (autoTimer) clearInterval(autoTimer);
  autoTimer = null;
  autoPending = null;
}

function renderShareMenu() {
  const fps = $('#share-fps');
  const res = $('#share-res');
  fps.replaceChildren(
    ...[30, 60].map(v =>
      optionRow(`${v} FPS`, shareFps === v, () => {
        shareFps = v;
        localStorage.setItem('concord-fps', v);
        autoRung = null; // a manual pick resets any automatic step-down
        applyShareQuality();
      })
    )
  );
  res.replaceChildren(
    ...[360, 480, 720, 1080].map(v =>
      optionRow(`${v}p`, shareHeight === v, () => {
        shareHeight = v;
        localStorage.setItem('concord-res', v);
        autoRung = null; // a manual pick resets any automatic step-down
        applyShareQuality();
      })
    )
  );

  const auto = $('#share-auto');
  auto.replaceChildren(
    optionRow('Adjust automatically', shareAuto, () => {
      shareAuto = !shareAuto;
      localStorage.setItem('concord-auto', shareAuto ? '1' : '0');
      if (!shareAuto) autoRung = null;
      applyShareQuality();
    })
  );

  // Switching source only means anything while something is being shared.
  const sharing = videoKind === 'screen';
  $('#share-change').hidden = !sharing;
  $('#share-menu-sep').hidden = !sharing;

  // Say so when the link, not the user, is setting the current quality.
  const active = shareQuality();
  const note = $('#share-menu .menu-note');
  note.textContent =
    shareAuto && autoRung !== null && active.label !== `${shareHeight}p${shareFps}`
      ? `link-limited: now ${active.label}`
      : 'applies to the next share';
}

function setShareMenuOpen(open) {
  $('#share-menu').hidden = !open;
  $('#btn-share-menu').classList.toggle('open', open);
  if (open) renderShareMenu();
}

$('#btn-share-menu').addEventListener('click', e => {
  e.stopPropagation();
  setShareMenuOpen($('#share-menu').hidden);
});

// Swap to a different window or screen without dropping out of the share.
$('#share-change').addEventListener('click', () => {
  setShareMenuOpen(false);
  openSharePicker();
});

// Click-away and Esc close it, like every other popover in the app.
document.addEventListener('click', e => {
  if (!$('#share-menu').hidden && !e.target.closest('#screen-wrap')) setShareMenuOpen(false);
});
window.addEventListener('keydown', e => {
  if (e.key === 'Escape' && !$('#share-menu').hidden) setShareMenuOpen(false);
});

renderShareMenu();

window.addEventListener('beforeunload', () => {
  if (inVoice) leaveVoice();
});

// Prefill from last session.
$('#join-server').value = localStorage.getItem('concord-server') || 'ws://localhost:3000';
$('#join-name').value = localStorage.getItem('concord-name') || '';
$('#join-room').value = localStorage.getItem('concord-room') || '';
