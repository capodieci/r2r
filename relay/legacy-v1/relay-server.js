#!/usr/bin/env node
/* R2R relay — zero-dependency reference implementation of RELAY-SPEC.md (v1).
   Run:  node relay-server.js          (Node 16+)
   Env:  PORT=8787  DATA_DIR=./r2r-relay-data  BLOB_TTL_DAYS=30  QUEUE_TTL_DAYS=30
         TURN_URL=turn:1.2.3.4:3478  TURN_USER=user  TURN_PASS=pass  CREDIT_MB=500
         IP_REQS_PER_MIN=240   (pre-auth per-IP limiter; loopback exempt)
   Everything stored on disk is end-to-end ciphertext. */
'use strict';
const http = require('http');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const PORT = parseInt(process.env.PORT || '8787', 10);
const DATA = process.env.DATA_DIR || './r2r-relay-data';
const BLOB_TTL = (parseFloat(process.env.BLOB_TTL_DAYS || '30')) * 86400e3;
const QUEUE_TTL = (parseFloat(process.env.QUEUE_TTL_DAYS || '30')) * 86400e3;
const MAX_BLOB = 17 * 1024 * 1024;
const MAX_PAYLOAD = 64 * 1024;
const QUEUE_CAP = 500;
const SENDS_PER_MIN = 60;
const IP_REQS_PER_MIN = parseInt(process.env.IP_REQS_PER_MIN || '240', 10);

fs.mkdirSync(path.join(DATA, 'queue'), { recursive: true });
fs.mkdirSync(path.join(DATA, 'blobs'), { recursive: true });
fs.mkdirSync(path.join(DATA, 'accounts'), { recursive: true });
const MAX_EVENT = 600 * 1024;
const DEFAULT_QUOTA_MB = parseFloat(process.env.DEFAULT_QUOTA_MB || '1');
const AK_FILE = path.join(DATA, 'admin.key');
let ADMIN_KEY = '';
try { ADMIN_KEY = fs.readFileSync(AK_FILE, 'utf8').trim(); } catch (e) { }
if (!/^[0-9a-f]{64}$/.test(ADMIN_KEY)) { ADMIN_KEY = crypto.randomBytes(32).toString('hex'); fs.writeFileSync(AK_FILE, ADMIN_KEY + '\n', { mode: 0o600 }); }
function acctDir(pub, sub) { return path.join(DATA, 'accounts', pub, sub || ''); }
function acctQuotaBytes(pub) { try { const mb = parseFloat(fs.readFileSync(acctDir(pub, 'quota'), 'utf8')); if (!isNaN(mb)) return mb < 0 ? -1 : mb * 1048576; } catch (e) { } return DEFAULT_QUOTA_MB * 1048576; }
function acctTtlDays(pub) { try { const d = parseFloat(fs.readFileSync(acctDir(pub, 'ttl'), 'utf8')); if (!isNaN(d)) return d < 0 ? -1 : d; } catch (e) { } return parseFloat(process.env.BLOB_TTL_DAYS || '30'); }
function acctUsed(pub) { let t = 0; try { fs.readdirSync(acctDir(pub, 'journal')).forEach(f => { try { t += fs.statSync(path.join(acctDir(pub, 'journal'), f)).size; } catch (e) { } }); } catch (e) { } return t; }
function nextSeq(pub) { fs.mkdirSync(acctDir(pub, 'journal'), { recursive: true }); let mx = 0; fs.readdirSync(acctDir(pub, 'journal')).forEach(f => { const v = parseInt(f, 10); if (v > mx) mx = v; }); return mx + 1; }

/* ---------- auth: ?pub&ts&sig, sig = ed25519("R2R-AUTH|"+ts) ---------- */
function verifyAuth(q) {
  try {
    const pub = String(q.pub || '').toLowerCase();
    if (!/^[0-9a-f]{64}$/.test(pub)) return null;
    const ts = parseInt(q.ts, 10);
    if (!ts || Math.abs(Date.now() / 1000 - ts) > 600) return null;
    const sig = Buffer.from(String(q.sig || ''), 'hex');
    if (sig.length !== 64) return null;
    const der = Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), Buffer.from(pub, 'hex')]);
    const key = crypto.createPublicKey({ key: der, format: 'der', type: 'spki' });
    return crypto.verify(null, Buffer.from('R2R-AUTH|' + ts), key, sig) ? pub : null;
  } catch (e) { return null; }
}
function parseQuery(url) { const q = {}; const i = url.indexOf('?'); if (i < 0) return q; url.slice(i + 1).split('&').forEach(p => { const [k, v] = p.split('='); q[decodeURIComponent(k)] = decodeURIComponent(v || ''); }); return q; }

/* ---------- per-account message queue (one JSON file per recipient) ---------- */
function qFile(pub) { return path.join(DATA, 'queue', pub + '.json'); }
function qLoad(pub) { try { return JSON.parse(fs.readFileSync(qFile(pub), 'utf8')); } catch (e) { return []; } }
function qSave(pub, list) { try { if (!list.length) fs.rmSync(qFile(pub), { force: true }); else fs.writeFileSync(qFile(pub), JSON.stringify(list)); } catch (e) { } }
function qPush(pub, item) { const l = qLoad(pub); if (l.some(x => x.id === item.id)) return; l.push(item); while (l.length > QUEUE_CAP) l.shift(); qSave(pub, l); }
function qDrop(pub, id) { const l = qLoad(pub); const n = l.filter(x => x.id !== id); if (n.length !== l.length) qSave(pub, n); return n.length !== l.length; }

/* ---------- live state ---------- */
const SOCKS = new Map();      // pub -> socket state
const WATCHERS = new Map();   // watched pub -> Set of watcher pubs
const LASTSEEN = new Map();   // pub -> unix ms
const RATE = new Map();       // pub -> [timestamps]

function presenceOf(pub) { const s = SOCKS.get(pub); return s ? (s.presState || 'online') : 'offline'; }
function pushPresence(pub) {
  const watchers = WATCHERS.get(pub); if (!watchers) return;
  const frame = JSON.stringify({ type: 'presence', pub, state: presenceOf(pub), seen: LASTSEEN.get(pub) || 0 });
  watchers.forEach(w => { const s = SOCKS.get(w); if (s) wsSendRaw(s.sock, frame); });
}
function rateOk(pub) { const now = Date.now(); let a = RATE.get(pub) || []; a = a.filter(t => now - t < 60e3); if (a.length >= SENDS_PER_MIN) return false; a.push(now); RATE.set(pub, a); return true; }

/* pre-auth per-IP limiter — checked BEFORE signature verification (anti CPU-flood) */
const IPRATE = new Map();     // ip -> [timestamps]
function ipOk(sock) { const ip = (sock && sock.remoteAddress) || ''; if (!ip || ip === '127.0.0.1' || ip === '::1' || ip === '::ffff:127.0.0.1') return true; const now = Date.now(); let a = IPRATE.get(ip) || []; a = a.filter(t => now - t < 60e3); if (a.length >= IP_REQS_PER_MIN) { IPRATE.set(ip, a); return false; } a.push(now); IPRATE.set(ip, a); return true; }

/* ---------- HTTP ---------- */
const server = http.createServer((req, res) => {
  const q = parseQuery(req.url);
  const route = req.url.split('?')[0];
  const cors = { 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Methods': 'GET,POST,OPTIONS', 'Access-Control-Allow-Headers': '*' };
  if (req.method === 'OPTIONS') { res.writeHead(204, cors); res.end(); return; }
  const json = (code, obj) => { res.writeHead(code, { ...cors, 'Content-Type': 'application/json' }); res.end(JSON.stringify(obj)); };
  if (!ipOk(req.socket)) return json(429, { error: 'rate' });

  if (route === '/info') {
    let queued = 0; try { queued = fs.readdirSync(path.join(DATA, 'queue')).length; } catch (e) { }
    return json(200, { name: 'r2r-relay', version: 1, ws: '/ws', maxBlob: MAX_BLOB, queued });
  }
  const pub = verifyAuth(q);
  if (route === '/credit') {
    if (!pub) return json(401, { error: 'auth' });
    return json(200, { mb: process.env.CREDIT_MB ? parseFloat(process.env.CREDIT_MB) : 999999 });
  }
  if (route === '/ice') {
    if (!pub) return json(401, { error: 'auth' });
    const ice = [{ urls: 'stun:stun.l.google.com:19302' }];
    if (process.env.TURN_URL) ice.push({ urls: process.env.TURN_URL, username: process.env.TURN_USER || '', credential: process.env.TURN_PASS || '' });
    return json(200, { iceServers: ice, ttl: 600 });
  }
  if (route === '/blob' && req.method === 'POST') {
    if (!pub) return json(401, { error: 'auth' });
    const chunks = []; let size = 0, dead = false;
    req.on('data', c => { size += c.length; if (size > MAX_BLOB) { dead = true; json(413, { error: 'too_big' }); req.destroy(); return; } chunks.push(c); });
    req.on('end', () => {
      if (dead) return;
      const buf = Buffer.concat(chunks);
      const id = crypto.createHash('sha256').update(buf).digest('hex').slice(0, 32);
      fs.writeFileSync(path.join(DATA, 'blobs', id), buf);
      // per-blob expiry: TTL follows the uploading account (owner-adjustable); never shortened
      const ttl = acctTtlDays(pub);
      const expF = path.join(DATA, 'blobs', id + '.exp');
      let prev = null; try { prev = fs.readFileSync(expF, 'utf8').trim(); } catch (e) { }
      const exp = ttl < 0 ? -1 : Date.now() + ttl * 86400e3;
      if (prev !== '-1' && !(prev !== null && exp >= 0 && parseFloat(prev) >= exp)) fs.writeFileSync(expF, String(exp));
      json(200, { id });
    });
    return;
  }
  if (route.startsWith('/blob/')) {
    if (!pub) return json(401, { error: 'auth' });
    const id = route.slice(6);
    if (!/^[0-9a-f]{32}$/.test(id)) return json(400, { error: 'bad_id' });
    const f = path.join(DATA, 'blobs', id);
    if (!fs.existsSync(f)) return json(404, { error: 'gone' });
    res.writeHead(200, { ...cors, 'Content-Type': 'application/octet-stream' });
    fs.createReadStream(f).pipe(res);
    return;
  }
  if (route === '/journal' && req.method === 'POST') {
    if (!pub) return json(401, { error: 'auth' });
    const chunks = []; let size = 0, dead = false;
    req.on('data', c => { size += c.length; if (size > MAX_EVENT) { dead = true; json(413, { error: 'too_big' }); req.destroy(); return; } chunks.push(c); });
    req.on('end', () => {
      if (dead) return;
      const body = Buffer.concat(chunks);
      if (!/^[\x20-\x7e]*$/.test(body.toString('latin1'))) return json(400, { error: 'binary' });
      const quota = acctQuotaBytes(pub);
      if (quota >= 0 && acctUsed(pub) + body.length > quota) return json(402, { error: 'quota' });
      const seq = nextSeq(pub);
      fs.writeFileSync(path.join(acctDir(pub, 'journal'), String(seq).padStart(10, '0')), body);
      json(200, { seq });
    });
    return;
  }
  if (route === '/journal' && req.method === 'GET') {
    if (!pub) return json(401, { error: 'auth' });
    const since = parseInt(q.since || '0', 10) || 0;
    let names = []; try { names = fs.readdirSync(acctDir(pub, 'journal')); } catch (e) { }
    const seqs = names.map(n => parseInt(n, 10)).filter(v => v > since).sort((a, b) => a - b);
    const out = []; let total = 0;
    for (const s of seqs) {
      if (out.length >= 200 || total > 2 * 1024 * 1024) break;
      try { const d = fs.readFileSync(path.join(acctDir(pub, 'journal'), String(s).padStart(10, '0')), 'utf8'); out.push({ seq: s, d }); total += d.length; } catch (e) { }
    }
    return json(200, out);
  }
  if (route === '/usage' && req.method === 'GET') {
    if (!pub) return json(401, { error: 'auth' });
    return json(200, { usedBytes: acctUsed(pub), quotaBytes: acctQuotaBytes(pub), ttlDays: acctTtlDays(pub) });
  }
  if (route.startsWith('/admin/')) {
    if (!ADMIN_KEY || (req.headers['x-admin-key'] || '') !== ADMIN_KEY) return json(401, { error: 'admin' });
    if (route === '/admin/accounts') {
      let pubs = []; try { pubs = fs.readdirSync(path.join(DATA, 'accounts')).filter(p => /^[0-9a-f]{64}$/.test(p)); } catch (e) { }
      return json(200, pubs.map(p => ({ pub: p, usedBytes: acctUsed(p), quotaBytes: acctQuotaBytes(p), ttlDays: acctTtlDays(p) })));
    }
    if (route === '/admin/quota' && req.method === 'POST') {
      const p2 = String(q.pub || '').toLowerCase(), mb = String(q.mb || '');
      if (!/^[0-9a-f]{64}$/.test(p2) || mb === '') return json(400, { error: 'args' });
      fs.mkdirSync(acctDir(p2), { recursive: true });
      fs.writeFileSync(acctDir(p2, 'quota'), mb);
      return json(200, { ok: true });
    }
    if (route === '/admin/ttl' && req.method === 'POST') {
      const p2 = String(q.pub || '').toLowerCase(), days = String(q.days || '');
      if (!/^[0-9a-f]{64}$/.test(p2) || days === '' || isNaN(parseFloat(days))) return json(400, { error: 'args' });
      fs.mkdirSync(acctDir(p2), { recursive: true });
      fs.writeFileSync(acctDir(p2, 'ttl'), days);
      return json(200, { ok: true });
    }
    return json(404, { error: 'not_found' });
  }
  json(404, { error: 'not_found' });
});

/* ---------- minimal WebSocket server (RFC 6455, text frames) ---------- */
const WS_GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11';
server.on('upgrade', (req, sock) => {
  const route = req.url.split('?')[0];
  if (route !== '/ws') { sock.destroy(); return; }
  if (!ipOk(sock)) { sock.write('HTTP/1.1 429 Too Many Requests\r\n\r\n'); sock.destroy(); return; }
  const pub = verifyAuth(parseQuery(req.url));
  const key = req.headers['sec-websocket-key'];
  if (!pub || !key) { sock.write('HTTP/1.1 401 Unauthorized\r\n\r\n'); sock.destroy(); return; }
  const accept = crypto.createHash('sha1').update(key + WS_GUID).digest('base64');
  sock.write('HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ' + accept + '\r\n\r\n');
  sock.setNoDelay(true);

  const old = SOCKS.get(pub);
  if (old) { try { old.sock.destroy(); } catch (e) { } }
  const st = { sock, pub, presState: 'online', watching: new Set(), buf: Buffer.alloc(0) };
  SOCKS.set(pub, st);
  LASTSEEN.set(pub, Date.now());
  pushPresence(pub);

  // flush queued messages
  qLoad(pub).forEach(m => wsSend(sock, { type: 'msg', id: m.id, from: m.from, ts: m.ts, payload: m.payload }));

  sock.on('data', d => {
    st.buf = Buffer.concat([st.buf, d]);
    let frame;
    while ((frame = readFrame(st))) {
      if (frame.op === 8) { sock.end(); return; }
      if (frame.op === 9) { writeFrame(sock, 10, frame.data); continue; }   // ping → pong
      if (frame.op !== 1) continue;
      let m; try { m = JSON.parse(frame.data.toString('utf8')); } catch (e) { continue; }
      handleMsg(st, m);
    }
    if (st.buf.length > 2 * 1024 * 1024) sock.destroy();   // runaway frame
  });
  const bye = () => {
    if (SOCKS.get(pub) === st) { SOCKS.delete(pub); LASTSEEN.set(pub, Date.now()); pushPresence(pub); }
    st.watching.forEach(w => { const set = WATCHERS.get(w); if (set) { set.delete(pub); if (!set.size) WATCHERS.delete(w); } });
  };
  sock.on('close', bye); sock.on('error', bye);
});

function readFrame(st) {
  const b = st.buf;
  if (b.length < 2) return null;
  const op = b[0] & 0x0f, masked = !!(b[1] & 0x80);
  let len = b[1] & 0x7f, off = 2;
  if (len === 126) { if (b.length < 4) return null; len = b.readUInt16BE(2); off = 4; }
  else if (len === 127) { if (b.length < 10) return null; len = Number(b.readBigUInt64BE(2)); off = 10; }
  if (len > 1024 * 1024) { st.sock.destroy(); return null; }
  const maskOff = off, dataOff = off + (masked ? 4 : 0);
  if (b.length < dataOff + len) return null;
  let data = b.slice(dataOff, dataOff + len);
  if (masked) { const mask = b.slice(maskOff, maskOff + 4); data = Buffer.from(data); for (let i = 0; i < data.length; i++) data[i] ^= mask[i & 3]; }
  st.buf = b.slice(dataOff + len);
  return { op, data };
}
function writeFrame(sock, op, payload) {
  const len = payload.length;
  let head;
  if (len < 126) { head = Buffer.from([0x80 | op, len]); }
  else if (len < 65536) { head = Buffer.alloc(4); head[0] = 0x80 | op; head[1] = 126; head.writeUInt16BE(len, 2); }
  else { head = Buffer.alloc(10); head[0] = 0x80 | op; head[1] = 127; head.writeBigUInt64BE(BigInt(len), 2); }
  try { sock.write(Buffer.concat([head, payload])); } catch (e) { }
}
function wsSendRaw(sock, str) { writeFrame(sock, 1, Buffer.from(str, 'utf8')); }
function wsSend(sock, obj) { wsSendRaw(sock, JSON.stringify(obj)); }

/* ---------- protocol ---------- */
function handleMsg(st, m) {
  if (!m || !m.type) return;
  if (m.type === 'ping') { wsSend(st.sock, { type: 'pong' }); return; }
  if (m.type === 'presence') { st.presState = m.state === 'away' ? 'away' : 'online'; pushPresence(st.pub); return; }
  if (m.type === 'watch') {
    st.watching.forEach(w => { const set = WATCHERS.get(w); if (set) set.delete(st.pub); });
    st.watching = new Set();
    (Array.isArray(m.pubs) ? m.pubs : []).slice(0, 5000).forEach(p => {
      p = String(p || '').toLowerCase(); if (!/^[0-9a-f]{64}$/.test(p)) return;
      st.watching.add(p);
      if (!WATCHERS.has(p)) WATCHERS.set(p, new Set());
      WATCHERS.get(p).add(st.pub);
      wsSend(st.sock, { type: 'presence', pub: p, state: presenceOf(p), seen: LASTSEEN.get(p) || 0 });
    });
    return;
  }
  if (m.type === 'send') {
    const to = String(m.to || '').toLowerCase(), id = String(m.id || '');
    if (!/^[0-9a-f]{64}$/.test(to) || !/^[0-9a-f]{4,32}$/.test(id)) return;
    if (typeof m.payload !== 'string' || m.payload.length > MAX_PAYLOAD) return;
    if (!rateOk(st.pub)) { wsSend(st.sock, { type: 'sent', id, queued: false, error: 'rate' }); return; }
    const item = { id, from: st.pub, to, ts: Date.now(), payload: m.payload };
    const rc = SOCKS.get(to);
    qPush(to, item);                       // queue first — delete on ack, so delivery survives a drop
    if (rc) wsSend(rc.sock, { type: 'msg', id, from: st.pub, ts: item.ts, payload: m.payload });
    wsSend(st.sock, { type: 'sent', id, queued: !rc });
    return;
  }
  if (m.type === 'ack') {
    const id = String(m.id || '');
    const l = qLoad(st.pub); const hit = l.find(x => x.id === id);
    if (hit) {
      qSave(st.pub, l.filter(x => x.id !== id));
      const snd = SOCKS.get(hit.from);
      if (snd) wsSend(snd.sock, { type: 'delivered', id });
    }
    return;
  }
  if (m.type === 'sig') {
    const to = String(m.to || '').toLowerCase();
    if (!/^[0-9a-f]{64}$/.test(to) || typeof m.payload !== 'string' || m.payload.length > MAX_PAYLOAD) return;
    const rc = SOCKS.get(to);
    if (rc) wsSend(rc.sock, { type: 'sig', from: st.pub, payload: m.payload });
    return;
  }
}

/* ---------- TTL sweep ---------- */
setInterval(() => {
  const now = Date.now();
  IPRATE.forEach((a, ip) => { if (!a.some(t => now - t < 60e3)) IPRATE.delete(ip); });
  try { fs.readdirSync(path.join(DATA, 'blobs')).forEach(f => {
    if (f.endsWith('.exp')) return;
    const p = path.join(DATA, 'blobs', f), expF = p + '.exp';
    let exp = NaN; try { exp = parseFloat(fs.readFileSync(expF, 'utf8')); } catch (e) { }
    try {
      if (!isNaN(exp)) { if (exp >= 0 && now > exp) { fs.rmSync(p); fs.rmSync(expF, { force: true }); } }
      else if (now - fs.statSync(p).mtimeMs > BLOB_TTL) { fs.rmSync(p); fs.rmSync(expF, { force: true }); }
    } catch (e) { }
  }); } catch (e) { }
  try {
    fs.readdirSync(path.join(DATA, 'queue')).forEach(f => {
      const pub = f.replace('.json', '');
      const l = qLoad(pub).filter(x => now - x.ts < QUEUE_TTL);
      qSave(pub, l);
    });
  } catch (e) { }
}, 3600e3);

server.listen(PORT, () => { console.log('R2R relay listening on :' + PORT + '  (data: ' + DATA + ')'); console.log('ADMIN KEY — copy this into the wallet (Settings → Relay owner) to manage per-identity storage & file lifetimes:');
console.log('  ' + ADMIN_KEY);
console.log('  (kept in ' + DATA + '/admin.key — printed at every start; delete that file + restart for a new one. Default quota: ' + DEFAULT_QUOTA_MB + ' MB/account)'); });
