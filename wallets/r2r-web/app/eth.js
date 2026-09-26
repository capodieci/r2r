/* R2RETH — self-contained crypto for the v2 relay protocol + storage market.
   sha256/hmac (hello fingerprints, RFC6979), keccak256 + secp256k1 + EIP-191
   personal-sign (storage-market vouchers), minimal JSON-RPC eth_call reads.
   No dependencies. BigInt required (all target browsers have it). */
window.R2RETH = (function () {
  'use strict';
  /* ---------- SHA-256 (sync) ---------- */
  var K256 = [0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2];
  function rotr(x, n) { return (x >>> n) | (x << (32 - n)); }
  function sha256(bytes) {
    var l = bytes.length, bl = l * 8;
    var padded = new Uint8Array(((l + 8) >> 6 << 6) + 64);
    padded.set(bytes); padded[l] = 0x80;
    var dv = new DataView(padded.buffer);
    dv.setUint32(padded.length - 8, Math.floor(bl / 0x100000000));
    dv.setUint32(padded.length - 4, bl >>> 0);
    var h = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];
    var w = new Array(64);
    for (var off = 0; off < padded.length; off += 64) {
      for (var i = 0; i < 16; i++) w[i] = dv.getUint32(off + i * 4);
      for (i = 16; i < 64; i++) {
        var s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >>> 3);
        var s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >>> 10);
        w[i] = (w[i - 16] + s0 + w[i - 7] + s1) | 0;
      }
      var a = h[0], b = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], hh = h[7];
      for (i = 0; i < 64; i++) {
        var S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
        var ch = (e & f) ^ (~e & g);
        var t1 = (hh + S1 + ch + K256[i] + w[i]) | 0;
        var S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
        var mj = (a & b) ^ (a & c) ^ (b & c);
        var t2 = (S0 + mj) | 0;
        hh = g; g = f; f = e; e = (d + t1) | 0; d = c; c = b; b = a; a = (t1 + t2) | 0;
      }
      h[0] = (h[0] + a) | 0; h[1] = (h[1] + b) | 0; h[2] = (h[2] + c) | 0; h[3] = (h[3] + d) | 0;
      h[4] = (h[4] + e) | 0; h[5] = (h[5] + f) | 0; h[6] = (h[6] + g) | 0; h[7] = (h[7] + hh) | 0;
    }
    var out = new Uint8Array(32), odv = new DataView(out.buffer);
    for (i = 0; i < 8; i++) odv.setUint32(i * 4, h[i] >>> 0);
    return out;
  }
  function hmac256(key, msg) {
    if (key.length > 64) key = sha256(key);
    var ik = new Uint8Array(64 + msg.length), ok = new Uint8Array(64 + 32);
    for (var i = 0; i < 64; i++) { ik[i] = 0x36 ^ (key[i] || 0); ok[i] = 0x5c ^ (key[i] || 0); }
    ik.set(msg, 64);
    ok.set(sha256(ik), 64);
    return sha256(ok);
  }
  /* ---------- keccak-256 ---------- */
  var KRC = ['0x0000000000000001', '0x0000000000008082', '0x800000000000808a', '0x8000000080008000', '0x000000000000808b', '0x0000000080000001', '0x8000000080008081', '0x8000000000008009', '0x000000000000008a', '0x0000000000000088', '0x0000000080008009', '0x000000008000000a', '0x000000008000808b', '0x800000000000008b', '0x8000000000008089', '0x8000000000008003', '0x8000000000008002', '0x8000000000000080', '0x000000000000800a', '0x800000008000000a', '0x8000000080008081', '0x8000000000008080', '0x0000000080000001', '0x8000000080008008'].map(BigInt);
  var KROT = [[0, 36, 3, 41, 18], [1, 44, 10, 45, 2], [62, 6, 43, 15, 61], [28, 55, 25, 21, 56], [27, 20, 39, 8, 14]];
  var M64 = (1n << 64n) - 1n;
  function rotl64(x, n) { n = BigInt(n); return ((x << n) | (x >> (64n - n))) & M64; }
  function keccakF(st) {
    for (var round = 0; round < 24; round++) {
      var C = [], D = [], x, y;
      for (x = 0; x < 5; x++) C[x] = st[x][0] ^ st[x][1] ^ st[x][2] ^ st[x][3] ^ st[x][4];
      for (x = 0; x < 5; x++) D[x] = C[(x + 4) % 5] ^ rotl64(C[(x + 1) % 5], 1);
      for (x = 0; x < 5; x++) for (y = 0; y < 5; y++) st[x][y] = st[x][y] ^ D[x];
      var B = [[], [], [], [], []];
      for (x = 0; x < 5; x++) for (y = 0; y < 5; y++) B[y][(2 * x + 3 * y) % 5] = rotl64(st[x][y], KROT[x][y]);
      for (x = 0; x < 5; x++) for (y = 0; y < 5; y++) st[x][y] = (B[x][y] ^ ((~B[(x + 1) % 5][y]) & M64 & B[(x + 2) % 5][y])) & M64;
      st[0][0] = st[0][0] ^ KRC[round];
    }
  }
  function keccak256(bytes) {
    var rate = 136;
    var padded = new Uint8Array((Math.floor(bytes.length / rate) + 1) * rate);
    padded.set(bytes);
    padded[bytes.length] = 0x01;
    padded[padded.length - 1] |= 0x80;
    var st = [[], [], [], [], []];
    for (var x = 0; x < 5; x++) for (var y = 0; y < 5; y++) st[x][y] = 0n;
    for (var off = 0; off < padded.length; off += rate) {
      for (var i = 0; i < rate / 8; i++) {
        var lane = 0n;
        for (var b = 7; b >= 0; b--) lane = (lane << 8n) | BigInt(padded[off + i * 8 + b]);
        st[i % 5][Math.floor(i / 5)] = st[i % 5][Math.floor(i / 5)] ^ lane;
      }
      keccakF(st);
    }
    var out = new Uint8Array(32);
    for (i = 0; i < 4; i++) {
      var l = st[i % 5][Math.floor(i / 5)];
      for (b = 0; b < 8; b++) { out[i * 8 + b] = Number(l & 0xffn); l >>= 8n; }
    }
    return out;
  }
  /* ---------- byte/bigint helpers ---------- */
  function utf8(s) { return new TextEncoder().encode(s); }
  function cat() { var n = 0, i; for (i = 0; i < arguments.length; i++) n += arguments[i].length; var o = new Uint8Array(n), p = 0; for (i = 0; i < arguments.length; i++) { o.set(arguments[i], p); p += arguments[i].length; } return o; }
  function toHex(u) { var s = ''; for (var i = 0; i < u.length; i++) s += (u[i] < 16 ? '0' : '') + u[i].toString(16); return s; }
  function hexToBytes(h) { h = String(h || '').replace(/^0x/i, ''); if (!/^[0-9a-fA-F]*$/.test(h) || h.length % 2) return null; var u = new Uint8Array(h.length / 2); for (var i = 0; i < u.length; i++) u[i] = parseInt(h.substr(i * 2, 2), 16); return u; }
  function bnToBytes(bn, len) { var out = new Uint8Array(len); for (var i = len - 1; i >= 0; i--) { out[i] = Number(bn & 0xffn); bn >>= 8n; } return out; }
  function bytesToBn(u) { var bn = 0n; for (var i = 0; i < u.length; i++) bn = (bn << 8n) | BigInt(u[i]); return bn; }
  /* ---------- secp256k1 ---------- */
  var P = 2n ** 256n - 2n ** 32n - 977n;
  var N = BigInt('0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141');
  var Gx = BigInt('0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798');
  var Gy = BigInt('0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8');
  function mod(a, m) { var r = a % m; return r >= 0n ? r : r + m; }
  function modinv(a, m) {
    a = mod(a, m);
    var g0 = m, g1 = a, u0 = 0n, u1 = 1n;
    while (g1 !== 0n) { var q = g0 / g1; var t = g0 - q * g1; g0 = g1; g1 = t; t = u0 - q * u1; u0 = u1; u1 = t; }
    return mod(u0, m);
  }
  // affine points as [x, y]; null = infinity
  function ptAdd(p1, p2) {
    if (!p1) return p2; if (!p2) return p1;
    if (p1[0] === p2[0]) {
      if (mod(p1[1] + p2[1], P) === 0n) return null;
      var s = mod(3n * p1[0] * p1[0] * modinv(2n * p1[1], P), P);
    } else {
      s = mod((p2[1] - p1[1]) * modinv(p2[0] - p1[0], P), P);
    }
    var x3 = mod(s * s - p1[0] - p2[0], P);
    var y3 = mod(s * (p1[0] - x3) - p1[1], P);
    return [x3, y3];
  }
  function ptMul(pt, k) {
    var r = null, a = pt;
    while (k > 0n) { if (k & 1n) r = ptAdd(r, a); a = ptAdd(a, a); k >>= 1n; }
    return r;
  }
  function genPriv() {
    var rnd = (window.nacl && nacl.randomBytes) ? nacl.randomBytes(32) : crypto.getRandomValues(new Uint8Array(32));
    var d = mod(bytesToBn(rnd), N - 1n) + 1n;
    return toHex(bnToBytes(d, 32));
  }
  function pubOf(privHex) { return ptMul([Gx, Gy], bytesToBn(hexToBytes(privHex))); }
  function addressOf(privHex) {
    var pt = pubOf(privHex);
    var raw = cat(bnToBytes(pt[0], 32), bnToBytes(pt[1], 32));
    return '0x' + toHex(keccak256(raw).slice(12));
  }
  /* RFC 6979 deterministic nonce */
  function rfc6979(privBytes, hash32) {
    var V = new Uint8Array(32).fill(1), K = new Uint8Array(32);
    K = hmac256(K, cat(V, new Uint8Array([0]), privBytes, hash32));
    V = hmac256(K, V);
    K = hmac256(K, cat(V, new Uint8Array([1]), privBytes, hash32));
    V = hmac256(K, V);
    for (var i = 0; i < 64; i++) {
      V = hmac256(K, V);
      var k = bytesToBn(V);
      if (k >= 1n && k < N) return k;
      K = hmac256(K, cat(V, new Uint8Array([0])));
      V = hmac256(K, V);
    }
    throw new Error('rfc6979');
  }
  /* ECDSA over a 32-byte hash → {r,s,v} eth style, low-s */
  function signHash(hash32, privHex) {
    var priv = hexToBytes(privHex);
    var d = bytesToBn(priv);
    var z = bytesToBn(hash32);
    for (var tries = 0; tries < 8; tries++) {
      var k = rfc6979(priv, hash32);
      var R = ptMul([Gx, Gy], k);
      var r = mod(R[0], N);
      if (r === 0n) { hash32 = sha256(hash32); continue; }
      var s = mod(modinv(k, N) * mod(z + r * d, N), N);
      if (s === 0n) { hash32 = sha256(hash32); continue; }
      var recId = Number(R[1] & 1n);
      if (R[0] >= N) recId += 2;
      if (s > N / 2n) { s = N - s; recId ^= 1; }
      return { r: r, s: s, v: 27 + recId };
    }
    throw new Error('sign');
  }
  /* EIP-191 personal sign over a 32-byte payload hash → 0x + 130 hex (r‖s‖v) */
  function personalSign(hash32, privHex) {
    var ethHash = keccak256(cat(utf8('\u0019Ethereum Signed Message:\n32'), hash32));
    var sig = signHash(ethHash, privHex);
    return '0x' + toHex(bnToBytes(sig.r, 32)) + toHex(bnToBytes(sig.s, 32)) + (sig.v === 27 ? '1b' : '1c');
  }
  /* r2r storage voucher: keccak256("r2r-voucher-v1" ‖ vault20 ‖ chainId u256 ‖ payout20 ‖ cumulative u256) */
  function voucherHash(vaultAddr, chainId, payoutAddr, cumulativeMicro) {
    var vault = hexToBytes(String(vaultAddr).replace(/^0x/i, ''));
    var payout = hexToBytes(String(payoutAddr).replace(/^0x/i, ''));
    if (!vault || vault.length !== 20 || !payout || payout.length !== 20) return null;
    return keccak256(cat(utf8('r2r-voucher-v1'), vault, bnToBytes(BigInt(chainId), 32), payout, bnToBytes(BigInt(cumulativeMicro), 32)));
  }
  /* ---------- minimal JSON-RPC reads ---------- */
  function ethCall(rpcUrl, to, dataHex) {
    return fetch(rpcUrl, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'eth_call', params: [{ to: to, data: dataHex }, 'latest'] })
    }).then(function (r) { return r.json(); }).then(function (j) { if (j.error) throw new Error(j.error.message || 'rpc'); return j.result; });
  }
  function selector(sigText) { return '0x' + toHex(keccak256(utf8(sigText)).slice(0, 4)); }
  function encAddr(a) { return String(a).replace(/^0x/i, '').toLowerCase().padStart(64, '0'); }
  function encB32(hex64) { return String(hex64).replace(/^0x/i, '').toLowerCase().padStart(64, '0'); }
  return {
    sha256: sha256, hmac256: hmac256, keccak256: keccak256,
    utf8: utf8, cat: cat, toHex: toHex, hexToBytes: hexToBytes,
    genPriv: genPriv, addressOf: addressOf, signHash: signHash, personalSign: personalSign,
    voucherHash: voucherHash,
    ethCall: ethCall, selector: selector, encAddr: encAddr, encB32: encB32
  };
})();
