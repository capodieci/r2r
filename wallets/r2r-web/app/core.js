/* R-2-Я core — standalone chat & calls engine, relay protocol v2 (r2r-relay network).
   Identity: ed25519 from a 32-byte seed; relay-side address = fingerprint
   sha256("r2r-id-v1" ‖ pub). Transport: WebSocket frames with {"t":...}; auth via a
   signed hello frame ("r2r-client-v1\n"+fp+"\n"+ts+"\n"+nonce); HTTP (blobs) via the
   X-R2R-Auth header. Messages: nacl.box, wire body = b64(senderPub32 ‖ nonce24 ‖ box).
   Vault: localStorage, secretbox under a PIN-derived key wrapping the seed.
   Storage market: see app/eth.js (secp256k1 + EIP-191 vouchers). */
window.R2R = (function () {
  'use strict';
  var sha3 = function (bytes) { return new Uint8Array(window.sha3_256.array(bytes)); };
  var E = function () { return window.R2RETH; };
  function utf8(s) { return new TextEncoder().encode(s); }
  function unutf8(u) { return new TextDecoder().decode(u); }
  function hexToBytes(h) { h = String(h || '').trim().toLowerCase().replace(/^0x/, ''); if (!/^[0-9a-f]*$/.test(h) || h.length % 2) return null; var u = new Uint8Array(h.length / 2); for (var i = 0; i < u.length; i++) u[i] = parseInt(h.substr(i * 2, 2), 16); return u; }
  function toHex(u) { var s = ''; for (var i = 0; i < u.length; i++) s += (u[i] < 16 ? '0' : '') + u[i].toString(16); return s; }
  function b64(u) { var s = ''; for (var i = 0; i < u.length; i++) s += String.fromCharCode(u[i]); return btoa(s); }
  function unb64(str) { var s = atob(str), u = new Uint8Array(s.length); for (var i = 0; i < s.length; i++) u[i] = s.charCodeAt(i); return u; }
  function cat() { var n = 0, i, a; for (i = 0; i < arguments.length; i++) n += arguments[i].length; var o = new Uint8Array(n), p = 0; for (i = 0; i < arguments.length; i++) { a = arguments[i]; o.set(a, p); p += a.length; } return o; }

  /* ---- ed25519 → curve25519 ---- */
  var ll = null;
  function gf(init) { var i, r = new Float64Array(16); if (init) for (i = 0; i < init.length; i++) r[i] = init[i]; return r; }
  var gf0 = gf(), gf1 = gf([1]);
  var D = gf([0x78a3, 0x1359, 0x4dca, 0x75eb, 0xd8ab, 0x4141, 0x0a4d, 0x0070, 0xe898, 0x7779, 0x4079, 0x8cc7, 0xfe73, 0x2b6f, 0x6cee, 0x5203]);
  var I = gf([0xa0b0, 0x4a0e, 0x1b27, 0xc4ee, 0xe478, 0xad2f, 0x1806, 0x2f43, 0xd7a7, 0x3dfb, 0x0099, 0x2b4d, 0xdf0b, 0x4fc1, 0x2480, 0x2b83]);
  function car25519(o) { var i, v, c = 1; for (i = 0; i < 16; i++) { v = o[i] + c + 65535; c = Math.floor(v / 65536); o[i] = v - c * 65536; } o[0] += c - 1 + 37 * (c - 1); }
  function sel25519(p, q, b) { var t, c = ~(b - 1); for (var i = 0; i < 16; i++) { t = c & (p[i] ^ q[i]); p[i] ^= t; q[i] ^= t; } }
  function pack25519(o, n) { var i, j, b, m = gf(), t = gf(); for (i = 0; i < 16; i++) t[i] = n[i]; car25519(t); car25519(t); car25519(t); for (j = 0; j < 2; j++) { m[0] = t[0] - 0xffed; for (i = 1; i < 15; i++) { m[i] = t[i] - 0xffff - ((m[i - 1] >> 16) & 1); m[i - 1] &= 0xffff; } m[15] = t[15] - 0x7fff - ((m[14] >> 16) & 1); b = (m[15] >> 16) & 1; m[14] &= 0xffff; sel25519(t, m, 1 - b); } for (i = 0; i < 16; i++) { o[2 * i] = t[i] & 0xff; o[2 * i + 1] = t[i] >> 8; } }
  function unpack25519(o, n) { for (var i = 0; i < 16; i++) o[i] = n[2 * i] + (n[2 * i + 1] << 8); o[15] &= 0x7fff; }
  function A2(o, a, b) { for (var i = 0; i < 16; i++) o[i] = a[i] + b[i]; }
  function Z2(o, a, b) { for (var i = 0; i < 16; i++) o[i] = a[i] - b[i]; }
  function M2(o, a, b) { var i, j, t = new Float64Array(31); for (i = 0; i < 31; i++) t[i] = 0; for (i = 0; i < 16; i++) for (j = 0; j < 16; j++) t[i + j] += a[i] * b[j]; for (i = 0; i < 15; i++) t[i] += 38 * t[i + 16]; for (i = 0; i < 16; i++) o[i] = t[i]; car25519(o); car25519(o); }
  function S2(o, a) { M2(o, a, a); }
  function inv25519(o, i) { var c = gf(), a; for (a = 0; a < 16; a++) c[a] = i[a]; for (a = 253; a >= 0; a--) { S2(c, c); if (a !== 2 && a !== 4) M2(c, c, i); } for (a = 0; a < 16; a++) o[a] = c[a]; }
  function pow2523(o, i) { var c = gf(), a; for (a = 0; a < 16; a++) c[a] = i[a]; for (a = 250; a >= 0; a--) { S2(c, c); if (a !== 1) M2(c, c, i); } for (a = 0; a < 16; a++) o[a] = c[a]; }
  function set25519(r, a) { for (var i = 0; i < 16; i++) r[i] = a[i] | 0; }
  function vn(x, xi, y, yi, n) { var i, d = 0; for (i = 0; i < n; i++) d |= x[xi + i] ^ y[yi + i]; return (1 & ((d - 1) >>> 8)) - 1; }
  function neq25519(a, b) { var c = new Uint8Array(32), d = new Uint8Array(32); pack25519(c, a); pack25519(d, b); return vn(c, 0, d, 0, 32); }
  function par25519(a) { var d = new Uint8Array(32); pack25519(d, a); return d[0] & 1; }
  function unpackneg(r, p) { var t = gf(), chk = gf(), num = gf(), den = gf(), den2 = gf(), den4 = gf(), den6 = gf(); set25519(r[2], gf1); unpack25519(r[1], p); S2(num, r[1]); M2(den, num, D); Z2(num, num, r[2]); A2(den, r[2], den); S2(den2, den); S2(den4, den2); M2(den6, den4, den2); M2(t, den6, num); M2(t, t, den); pow2523(t, t); M2(t, t, num); M2(t, t, den); M2(t, t, den); M2(r[0], t, den); S2(chk, r[0]); M2(chk, chk, den); if (neq25519(chk, num)) M2(r[0], r[0], I); S2(chk, r[0]); M2(chk, chk, den); if (neq25519(chk, num)) return -1; if (par25519(r[0]) === (p[31] >> 7)) Z2(r[0], gf0, r[0]); M2(r[3], r[0], r[1]); return 0; }
  function edPubToCurve(pk) { if (!pk || pk.length < 32) return null; var z = new Uint8Array(32), q = [gf(), gf(), gf(), gf()], a = gf(), b = gf(); if (unpackneg(q, pk)) return null; var y = q[1]; A2(a, gf1, y); Z2(b, gf1, y); inv25519(b, b); M2(a, a, b); pack25519(z, a); return z; }
  function edSeedToCurveSec(seed) { if (!ll) ll = nacl.lowlevel; var d = new Uint8Array(64), o = new Uint8Array(32), i; ll.crypto_hash(d, seed, 32); d[0] &= 248; d[31] &= 127; d[31] |= 64; for (i = 0; i < 32; i++) o[i] = d[i]; return o; }
  function curvePubOfSeed(seed) { if (!ll) ll = nacl.lowlevel; var sec = edSeedToCurveSec(seed); var pub = new Uint8Array(32); ll.crypto_scalarmult_base(pub, sec); return pub; }

  /* ---- address codec: R2R_ + base32(pub || 3-byte sha3 checksum) (unchanged; encodes the PUBKEY) ---- */
  var B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  function b32enc(bytes) { var bits = 0, val = 0, out = ''; for (var i = 0; i < bytes.length; i++) { val = (val << 8) | bytes[i]; bits += 8; while (bits >= 5) { out += B32[(val >>> (bits - 5)) & 31]; bits -= 5; } } if (bits > 0) out += B32[(val << (5 - bits)) & 31]; return out; }
  function b32dec(s) { var bits = 0, val = 0, out = []; for (var i = 0; i < s.length; i++) { var x = B32.indexOf(s[i]); if (x < 0) return null; val = (val << 5) | x; bits += 5; if (bits >= 8) { out.push((val >>> (bits - 8)) & 255); bits -= 8; } } return new Uint8Array(out); }
  function addrOf(pub) { var buf = cat(pub, utf8('R2R')); var ck = sha3(buf).slice(0, 3); var s = b32enc(cat(pub, ck)); var g = []; for (var i = 0; i < s.length; i += 8) g.push(s.substr(i, 8)); return 'R2R_' + g.join('_'); }
  function pubOfAddr(addr) {
    var s = String(addr || '').trim().toUpperCase().replace(/^R2R[_-]?/, '').replace(/[^A-Z2-7]/g, ''); var raw = b32dec(s); if (!raw || raw.length < 35) return null;
    var pub = raw.slice(0, 32), ck = raw.slice(32, 35);
    var want = sha3(cat(pub, utf8('R2R'))).slice(0, 3);
    return (ck[0] === want[0] && ck[1] === want[1] && ck[2] === want[2]) ? pub : null;
  }
  function shortAddr(a) { return a ? a.slice(0, 12) + '…' + a.slice(-8) : ''; }

  /* ---- fingerprint (the v2 relay-side account id) ---- */
  var _fpMemo = {};
  function fpOfPubBytes(pub) { return E().toHex(E().sha256(cat(utf8('r2r-id-v1'), pub))); }
  function fpOf(pubHex) { if (!_fpMemo[pubHex]) _fpMemo[pubHex] = fpOfPubBytes(hexToBytes(pubHex)); return _fpMemo[pubHex]; }
  var _fp2pub = {};   // reverse map, filled as contacts/identity appear
  function regFp(pubHex) { _fp2pub[fpOf(pubHex)] = pubHex; }
  function pubOfFp(fp) { return _fp2pub[fp] || null; }

  /* A private key is 32 random bytes, entered as 64 hex characters — nothing else. Hashing a
     typed phrase into a key (a "brain wallet") is refused: such keys are cracked in bulk from
     lists of likely phrases, however long they are, because nothing secret or salted is mixed in. */
  function seedFromInput(str) { str = String(str || '').trim().replace(/^0x/i, ''); if (!str) return null; var h = hexToBytes(str); return (h && h.length === 32) ? h : null; }

  /* ---- message envelope: b64( senderEdPub32 ‖ nonce24 ‖ box ) — the box authenticates the sender ---- */
  function encTo(plain, theirEdPub) { var tc = edPubToCurve(theirEdPub); if (!tc) throw new Error('bad recipient key'); var sec = edSeedToCurveSec(ID.seed); var nonce = nacl.randomBytes(24); var box = nacl.box(typeof plain === 'string' ? utf8(plain) : plain, nonce, tc, sec); return b64(cat(ID.kp.publicKey, nonce, box)); }
  function decEnvelope(bodyB64) {
    try {
      var raw = unb64(String(bodyB64 || '')); if (raw.length < 57) return null;
      var pub = raw.slice(0, 32);
      var tc = edPubToCurve(pub); if (!tc) return null;
      var open = nacl.box.open(raw.slice(56), raw.slice(32, 56), tc, edSeedToCurveSec(ID.seed));
      if (!open) return null;
      var obj; try { obj = JSON.parse(unutf8(open)); } catch (e) { return null; }
      var pubHex = toHex(pub); regFp(pubHex);
      return { from: pubHex, obj: obj };
    } catch (e) { return null; }
  }
  function encBytesTo(bytes, theirEdPub) { var tc = edPubToCurve(theirEdPub); var sec = edSeedToCurveSec(ID.seed); var nonce = nacl.randomBytes(24); return cat(nonce, nacl.box(bytes, nonce, tc, sec)); }
  function decBytesFrom(raw, theirEdPub) { try { var tc = edPubToCurve(theirEdPub); return nacl.box.open(raw.slice(24), raw.slice(0, 24), tc, edSeedToCurveSec(ID.seed)); } catch (e) { return null; } }

  /* ---- onion sealing: X25519 → HKDF-SHA256 → AES-256-GCM, byte-compatible with the relay's
     crypto::seal (layout 0x01 ‖ eph_pub32 ‖ nonce12 ‖ ct ‖ tag16; AAD 0x01 ‖ eph_pub ‖ recipient_pub).
     Pure JS on purpose: WebCrypto is missing on plain-http pages, which is exactly where a wallet
     talking to ws:// relays runs. ---- */
  var AES_SBOX = (function () {
    var s = new Uint8Array(256), p = 1, q = 1;
    do {
      p = p ^ ((p << 1) & 0xff) ^ (p & 0x80 ? 0x1b : 0);
      q ^= q << 1; q ^= q << 2; q ^= q << 4; q &= 0xff; if (q & 0x80) q ^= 0x09;
      var x = q ^ ((q << 1) | (q >> 7)) ^ ((q << 2) | (q >> 6)) ^ ((q << 3) | (q >> 5)) ^ ((q << 4) | (q >> 4));
      s[p] = (x ^ 0x63) & 0xff;
    } while (p !== 1);
    s[0] = 0x63; return s;
  })();
  function aesExpandKey256(key) {
    var w = new Uint8Array(240), rcon = 1, i, t = new Uint8Array(4);
    w.set(key);
    for (i = 32; i < 240; i += 4) {
      t[0] = w[i - 4]; t[1] = w[i - 3]; t[2] = w[i - 2]; t[3] = w[i - 1];
      if (i % 32 === 0) {
        var t0 = t[0]; t[0] = AES_SBOX[t[1]] ^ rcon; t[1] = AES_SBOX[t[2]]; t[2] = AES_SBOX[t[3]]; t[3] = AES_SBOX[t0];
        rcon = (rcon << 1) ^ (rcon & 0x80 ? 0x11b : 0);
      } else if (i % 32 === 16) { t[0] = AES_SBOX[t[0]]; t[1] = AES_SBOX[t[1]]; t[2] = AES_SBOX[t[2]]; t[3] = AES_SBOX[t[3]]; }
      w[i] = w[i - 32] ^ t[0]; w[i + 1] = w[i - 31] ^ t[1]; w[i + 2] = w[i - 30] ^ t[2]; w[i + 3] = w[i - 29] ^ t[3];
    }
    return w;
  }
  function xt(b) { return ((b << 1) ^ (b & 0x80 ? 0x1b : 0)) & 0xff; }
  function aesEncryptBlock(w, inp) {
    var s = new Uint8Array(16), r, c, i, a0, a1, a2, a3, t;
    for (i = 0; i < 16; i++) s[i] = inp[i] ^ w[i];
    for (r = 1; r <= 14; r++) {
      for (i = 0; i < 16; i++) s[i] = AES_SBOX[s[i]];
      t = s[1]; s[1] = s[5]; s[5] = s[9]; s[9] = s[13]; s[13] = t;
      t = s[2]; s[2] = s[10]; s[10] = t; t = s[6]; s[6] = s[14]; s[14] = t;
      t = s[15]; s[15] = s[11]; s[11] = s[7]; s[7] = s[3]; s[3] = t;
      if (r < 14) for (c = 0; c < 16; c += 4) {
        a0 = s[c]; a1 = s[c + 1]; a2 = s[c + 2]; a3 = s[c + 3]; t = a0 ^ a1 ^ a2 ^ a3;
        s[c] ^= t ^ xt(a0 ^ a1); s[c + 1] ^= t ^ xt(a1 ^ a2); s[c + 2] ^= t ^ xt(a2 ^ a3); s[c + 3] ^= t ^ xt(a3 ^ a0);
      }
      for (i = 0; i < 16; i++) s[i] ^= w[r * 16 + i];
    }
    return s;
  }
  function gfMul(x, y) {   // GCM multiply in GF(2^128); blocks as 4 big-endian uint32 words
    var z0 = 0, z1 = 0, z2 = 0, z3 = 0, v0 = y[0], v1 = y[1], v2 = y[2], v3 = y[3], i, lsb;
    for (i = 0; i < 128; i++) {
      if ((x[i >>> 5] >>> (31 - (i & 31))) & 1) { z0 ^= v0; z1 ^= v1; z2 ^= v2; z3 ^= v3; }
      lsb = v3 & 1;
      v3 = (v3 >>> 1) | (v2 << 31); v2 = (v2 >>> 1) | (v1 << 31); v1 = (v1 >>> 1) | (v0 << 31); v0 = v0 >>> 1;
      if (lsb) v0 ^= 0xe1000000;
    }
    return [z0 >>> 0, z1 >>> 0, z2 >>> 0, z3 >>> 0];
  }
  function words(b, o) { return [((b[o] << 24) | (b[o + 1] << 16) | (b[o + 2] << 8) | b[o + 3]) >>> 0, ((b[o + 4] << 24) | (b[o + 5] << 16) | (b[o + 6] << 8) | b[o + 7]) >>> 0, ((b[o + 8] << 24) | (b[o + 9] << 16) | (b[o + 10] << 8) | b[o + 11]) >>> 0, ((b[o + 12] << 24) | (b[o + 13] << 16) | (b[o + 14] << 8) | b[o + 15]) >>> 0]; }
  function aesGcmEncrypt(key, iv12, pt, aad) {
    var w = aesExpandKey256(key), H = words(aesEncryptBlock(w, new Uint8Array(16)), 0);
    var j0 = new Uint8Array(16); j0.set(iv12); j0[15] = 1;
    var ctr = j0.slice(), out = new Uint8Array(pt.length + 16), i, k, ks, n;
    for (i = 0; i < pt.length; i += 16) {
      for (k = 15; k >= 12; k--) { ctr[k] = (ctr[k] + 1) & 0xff; if (ctr[k]) break; }
      ks = aesEncryptBlock(w, ctr); n = Math.min(16, pt.length - i);
      for (k = 0; k < n; k++) out[i + k] = pt[i + k] ^ ks[k];
    }
    var y = [0, 0, 0, 0];
    function absorb(data, len) { for (var o = 0; o < len; o += 16) { var blk = new Uint8Array(16); blk.set(data.subarray(o, Math.min(o + 16, len))); var b = words(blk, 0); y = gfMul([y[0] ^ b[0], y[1] ^ b[1], y[2] ^ b[2], y[3] ^ b[3]], H); } }
    absorb(aad, aad.length); absorb(out, pt.length);
    var lens = new Uint8Array(16), ab = aad.length * 8, cb = pt.length * 8;
    lens[4] = (ab >>> 24) & 255; lens[5] = (ab >>> 16) & 255; lens[6] = (ab >>> 8) & 255; lens[7] = ab & 255;
    lens[12] = (cb >>> 24) & 255; lens[13] = (cb >>> 16) & 255; lens[14] = (cb >>> 8) & 255; lens[15] = cb & 255;
    absorb(lens, 16);
    var ek = aesEncryptBlock(w, j0);
    for (k = 0; k < 16; k++) out[pt.length + k] = ek[k] ^ ((y[k >> 2] >>> (24 - 8 * (k & 3))) & 255);
    return out;
  }
  function hkdf32(ikm, salt, info) {   // HKDF-SHA256, L = 32 (one expand block)
    var prk = E().hmac256(salt && salt.length ? salt : new Uint8Array(32), ikm);
    return E().hmac256(prk, cat(utf8(info), new Uint8Array([1])));
  }
  function onionSeal(recipientX, plain, ephOpt, nonceOpt) {
    if (!recipientX || recipientX.length !== 32) throw new Error('bad hop key');
    var eph = ephOpt || nacl.randomBytes(32);
    var ephPub = nacl.scalarMult.base(eph);
    var shared = nacl.scalarMult(eph, recipientX);
    var acc = 0; for (var i = 0; i < 32; i++) acc |= shared[i];
    if (!acc) throw new Error('small-order hop key');
    var key = hkdf32(shared, cat(ephPub, recipientX), 'r2r-seal-v1');
    var nonce = nonceOpt || nacl.randomBytes(12);
    var hdr = cat(new Uint8Array([1]), ephPub);
    return cat(hdr, nonce, aesGcmEncrypt(key, nonce, plain, cat(hdr, recipientX)));
  }
  /* v2 layer: the content is encrypted once under a fresh key K, and K is sealed (above) to each
     of 1–3 candidate relays — any of them can open it:
       0x02 ‖ n ‖ n × seal(candidate, K)[93] ‖ nonce12 ‖ AES-256-GCM(K, pt, aad = everything before nonce) */
  function onionSealMulti(keys, pt, kOpt, nonceOpt, slotEphs, slotNonces) {   // the *Opt arguments exist only for test vectors
    if (!keys.length || keys.length > 3) throw new Error('1..3 candidates per layer');
    var K = kOpt || nacl.randomBytes(32), parts = [new Uint8Array([2, keys.length])];
    for (var i = 0; i < keys.length; i++) parts.push(onionSeal(keys[i], K, slotEphs && slotEphs[i], slotNonces && slotNonces[i]));
    var head = cat.apply(null, parts), nonce = nonceOpt || nacl.randomBytes(12);
    return cat(head, nonce, aesGcmEncrypt(K, nonce, pt, head));
  }
  /* sets: [[{address, x25519:Uint8Array}] × 1..3] per route position, entry first; the last set
     holds the terminal candidates, the recipient's relay first. Plaintexts are binary, so each
     hop adds a fixed ~300 bytes instead of inflating everything by base64 again:
       routing  0x01 ‖ n ‖ n × (len8 ‖ "host:port") ‖ inner layer
       terminal 0x02 ‖ len16 ‖ JSON {to:"fp@home", id, hint?} ‖ body */
  function onionBuild(sets, to, id, body) {
    if (!sets.length || sets.length > 8) throw new Error('route length');
    var meta = utf8(JSON.stringify({ to: to, id: id }));
    var pt = cat(new Uint8Array([2, meta.length >> 8, meta.length & 255]), meta, body);
    var blob = null;
    for (var i = sets.length - 1; i >= 0; i--) {
      blob = onionSealMulti(sets[i].map(function (h) { return h.x25519; }), pt);
      if (i === 0) break;
      var hdr = [new Uint8Array([1, sets[i].length])];
      sets[i].forEach(function (h) { var a = utf8(h.address); if (!a.length || a.length > 255) throw new Error('address'); hdr.push(new Uint8Array([a.length]), a); });
      hdr.push(blob);
      pt = cat.apply(null, hdr);
    }
    return blob;
  }

  /* ---- PIN / passphrase KDF: scrypt, 64 MiB per guess ---- */
  /* scrypt (RFC 7914) in plain JS: memory-hard, so every guess at a PIN costs an attacker
     N×r×128 bytes of RAM and matching time — GPUs and ASICs lose most of their edge. */
  function pbkdf2Sha256(pw, salt, dkLen) {   // c = 1, which is all scrypt uses
    var out = new Uint8Array(dkLen), blocks = Math.ceil(dkLen / 32), ib = new Uint8Array(salt.length + 4);
    ib.set(salt);
    for (var i = 1; i <= blocks; i++) {
      ib[salt.length] = (i >>> 24) & 255; ib[salt.length + 1] = (i >>> 16) & 255; ib[salt.length + 2] = (i >>> 8) & 255; ib[salt.length + 3] = i & 255;
      var u = E().hmac256(pw, ib); out.set(u.subarray(0, Math.min(32, dkLen - (i - 1) * 32)), (i - 1) * 32);
    }
    return out;
  }
  function salsa8(B, x) {
    var i, j0 = B[0], j1 = B[1], j2 = B[2], j3 = B[3], j4 = B[4], j5 = B[5], j6 = B[6], j7 = B[7], j8 = B[8], j9 = B[9], j10 = B[10], j11 = B[11], j12 = B[12], j13 = B[13], j14 = B[14], j15 = B[15], u;
    for (i = 0; i < 8; i += 2) {
      u = j0 + j12; j4 ^= u << 7 | u >>> 25; u = j4 + j0; j8 ^= u << 9 | u >>> 23; u = j8 + j4; j12 ^= u << 13 | u >>> 19; u = j12 + j8; j0 ^= u << 18 | u >>> 14;
      u = j5 + j1; j9 ^= u << 7 | u >>> 25; u = j9 + j5; j13 ^= u << 9 | u >>> 23; u = j13 + j9; j1 ^= u << 13 | u >>> 19; u = j1 + j13; j5 ^= u << 18 | u >>> 14;
      u = j10 + j6; j14 ^= u << 7 | u >>> 25; u = j14 + j10; j2 ^= u << 9 | u >>> 23; u = j2 + j14; j6 ^= u << 13 | u >>> 19; u = j6 + j2; j10 ^= u << 18 | u >>> 14;
      u = j15 + j11; j3 ^= u << 7 | u >>> 25; u = j3 + j15; j7 ^= u << 9 | u >>> 23; u = j7 + j3; j11 ^= u << 13 | u >>> 19; u = j11 + j7; j15 ^= u << 18 | u >>> 14;
      u = j0 + j3; j1 ^= u << 7 | u >>> 25; u = j1 + j0; j2 ^= u << 9 | u >>> 23; u = j2 + j1; j3 ^= u << 13 | u >>> 19; u = j3 + j2; j0 ^= u << 18 | u >>> 14;
      u = j5 + j4; j6 ^= u << 7 | u >>> 25; u = j6 + j5; j7 ^= u << 9 | u >>> 23; u = j7 + j6; j4 ^= u << 13 | u >>> 19; u = j4 + j7; j5 ^= u << 18 | u >>> 14;
      u = j10 + j9; j11 ^= u << 7 | u >>> 25; u = j11 + j10; j8 ^= u << 9 | u >>> 23; u = j8 + j11; j9 ^= u << 13 | u >>> 19; u = j9 + j8; j10 ^= u << 18 | u >>> 14;
      u = j15 + j14; j12 ^= u << 7 | u >>> 25; u = j12 + j15; j13 ^= u << 9 | u >>> 23; u = j13 + j12; j14 ^= u << 13 | u >>> 19; u = j14 + j13; j15 ^= u << 18 | u >>> 14;
    }
    x[0] = j0; x[1] = j1; x[2] = j2; x[3] = j3; x[4] = j4; x[5] = j5; x[6] = j6; x[7] = j7; x[8] = j8; x[9] = j9; x[10] = j10; x[11] = j11; x[12] = j12; x[13] = j13; x[14] = j14; x[15] = j15;
    for (i = 0; i < 16; i++) B[i] = (B[i] + x[i]) | 0;
  }
  function blockMix(B, Y, r, X, t) {   // B: 32r words in/out
    var i, k, n = 2 * r;
    X.set(B.subarray((n - 1) * 16, n * 16));
    for (i = 0; i < n; i++) {
      for (k = 0; k < 16; k++) X[k] ^= B[i * 16 + k];
      salsa8(X, t);
      Y.set(X, (i & 1 ? r + (i >> 1) : (i >> 1)) * 16);
    }
    B.set(Y);
  }
  function scrypt(pw, salt, N, r, p, dkLen) {
    if (N < 2 || (N & (N - 1))) throw new Error('scrypt N');
    var blen = 128 * r, Bb = pbkdf2Sha256(pw, salt, p * blen), w = 32 * r;
    var V = new Int32Array(w * N), X = new Int32Array(w), Y = new Int32Array(w), T = new Int32Array(16), U = new Int32Array(16), i, j, k, q, o;
    for (q = 0; q < p; q++) {
      o = q * blen;
      for (k = 0; k < w; k++) X[k] = Bb[o + 4 * k] | (Bb[o + 4 * k + 1] << 8) | (Bb[o + 4 * k + 2] << 16) | (Bb[o + 4 * k + 3] << 24);
      for (i = 0; i < N; i++) { V.set(X, i * w); blockMix(X, Y, r, T, U); }
      for (i = 0; i < N; i++) {
        j = X[(2 * r - 1) * 16] & (N - 1);
        for (k = 0; k < w; k++) X[k] ^= V[j * w + k];
        blockMix(X, Y, r, T, U);
      }
      for (k = 0; k < w; k++) { Bb[o + 4 * k] = X[k] & 255; Bb[o + 4 * k + 1] = (X[k] >>> 8) & 255; Bb[o + 4 * k + 2] = (X[k] >>> 16) & 255; Bb[o + 4 * k + 3] = (X[k] >>> 24) & 255; }
    }
    V = null;
    return pbkdf2Sha256(pw, Bb, dkLen);
  }

  var KDF = { alg: 'scrypt', N: 65536, r: 8, p: 1 };
  function legacyKdf(pin, salt) { var k = sha3(cat(salt, utf8(String(pin)))); for (var i = 0; i < 60000; i++) k = sha3(cat(k, salt)); return k; }
  function kdfOk(prm) { return prm && prm.alg === 'scrypt' && prm.N >= 16384 && prm.N <= 1048576 && !(prm.N & (prm.N - 1)) && prm.r >= 1 && prm.r <= 16 && prm.p >= 1 && prm.p <= 4; }
  /* Derive with the parameters a record was written with; records without any are the old
     SHA3 chain and get rewrapped with scrypt on the next successful unlock. */
  function kdfWith(pin, salt, prm) {
    if (!prm) return legacyKdf(pin, salt);
    if (!kdfOk(prm)) throw new Error('unsupported key-derivation parameters');
    return scrypt(utf8(String(pin)), salt, prm.N, prm.r, prm.p, 32);
  }
  function kdf(pin, salt) { return kdfWith(pin, salt, KDF); }
  /* PIN or passphrase policy, enforced on every path that sets one. Estimates what an offline
     attacker with a fast GPU faces at roughly 10 000 scrypt guesses per second. */
  function pinCheck(p) {
    p = String(p || '');
    if (p.length < 8) return { ok: false, lvl: 0, bits: 0, label: 'Too short — at least 8 characters' };
    if (/^(.)\1+$/.test(p)) return { ok: false, lvl: 0, bits: 0, label: 'One repeated character is guessed instantly' };
    if (/^\d+$/.test(p) && p.length < 12) return { ok: false, lvl: 1, bits: 0, label: 'Digits only need 12 or more — or use letters, or a passphrase' };
    var sets = 0; if (/[a-z]/.test(p)) sets += 26; if (/[A-Z]/.test(p)) sets += 26; if (/[0-9]/.test(p)) sets += 10; if (/[^A-Za-z0-9]/.test(p)) sets += 33;
    var bits = p.length * Math.log(sets || 1) / Math.LN2;
    var words = p.trim().split(/\s+/).filter(function (w) { return w.length >= 2; });
    // Be conservative: crackers try dictionary words with swaps (Tr0ub4dor) long before random
    // strings, so a single "word" counts ~4.5 bits per character, and a phrase ~11 bits per word
    // (as if drawn from 2000 common words).
    if (words.length >= 3) bits = Math.min(bits, words.length * 11 + 6);
    else bits = Math.min(bits, p.length * 4.5);
    var secs = Math.pow(2, bits - 1) / 10000, years = secs / 3.15e7;
    var t = secs < 3600 ? 'minutes' : secs < 86400 * 2 ? 'hours' : secs < 86400 * 60 ? Math.round(secs / 86400) + ' days' : years < 2 ? Math.round(secs / 2.6e6) + ' months' : years < 1e5 ? Math.round(years).toLocaleString() + ' years' : 'far longer than a lifetime';
    var lvl = years < 10 ? 1 : years < 10000 ? 2 : 3;
    var label = (lvl === 1 ? 'Weak' : lvl === 2 ? 'Decent' : 'Strong') + ' — a thief with a fast GPU needs ~' + t + ' to guess it' + (lvl < 3 ? '. A passphrase of 4–5 random words is far stronger' : '');
    return { ok: true, lvl: lvl, bits: Math.round(bits), label: label };
  }
  function sbox(objOrStr, key) { var nonce = nacl.randomBytes(24); var msg = typeof objOrStr === 'string' ? utf8(objOrStr) : utf8(JSON.stringify(objOrStr)); return b64(cat(nonce, nacl.secretbox(msg, nonce, key))); }
  function unsbox(s, key) { try { var raw = unb64(s); var open = nacl.secretbox.open(raw.slice(24), raw.slice(0, 24), key); return open ? unutf8(open) : null; } catch (e) { return null; } }

  /* ---- events ---- */
  var LIS = {};
  function on(ev, fn) { (LIS[ev] = LIS[ev] || []).push(fn); }
  function emit(ev, a, b) { (LIS[ev] || []).forEach(function (f) { try { f(a, b); } catch (e) { } }); }
  var _updT = null;
  function poke() { if (_updT) return; _updT = setTimeout(function () { _updT = null; emit('update'); }, 30); }
  function toast(msg, kind) { emit('toast', { msg: msg, kind: kind || '' }); }

  /* ---- identity + store ---- */
  var ID = null;    // {seed, kp, pubHex, fp, addr}
  var ST = null;
  var storeKeyB = null;
  function defaultStore() { return { name: '', contacts: [], threads: {}, callLog: [], relays: [], outbox: [], groups: {}, relayMeta: {}, myInvites: [], market: { rpc: '', rentals: [] }, onion: true, v: 2 }; }
  function storeLsKey() { return 'r2r1_data_' + ID.pubHex.slice(0, 16); }
  var _saveT = null;
  function save() { if (!ST || !ID) return; if (_saveT) return; _saveT = setTimeout(function () { _saveT = null; try { localStorage.setItem(storeLsKey(), sbox(ST, storeKeyB)); } catch (e) { toast('Could not save — storage full?', 'err'); } }, 350); }
  function hasVault() { try { return !!localStorage.getItem('r2r1_wrap'); } catch (e) { return false; } }
  function makeIdentity(seed) { var kp = nacl.sign.keyPair.fromSeed(seed); var pubHex = toHex(kp.publicKey); var id = { seed: seed, kp: kp, pubHex: pubHex, fp: fpOfPubBytes(kp.publicKey), addr: addrOf(kp.publicKey) }; _fp2pub[id.fp] = pubHex; return id; }
  function openStore() {
    storeKeyB = sha3(cat(ID.seed, utf8('r2r-store')));
    var raw = null; try { raw = localStorage.getItem(storeLsKey()); } catch (e) { }
    var j = raw ? unsbox(raw, storeKeyB) : null;
    ST = j ? JSON.parse(j) : defaultStore();
    ST.relayMeta = ST.relayMeta || {}; ST.market = ST.market || { rpc: '', rentals: [] }; ST.myInvites = ST.myInvites || [];
    (ST.contacts || []).forEach(function (c) { try { regFp(c.pub); } catch (e) { } });
  }
  function createVault(keyInput, pin, relayUrl) {
    var seed = seedFromInput(keyInput); if (!seed) return { err: 'Enter the private key: 64 hex characters (or generate a new one)' };
    var pc = pinCheck(pin); if (!pc.ok) return { err: pc.label };
    var salt = nacl.randomBytes(16);
    var wrap = sbox(toHex(seed), kdf(pin, salt));
    try { localStorage.setItem('r2r1_wrap', JSON.stringify({ salt: toHex(salt), kdf: KDF, wrap: wrap })); } catch (e) { return { err: 'localStorage unavailable' }; }
    ID = makeIdentity(seed); openStore();
    if (relayUrl && !ST.relays.length) { var rl = String(relayUrl).split(/[\n,\s]+/).map(function (x) { return x.trim(); }).filter(Boolean); if (rl.length) ST.relays = rl; }
    save(); afterUnlock(); return { ok: true };
  }
  function unlock(pin) {
    var w; try { w = JSON.parse(localStorage.getItem('r2r1_wrap') || 'null'); } catch (e) { }
    if (!w) return { err: 'No vault on this device' };
    var pep = new Uint8Array(0);
    if (w.pep) { try { pep = hexToBytes(localStorage.getItem('r2r1_pepper') || '') || new Uint8Array(0); } catch (e) { } }
    var hex; try { hex = unsbox(w.wrap, kdfWith(pin, cat(hexToBytes(w.salt), pep), w.kdf)); } catch (e) { return { err: e.message }; }
    if (!hex) return { err: 'Wrong PIN' };
    if (!w.kdf) {   // upgrade an old SHA3-chain vault to scrypt now that we hold the PIN
      try { var ns = nacl.randomBytes(16); w.wrap = sbox(hex, kdf(pin, cat(ns, pep))); w.salt = toHex(ns); w.kdf = KDF; localStorage.setItem('r2r1_wrap', JSON.stringify(w)); } catch (e) { }
    }
    ID = makeIdentity(hexToBytes(hex)); openStore(); afterUnlock(); return { ok: true };
  }
  function lock() { flushSave(); teardownWs(); ID = null; ST = null; storeKeyB = null; poke(); }
  function forget() { try { localStorage.removeItem('r2r1_wrap'); localStorage.removeItem('r2r1_pepper'); } catch (e) { } lock(); }
  function flushSave() { if (_saveT) { clearTimeout(_saveT); _saveT = null; } if (ST && ID) try { localStorage.setItem(storeLsKey(), sbox(ST, storeKeyB)); } catch (e) { } }
  window.addEventListener('beforeunload', flushSave);
  function afterUnlock() { poke(); connect(); setInterval2(); setTimeout(runRentalCycle, 4000); }

  /* ---- contacts (keyed locally by ed25519 pubHex; the fp is derived per pub) ---- */
  function findC(pubHex) { for (var i = 0; i < ST.contacts.length; i++) if (ST.contacts[i].pub === pubHex) return ST.contacts[i]; return null; }
  function parseContactInput(input) {
    var s = String(input || '').trim();
    var relay = null;
    var m = s.match(/^r2r:([^?]+)(\?.*)?$/i);
    if (m) { s = m[1]; if (m[2]) { var r = /[?&]relay=([^&]+)/.exec(m[2]); if (r) relay = decodeURIComponent(r[1]); } }
    var pub = pubOfAddr(s);
    if (!pub) { var h = hexToBytes(s); if (h && h.length === 32) pub = h; }
    return pub ? { pub: pub, relay: relay } : null;
  }
  function addContact(input, name) {
    var p = parseContactInput(input); if (!p) return { err: 'Not a valid address' };
    var pubHex = toHex(p.pub);
    if (pubHex === ID.pubHex) return { err: 'That is your own address' };
    var c = findC(pubHex);
    if (!c) { c = { pub: pubHex, addr: addrOf(p.pub), name: name || '', added: Date.now() }; ST.contacts.push(c); }
    else if (name) c.name = name;
    if (p.relay) { c.relay = normRelay(p.relay); if (!ST.relays.length) ST.relays = [c.relay]; }
    regFp(pubHex);
    jrec({ k: 'contact', c: { pub: c.pub, addr: c.addr, name: c.name || '', relay: c.relay || '' } });
    save(); watchAll(); poke(); return { ok: true, pub: pubHex, relay: p.relay };
  }
  function removeContact(pubHex) { ST.contacts = ST.contacts.filter(function (c) { return c.pub !== pubHex; }); delete ST.threads[pubHex]; jrec({ k: 'delcontact', pub: pubHex }); save(); poke(); }
  function renameContact(pubHex, name) { var c = findC(pubHex); if (c) { c.name = name; jrec({ k: 'rename', pub: pubHex, name: name }); save(); poke(); } }
  function nameOf(pubHex) { if (isGKey(pubHex)) { var g = groupOf(String(pubHex).slice(2)); return g ? g.name : 'Group'; } var c = findC(pubHex); if (c && c.name) return c.name; return shortAddr(addrOf(hexToBytes(pubHex))); }
  function ensureContact(pubHex) { if (!findC(pubHex)) { ST.contacts.push({ pub: pubHex, addr: addrOf(hexToBytes(pubHex)), name: '', added: Date.now() }); regFp(pubHex); save(); watchAll(); } }

  /* ---- threads ---- */
  function thread(pubHex) { return ST.threads[pubHex] = ST.threads[pubHex] || []; }
  function pushMsg(pubHex, m) { thread(pubHex).push(m); var t = thread(pubHex); if (t.length > 3000) ST.threads[pubHex] = t.slice(-2500); save(); poke(); if (ST.vouchReqs && ST.vouchReqs[pubHex]) tryVouch(pubHex); }
  function markRead(pubHex) { var t = ST.threads[pubHex]; if (!t) return; var ch = false; t.forEach(function (m) { if (m.dir === 'in' && !m.read) { m.read = true; ch = true; } }); if (ch) { save(); poke(); } }
  function unreadOf(pubHex) { var t = ST.threads[pubHex] || [], n = 0; t.forEach(function (m) { if (m.dir === 'in' && !m.read) n++; }); return n; }

  /* ---- groups: pure client-side fan-out; the relay never learns the group exists ---- */
  var GROUP_MAX = 8, GCALL_MAX = 4;
  function isGKey(k) { return String(k || '').slice(0, 2) === 'g:'; }
  function gkey(gid) { return 'g:' + gid; }
  function validGid(gid) { return /^[0-9a-f][0-9a-f-]{7,40}$/i.test(String(gid || '')); }
  function groupsAll() { return (ST && ST.groups) || {}; }
  function groupOf(gid) { return (ST && ST.groups && ST.groups[gid]) || null; }
  function groupPeers(g) { return (g && g.members || []).filter(function (p) { return p !== ID.pubHex; }); }
  function gSlim(g) { return { gid: g.gid, name: g.name, creator: g.creator, members: g.members }; }
  function validMembers(list) { var out = []; (list || []).forEach(function (p) { p = String(p || '').toLowerCase(); if (/^[0-9a-f]{64}$/.test(p) && out.indexOf(p) < 0) out.push(p); }); return out.slice(0, GROUP_MAX); }
  function createGroup(name, memberPubs) {
    name = String(name || '').trim(); if (!name) return { err: 'Give the group a name' };
    var mem = validMembers(memberPubs).filter(function (p) { return p !== ID.pubHex; });
    if (!mem.length) return { err: 'Pick at least one member' };
    if (mem.length > GROUP_MAX - 1) return { err: 'Max ' + GROUP_MAX + ' people per group (you + ' + (GROUP_MAX - 1) + ')' };
    var g = { gid: newId(), name: name, creator: ID.pubHex, members: [ID.pubHex].concat(mem), created: Date.now() };
    ST.groups = ST.groups || {}; ST.groups[g.gid] = g;
    jrec({ k: 'group', g: gSlim(g) }); save(); poke();
    gSendInfo(g);
    return { ok: true, gid: g.gid };
  }
  function updateGroup(gid, name, memberPubs) {
    var g = groupOf(gid); if (!g) return { err: 'No such group' };
    if (g.creator !== ID.pubHex) return { err: 'Only the group creator can change it' };
    if (name && String(name).trim()) g.name = String(name).trim().slice(0, 80);
    if (memberPubs) {
      var mem = validMembers(memberPubs).filter(function (p) { return p !== ID.pubHex; });
      if (!mem.length) return { err: 'A group needs at least one other member' };
      g.members = [ID.pubHex].concat(mem);
    }
    jrec({ k: 'group', g: gSlim(g) }); save(); poke();
    gSendInfo(g);
    return { ok: true };
  }
  function deleteGroup(gid) { if (!ST || !ST.groups) return; delete ST.groups[gid]; delete ST.threads[gkey(gid)]; jrec({ k: 'gdel', gid: gid }); save(); poke(); }
  function gSendInfo(g) { groupPeers(g).forEach(function (p) { queueSend(p, newId(), { t: 'ginfo', gid: g.gid, g: gSlim(g) }); }); }
  function gFanout(g, msgId, obj) { groupPeers(g).forEach(function (p) { queueSend(p, newId(), obj, msgId); }); }
  function sendGText(gid, text) {
    var g = groupOf(gid); if (!g) return;
    text = String(text || '').trim(); if (!text) return;
    var id = newId(); var m = { id: id, dir: 'out', kind: 'text', body: text, ts: Date.now(), status: 'pending' };
    pushMsg(gkey(gid), m); jrecMsg(gkey(gid), m);
    gFanout(g, id, { t: 'gtext', gid: gid, g: gSlim(g), body: text });
  }
  function sendGFile(gid, file, extra) {
    var g = groupOf(gid); if (!g || !file) return;
    if (file.size > BLOB_MAX) { toast('File too large (max 16 MB)', 'err'); return; }
    var id = newId();
    var m = { id: id, dir: 'out', kind: 'file', name: file.name, size: file.size, mime: file.type || 'application/octet-stream', ts: Date.now(), status: 'uploading' };
    if (extra && extra.vm) { m.vm = extra.vm; m.dur = extra.dur | 0; }
    pushMsg(gkey(gid), m);
    file.arrayBuffer().then(function (ab) {
      var bytes = new Uint8Array(ab);
      var kB = nacl.randomBytes(32);
      var nonce = nacl.randomBytes(24);
      var cipher = cat(nonce, nacl.secretbox(bytes, nonce, kB));
      if (bytes.length <= KEEP_LOCAL_MAX) m.dataB64 = b64(bytes);
      m.key = toHex(kB);
      var base = { t: 'gfile', gid: gid, g: gSlim(g), name: m.name, size: m.size, mime: m.mime, vm: m.vm, dur: m.dur, key: m.key };
      if (cipher.length <= INLINE_MAX) {
        m.status = 'pending'; save(); poke(); jrecMsg(gkey(gid), m);
        base.inline = b64(cipher); gFanout(g, id, base);
      } else {
        var u = myPrimary();
        if (!connReady(u)) { m.status = 'failed'; save(); poke(); toast('Your relay is unreachable \u2014 large files need it', 'err'); return; }
        blobUpload(u, cipher)
          .then(function (j) { m.blob = j.id; m.blobRelay = u; m.status = 'pending'; save(); poke(); jrecMsg(gkey(gid), m); base.blob = j.id; base.blobRelay = u; gFanout(g, id, base); })
          .catch(function () { m.status = 'failed'; save(); poke(); toast('Attachment upload failed', 'err'); });
      }
    });
  }
  function handleGroupMsg(from, mid, mts, obj) {
    var gin = obj.g || {}; var gid = String(obj.gid || gin.gid || '');
    if (!validGid(gid)) return;
    if (validMembers(gin.members).indexOf(from) < 0) return;
    ST.groups = ST.groups || {};
    var g = ST.groups[gid];
    if (!g) {
      g = ST.groups[gid] = { gid: gid, name: String(gin.name || 'Group').slice(0, 80), creator: String(gin.creator || from).toLowerCase(), members: validMembers(gin.members), created: Date.now() };
      jrec({ k: 'group', g: gSlim(g) }); save(); poke();
    } else if (from === g.creator && gin.members) {
      var slim = JSON.stringify(gSlim(g));
      g.name = String(gin.name || g.name).slice(0, 80); g.members = validMembers(gin.members);
      if (JSON.stringify(gSlim(g)) !== slim) { jrec({ k: 'group', g: gSlim(g) }); save(); poke(); }
    }
    ensureContact(from);
    if (obj.t === 'ginfo') { poke(); return; }
    var gt = ST.threads[gkey(gid)] || [];
    for (var i = gt.length - 1; i >= 0 && i > gt.length - 60; i--) if (gt[i].id === mid) return;
    var rec = { id: mid, dir: 'in', sender: from, ts: mts || Date.now(), read: false };
    if (obj.t === 'gtext') { rec.kind = 'text'; rec.body = String(obj.body || ''); }
    else {
      rec.kind = 'file'; rec.name = String(obj.name || 'file'); rec.size = obj.size | 0; rec.mime = String(obj.mime || 'application/octet-stream');
      if (obj.vm === 'a' || obj.vm === 'v') { rec.vm = obj.vm; rec.dur = obj.dur | 0; }
      rec.key = String(obj.key || '');
      if (obj.inline) rec.inline = obj.inline; else { rec.blob = String(obj.blob || ''); if (obj.blobRelay) rec.blobRelay = String(obj.blobRelay); }
    }
    pushMsg(gkey(gid), rec);
    emit('message', { from: gkey(gid), msg: rec });
    dackQueue(from, mid);
    if (rec.kind === 'file' && (rec.inline || rec.blob)) fetchAttachment(gkey(gid), rec.id).then(function () { jrecMsg(gkey(gid), rec); }).catch(function () { jrecMsg(gkey(gid), rec); });
    else jrecMsg(gkey(gid), rec);
  }

  /* ================= relay connections (v2: hello/welcome frames) ================= */
  var CONNS = {};       // url -> conn
  var WIRE2MSG = {};
  var PRES = {};        // pubHex -> {state, seen, t, via}
  var RELAYINFO = { reachable: false, url: '', stats: null, usage: null, owner: false, nodeId: '', pickup: null, proto: 2 };
  function normRelay(u) {
    u = String(u || '').trim().replace(/\/+$/, ''); if (!u) return null;
    if (!/^[a-z]+:\/\//i.test(u)) u = 'ws://' + u;
    u = u.replace(/^http:/i, 'ws:').replace(/^https:/i, 'wss:');
    return u;
  }
  function httpBase(u) { return normRelay(u).replace(/^ws:/i, 'http:').replace(/^wss:/i, 'https:'); }
  function mixedBlocked(u) { try { return location.protocol === 'https:' && /^(ws|http):\/\//i.test(normRelay(u) || ''); } catch (e) { return false; } }
  function mixedErr() { return 'This page runs on https, so the browser blocks plain ws:// relays (mixed content). Open the wallet over http:// or as a local file, or give the relay TLS and use wss://.'; }
  function relays() { return (ST && ST.relays || []).slice(); }
  function setRelays(list) { ST.relays = list.map(function (u) { return String(u).trim(); }).filter(Boolean); save(); teardownWs(); connectAll(); poke(); }
  function myPrimary() { return (ST && ST.relays && ST.relays[0]) ? normRelay(ST.relays[0]) : null; }
  function relayOfContact(c) { return (c && c.relay) ? normRelay(c.relay) : myPrimary(); }
  function relayOfPub(pubHex) { return relayOfContact(findC(pubHex)); }
  function connReady(u) { return !!(u && CONNS[u] && CONNS[u].open); }
  function metaOf(u) { return (ST && ST.relayMeta && ST.relayMeta[normRelay(u)]) || {}; }
  function advertiseOf(u) { return metaOf(u).advertise || String(normRelay(u) || '').replace(/^wss?:\/\//i, '').replace(/\/.*$/, ''); }
  function wantedRelays() {
    var set = {};
    if (!ST) return set;
    (ST.relays || []).forEach(function (u) { u = normRelay(u); if (u) set[u] = 1; });
    ST.contacts.forEach(function (c) { if (c.relay) { var u = normRelay(c.relay); if (u) set[u] = 1; } });
    return set;
  }
  /* hello proof fields for any ed25519 keypair */
  function helloFields(kp) {
    var fp = fpOfPubBytes(kp.publicKey);
    var ts = Math.floor(Date.now() / 1000);
    var nonce = toHex(nacl.randomBytes(12));
    var sig = b64(nacl.sign.detached(utf8('r2r-client-v1\n' + fp + '\n' + ts + '\n' + nonce), kp.secretKey));
    return { id: fp, pubkey: b64(kp.publicKey), ts: ts, nonce: nonce, sig: sig };
  }
  function authHeaderFor(kp) { return { 'X-R2R-Auth': btoa(JSON.stringify(helloFields(kp))) }; }
  function authHeader() { return authHeaderFor(ID.kp); }
  function closeConn(u) { var c = CONNS[u]; if (!c) return; delete CONNS[u]; try { if (c.timer) clearTimeout(c.timer); } catch (e) { } try { if (c.hb) clearInterval(c.hb); } catch (e) { } try { (c.pend || []).forEach(function (p) { try { p.reject(new Error('closed')); } catch (e2) { } }); } catch (e) { } try { if (c.ws) { c.ws.onclose = null; c.ws.close(); } } catch (e) { } }
  function teardownWs() { Object.keys(CONNS).forEach(closeConn); PRES = {}; RELAYINFO.reachable = false; RELAYINFO.stats = null; RELAYINFO.owner = false; }
  function updReach() { var p = myPrimary(); RELAYINFO.url = p || ''; RELAYINFO.reachable = p ? connReady(p) : Object.keys(CONNS).some(function (u) { return CONNS[u].open; }); }
  function connectAll() {
    if (!ID || !ST) { return; }
    var want = wantedRelays();
    Object.keys(CONNS).forEach(function (u) { if (!want[u]) closeConn(u); });
    Object.keys(want).forEach(function (u) { ensureConn(u); });
    updReach(); poke();
  }
  function connect() { connectAll(); }
  function ensureConn(u) {
    var c = CONNS[u];
    if (c && c.ws && c.ws.readyState <= 1) return c;
    c = CONNS[u] = { url: u, ws: null, open: false, retryN: (c ? c.retryN : 0), timer: null, hb: null, pend: [], ackQ: [], ackT: null };
    var ws;
    try { ws = new WebSocket(u + '/ws'); } catch (e) { schedRetry(u); return c; }
    c.ws = ws;
    ws.onopen = function () {
      var h = helloFields(ID.kp); h.t = 'hello';
      try { h.x25519 = b64(curvePubOfSeed(ID.seed)); } catch (e) { }
      try { ws.send(JSON.stringify(h)); } catch (e) { }
    };
    ws.onmessage = function (ev) { try { handleWs(JSON.parse(ev.data), u); } catch (e) { } };
    ws.onclose = function () { c.open = false; updReach(); Object.keys(PRES).forEach(function (p) { if (PRES[p].via === u) delete PRES[p]; }); poke(); schedRetry(u); };
    ws.onerror = function () { };
    c.hb = setInterval(function () { sendOn(u, { t: 'ping' }); }, 25000);
    return c;
  }
  function schedRetry(u) { if (!ID) return; var c = CONNS[u]; if (!c) return; c.retryN++; var d = Math.min(30000, 1000 * Math.pow(1.7, c.retryN)); if (c.timer) clearTimeout(c.timer); c.timer = setTimeout(function () { if (CONNS[u] === c && wantedRelays()[u]) { delete CONNS[u]; var n = ensureConn(u); n.retryN = c.retryN; } }, d); }
  function sendOn(u, obj) { try { var c = CONNS[u]; if (c && c.ws && c.ws.readyState === 1) { c.ws.send(JSON.stringify(obj)); return true; } } catch (e) { } return false; }
  /* frame request/response over a live connection: resolves on the first frame whose t matches */
  function req(u, frame, types, timeoutMs) {
    return new Promise(function (resolve, reject) {
      var c = CONNS[u];
      if (!c || !c.ws || c.ws.readyState !== 1) { reject(new Error('relay not connected')); return; }
      var p = { types: types, resolve: resolve, reject: reject };
      p.tm = setTimeout(function () { var ix = c.pend.indexOf(p); if (ix >= 0) c.pend.splice(ix, 1); reject(new Error('timeout')); }, timeoutMs || 15000);
      c.pend.push(p);
      try { c.ws.send(JSON.stringify(frame)); } catch (e) { clearTimeout(p.tm); var ix = c.pend.indexOf(p); if (ix >= 0) c.pend.splice(ix, 1); reject(e); }
    });
  }
  function settlePend(c, m) {
    for (var i = 0; i < c.pend.length; i++) {
      if (c.pend[i].types.indexOf(m.t) >= 0) { var p = c.pend.splice(i, 1)[0]; clearTimeout(p.tm); p.resolve(m); return true; }
    }
    if (m.t === 'err' && c.pend.length) { var p2 = c.pend.shift(); clearTimeout(p2.tm); p2.reject(new Error(m.code === 'quota' ? 'quota' : (m.msg || m.code || 'relay error'))); return true; }
    return false;
  }
  function ackQueue(u, id) {
    var c = CONNS[u]; if (!c) return;
    c.ackQ.push(id);
    if (c.ackT) return;
    c.ackT = setTimeout(function () { c.ackT = null; var ids = c.ackQ.splice(0, 200); if (ids.length) sendOn(u, { t: 'ack', ids: ids }); }, 250);
  }
  function watchOn(u) { if (!ST) return; var ids = ST.contacts.map(function (c) { return fpOf(c.pub); }); if (ids.length) sendOn(u, { t: 'watch', ids: ids }); }
  function watchAll() { connectAll(); Object.keys(CONNS).forEach(function (u) { if (CONNS[u].open) watchOn(u); }); }
  function presenceOn(u) { sendOn(u, { t: 'presence', state: document.hidden ? 'away' : 'online' }); }
  function sendPresence() { Object.keys(CONNS).forEach(function (u) { if (CONNS[u].open) presenceOn(u); }); }
  document.addEventListener('visibilitychange', function () { if (ID) sendPresence(); });
  function presenceOf(pubHex) { var p = PRES[pubHex]; if (!p) { return { state: connReady(relayOfPub(pubHex)) ? 'offline' : 'unknown' }; } if (Date.now() - p.t > 180000) return { state: 'offline', seen: p.seen }; return p; }
  function learnRelay(pubHex, rr, ra) {
    var c = findC(pubHex); if (!c) return;
    var changed = false;
    if (rr) { var u = normRelay(String(rr)); if (u && normRelay(c.relay || '') !== u) { c.relay = u; changed = true; if (!ST.relays.length) ST.relays = [u]; } }
    if (ra && c.relayAddr !== String(ra)) { c.relayAddr = String(ra); changed = true; }
    if (changed) { save(); connectAll(); watchAll(); }
  }
  function fetchNodeMeta(u) {
    u = normRelay(u);
    fetch(httpBase(u) + '/node.json').then(function (r) { return r.ok ? r.json() : null; }).then(function (j) {
      if (!j || !ST) return;
      ST.relayMeta[u] = { nodeId: j.node_id || '', advertise: j.advertise || '', base: j.base || '', x25519: j.x25519 || '' };
      if (u === myPrimary()) RELAYINFO.nodeId = j.node_id || '';
      save(); poke();
    }).catch(function () { });
  }
  function onWelcome(u, m) {
    var c = CONNS[u]; if (!c) return;
    c.open = true; c.retryN = 0; c.info = m;
    updReach();
    if (ST) {
      ST.relayMeta[u] = ST.relayMeta[u] || {};
      if (m.node_id) ST.relayMeta[u].nodeId = m.node_id;
      if (m.x25519) ST.relayMeta[u].x25519 = m.x25519;          // onion sealing key of this relay
      if (m.advertise) ST.relayMeta[u].advertise = m.advertise;
    }
    fetchNodeMeta(u);
    sendOn(u, { t: 'subscribe', push: true });
    watchOn(u); presenceOn(u); flushOutbox();
    fetchLoop(u);
    if (u === myPrimary()) {
      RELAYINFO.owner = !!m.owner;
      RELAYINFO.usage = { usedBytes: m.used_bytes != null ? m.used_bytes : null, quotaBytes: m.quota_bytes != null ? m.quota_bytes : null };
      RELAYINFO.maxPayload = m.max_payload || 262144;
      refreshStats();
      locateNow();
      refreshInviteStatus();
      if (_pulledFor !== ID.pubHex) { _pulledFor = ID.pubHex; jPull().then(function (n) { if (n > 3) toast('History restored from your relay (' + n + ' items)'); jFlush(); }); }
      else jFlush();
    }
    poke();
  }
  function fetchLoop(u) {
    req(u, { t: 'fetch', since: 0, max: 100 }, ['fetch_done'], 30000).then(function (d) {
      if (d.more) fetchLoop(u);
    }).catch(function () { });
  }

  /* ---- outbox / send ---- */
  function newId() { try { return crypto.randomUUID(); } catch (e) { } var b = nacl.randomBytes(16); b[6] = (b[6] & 0x0f) | 0x40; b[8] = (b[8] & 0x3f) | 0x80; var h = toHex(b); return h.slice(0, 8) + '-' + h.slice(8, 12) + '-' + h.slice(12, 16) + '-' + h.slice(16, 20) + '-' + h.slice(20); }
  function sendText(pubHex, text) {
    if (isGKey(pubHex)) return sendGText(pubHex.slice(2), text);
    text = String(text || '').trim(); if (!text) return;
    var id = newId(); var m = { id: id, dir: 'out', kind: 'text', body: text, ts: Date.now(), status: 'pending' };
    pushMsg(pubHex, m); jrecMsg(pubHex, m); queueSend(pubHex, id, { t: 'text', body: text });
  }
  function queueSend(pubHex, id, obj, msgId) {
    var rr = myPrimary(); if (rr) { obj.rr = rr; obj.ra = advertiseOf(rr); }
    var payload; try { payload = encTo(JSON.stringify(obj), hexToBytes(pubHex)); } catch (e) { toast('Encryption failed', 'err'); return; }
    ST.outbox.push({ id: id, to: pubHex, payload: payload, ts: Date.now(), msgId: msgId || id, sys: (obj.t === 'dack' || obj.t === 'vouchreq') ? 1 : 0 }); save();
    flushOutbox();
  }
  function routeFor(pubHex) {
    // prefer the contact's own relay directly; else route via my primary with fp@addr
    var cu = relayOfPub(pubHex);
    if (connReady(cu)) return { u: cu, to: fpOf(pubHex) };
    var p = myPrimary();
    if (connReady(p)) {
      var c = findC(pubHex);
      var addr = (c && c.relayAddr) || (c && c.relay ? advertiseOf(c.relay) : null);
      return { u: p, to: addr && cu !== p ? (fpOf(pubHex) + '@' + addr) : fpOf(pubHex) };
    }
    return null;
  }
  function directSend(o) {
    var rt = routeFor(o.to); if (!rt) { var cu = relayOfPub(o.to); if (cu) ensureConn(cu); return; }
    sendOn(rt.u, { t: 'send', id: o.id, to: rt.to, body: o.payload });
  }
  function flushOutbox() {
    if (!ST) return;
    var now = Date.now();
    ST.outbox.forEach(function (o) {
      if (onionOn() && !o.direct) {
        if (!o.onionAt) { onionSend(o); return; }
        if (now - o.onionAt < ONION_RETRY_MS) return;
        // No delivery receipt long after the onion left: the route may have lost it (onion
        // layers cannot be parked). Resend once directly; the same id deduplicates if it did arrive.
        o.direct = true; save();
      }
      directSend(o);
    });
  }

  /* ---- onion routing (on by default): every stored payload (text, files, mail, groups, receipts)
     leaves on a fresh ANONYMOUS socket, sealed in 1–3 layers: entry → middle → the recipient's relay.
     No relay sees both the sender and the recipient: the entry sees this device but not who the
     message is for; the last hop files it for the recipient but cannot tell who sent it.
     Relays stay silent when a layer is accepted, so success = no error within ONION_WAIT_MS.
     Calls (sig) stay direct: signalling is live and onion terminals only store. ---- */
  var ONION_RETRY_MS = 15 * 60000, ONION_WAIT_MS = 2500, ONION_MAX_B64 = 900000;
  var _onDir = { t: 0, list: [] }, _onDirP = null, _onBusy = {}, _onBad = {};   // _onBad: entry address → retry-after ms
  var ONIONSTAT = { last: null };
  function onionOn() { return !!(ST && ST.onion !== false); }
  function setOnionEnabled(b) { if (!ST) return; ST.onion = !!b; save(); poke(); if (b) flushOutbox(); }
  function onionDirectory() {
    if (Date.now() - _onDir.t < 180000 && _onDir.list.length) return Promise.resolve(_onDir.list);
    if (_onDirP) return _onDirP;
    var p = myPrimary(); if (!p || mixedBlocked(p)) return Promise.resolve(_onDir.list);
    _onDirP = fetch(httpBase(p) + '/peers.json').then(function (r) { return r.ok ? r.json() : null; }).then(function (j) {
      var list = [];
      if (j && j.node && j.node.advertise && j.node.x25519) list.push({ address: String(j.node.advertise), x25519: String(j.node.x25519), url: p });
      // Only relays my primary has heard from recently (handshake or ping reply): a route
      // through a relay that has gone quiet loses the whole message if its standbys are gone too.
      // Relays ping their links every 30 s, so a live linked peer was heard within the last
      // minute or so; three minutes of silence means it is gone.
      var fresh = Math.floor(Date.now() / 1000) - 180;
      ((j && j.peers) || []).forEach(function (pe) {
        if (pe && pe.verified && pe.address && pe.x25519 && (pe.last_ok | 0) >= fresh) list.push({ address: String(pe.address), x25519: String(pe.x25519) });
      });
      _onDir = { t: Date.now(), list: list };
      return list;
    }).catch(function () { return _onDir.list; }).then(function (l) { _onDirP = null; return l; });
    return _onDirP;
  }
  function knownHops() {   // relays this wallet already talks to, with the keys their node.json / welcome gave
    var out = [];
    Object.keys(wantedRelays()).forEach(function (u) { var m = metaOf(u); if (m.x25519) out.push({ address: m.advertise || '', x25519: m.x25519, url: u }); });
    return out;
  }
  function shuffled(a) { a = a.slice(); var r = nacl.randomBytes(a.length || 1); for (var i = a.length - 1; i > 0; i--) { var j = r[i] % (i + 1), t = a[i]; a[i] = a[j]; a[j] = t; } return a; }
  function entryUrlOf(h) {
    if (h.url && !mixedBlocked(h.url)) return normRelay(h.url);
    if (h.address && !mixedBlocked('ws://' + h.address)) return 'ws://' + h.address;
    return null;
  }
  /* Route = sets of up to ONION_ALTS candidates per position:
       entry set (reachable from this browser; my primary last — it already knows who I am)
       → 1 middle set (standard) or 3 (extra privacy)
       → terminal set: the recipient's relay, then up to two alternatives that forward to it.
     Relays are spread across sets when enough are known; a small network reuses them, but a
     relay never follows itself. */
  var ONION_ALTS = 3;
  function onionLevel() { return (ST && ST.onionLevel === 'extra') ? 'extra' : 'standard'; }
  function setOnionLevel(l) { if (!ST) return; ST.onionLevel = l === 'extra' ? 'extra' : 'standard'; save(); poke(); }
  function onionRoute(pubHex) {
    return onionDirectory().then(function (dir) {
      var byAddr = {};
      dir.concat(knownHops()).forEach(function (h) {
        var k = h.address || ('url:' + h.url);
        byAddr[k] = byAddr[k] || {}; for (var f in h) if (h[f]) byAddr[k][f] = h[f];
      });
      var pool = Object.keys(byAddr).map(function (k) { return byAddr[k]; });
      // Terminal: the relay the recipient collects from (its own relay, else mine) — must carry a key.
      var tu = relayOfPub(pubHex), c = findC(pubHex), tm = metaOf(tu), T = null;
      if (tm.x25519) T = { address: tm.advertise || '', x25519: tm.x25519, url: tu };
      else if (c && c.relayAddr) pool.forEach(function (h) { if (h.address === c.relayAddr) T = h; });
      if (!T) return null;
      if (!T.address) { var u0 = entryUrlOf(T); return u0 ? { urls: [u0], sets: [[T]], to: fpOf(pubHex) } : null; }   // not dialable by other relays: one hop
      var now = Date.now(), prim = myPrimary();
      var others = shuffled(pool.filter(function (h) { return h.address && h.address !== T.address && !(_onBad[h.address] > now); }));
      var used = {};
      function take(cands, n, avoid) {   // prefer relays not used yet in this route, never ones in `avoid`
        var fresh = cands.filter(function (h) { return !used[h.address] && !avoid[h.address]; });
        var reuse = cands.filter(function (h) { return used[h.address] && !avoid[h.address]; });
        var out = fresh.concat(reuse).slice(0, n);
        out.forEach(function (h) { used[h.address] = 1; });
        return out;
      }
      var entries = others.filter(function (h) { return entryUrlOf(h); });
      entries.sort(function (a, b) { return (normRelay(a.url || '') === prim ? 1 : 0) - (normRelay(b.url || '') === prim ? 1 : 0); });
      // Spread what is known over the positions, so a small network still gets a middle hop
      // before it gets standby relays.
      var middles = onionLevel() === 'extra' ? 3 : 1;
      var per = Math.max(1, Math.min(ONION_ALTS, Math.floor(others.length / (middles + 1))));
      var E = take(entries, per, {});
      if (!E.length) { var u1 = entryUrlOf(T); return u1 ? { urls: [u1], sets: [[T]], to: fpOf(pubHex) + '@' + T.address } : null; }
      var sets = [E], prev = E;
      for (var m = 0; m < middles; m++) {
        var avoid = {}; prev.forEach(function (h) { avoid[h.address] = 1; });
        var M = take(others, per, avoid);
        if (!M.length) break;       // not enough relays yet: a shorter route
        sets.push(M); prev = M;
      }
      var tAvoid = {}; prev.forEach(function (h) { tAvoid[h.address] = 1; });
      var alts = others.filter(function (h) { return !tAvoid[h.address]; }).slice(0, ONION_ALTS - 1);
      sets.push([T].concat(alts));
      return { urls: E.map(entryUrlOf), entries: E.map(function (h) { return h.address; }), sets: sets, to: fpOf(pubHex) + '@' + T.address };
    });
  }
  function onionSubmitAny(urls, blobB64, entries) {   // the entry layer opens for any of them: try in order
    var i = 0;
    function next(last) {
      if (i >= urls.length) return Promise.resolve(last || { err: 'no entry' });
      var k = i++;
      return onionSubmit(urls[k], blobB64).then(function (r) {
        if (r.ok) return r;
        if ((r.err === 'connect' || r.err === 'timeout' || r.err === 'closed') && entries && entries[k]) { _onBad[entries[k]] = Date.now() + 600000; return next(r); }
        return r;   // the relay answered with an error: the route itself is at fault
      });
    }
    return next(null);
  }
  function onionSubmit(url, blobB64) {
    return new Promise(function (resolve) {
      var ws, done = false, wait = null;
      function fin(r) { if (done) return; done = true; if (wait) clearTimeout(wait); try { ws.close(); } catch (e) { } resolve(r); }
      if (mixedBlocked(url)) { resolve({ err: 'blocked' }); return; }
      try { ws = new WebSocket(normRelay(url) + '/ws'); } catch (e) { resolve({ err: 'connect' }); return; }
      ws.onopen = function () {   // no hello: the entry relay must not learn who is sending
        try { ws.send(JSON.stringify({ t: 'onion', blob: blobB64 })); } catch (e) { fin({ err: 'send' }); return; }
        wait = setTimeout(function () { fin({ ok: true }); }, ONION_WAIT_MS);
      };
      ws.onmessage = function (ev) { var m; try { m = JSON.parse(ev.data); } catch (e) { return; } if (m && m.t === 'err') fin({ err: m.code || 'refused' }); };
      ws.onerror = function () { fin({ err: 'connect' }); };
      ws.onclose = function () { fin({ err: 'closed' }); };
      setTimeout(function () { fin({ err: 'timeout' }); }, 9000);
    });
  }
  function onionTry(o) {
    return onionRoute(o.to).then(function (rt) {
      if (!rt) return { err: 'no route' };
      var blob;
      try { blob = b64(onionBuild(rt.sets.map(function (set) { return set.map(function (h) { return { address: h.address, x25519: unb64(h.x25519) }; }); }), rt.to, o.id, unb64(o.payload))); }
      catch (e) { return { err: 'seal' }; }
      if (blob.length > ONION_MAX_B64) return { err: 'too big' };
      return onionSubmitAny(rt.urls, blob, rt.entries).then(function (r) {
        r.hops = rt.sets.length;
        r.alts = rt.sets.map(function (x) { return x.length; });
        // Every entry unreachable: build a fresh route once (unreachable ones are now skipped).
        if (r.err === 'connect' || r.err === 'timeout' || r.err === 'closed') r.retry = true;
        return r;
      });
    });
  }
  function onionSend(o) {
    if (_onBusy[o.id]) return;
    _onBusy[o.id] = 1;
    onionTry(o).then(function (r) { return r.retry ? onionTry(o) : r; })   // one more route before giving up on the onion
    .catch(function () { return { err: 'route' }; }).then(function (r) {
      delete _onBusy[o.id];
      ONIONSTAT.last = { t: Date.now(), ok: !!r.ok, hops: r.hops || 0, alts: r.alts || [], err: r.err || '' };
      if (!ST || ST.outbox.indexOf(o) < 0) return;
      if (r.ok) {
        o.onionAt = Date.now(); o.via = 'onion';
        if (o.sys) ST.outbox = ST.outbox.filter(function (x) { return x !== o; });   // receipts are fire-and-forget
        else { var mid = o.msgId || o.id; WIRE2MSG[o.id] = mid; if (!pendingFor(mid)) setMsgStatus(mid, 'sent'); }
        save(); poke(); return;
      }
      o.direct = true; save(); directSend(o);   // could not route through the onion: deliver directly
    });
  }
  /* true while some non-receipt copy of this message has not yet left through any path */
  function pendingFor(mid) { return ST.outbox.some(function (o) { return !o.sys && (o.msgId || o.id) === mid && o.via !== 'onion'; }); }
  setInterval(function () { if (ID && ST && ST.outbox.length) flushOutbox(); }, 20000);
  function setMsgStatus(id, status) {
    for (var i2 = 0; ST.mails && i2 < ST.mails.length; i2++) if (ST.mails[i2].id === id) { if (ST.mails[i2].status !== 'delivered') { ST.mails[i2].status = status; save(); poke(); } return; }
    for (var pub in ST.threads) { var t = ST.threads[pub]; for (var i = t.length - 1; i >= 0; i--) if (t[i].id === id) { if (t[i].status !== 'delivered') t[i].status = status; save(); poke(); return; } }
  }
  /* client-side delivery receipts: batched encrypted 'dack' payloads (the relay has no receipts in v2) */
  var _dackQ = {}, _dackT = null;
  function dackQueue(pubHex, wireId) {
    (_dackQ[pubHex] = _dackQ[pubHex] || []).push(wireId);
    if (_dackT) return;
    _dackT = setTimeout(function () {
      _dackT = null; var q = _dackQ; _dackQ = {};
      Object.keys(q).forEach(function (p) { try { queueSend(p, newId(), { t: 'dack', ids: q[p] }); } catch (e) { } });
    }, 900);
  }

  /* ---- attachments (blobs: HTTP with X-R2R-Auth header) ---- */
  var INLINE_MAX = 48 * 1024, BLOB_MAX = 16 * 1024 * 1024, KEEP_LOCAL_MAX = 1.5 * 1024 * 1024;
  function blobUpload(u, cipher) {
    return fetch(httpBase(u) + '/blob', { method: 'POST', headers: authHeader(), body: cipher })
      .then(function (r) { if (!r.ok) throw 0; return r.json(); });
  }
  function blobDownload(u, id) {
    return fetch(httpBase(u) + '/blob/' + id, { headers: authHeader() })
      .then(function (r) { if (!r.ok) throw new Error(r.status === 404 ? 'expired' : 'fetch'); return r.arrayBuffer(); })
      .then(function (ab) { return new Uint8Array(ab); });
  }
  function sendFile(pubHex, file, extra) {
    if (isGKey(pubHex)) return sendGFile(pubHex.slice(2), file, extra);
    if (!file) return;
    if (file.size > BLOB_MAX) { toast('File too large (max 16 MB)', 'err'); return; }
    var id = newId();
    var m = { id: id, dir: 'out', kind: 'file', name: file.name, size: file.size, mime: file.type || 'application/octet-stream', ts: Date.now(), status: 'uploading' };
    if (extra && extra.vm) { m.vm = extra.vm; m.dur = extra.dur | 0; }
    pushMsg(pubHex, m);
    file.arrayBuffer().then(function (ab) {
      var bytes = new Uint8Array(ab);
      var cipher = encBytesTo(bytes, hexToBytes(pubHex));
      if (bytes.length <= KEEP_LOCAL_MAX) { m.dataB64 = b64(bytes); }
      if (cipher.length <= INLINE_MAX) {
        m.status = 'pending'; save(); poke(); jrecMsg(pubHex, m);
        queueSend(pubHex, id, { t: 'file', name: m.name, size: m.size, mime: m.mime, vm: m.vm, dur: m.dur, inline: b64(cipher) });
      } else {
        var u = connReady(relayOfPub(pubHex)) ? relayOfPub(pubHex) : myPrimary();
        if (!connReady(u)) { m.status = 'failed'; save(); poke(); toast('No relay reachable — large files need one', 'err'); return; }
        blobUpload(u, cipher)
          .then(function (j) { m.blob = j.id; m.blobRelay = u; m.status = 'pending'; save(); poke(); jrecMsg(pubHex, m); queueSend(pubHex, id, { t: 'file', name: m.name, size: m.size, mime: m.mime, vm: m.vm, dur: m.dur, blob: j.id, blobRelay: u }); })
          .catch(function () { m.status = 'failed'; save(); poke(); toast('Attachment upload failed', 'err'); });
      }
    });
  }
  function sendMedia(pubHex, blob, vmKind, dur) {
    var name = (vmKind === 'v' ? 'video-message-' : 'voice-message-') + new Date().toISOString().slice(0, 19).replace(/[:T]/g, '-') + '.webm';
    var f; try { f = new File([blob], name, { type: blob.type || 'application/octet-stream' }); } catch (e) { f = blob; f.name = name; }
    sendFile(pubHex, f, { vm: vmKind === 'v' ? 'v' : 'a', dur: dur | 0 });
  }
  function fetchAttachment(pubHex, msgId) {
    var t = ST.threads[pubHex] || []; var m = null; t.forEach(function (x) { if (x.id === msgId) m = x; });
    if (!m) return Promise.reject();
    if (m.dataB64) return Promise.resolve(dataUrlOf(m));
    var bu = m.blobRelay ? normRelay(m.blobRelay) : myPrimary();
    var src = m.inline ? Promise.resolve(unb64(m.inline)) : blobDownload(bu, m.blob);
    return src.then(function (cipher) {
      var plain;
      if (m.key) { try { plain = nacl.secretbox.open(cipher.slice(24), cipher.slice(0, 24), hexToBytes(m.key)); } catch (e) { plain = null; } }
      else plain = decBytesFrom(cipher, hexToBytes(isGKey(pubHex) ? (m.sender || '') : pubHex));
      if (!plain) throw new Error('decrypt');
      if (plain.length <= KEEP_LOCAL_MAX) { m.dataB64 = b64(plain); delete m.inline; save(); }
      return dataUrlOf(m, plain);
    });
  }
  function dataUrlOf(m, plainOpt) { var bytes = plainOpt || unb64(m.dataB64); var bl = new Blob([bytes], { type: m.mime }); return URL.createObjectURL(bl); }

  /* ---- inbound frames ---- */
  var _gatherT = null;
  function handleWs(m, via) {
    if (!m || !m.t) return;
    var c = CONNS[via];
    if (m.t === 'welcome') { onWelcome(via, m); return; }
    if (c && settlePend(c, m)) {
      if (m.t === 'located') applyLocated(m);
      return;
    }
    if (m.t === 'drop') { handleDrop(m, via); return; }
    if (m.t === 'sent') {
      var ob = null; ST.outbox.forEach(function (o) { if (o.id === m.id) ob = o; });
      ST.outbox = ST.outbox.filter(function (o) { return o.id !== m.id; });
      if (ob && !ob.sys) {
        WIRE2MSG[m.id] = ob.msgId || ob.id;
        if (!pendingFor(ob.msgId || ob.id)) setMsgStatus(ob.msgId || ob.id, 'sent');
      }
      save(); return;
    }
    if (m.t === 'mail') { fetchLoop(via); return; }
    if (m.t === 'mail_at') {
      if (_gatherT) clearTimeout(_gatherT);
      _gatherT = setTimeout(function () { _gatherT = null; locateNow(true); }, 1500);
      return;
    }
    if (m.t === 'presence') {
      var fp = String(m.id || '').toLowerCase(); var pub = pubOfFp(fp); if (!pub) return;
      PRES[pub] = { state: m.state || 'offline', seen: m.seen || 0, t: Date.now(), via: via }; poke(); return;
    }
    if (m.t === 'sig') {
      var env = decEnvelope(m.body); if (!env) return;
      var s = env.obj;
      if (s.t === 'offer') { ensureContact(env.from); }
      learnRelay(env.from, s.rr, s.ra);
      handleSignal(env.from, s); return;
    }
    if (m.t === 'quota') { RELAYINFO.usage = { usedBytes: m.used_bytes != null ? m.used_bytes : null, quotaBytes: m.quota_bytes != null ? m.quota_bytes : null }; poke(); return; }
    if (m.t === 'err') {
      if (m.code === 'quota') { RELAYINFO.sync = { t: Date.now(), state: 'quota' }; poke(); }
      return;
    }
  }
  function handleDrop(m, via) {
    ackQueue(via, m.id);   // queued now, sent only after the handler below persisted synchronously
    schedInviteRefresh();
    var env = decEnvelope(m.body); if (!env) return;
    var from = env.from, obj = env.obj;
    if (obj.t === 'dack') {
      var dids = obj.ids || [];
      dids.forEach(function (id) { setMsgStatus(WIRE2MSG[id] || id, 'delivered'); });
      // A receipt closes the book on onion-sent copies still waiting in the outbox.
      var n0 = ST.outbox.length; ST.outbox = ST.outbox.filter(function (o) { return dids.indexOf(o.id) < 0; });
      if (ST.outbox.length !== n0) save();
      return;
    }
    var t = ST.threads[from] || []; for (var i = t.length - 1; i >= 0 && i > t.length - 60; i--) if (t[i].id === m.id) return;
    ensureContact(from);
    learnRelay(from, obj.rr, obj.ra);
    var ts = m.created_at ? (m.created_at > 1e12 ? m.created_at : m.created_at * 1000) : Date.now();
    var rec = { id: m.id, dir: 'in', ts: ts, read: false };
    if (obj.t === 'text') { rec.kind = 'text'; rec.body = String(obj.body || ''); }
    else if (obj.t === 'file') {
      rec.kind = 'file'; rec.name = String(obj.name || 'file'); rec.size = obj.size | 0; rec.mime = String(obj.mime || 'application/octet-stream');
      if (obj.vm === 'a' || obj.vm === 'v') { rec.vm = obj.vm; rec.dur = obj.dur | 0; }
      if (obj.inline) rec.inline = obj.inline; else { rec.blob = String(obj.blob || ''); if (obj.blobRelay) rec.blobRelay = String(obj.blobRelay); }
    } else if (obj.t === 'mail') {
      ST.mails = ST.mails || [];
      for (var mi = 0; mi < ST.mails.length; mi++) if (ST.mails[mi].id === m.id) return;
      var mrec = { id: m.id, dir: 'in', peer: from, peers: validMembers(obj.to).filter(function (p) { return p !== ID.pubHex && p !== from; }), ts: ts, read: false, subj: String(obj.subj || '').slice(0, 200), body: String(obj.body || '').slice(0, 65536), atts: [] };
      (obj.atts || []).slice(0, 8).forEach(function (a) {
        if (!a) return;
        var att = { name: String(a.name || 'file'), size: a.size | 0, mime: String(a.mime || 'application/octet-stream') };
        if (a.key && /^[0-9a-f]{64}$/.test(String(a.key))) att.key = String(a.key);
        if (a.inline) att.inline = String(a.inline); else if (a.blob) { att.blob = String(a.blob); if (a.blobRelay) att.blobRelay = String(a.blobRelay); }
        mrec.atts.push(att);
      });
      ST.mails.push(mrec);
      save(); poke(); emit('mail', mrec);
      dackQueue(from, m.id);
      jrec({ k: 'mailrec', rec: mailSnapshot(mrec) });
      return;
    } else if (obj.t === 'ginfo' || obj.t === 'gtext' || obj.t === 'gfile') { handleGroupMsg(from, m.id, ts, obj); return; }
    else if (obj.t === 'vouchreq') {
      // Someone I invited asks me to vouch for them once we have really chatted.
      ST.vouchReqs = ST.vouchReqs || {};
      if (!ST.vouchReqs[from]) { ST.vouchReqs[from] = { relay: normRelay(String(obj.relay || obj.rr || '')), t: Date.now() }; save(); }
      tryVouch(from); return;
    }
    else return;
    pushMsg(from, rec);
    emit('message', { from: from, msg: rec });
    dackQueue(from, m.id);
    if (rec.kind === 'file' && (rec.inline || rec.blob)) fetchAttachment(from, rec.id).then(function () { jrecMsg(from, rec); }).catch(function () { jrecMsg(from, rec); });
    else jrecMsg(from, rec);
  }

  /* ---- invite activation: a member's own codes unlock once it has received real traffic
     on its relay and the person who invited it has vouched. The inviter's wallet vouches
     automatically after at least one message has gone each way between the two. ---- */
  var _vouchBusy = {}, _invT = null;
  function tryVouch(pubHex) {
    var r = ST && ST.vouchReqs && ST.vouchReqs[pubHex];
    if (!r || r.done || _vouchBusy[pubHex] || !r.relay) return;
    var t = ST.threads[pubHex] || [];
    var hasIn = t.some(function (m) { return m.dir === 'in'; }), hasOut = t.some(function (m) { return m.dir === 'out'; });
    if (!hasIn || !hasOut) return;
    _vouchBusy[pubHex] = 1;
    oneShot(r.relay, ID.kp).then(function (api) {
      return api.rpc({ t: 'vouch', id: fpOf(pubHex) }, ['vouch_ok'], 15000).then(function (m) {
        api.close(); r.done = true; r.active = !!m.active; save();
        toast('You vouched for ' + nameOf(pubHex) + ' — their invite codes can now unlock');
      }, function (e) {
        api.close();
        if (/not.?(authori[sz]ed|your)|did not invite/i.test(String(e.message))) { r.done = true; save(); }   // not my invitee there
      });
    }).catch(function () { }).then(function () { delete _vouchBusy[pubHex]; });
  }
  function refreshInviteStatus() {
    var p = myPrimary(); if (!connReady(p) || !ST) return;
    req(p, { t: 'invite_status' }, ['invite_status']).then(function (m) {
      if (!m.registered) return;
      var st = {};
      (m.invites || []).forEach(function (iv) { st[iv.code] = iv.state; });
      ST.myInvites = (m.invites || []).map(function (iv) { return iv.code; });
      ST.inviteState = { active: !!m.active, received: m.received | 0, needed: m.received_needed | 0, vouchNeeded: !!m.vouch_needed, vouched: !!m.vouched, inviter: m.inviter ? m.inviter.id : '', states: st };
      save(); poke();
    }).catch(function () { });
  }
  function schedInviteRefresh() { if (_invT || !ST || !ST.inviteState || ST.inviteState.active) return; _invT = setTimeout(function () { _invT = null; refreshInviteStatus(); }, 4000); }
  function inviteStatus() { return ST && ST.inviteState ? JSON.parse(JSON.stringify(ST.inviteState)) : null; }

  /* ---- pointers / consolidation: gather mail parked on other relays ---- */
  function applyLocated(m) {
    RELAYINFO.pickup = { t: Date.now(), pending: m.pending | 0, pointers: m.pointers || [] };
    poke();
    if ((m.pointers || []).length) gatherNow();
  }
  function locateNow(silent) {
    var p = myPrimary(); if (!connReady(p)) return Promise.resolve(null);
    return req(p, { t: 'locate' }, ['located']).then(function (m) { applyLocated(m); return m; }).catch(function () { return null; });
  }
  function collectAuth(address, scope) {
    var ts = Math.floor(Date.now() / 1000);
    var nonce = toHex(nacl.randomBytes(12));
    var sig = b64(nacl.sign.detached(utf8('r2r-collect-v1\n' + ID.fp + '\n' + address + '\n' + scope + '\n' + ts + '\n' + nonce), ID.kp.secretKey));
    return { address: address, ts: ts, nonce: nonce, sig: sig };
  }
  function gatherNow() {
    var p = myPrimary(); if (!connReady(p)) return Promise.resolve({ err: 'Relay not connected' });
    var ptrs = (RELAYINFO.pickup && RELAYINFO.pickup.pointers) || [];
    if (!ptrs.length) return Promise.resolve({ ok: true, targets: 0 });
    var frame = { t: 'deposit', id: ID.fp, pubkey: b64(ID.kp.publicKey), scope: 'collect-delete', targets: ptrs.map(function (pt) { return collectAuth(pt.address, 'collect-delete'); }) };
    return req(p, frame, ['deposit_ok'], 30000).then(function (d) {
      RELAYINFO.pickup = { t: Date.now(), pending: 0, pointers: [] }; poke();
      return { ok: true, targets: d.targets | 0 };
    }).catch(function (e) { return { err: e.message || 'gather failed' }; });
  }

  /* ---- ICE / stats / relay probes ---- */
  var STUN = [{ urls: 'stun:stun.l.google.com:19302' }];
  function fetchIce() {
    var p = myPrimary(); if (!connReady(p)) return Promise.resolve(null);
    return req(p, { t: 'ice' }, ['ice']).then(function (m) { return { iceServers: m.iceServers }; }).catch(function () { return null; });
  }
  function refreshStats() {
    var p = myPrimary(); if (!p) return;
    fetch(httpBase(p) + '/status.json').then(function (r) { return r.ok ? r.json() : null; }).then(function (j) { RELAYINFO.stats = j; poke(); }).catch(function () { });
  }
  function refreshUsage() {
    var p = myPrimary(); if (!connReady(p)) return;
    req(p, { t: 'quota' }, ['quota']).then(function (m) { RELAYINFO.usage = { usedBytes: m.used_bytes != null ? m.used_bytes : null, quotaBytes: m.quota_bytes != null ? m.quota_bytes : null }; poke(); }).catch(function () { });
  }
  function testRelay(url) {
    var u = normRelay(url); if (!u) return Promise.resolve({ err: 'Enter a relay address first' });
    if (mixedBlocked(u)) return Promise.resolve({ err: 'Blocked by the browser: ' + mixedErr() });
    var ctl = (typeof AbortController !== 'undefined') ? new AbortController() : null;
    var to = setTimeout(function () { if (ctl) ctl.abort(); }, 6000);
    return fetch(httpBase(u) + '/node.json', ctl ? { signal: ctl.signal } : {})
      .then(function (r) { if (!r.ok) throw 0; return r.json(); })
      .then(function (j) {
        clearTimeout(to);
        if (!j || !j.node_id) return { err: 'Something replied, but it is not an R-2-Я relay (v2)' };
        if (ST) { ST.relayMeta[u] = { nodeId: j.node_id, advertise: j.advertise || '', base: j.base || '', x25519: j.x25519 || '' }; save(); }
        return { ok: true, name: String(j.advertise || j.node_id.slice(0, 12)), nodeId: j.node_id };
      })
      .catch(function () { clearTimeout(to); return { err: 'No reply — check the address, port and firewall (v2 relays answer /node.json)' }; });
  }
  function relayDownloadsUrl() { var p = myPrimary(); return p ? httpBase(p) + '/downloads' : null; }

  /* ---- one-shot authenticated sessions (locator ops, migration, market, claims) ---- */
  function oneShot(url, kp, firstFrame) {
    // opens a ws, sends hello (or firstFrame instead), resolves {rpc, close, welcome}
    return new Promise(function (resolve, reject) {
      var u = normRelay(url);
      if (mixedBlocked(u)) { reject(new Error(mixedErr())); return; }
      var ws;
      try { ws = new WebSocket(u + '/ws'); } catch (e) { reject(e); return; }
      var pend = [], opened = false;
      var to = setTimeout(function () { if (!opened) { try { ws.close(); } catch (e) { } reject(new Error('No reply from ' + u.replace(/^wss?:\/\//, ''))); } }, 9000);
      var api = {
        rpc: function (frame, types, tmo) {
          return new Promise(function (res, rej) {
            var p = { types: types, resolve: res, reject: rej };
            p.tm = setTimeout(function () { var ix = pend.indexOf(p); if (ix >= 0) pend.splice(ix, 1); rej(new Error('timeout')); }, tmo || 15000);
            pend.push(p);
            try { ws.send(JSON.stringify(frame)); } catch (e) { rej(e); }
          });
        },
        close: function () { try { ws.close(); } catch (e) { } }
      };
      ws.onopen = function () {
        var h;
        if (firstFrame) h = firstFrame;
        else { h = helloFields(kp); h.t = 'hello'; }
        try { ws.send(JSON.stringify(h)); } catch (e) { }
      };
      ws.onmessage = function (ev) {
        var m; try { m = JSON.parse(ev.data); } catch (e) { return; }
        if (!opened) {
          if (m.t === 'welcome' || (firstFrame && m.t !== 'err')) { opened = true; clearTimeout(to); api.welcome = m; resolve(api); if (firstFrame) { /* deliver first reply too */ for (var j = 0; j < pend.length; j++) { } api.first = m; } return; }
          // Keep the machine-readable code: callers map it (invite_used, market_off, …) to UI text.
          if (m.t === 'err') { clearTimeout(to); try { ws.close(); } catch (e) { } reject(new Error((m.code ? m.code + ': ' : '') + (m.msg || 'refused'))); return; }
        }
        for (var i = 0; i < pend.length; i++) {
          if (pend[i].types.indexOf(m.t) >= 0) { var p = pend.splice(i, 1)[0]; clearTimeout(p.tm); p.resolve(m); return; }
        }
        if (m.t === 'err' && pend.length) { var p2 = pend.shift(); clearTimeout(p2.tm); p2.reject(new Error(m.code === 'quota' ? 'quota' : ((m.code ? m.code + ': ' : '') + (m.msg || 'relay error')))); }
      };
      ws.onclose = function () { pend.forEach(function (p) { clearTimeout(p.tm); p.reject(new Error('closed')); }); pend = []; };
      ws.onerror = function () { };
    });
  }

  /* ---- invites (v2 registration) ---- */
  function parseInviteCode(text) {
    var s = String(text || '').trim();
    var relay = null;
    var mu = s.match(/^https?:\/\/([^\/\s]+)((?:\/[^\/\s]+)*)\/([^\/\s]+)\/?$/i);
    if (mu) { relay = 'wss://' + mu[1] + (mu[2] || ''); s = mu[3]; }
    var code = null;
    if (/^R2R-[A-Z0-9]{4}(-[A-Z0-9]{4}){1,5}$/i.test(s)) code = s.toUpperCase();
    else if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(s)) code = s.toLowerCase();
    if (!code) return null;
    if (!relay && /^R2R-/i.test(code)) {
      var flat = code.replace(/^R2R-/i, '').replace(/-/g, '');
      var hex8 = flat.slice(0, 8);
      if (/^[0-9A-F]{8}$/i.test(hex8)) {
        var b = hexToBytes(hex8.toLowerCase());
        if (b && b.length === 4 && b[0] > 0) relay = 'ws://' + b[0] + '.' + b[1] + '.' + b[2] + '.' + b[3] + ':8787';
      }
    }
    return { code: code, relay: relay };
  }
  function claimInvite(codeText, relayUrl) {
    if (!ID) return Promise.resolve({ err: 'Unlock first' });
    var pc = parseInviteCode(codeText);
    if (!pc) return Promise.resolve({ err: 'Not an invite code (expected R2R-XXXX-XXXX-…)' });
    var u = normRelay(relayUrl || pc.relay || myPrimary());
    if (!u) return Promise.resolve({ err: 'No relay to claim on — enter the relay address' });
    var frame = helloFields(ID.kp);
    frame.t = 'invite_claim'; frame.code = pc.code;
    try { frame.x25519 = b64(curvePubOfSeed(ID.seed)); } catch (e) { }
    var hr = advertiseOf(myPrimary() || u); if (hr) frame.home_relay = hr;
    return oneShot(u, ID.kp, frame).then(function (api) {
      var w = api.first || api.welcome;
      api.close();
      if (!w || w.t !== 'invite_ok') return { err: 'Unexpected reply' };
      ST.myInvites = (w.invites || []).slice();
      ST.inviteState = { active: !w.locked, received: 0, needed: (w.unlock && w.unlock.received_needed) | 0, vouchNeeded: !!(w.unlock && w.unlock.vouch_needed), vouched: false, inviter: w.inviter ? w.inviter.id : '', states: {} };
      ST.myInvites.forEach(function (c) { ST.inviteState.states[c] = w.locked ? 'locked' : 'open'; });
      // Whoever invited me becomes my first contact; a vouch request rides along so their
      // wallet can vouch for me once we have chatted.
      var ipub = null; try { ipub = w.inviter && w.inviter.pubkey ? unb64(w.inviter.pubkey) : null; } catch (e) { }
      if (ipub && ipub.length === 32 && toHex(ipub) !== ID.pubHex && fpOf(toHex(ipub)) === w.inviter.id) {
        var ih = toHex(ipub), ic = findC(ih);
        if (!ic) { ic = { pub: ih, addr: addrOf(ipub), name: 'Invited me', added: Date.now(), relay: u }; ST.contacts.push(ic); regFp(ih); jrec({ k: 'contact', c: { pub: ic.pub, addr: ic.addr, name: ic.name, relay: u } }); }
        else if (!ic.relay) ic.relay = u;
        ST.inviteState.inviterPub = ih;
        queueSend(ih, newId(), { t: 'vouchreq', relay: u });
      }
      if (!ST.relays.length || ST.relays.indexOf(u) < 0 && !ST.relays.length) ST.relays = [u];
      if (!ST.relays.length) ST.relays = [u];
      ST.registeredOn = ST.registeredOn || {}; ST.registeredOn[u] = { t: Date.now(), node: w.node_id || '' };
      save(); connectAll(); poke();
      return { ok: true, invites: ST.myInvites.slice(), relay: u };
    }).catch(function (e) {
      var msg = String(e.message || e);
      if (/invite_invalid/.test(msg)) msg = 'That invite code is not valid on this relay';
      if (/invite_used/.test(msg)) msg = 'That invite code was already used';
      if (/invite_revoked/.test(msg)) msg = 'That invite code was revoked';
      if (/invite_locked/.test(msg)) msg = 'That invite is not active yet — the person who shared it unlocks their codes by chatting on R2R first';
      if (/already_registered/.test(msg)) msg = 'This identity is already registered on that relay — invite codes are for new people';
      return { err: msg };
    });
  }
  function setupWithInvite(codeText, pin, relayUrl) {
    var pc = parseInviteCode(codeText);
    if (!pc) return Promise.resolve({ err: 'Not an invite code (expected R2R-XXXX-XXXX-… or the invite URL)' });
    var u = normRelay(relayUrl || pc.relay);
    if (!u) return Promise.resolve({ err: 'This code does not name its relay — enter the relay address too' });
    var r = createVault(toHex(nacl.randomBytes(32)), pin, u);
    if (r.err) return Promise.resolve(r);
    return claimInvite(codeText, u).then(function (cr) {
      if (cr.err) { toast('Identity created, but the invite claim failed: ' + cr.err, 'err'); return { ok: true, claimErr: cr.err }; }
      toast('Registered — you got ' + (cr.invites || []).length + ' invite codes to pass on');
      return { ok: true, invites: cr.invites };
    });
  }
  function myInvites() { return (ST && ST.myInvites || []).slice(); }
  function inviteShareUrl(code) {
    var p = myPrimary(); if (!p) return code;
    return httpBase(p).replace(/^http:/i, 'https:') + '/' + code;
  }

  /* ---- calls (WebRTC — signaling now routed sig frames) ---- */
  var CALL = null, RING = null;
  function callInfo() { return CALL; }
  function ringInfo() { return RING; }
  function sendSig(pubHex, obj) {
    try {
      var rr = myPrimary(); if (rr) { obj.rr = rr; obj.ra = advertiseOf(rr); }
      var body = encTo(JSON.stringify(obj), hexToBytes(pubHex));
      var rt = routeFor(pubHex); if (!rt) return false;
      return sendOn(rt.u, { t: 'sig', to: rt.to, body: body });
    } catch (e) { return false; }
  }
  function devPref() { try { return JSON.parse(localStorage.getItem('r2r1_devs') || '{}'); } catch (e) { return {}; } }
  function devPrefSave(o) { try { localStorage.setItem('r2r1_devs', JSON.stringify(o)); } catch (e) { } }
  function mediaConstraints(video) { var p = devPref(); return { video: video ? (p.cam ? { deviceId: { ideal: p.cam } } : true) : false, audio: p.mic ? { deviceId: { ideal: p.mic } } : true }; }
  function acquireMedia(video) {
    return navigator.mediaDevices.getUserMedia(mediaConstraints(video)).catch(function () {
      return navigator.mediaDevices.getUserMedia({ audio: mediaConstraints(false).audio }).then(function (a) {
        toast('Camera unavailable — continuing with audio only', 'err');
        return a;
      }).catch(function () {
        if (!video) { toast('Microphone is in use or blocked — the other side can\u2019t hear you', 'err'); return null; }
        return navigator.mediaDevices.getUserMedia({ video: true }).then(function (v) { toast('Microphone is in use or blocked — the other side can\u2019t hear you', 'err'); return v; }).catch(function () { toast('No camera or microphone available', 'err'); return null; });
      });
    });
  }
  function buildPC(ice) {
    var pc = new RTCPeerConnection({ iceServers: ice || STUN, iceCandidatePoolSize: 2 });
    pc.onicecandidate = function (e) { if (e.candidate && CALL) sendSig(CALL.pub, { t: 'cand', cand: e.candidate, callId: CALL.id }); };
    pc.ontrack = function (e) {
      if (!CALL) return; CALL.remoteStream = e.streams[0]; emit('call');
      try { var tr = e.track; tr.onunmute = function () { emit('call'); }; tr.onmute = function () { emit('call'); }; tr.onended = function () { emit('call'); }; } catch (err) { }
    };
    pc.oniceconnectionstatechange = function () {
      if (!CALL || !pc) return; var s = pc.iceConnectionState;
      if (s === 'connected' || s === 'completed') detectRoute();
      else if (s === 'failed') escalateToTurn();
      else if (s === 'disconnected') setCallState('reconnecting');
    };
    return pc;
  }
  async function detectRoute() {
    if (!CALL || !CALL.pc || !CALL.pc.getStats) return;
    try {
      var stats = await CALL.pc.getStats(); var pair = null, cands = {};
      stats.forEach(function (r) { if (r.type === 'candidate-pair' && (r.selected || r.nominated) && r.state === 'succeeded') pair = r; if (r.type === 'local-candidate' || r.type === 'remote-candidate') cands[r.id] = r; });
      var relay = false;
      if (pair) { var lc = cands[pair.localCandidateId], rc = cands[pair.remoteCandidateId]; relay = (lc && lc.candidateType === 'relay') || (rc && rc.candidateType === 'relay'); }
      applyRoute(relay ? 'relay' : 'direct');
    } catch (e) { applyRoute('direct'); }
  }
  async function escalateToTurn() {
    if (!CALL || CALL.turnTried) { if (CALL) setCallState('failed'); return; }
    CALL.turnTried = true; setCallState('connecting-relay');
    var ice = await fetchIce();
    if (!ice || !CALL || !CALL.pc) { setCallState('failed'); return; }
    if (!ice.iceServers) { toast('No TURN relay available — couldn\u2019t connect', 'err'); setCallState('failed'); return; }
    try {
      CALL.pc.setConfiguration({ iceServers: STUN.concat(ice.iceServers) }); CALL.pc.restartIce();
      var offer = await CALL.pc.createOffer({ iceRestart: true }); await CALL.pc.setLocalDescription(offer);
      sendSig(CALL.pub, { t: 'offer', sdp: offer, mode: CALL.mode, callId: CALL.id, iceRestart: true });
    } catch (e) { setCallState('failed'); }
  }
  function applyRoute(route) { if (!CALL) return; CALL.route = route; emit('call'); }
  function setCallState(s) { if (!CALL) return; CALL.state = s; emit('call'); }
  function startCall(pubHex, mode) {
    if (isGKey(pubHex)) return startGroupCall(String(pubHex).slice(2), mode);
    if (CALL) { toast('Already in a call', 'err'); return; }
    mode = mode || 'voice';
    CALL = { pub: pubHex, mode: mode, dir: 'out', id: newId(), route: 'direct', t0: 0, dur: 0, dataMB: 0, muted: false, camOff: mode !== 'video', stream: null, remoteStream: null, screen: null, pc: null, timer: null, connected: false, turnTried: false, state: 'init' };
    emit('call');
    if (!connReady(relayOfPub(pubHex)) && !connReady(myPrimary())) { setCallState('no-relay'); return; }
    placeCall();
  }
  async function placeCall() {
    setCallState('connecting');
    CALL.stream = await acquireMedia(CALL.mode === 'video');
    if (!CALL) return;
    CALL.pc = buildPC(STUN);
    if (CALL.stream) CALL.stream.getTracks().forEach(function (t) { CALL.pc.addTrack(t, CALL.stream); });
    try {
      var offer = await CALL.pc.createOffer({ offerToReceiveAudio: true, offerToReceiveVideo: CALL.mode === 'video' });
      await CALL.pc.setLocalDescription(offer);
      if (!sendSig(CALL.pub, { t: 'offer', sdp: offer, mode: CALL.mode, callId: CALL.id })) { setCallState('no-relay'); return; }
      setCallState('ringing');
      CALL.ringTO = setTimeout(function () { if (CALL && !CALL.connected) { toast('No answer'); logCall(true); endCall(); } }, 35000);
    } catch (e) { setCallState('failed'); }
  }
  function handleSignal(from, s) {
    if (!s || !s.t) return;
    if (CALL && CALL.group) {
      if (s.t === 'offer' && s.gid === CALL.group && s.callId === CALL.id) {
        var pe0 = CALL.peers[from];
        if (pe0 && pe0.pc && s.sdp) {
          (async function () {
            try { await pe0.pc.setRemoteDescription(s.sdp); var an = await pe0.pc.createAnswer(); await pe0.pc.setLocalDescription(an); sendSig(from, { t: 'answer', sdp: an, callId: CALL.id, gid: CALL.group, renegotiate: true }); } catch (e) { }
          })();
        } else if (!pe0 && Object.keys(CALL.peers).length < GCALL_MAX - 1 && gcAllowed(from)) gcAnswer(from, s, []);
        return;
      }
      var pe = CALL.peers[from]; if (!pe && s.t !== 'gjoin') return;
      if (s.t === 'answer' && s.sdp && pe && pe.pc) { pe.pc.setRemoteDescription(s.sdp).catch(function () { }); return; }
      if (s.t === 'cand' && s.cand && pe && pe.pc) { pe.pc.addIceCandidate(s.cand).catch(function () { }); return; }
      if (s.t === 'bye') { gcDrop(from); return; }
      if (s.t === 'gjoin' && s.callId === CALL.id) {
        (s.joined || []).forEach(function (p) {
          p = String(p || '').toLowerCase();
          if (/^[0-9a-f]{64}$/.test(p) && p !== ID.pubHex && !CALL.peers[p] && ID.pubHex < p && Object.keys(CALL.peers).length < GCALL_MAX - 1 && gcAllowed(p)) gcOffer(p);
        });
        return;
      }
      return;
    }
    if (s.t === 'offer') {
      if (!CALL) { incomingRing(from, s); return; }
      if (from !== CALL.pub) return;
      if (CALL.pc && s.sdp) {
        (async function () {
          try {
            await CALL.pc.setRemoteDescription(s.sdp);
            var ans = await CALL.pc.createAnswer(); await CALL.pc.setLocalDescription(ans);
            sendSig(CALL.pub, { t: 'answer', sdp: ans, callId: CALL.id, renegotiate: true });
          } catch (e) { }
        })();
      }
      return;
    }
    if (!CALL) {
      if (RING && from === RING.from) {
        if (s.t === 'cand' && s.cand) { RING.cands.push(s.cand); return; }
        if (s.t === 'bye') { stopRing(true); return; }
      }
      return;
    }
    if (from !== CALL.pub) return;
    if (s.t === 'answer' && s.sdp) { if (CALL.pc) CALL.pc.setRemoteDescription(s.sdp).catch(function () { }); if (!CALL.connected && !s.renegotiate) onAnswered(); return; }
    if (s.t === 'cand' && s.cand && CALL.pc) { CALL.pc.addIceCandidate(s.cand).catch(function () { }); return; }
    if (s.t === 'bye') { logCall(); endCall(); return; }
  }
  function incomingRing(from, s) {
    ensureContact(from);
    if (RING) { if (RING.from === from) RING.m = s; return; }
    RING = { m: s, from: from, mode: s.mode === 'video' ? 'video' : 'voice', gid: s.gid || null, gname: s.gname || '', cands: [], actx: null };
    emit('ring'); poke();
    ringTone(); RING.iv = setInterval(ringTone, 1900);
    RING.to = setTimeout(function () { stopRing(true); }, 45000);
    try { if (navigator.vibrate) navigator.vibrate([300, 150, 300]); } catch (e) { }
  }
  function ringTone() {
    if (!RING) return;
    try {
      var ctx = RING.actx || new (window.AudioContext || window.webkitAudioContext)(); RING.actx = ctx;
      if (ctx.state === 'suspended') ctx.resume().catch(function () { });
      var burst = function (f, at, dur) { var o = ctx.createOscillator(), g = ctx.createGain(); o.type = 'sine'; o.frequency.value = f; o.connect(g); g.connect(ctx.destination); g.gain.setValueAtTime(0.0001, at); g.gain.linearRampToValueAtTime(0.22, at + 0.03); g.gain.setValueAtTime(0.22, Math.max(at + 0.04, at + dur - 0.06)); g.gain.linearRampToValueAtTime(0.0001, at + dur); o.start(at); o.stop(at + dur + 0.02); };
      var t = ctx.currentTime + 0.05;
      burst(880, t, 0.35); burst(660, t + 0.45, 0.35);
    } catch (e) { }
  }
  function stopRing(missed) {
    if (!RING) return; var r = RING; RING = null;
    try { if (r.iv) clearInterval(r.iv); } catch (e) { }
    try { if (r.to) clearTimeout(r.to); } catch (e) { }
    try { if (r.actx) r.actx.close(); } catch (e) { }
    if (missed) { var l = { pub: r.from, mode: r.mode, dir: 'in', missed: true, dur: 0, t: Date.now() }; ST.callLog.unshift(l); jrec({ k: 'call', l: l }); save(); toast('Missed call from ' + nameOf(r.from), 'err'); }
    poke(); emit('ring');
  }
  function declineCall() { var to = RING && RING.from; stopRing(false); if (to) { sendSig(to, { t: 'bye' }); var l = { pub: to, mode: 'voice', dir: 'in', missed: true, dur: 0, t: Date.now() }; ST.callLog.unshift(l); jrec({ k: 'call', l: l }); save(); } }
  async function answerCall() {
    if (!RING) return;
    if (RING.gid) return answerGroupCall();
    var r = RING; stopRing(false);
    CALL = { pub: r.from, mode: r.mode, dir: 'in', id: r.m.callId || newId(), route: 'direct', t0: 0, dur: 0, dataMB: 0, muted: false, camOff: r.mode !== 'video', stream: null, remoteStream: null, screen: null, pc: null, timer: null, connected: false, turnTried: false, state: 'connecting', answerer: true };
    emit('call');
    CALL.stream = await acquireMedia(r.mode === 'video');
    if (!CALL) return;
    CALL.pc = buildPC(STUN);
    if (CALL.stream) CALL.stream.getTracks().forEach(function (t) { CALL.pc.addTrack(t, CALL.stream); });
    try {
      await CALL.pc.setRemoteDescription(r.m.sdp);
      (r.cands || []).forEach(function (c) { try { CALL.pc.addIceCandidate(c); } catch (e) { } });
      var ans = await CALL.pc.createAnswer(); await CALL.pc.setLocalDescription(ans);
      if (!sendSig(CALL.pub, { t: 'answer', sdp: ans, callId: CALL.id })) { setCallState('no-relay'); return; }
      onAnswered();
    } catch (e) { setCallState('failed'); }
  }
  function onAnswered() {
    if (!CALL) return;
    if (CALL.ringTO) { clearTimeout(CALL.ringTO); CALL.ringTO = null; }
    CALL.connected = true; CALL.t0 = Date.now();
    CALL.timer = setInterval(function () { if (CALL) { CALL.dur = (Date.now() - CALL.t0) / 1000; emit('call-tick'); } }, 500);
    setCallState('connected');
  }
  function logCall(missed) {
    if (!CALL) return;
    var l = { pub: CALL.group ? gkey(CALL.group) : CALL.pub, mode: CALL.mode, dir: CALL.dir, missed: !!missed || !CALL.connected, dur: Math.round(CALL.dur), route: CALL.route, dataMB: Math.round(CALL.dataMB * 10) / 10, t: Date.now() };
    ST.callLog.unshift(l); jrec({ k: 'call', l: l });
    if (ST.callLog.length > 200) ST.callLog = ST.callLog.slice(0, 200);
    save();
  }
  function endCall() {
    if (!CALL) return; var c = CALL;
    if (c.group) { for (var gp in (c.peers || {})) sendSig(gp, { t: 'bye' }); if (!c._logged) { c._logged = true; if (c.connected) logCall(); } }
    else if (c.connected || c.dir === 'out') { if (!c._logged) { c._logged = true; if (c.state !== 'ended') { sendSig(c.pub, { t: 'bye' }); } if (c.connected) logCall(); } }
    CALL = null;
    try { if (c.timer) clearInterval(c.timer); } catch (e) { }
    try { if (c.ringTO) clearTimeout(c.ringTO); } catch (e) { }
    try { if (c.pc) c.pc.close(); } catch (e) { }
    try { for (var pk in (c.peers || {})) { if (c.peers[pk].pc) c.peers[pk].pc.close(); } } catch (e) { }
    [c.stream, c.screen].forEach(function (s) { if (s) try { s.getTracks().forEach(function (t) { t.stop(); }); } catch (e) { } });
    poke(); emit('call');
  }
  function toggleMute() { if (!CALL) return; CALL.muted = !CALL.muted; if (CALL.stream) CALL.stream.getAudioTracks().forEach(function (t) { t.enabled = !CALL.muted; }); emit('call'); }
  function toggleCam() { if (!CALL) return; CALL.camOff = !CALL.camOff; if (CALL.stream) CALL.stream.getVideoTracks().forEach(function (t) { t.enabled = !CALL.camOff; }); emit('call'); }
  function callPcs() { if (!CALL) return []; if (CALL.group) { var out = []; for (var p in CALL.peers) if (CALL.peers[p].pc) out.push({ pub: p, pc: CALL.peers[p].pc }); return out; } return CALL.pc ? [{ pub: CALL.pub, pc: CALL.pc }] : []; }
  async function toggleScreen() {
    if (!CALL) return;
    if (CALL.screen) { stopScreen(); return; }
    try {
      var scr = await navigator.mediaDevices.getDisplayMedia({ video: true });
      CALL.screen = scr;
      var vt = scr.getVideoTracks()[0];
      vt.onended = function () { stopScreen(); };
      CALL._camTrack = null;
      var pcs = callPcs();
      for (var i = 0; i < pcs.length; i++) {
        var sender = pcs[i].pc.getSenders().find(function (s) { return s.track && s.track.kind === 'video'; });
        if (sender) { if (!CALL._camTrack) CALL._camTrack = sender.track; await sender.replaceTrack(vt); }
        else { pcs[i].pc.addTrack(vt, scr); await renegotiateWith(pcs[i].pub, pcs[i].pc); }
      }
      emit('call');
    } catch (e) { }
  }
  async function stopScreen() {
    if (!CALL || !CALL.screen) return;
    try { CALL.screen.getTracks().forEach(function (t) { t.stop(); }); } catch (e) { }
    var pcs = callPcs();
    for (var i = 0; i < pcs.length; i++) {
      var sender = pcs[i].pc.getSenders().find(function (s) { return s.track && s.track.kind === 'video'; });
      if (sender && CALL._camTrack && CALL._camTrack.readyState === 'live') { try { await sender.replaceTrack(CALL._camTrack); } catch (e) { } }
    }
    CALL.screen = null; CALL._camTrack = null; emit('call');
  }
  async function renegotiateWith(to, pc) {
    if (!CALL) return;
    try {
      var offer = await pc.createOffer(); await pc.setLocalDescription(offer);
      var o = { t: 'offer', sdp: offer, mode: CALL.mode, callId: CALL.id, renegotiate: true };
      if (CALL.group) o.gid = CALL.group;
      sendSig(to, o);
    } catch (e) { }
  }
  function gcAllowed(pub) { var g = groupOf(CALL && CALL.group); return !!(g && g.members.indexOf(pub) >= 0); }
  function gcJoined() { var l = [ID.pubHex]; for (var p in CALL.peers) if (CALL.peers[p].connected) l.push(p); return l; }
  function gcPeer(pub) { var pe = CALL.peers[pub]; if (!pe) pe = CALL.peers[pub] = { pub: pub, pc: null, remoteStream: null, connected: false }; return pe; }
  function gcBuildPC(pub) {
    var pc = new RTCPeerConnection({ iceServers: STUN, iceCandidatePoolSize: 2 });
    pc.onicecandidate = function (e) { if (e.candidate && CALL && CALL.group) sendSig(pub, { t: 'cand', cand: e.candidate, callId: CALL.id }); };
    pc.ontrack = function (e) {
      var pe = CALL && CALL.peers && CALL.peers[pub]; if (!pe) return;
      pe.remoteStream = e.streams[0]; emit('call');
      try { var tr = e.track; tr.onunmute = function () { emit('call'); }; tr.onmute = function () { emit('call'); }; tr.onended = function () { emit('call'); }; } catch (err) { }
    };
    pc.oniceconnectionstatechange = function () {
      var pe = CALL && CALL.peers && CALL.peers[pub]; if (!pe || pe.pc !== pc) return;
      var st = pc.iceConnectionState;
      if (st === 'connected' || st === 'completed') { if (!pe.connected) { pe.connected = true; if (!CALL.anyConnected) { CALL.anyConnected = true; setCallState('connected'); } gcSync(); } emit('call'); }
      else if (st === 'failed' || st === 'closed') gcDrop(pub, true);
      else emit('call');
    };
    return pc;
  }
  function gcSync() { if (!CALL || !CALL.group) return; var j = gcJoined(); for (var p in CALL.peers) if (CALL.peers[p].connected) sendSig(p, { t: 'gjoin', callId: CALL.id, gid: CALL.group, joined: j }); }
  async function gcOffer(pub) {
    var pe = gcPeer(pub);
    pe.pc = gcBuildPC(pub);
    if (CALL.stream) CALL.stream.getTracks().forEach(function (t) { pe.pc.addTrack(t, CALL.stream); });
    if (CALL.screen) { var svt = CALL.screen.getVideoTracks()[0]; if (svt) { var vs = pe.pc.getSenders().find(function (x) { return x.track && x.track.kind === 'video'; }); if (vs) { if (!CALL._camTrack) CALL._camTrack = vs.track; vs.replaceTrack(svt); } else pe.pc.addTrack(svt, CALL.screen); } }
    try {
      var offer = await pe.pc.createOffer({ offerToReceiveAudio: true, offerToReceiveVideo: CALL.mode === 'video' });
      await pe.pc.setLocalDescription(offer);
      var g = groupOf(CALL.group);
      sendSig(pub, { t: 'offer', sdp: offer, mode: CALL.mode, callId: CALL.id, gid: CALL.group, gname: (g && g.name) || 'Group', joined: gcJoined() });
    } catch (e) { gcDrop(pub, true); }
  }
  async function gcAnswer(pub, s, cands) {
    var pe = gcPeer(pub);
    pe.pc = gcBuildPC(pub);
    if (CALL.stream) CALL.stream.getTracks().forEach(function (t) { pe.pc.addTrack(t, CALL.stream); });
    try {
      await pe.pc.setRemoteDescription(s.sdp);
      (cands || []).forEach(function (c) { try { pe.pc.addIceCandidate(c); } catch (e) { } });
      var ans = await pe.pc.createAnswer(); await pe.pc.setLocalDescription(ans);
      sendSig(pub, { t: 'answer', sdp: ans, callId: CALL.id, gid: CALL.group });
    } catch (e) { gcDrop(pub, true); }
  }
  function gcDrop(pub, failed) {
    if (!CALL || !CALL.peers || !CALL.peers[pub]) return;
    var pe = CALL.peers[pub]; delete CALL.peers[pub];
    try { if (pe.pc) pe.pc.close(); } catch (e) { }
    if (failed && pe.connected) toast(nameOf(pub) + ' left the call', '');
    emit('call'); poke();
    if (!Object.keys(CALL.peers).length && CALL.anyConnected) endCall();
  }
  function startGroupCall(gid, mode) {
    if (CALL) { toast('Already in a call', 'err'); return; }
    var g = groupOf(gid); if (!g) return;
    var peers = groupPeers(g);
    if (peers.length > GCALL_MAX - 1) { toast('Group calls support up to ' + GCALL_MAX + ' people \u2014 this group is bigger', 'err'); return; }
    if (!connReady(myPrimary())) { toast('No relay connection \u2014 calls need it for signaling', 'err'); return; }
    mode = mode || 'voice';
    CALL = { group: gid, mode: mode, dir: 'out', id: newId(), route: 'direct', t0: 0, dur: 0, dataMB: 0, muted: false, camOff: mode !== 'video', stream: null, remoteStream: null, screen: null, pc: null, peers: {}, timer: null, connected: false, anyConnected: false, turnTried: true, state: 'connecting' };
    emit('call');
    (async function () {
      CALL.stream = await acquireMedia(mode === 'video');
      if (!CALL) return;
      CALL.connected = true; CALL.t0 = Date.now();
      CALL.timer = setInterval(function () { if (CALL) { CALL.dur = (Date.now() - CALL.t0) / 1000; emit('call-tick'); } }, 500);
      setCallState('ringing');
      peers.forEach(function (p) { gcOffer(p); });
      CALL.ringTO = setTimeout(function () { if (CALL && !CALL.anyConnected) { toast('No answer'); logCall(true); endCall(); } }, 40000);
    })();
  }
  async function answerGroupCall() {
    var r = RING; stopRing(false);
    CALL = { group: r.gid, mode: r.mode, dir: 'in', id: r.m.callId || newId(), route: 'direct', t0: 0, dur: 0, dataMB: 0, muted: false, camOff: r.mode !== 'video', stream: null, remoteStream: null, screen: null, pc: null, peers: {}, timer: null, connected: false, anyConnected: false, turnTried: true, state: 'connecting', answerer: true };
    if (!groupOf(r.gid)) { ST.groups = ST.groups || {}; ST.groups[r.gid] = { gid: r.gid, name: r.gname || 'Group', creator: r.from, members: [ID.pubHex, r.from], created: Date.now() }; save(); }
    emit('call');
    CALL.stream = await acquireMedia(r.mode === 'video');
    if (!CALL) return;
    CALL.connected = true; CALL.t0 = Date.now();
    CALL.timer = setInterval(function () { if (CALL) { CALL.dur = (Date.now() - CALL.t0) / 1000; emit('call-tick'); } }, 500);
    await gcAnswer(r.from, r.m, r.cands);
    (r.m.joined || []).forEach(function (p) {
      p = String(p || '').toLowerCase();
      if (!/^[0-9a-f]{64}$/.test(p) || p === ID.pubHex || p === r.from || CALL.peers[p]) return;
      if (Object.keys(CALL.peers).length >= GCALL_MAX - 1) return;
      if (ID.pubHex < p) gcOffer(p);
      else sendSig(p, { t: 'gjoin', callId: CALL.id, gid: CALL.group, joined: [ID.pubHex] });
    });
  }
  async function listDevices() {
    try { var devs = await navigator.mediaDevices.enumerateDevices(); return { mics: devs.filter(function (d) { return d.kind === 'audioinput'; }), cams: devs.filter(function (d) { return d.kind === 'videoinput'; }) }; } catch (e) { return { mics: [], cams: [] }; }
  }
  async function switchDevice(kind, deviceId) {
    var p = devPref(); p[kind === 'cam' ? 'cam' : 'mic'] = deviceId; devPrefSave(p);
    if (!CALL || !CALL.stream) return;
    try {
      var fresh = await navigator.mediaDevices.getUserMedia(kind === 'cam' ? { video: { deviceId: { exact: deviceId } } } : { audio: { deviceId: { exact: deviceId } } });
      var newTrack = kind === 'cam' ? fresh.getVideoTracks()[0] : fresh.getAudioTracks()[0];
      var pcs = callPcs();
      for (var di = 0; di < pcs.length; di++) {
        var sender = pcs[di].pc.getSenders().find(function (s) { return s.track && s.track.kind === newTrack.kind; });
        if (sender) await sender.replaceTrack(newTrack);
      }
      var old = (kind === 'cam' ? CALL.stream.getVideoTracks() : CALL.stream.getAudioTracks())[0];
      if (old) { CALL.stream.removeTrack(old); old.stop(); }
      CALL.stream.addTrack(newTrack);
      if (kind === 'mic') newTrack.enabled = !CALL.muted;
      if (kind === 'cam') newTrack.enabled = !CALL.camOff;
      emit('call');
    } catch (e) { toast('Could not switch device', 'err'); }
  }
  function hasRemoteVideo() { try { if (!CALL) return false; if (CALL.group) { for (var p in CALL.peers) { var rs = CALL.peers[p].remoteStream; if (rs && rs.getVideoTracks().some(function (t) { return t.readyState === 'live' && !t.muted; })) return true; } return false; } return !!(CALL.remoteStream && CALL.remoteStream.getVideoTracks().some(function (t) { return t.readyState === 'live' && !t.muted; })); } catch (e) { return false; } }

  /* ---- JOURNAL (v2: journal_append / journal_read frames; semantics unchanged) ---- */
  var _jFlushT = null, _pulledFor = null;
  function syncOff() { return !!(ST && ST.syncOff); }
  function jkey() { return sha3(cat(ID.seed, utf8('r2r-journal'))); }
  function backupKey() { return sha3(cat(ID.seed, utf8('r2r-backup'))); }
  function jrec(ev) { if (syncOff() || !ID || !ST) return; (ST.jout = ST.jout || []).push(sbox(ev, jkey())); save(); schedJFlush(); }
  function msgSnapshot(m) {
    var c = JSON.parse(JSON.stringify(m));
    if (c.dir === 'out' && (c.status === 'pending' || c.status === 'uploading')) c.status = 'sent';
    if (c.dataB64 && c.dataB64.length > 350000) delete c.dataB64;
    return c;
  }
  function jrecMsg(pubHex, m) { jrec({ k: 'msg', peer: pubHex, rec: msgSnapshot(m) }); }
  function schedJFlush() { if (_jFlushT) return; _jFlushT = setTimeout(jFlush, 1200); }
  function jFlush() {
    if (_jFlushT) { clearTimeout(_jFlushT); _jFlushT = null; }
    var p = myPrimary(); if (!connReady(p) || syncOff() || !ST || !(ST.jout || []).length) return;
    var ev = ST.jout[0];
    req(p, { t: 'journal_append', data: ev }, ['journal_ok'])
      .then(function (j) {
        ST.jout.shift(); if ((j.seq | 0) > (ST.jseq | 0)) ST.jseq = j.seq | 0;
        RELAYINFO.sync = { t: Date.now(), state: 'ok' }; save(); poke();
        if (ST.jout.length) jFlush(); else { refreshUsage(); schedReplicate(); }
      })
      .catch(function (e) { RELAYINFO.sync = { t: Date.now(), state: String(e.message) === 'quota' ? 'quota' : 'err' }; poke(); });
  }
  function applyEvent(ev) {
    if (!ev || !ev.k) return false;
    if (ev.k === 'msg' && ev.rec && ev.rec.id && (/^[0-9a-f]{64}$/.test(String(ev.peer || '')) || /^g:[0-9a-f][0-9a-f-]{7,40}$/i.test(String(ev.peer || '')))) {
      var t = thread(ev.peer); for (var i = 0; i < t.length; i++) if (t[i].id === ev.rec.id) return false;
      t.push(ev.rec); t.sort(function (a, b) { return (a.ts || 0) - (b.ts || 0); });
      if (!isGKey(ev.peer) && !findC(ev.peer)) { ST.contacts.push({ pub: ev.peer, addr: addrOf(hexToBytes(ev.peer)), name: '', added: Date.now() }); regFp(ev.peer); }
      return true;
    }
    if (ev.k === 'group' && ev.g && validGid(ev.g.gid)) {
      ST.groups = ST.groups || {};
      var prev = ST.groups[ev.g.gid] ? JSON.stringify(gSlim(ST.groups[ev.g.gid])) : '';
      ST.groups[ev.g.gid] = { gid: ev.g.gid, name: String(ev.g.name || 'Group').slice(0, 80), creator: String(ev.g.creator || ''), members: validMembers(ev.g.members), created: ev.g.created || Date.now() };
      return JSON.stringify(gSlim(ST.groups[ev.g.gid])) !== prev;
    }
    if (ev.k === 'gdel') { var hadG = !!(ST.groups && ST.groups[ev.gid]); if (ST.groups) delete ST.groups[ev.gid]; delete ST.threads[gkey(ev.gid)]; return hadG; }
    if (ev.k === 'contact' && ev.c && ev.c.pub) { var c = findC(ev.c.pub); if (!c) { ST.contacts.push(ev.c); regFp(ev.c.pub); return true; } if (ev.c.name && !c.name) c.name = ev.c.name; if (ev.c.relay && !c.relay) c.relay = ev.c.relay; return false; }
    if (ev.k === 'rename') { var c2 = findC(ev.pub); if (c2 && c2.name !== ev.name) { c2.name = ev.name; return true; } return false; }
    if (ev.k === 'delcontact') { var had = !!findC(ev.pub); ST.contacts = ST.contacts.filter(function (c) { return c.pub !== ev.pub; }); delete ST.threads[ev.pub]; return had; }
    if (ev.k === 'mailrec' && ev.rec && ev.rec.id) {
      ST.mails = ST.mails || [];
      if (ST.mails.some(function (x) { return x.id === ev.rec.id; })) return false;
      ST.mails.push(ev.rec); ST.mails.sort(function (a, b) { return (a.ts || 0) - (b.ts || 0); });
      if (ev.rec.peer && /^[0-9a-f]{64}$/.test(ev.rec.peer) && !findC(ev.rec.peer)) { ST.contacts.push({ pub: ev.rec.peer, addr: addrOf(hexToBytes(ev.rec.peer)), name: '', added: Date.now() }); regFp(ev.rec.peer); }
      return true;
    }
    if (ev.k === 'maildel') { var n0 = (ST.mails || []).length; ST.mails = (ST.mails || []).filter(function (x) { return x.id !== ev.id; }); return ST.mails.length !== n0; }
    if (ev.k === 'mailread') { var mr = (ST.mails || []).filter(function (x) { return x.id === ev.id; })[0]; if (mr && !mr.read) { mr.read = true; return true; } return false; }
    if (ev.k === 'call' && ev.l) { var dup = (ST.callLog || []).some(function (x) { return x.t === ev.l.t && x.pub === ev.l.pub; }); if (!dup) { ST.callLog.unshift(ev.l); ST.callLog.sort(function (a, b) { return (b.t || 0) - (a.t || 0); }); return true; } return false; }
    if (ev.k === 'name') { if (!ST.name && ev.name) ST.name = ev.name; return false; }
    return false;
  }
  function jPull() {
    var p = myPrimary(); if (!connReady(p) || syncOff()) return Promise.resolve(0);
    var got = 0;
    var loop = function () {
      return req(p, { t: 'journal_read', since: (ST.jseq | 0), max: 200 }, ['journal'])
        .then(function (m) {
          var list = m.entries || [];
          if (!list.length) return got;
          list.forEach(function (it) {
            if ((it.seq | 0) <= (ST.jseq | 0)) return;
            ST.jseq = it.seq | 0;
            var j = unsbox(it.data, jkey()); if (!j) return;
            var ev; try { ev = JSON.parse(j); } catch (e) { return; }
            if (applyEvent(ev)) got++;
          });
          save(); poke();
          return m.more ? loop() : got;
        });
    };
    return loop().then(function (n) { connectAll(); watchAll(); RELAYINFO.sync = { t: Date.now(), state: 'ok' }; poke(); return n; }).catch(function () { return got; });
  }
  function setSyncEnabled(b) { ST.syncOff = !b; save(); if (b) { jPull().then(jFlush); } poke(); }

  /* ---- relay-owner admin (v2: frames on the authenticated connection, gated by welcome.owner) ---- */
  function adminReq(frame, types) {
    var p = myPrimary();
    if (!connReady(p)) return Promise.reject(new Error('relay not connected'));
    if (!RELAYINFO.owner) return Promise.reject(new Error('this identity is not the relay owner'));
    return req(p, frame, types, 20000);
  }
  function adminAccounts(max, offset) { return adminReq({ t: 'admin_accounts', max: max || 200, offset: offset || 0 }, ['admin_accounts']).then(function (m) { return m.accounts || m.rows || []; }); }
  function adminSearchAccounts(q) { return adminReq({ t: 'admin_search_accounts', q: String(q || '') }, ['admin_search_accounts', 'admin_accounts']).then(function (m) { return m.accounts || m.rows || []; }); }
  function idArgOf(who) {
    var pc = parseContactInput(who);
    if (pc) return fpOf(toHex(pc.pub));
    var s = String(who || '').toLowerCase().trim();
    return /^[0-9a-f]{64}$/.test(s) ? s : null;
  }
  function adminSetQuota(who, mb) { var id = idArgOf(who); if (!id) return Promise.reject(new Error('not a valid address or fingerprint')); return adminReq({ t: 'admin_set_quota', id: id, mb: mb === '' || mb == null ? null : Number(mb) }, ['admin_ok']); }
  function adminSetTtl(who, days) { var id = idArgOf(who); if (!id) return Promise.reject(new Error('not a valid address or fingerprint')); return adminReq({ t: 'admin_set_ttl', id: id, days: days === '' || days == null ? null : Number(days) }, ['admin_ok']); }
  function adminDeleteAccount(who) { var id = idArgOf(who); if (!id) return Promise.reject(new Error('not a valid address or fingerprint')); return adminReq({ t: 'admin_delete_account', id: id }, ['admin_ok']); }
  function adminMintInvites(count) { return adminReq({ t: 'admin_invites', count: count || 3 }, ['admin_invites']).then(function (m) { return m.invites || []; }); }
  function adminListInvites(state) { return adminReq({ t: 'admin_list_invites', state: state || 'open', max: 200, offset: 0 }, ['admin_list_invites', 'admin_invites']).then(function (m) { return m.invites || []; }); }
  function adminRevokeInvite(code, cascade) { return adminReq({ t: 'admin_revoke_invite', code: code, cascade: !!cascade }, ['admin_ok']); }
  function adminSetAdvertise(host) { return adminReq({ t: 'admin_set_advertise', host: String(host || '') }, ['admin_ok']); }
  function adminListRentals() { return adminReq({ t: 'admin_list_rentals' }, ['admin_ok', 'admin_rentals']); }
  function adminListVouchers() { return adminReq({ t: 'admin_list_vouchers' }, ['admin_ok', 'admin_vouchers']); }

  /* ---- backup / restore ---- */
  function backupPayload() { flushSave(); return 'R2RBK1:' + sbox(ST, backupKey()); }
  function restoreFromBackup(text, keyInput, pin) {
    var seed = seedFromInput(keyInput); if (!seed) return { err: 'Enter the private key the backup belongs to' };
    text = String(text || '').trim();
    if (!/^R2RBK1:/i.test(text)) return { err: 'Not a R-2-Я backup' };
    var key = sha3(cat(seed, utf8('r2r-backup')));
    var j = unsbox(text.slice(7), key);
    if (!j) return { err: 'Wrong private key for this backup' };
    var st; try { st = JSON.parse(j); } catch (e) { return { err: 'Backup is corrupted' }; }
    var pc = pinCheck(pin); if (!pc.ok) return { err: pc.label };
    var salt = nacl.randomBytes(16);
    try { localStorage.setItem('r2r1_wrap', JSON.stringify({ salt: toHex(salt), kdf: KDF, wrap: sbox(toHex(seed), kdf(pin, salt)) })); } catch (e) { return { err: 'localStorage unavailable' }; }
    ID = makeIdentity(seed); storeKeyB = sha3(cat(ID.seed, utf8('r2r-store'))); ST = st;
    ST.relayMeta = ST.relayMeta || {}; ST.market = ST.market || { rpc: '', rentals: [] }; ST.myInvites = ST.myInvites || [];
    save(); afterUnlock();
    return { ok: true };
  }

  /* ---- setup cards (R2RSC1) — locator accounts over v2 journal frames.
     A wrong PIN derives a different locator whose journal is simply empty:
     indistinguishable from a brand-new user. ---- */
  function parseSetupCard(text) {
    var m = String(text || '').trim().match(/^R2RSC1:([0-9a-fA-F]{64}):(.+)$/i);
    if (!m) return null;
    var rl = m[2].split(',').map(function (x) { return x.trim(); }).filter(Boolean);
    return rl.length ? { pepper: m[1].toLowerCase(), relays: rl } : null;
  }
  function locatorOf(pin, pepperHex) {
    var K = kdf(String(pin), hexToBytes(pepperHex));
    return {
      kp: nacl.sign.keyPair.fromSeed(sha3(cat(K, utf8('r2r-locator')))),
      blobKey: sha3(cat(K, utf8('r2r-idblob')))
    };
  }
  function readLocatorJournal(api) {
    // full read of a (small) locator journal
    var out = [];
    var loop = function (since) {
      return api.rpc({ t: 'journal_read', since: since, max: 200 }, ['journal']).then(function (m) {
        (m.entries || []).forEach(function (e2) { out.push(e2); });
        var last = out.length ? out[out.length - 1].seq | 0 : since;
        return m.more ? loop(last) : out;
      });
    };
    return loop(0);
  }
  function finalizeVault(seed, pin, pepperHex, relayList) {
    var salt = nacl.randomBytes(16);
    var pepB = pepperHex ? hexToBytes(pepperHex) : new Uint8Array(0);
    try {
      localStorage.setItem('r2r1_wrap', JSON.stringify({ salt: toHex(salt), kdf: KDF, pep: pepperHex ? 1 : 0, wrap: sbox(toHex(seed), kdf(pin, cat(salt, pepB))) }));
      if (pepperHex) localStorage.setItem('r2r1_pepper', pepperHex);
    } catch (e) { return { err: 'localStorage unavailable' }; }
    ID = makeIdentity(seed); openStore();
    if (pepperHex && relayList && relayList.length) { try { localStorage.setItem('r2r1_cardrelays', JSON.stringify(relayList)); } catch (e) { } }
    if (relayList && relayList.length && !ST.relays.length) ST.relays = relayList.slice();
    save(); afterUnlock(); return { ok: true };
  }
  async function setupFromCard(cardText, pin) {
    var card = parseSetupCard(cardText); if (!card) return { err: 'Not a setup card' };
    var pc = pinCheck(pin); if (!pc.ok) return { err: pc.label };
    if (card.relays.every(mixedBlocked)) return { err: mixedErr() };
    var loc = locatorOf(pin, card.pepper);
    var reach = [], seed = null;
    for (var i = 0; i < card.relays.length; i++) {
      try {
        var api = await oneShot(card.relays[i], loc.kp);
        var recs = await readLocatorJournal(api);
        reach.push({ u: card.relays[i], api: api, recs: recs });
      } catch (e) { }
    }
    if (!reach.length) return { err: 'Could not reach any relay on the card — check that the relays are up, and that this page may talk to them' };
    var missing = [];
    reach.forEach(function (x) {
      var found = null;
      (x.recs || []).forEach(function (it) {
        var j = unsbox(it.data, loc.blobKey); if (!j) return;
        try { var o = JSON.parse(j); if (o && o.r) { found = null; return; } var bb = o && o.s ? hexToBytes(o.s) : null; if (bb && bb.length === 32) found = bb; } catch (e) { }
      });
      if (found && !seed) seed = found;
      if (!found) missing.push(x);
    });
    var created = !seed, wrote = 0;
    if (created) seed = nacl.randomBytes(32);
    for (var m = 0; m < missing.length; m++) {
      try { await missing[m].api.rpc({ t: 'journal_append', data: sbox({ s: toHex(seed) }, loc.blobKey) }, ['journal_ok']); wrote++; } catch (e) { }
    }
    reach.forEach(function (x) { try { x.api.close(); } catch (e) { } });
    if (created && !wrote) return { err: 'No relay would store the identity record' };
    var fin = finalizeVault(seed, pin, card.pepper, card.relays);
    return fin.err ? fin : { ok: true, created: created };
  }

  /* ---- change PIN (locator re-registration over v2 frames; all-or-nothing) ---- */
  async function changePin(oldPin, newPin) {
    if (!ID) return { err: 'Unlock first' };
    oldPin = String(oldPin || ''); newPin = String(newPin || '');
    var npc = pinCheck(newPin); if (!npc.ok) return { err: 'New PIN: ' + npc.label };
    var w; try { w = JSON.parse(localStorage.getItem('r2r1_wrap') || 'null'); } catch (e) { }
    if (!w) return { err: 'No vault on this device' };
    var pepHex = w.pep ? String(localStorage.getItem('r2r1_pepper') || '') : '';
    var pepB = pepHex ? hexToBytes(pepHex) : new Uint8Array(0);
    var hex; try { hex = unsbox(w.wrap, kdfWith(oldPin, cat(hexToBytes(w.salt), pepB), w.kdf)); } catch (e) { return { err: e.message }; }
    if (!hex) return { err: 'Current PIN is wrong' };
    var seed = hexToBytes(hex);
    if (toHex(seed) !== toHex(ID.seed)) return { err: 'That PIN opens a different identity — unlock with it first, then change it there' };
    if (pepHex) {
      var relays_ = null; try { relays_ = JSON.parse(localStorage.getItem('r2r1_cardrelays') || 'null'); } catch (e) { }
      if (!relays_ || !relays_.length) relays_ = ST && ST.relays && ST.relays.length ? ST.relays.slice() : [];
      if (!relays_.length) return { err: 'No card relays known — add your relay in Settings first' };
      var oldLoc = locatorOf(oldPin, pepHex), newLoc = locatorOf(newPin, pepHex);
      var failed = [];
      for (var i = 0; i < relays_.length; i++) {
        var ok = false;
        try {
          var api = await oneShot(relays_[i], newLoc.kp);
          await api.rpc({ t: 'journal_append', data: sbox({ s: toHex(seed) }, newLoc.blobKey) }, ['journal_ok']);
          api.close(); ok = true;
        } catch (e) { }
        if (!ok) failed.push(String(relays_[i]).replace(/^wss?:\/\//i, ''));
      }
      if (failed.length) return { err: 'PIN unchanged — could not move the card record on: ' + failed.join(', ') + '. All card relays must confirm first, so a restore with the new PIN never finds an empty card. Try again when they are reachable.' };
      for (var t = 0; t < relays_.length; t++) {
        try { var api2 = await oneShot(relays_[t], oldLoc.kp); await api2.rpc({ t: 'journal_append', data: sbox({ r: 1 }, oldLoc.blobKey) }, ['journal_ok']); api2.close(); } catch (e) { }
      }
    }
    var salt = nacl.randomBytes(16);
    try { localStorage.setItem('r2r1_wrap', JSON.stringify({ salt: toHex(salt), kdf: KDF, pep: pepHex ? 1 : 0, wrap: sbox(toHex(seed), kdf(newPin, cat(salt, pepB))) })); } catch (e) { return { err: 'localStorage unavailable' }; }
    return { ok: true, card: !!pepHex };
  }

  /* ---- relay migration: ferry the (opaque) journal old → new primary ---- */
  async function migrateJournal(fromUrl, pin) {
    if (!ID || !ST) return { err: 'Unlock first' };
    var to = myPrimary(); if (!to) return { err: 'Add the new relay first — first line in Relays' };
    if (!connReady(to)) return { err: 'Your new relay is not connected' };
    if (normRelay(fromUrl) === to) return { err: 'Old and new relay are the same' };
    var copied = 0, lastSeq = 0, api;
    try { api = await oneShot(fromUrl, ID.kp); } catch (e) { return { err: 'Could not reach the old relay: ' + (e.message || ''), copied: 0 }; }
    try {
      var since = 0, more = true;
      while (more) {
        var m = await api.rpc({ t: 'journal_read', since: since, max: 200 }, ['journal']);
        var list = m.entries || [];
        for (var i = 0; i < list.length; i++) {
          since = list[i].seq | 0;
          var j;
          try { j = await req(to, { t: 'journal_append', data: list[i].data }, ['journal_ok']); }
          catch (e2) { api.close(); return { err: String(e2.message) === 'quota' ? ('New relay is out of storage after ' + copied + ' records — raise the quota there and rerun') : ('The new relay refused a record after ' + copied), copied: copied }; }
          if ((j.seq | 0) > lastSeq) lastSeq = j.seq | 0;
          copied++;
        }
        more = !!m.more && list.length > 0;
      }
    } catch (e) { api.close(); return { err: 'Lost the old relay after ' + copied + ' records', copied: copied }; }
    api.close();
    if (lastSeq) { ST.jseq = lastSeq; save(); }
    var cardMoved = false, cardErr = null;
    var pepper = null; try { pepper = localStorage.getItem('r2r1_pepper'); } catch (e) { }
    if (pin && pepper) {
      var w = null; try { w = JSON.parse(localStorage.getItem('r2r1_wrap') || 'null'); } catch (e) { }
      var okPin = false; try { okPin = !!(w && unsbox(w.wrap, kdfWith(String(pin), cat(hexToBytes(w.salt), hexToBytes(pepper)), w.kdf))); } catch (e) { }
      if (w && w.pep && !okPin) {
        cardErr = 'PIN did not match this device — card record not copied';
      } else {
        var loc = locatorOf(pin, pepper);
        try {
          var lapi = await oneShot(to, loc.kp);
          var recs = await readLocatorJournal(lapi);
          var have = (recs || []).some(function (it) { return !!unsbox(it.data, loc.blobKey); });
          if (have) cardMoved = true;
          else { await lapi.rpc({ t: 'journal_append', data: sbox({ s: toHex(ID.seed) }, loc.blobKey) }, ['journal_ok']); cardMoved = true; }
          lapi.close();
        } catch (e) { cardErr = 'Could not copy the card record'; }
      }
    }
    refreshUsage();
    return { ok: true, copied: copied, cardMoved: cardMoved, cardErr: cardErr };
  }

  /* ---- mail ---- */
  function mailSnapshot(m) {
    var c = JSON.parse(JSON.stringify(m));
    if (c.status === 'pending') c.status = 'sent';
    var tot = 0; (c.atts || []).forEach(function (a) { if (a.dataB64) tot += a.dataB64.length; });
    if (tot > 350000) (c.atts || []).forEach(function (a) { delete a.dataB64; });
    return c;
  }
  async function sendMail(pubHexOrList, subj, bodyHtml, files) {
    var peers = validMembers(Array.isArray(pubHexOrList) ? pubHexOrList : [pubHexOrList]).filter(function (p) { return p !== ID.pubHex; });
    if (!peers.length) return { err: 'Pick at least one recipient' };
    if (peers.length > 8) return { err: 'Max 8 recipients' };
    for (var pi = 0; pi < peers.length; pi++) if (!findC(peers[pi])) return { err: 'Unknown recipient — add them as a contact first' };
    subj = String(subj || '').slice(0, 200); bodyHtml = String(bodyHtml || '');
    if (bodyHtml.length > 40000) return { err: 'Mail body too long — keep it under ~40 KB of text' };
    files = Array.prototype.slice.call(files || []).slice(0, 8);
    var id = newId();
    var mrec = { id: id, dir: 'out', peer: peers[0], peers: peers, subj: subj, body: bodyHtml, atts: [], ts: Date.now(), read: true, status: 'pending' };
    var payloadAtts = [];
    for (var i = 0; i < files.length; i++) {
      var f = files[i];
      if (f.size > BLOB_MAX) return { err: f.name + ' is too large (max 16 MB)' };
      var bytes = new Uint8Array(await f.arrayBuffer());
      var kB = nacl.randomBytes(32); var nonce = nacl.randomBytes(24);
      var cipher = cat(nonce, nacl.secretbox(bytes, nonce, kB));
      var att = { name: f.name, size: f.size, mime: f.type || 'application/octet-stream', key: toHex(kB) };
      var patt = { name: att.name, size: att.size, mime: att.mime, key: att.key };
      if (bytes.length <= KEEP_LOCAL_MAX) att.dataB64 = b64(bytes);
      if (cipher.length <= INLINE_MAX) patt.inline = b64(cipher);
      else {
        var u = myPrimary();
        if (!connReady(u)) return { err: 'Your relay is unreachable — large attachments need it' };
        var jj;
        try { jj = await blobUpload(u, cipher); } catch (e) { return { err: 'Attachment upload failed' }; }
        patt.blob = jj.id; patt.blobRelay = u; att.blob = jj.id; att.blobRelay = u;
      }
      mrec.atts.push(att); payloadAtts.push(patt);
    }
    var obj = { t: 'mail', subj: subj, body: bodyHtml, atts: payloadAtts, to: peers };
    if (JSON.stringify(obj).length > 60000) return { err: 'Mail too large — small files ride inline, so attach fewer/bigger files instead of pasting them' };
    ST.mails = ST.mails || []; ST.mails.push(mrec);
    jrec({ k: 'mailrec', rec: mailSnapshot(mrec) });
    peers.forEach(function (p) { queueSend(p, newId(), obj, id); });
    save(); poke();
    return { ok: true };
  }
  function mailById(id) { return (ST && ST.mails || []).filter(function (x) { return x.id === id; })[0] || null; }
  function markMailRead(id) { var m = mailById(id); if (m && !m.read) { m.read = true; jrec({ k: 'mailread', id: id }); save(); poke(); } }
  function deleteMail(id) { if (!ST) return; ST.mails = (ST.mails || []).filter(function (x) { return x.id !== id; }); jrec({ k: 'maildel', id: id }); save(); poke(); }
  function fetchMailAtt(mailId, idx) {
    var m = mailById(mailId); if (!m) return Promise.reject(new Error('gone'));
    var a = (m.atts || [])[idx]; if (!a) return Promise.reject(new Error('gone'));
    if (a.dataB64) return Promise.resolve(dataUrlOf(a));
    var bu = a.blobRelay ? normRelay(a.blobRelay) : myPrimary();
    var src = a.inline ? Promise.resolve(unb64(a.inline)) : blobDownload(bu, a.blob);
    return src.then(function (cipher) {
      var plain;
      if (a.key) { try { plain = nacl.secretbox.open(cipher.slice(24), cipher.slice(0, 24), hexToBytes(a.key)); } catch (e) { plain = null; } }
      else plain = decBytesFrom(cipher, hexToBytes(m.peer));
      if (!plain) throw new Error('decrypt');
      if (plain.length <= KEEP_LOCAL_MAX) { a.dataB64 = b64(plain); delete a.inline; save(); }
      return dataUrlOf(a, plain);
    });
  }

  /* ================= STORAGE MARKET =================
     The user rents replica space on 1-5 relays; the wallet replicates the encrypted
     journal there, audits monthly, and pays by signed USDC voucher (EIP-191, see eth.js).
     The payment key is secp256k1, deliberately unlinked from the R2R identity. */
  var VAULT_ADDR = '';   // compiled-in R2RStorageVault address — EMPTY until the contract is deployed
  function market() { return ST && ST.market || { rpc: '', rentals: [] }; }
  function setMarketRpc(url) { ST.market.rpc = String(url || '').trim(); save(); poke(); }
  function marketStatusOf(url) {
    var ctl = (typeof AbortController !== 'undefined') ? new AbortController() : null;
    var to = setTimeout(function () { if (ctl) ctl.abort(); }, 6000);
    return fetch(httpBase(url) + '/status.json', ctl ? { signal: ctl.signal } : {})
      .then(function (r) { if (!r.ok) throw 0; return r.json(); })
      .then(function (j) { clearTimeout(to); return j; })
      .catch(function () { clearTimeout(to); return null; });
  }
  function httpOfAddress(addr) {
    // peers advertise "host:port"; over an https page only TLS relays are reachable
    var scheme = (location.protocol === 'https:') ? 'https://' : 'http://';
    return scheme + addr;
  }
  function marketDirectory() {
    var p = myPrimary();
    var own = p ? marketStatusOf(p).then(function (j) { return j ? [{ url: p, address: advertiseOf(p), status: j }] : []; }) : Promise.resolve([]);
    var peers = p ? fetch(httpBase(p) + '/peers.json').then(function (r) { return r.ok ? r.json() : null; }).catch(function () { return null; }) : Promise.resolve(null);
    return Promise.all([own, peers]).then(function (res) {
      var rows = res[0] || [];
      var list = (res[1] && (res[1].peers || res[1])) || [];
      if (!Array.isArray(list)) list = [];
      var jobs = list.slice(0, 16).map(function (pe) {
        var addr = typeof pe === 'string' ? pe : (pe.address || pe.advertise || '');
        if (!addr) return Promise.resolve(null);
        var base = typeof pe === 'object' && pe.base ? pe.base : '';
        var u = httpOfAddress(addr) + base;
        return marketStatusOf(u).then(function (j) { return j ? { url: normRelay(u), address: addr, status: j, nodeId: (typeof pe === 'object' && (pe.node_id || pe.nodeId)) || (j.node_id || '') } : null; });
      });
      return Promise.all(jobs).then(function (extra) {
        extra.forEach(function (x) { if (x) rows.push(x); });
        // only relays that actually sell
        return rows.filter(function (r) { return r.status && r.status.market && (r.status.market.enabled === undefined || r.status.market.enabled); })
          .map(function (r) {
            var mk = r.status.market;
            return {
              url: r.url, address: r.address, nodeId: r.nodeId || r.status.node_id || '',
              priceGbEpochMicro: mk.price_gb_epoch_micro, epochDays: mk.epoch_days || 31,
              availableBytes: mk.available_bytes, poolBytes: mk.pool_bytes, committedBytes: mk.committed_bytes,
              payout: mk.payout || '', vault: mk.vault || '', chainId: mk.chain_id || null
            };
          });
      });
    });
  }
  /* replica-diversity check against existing rentals: never share payout / host / /16 */
  function diversityIssues(row) {
    var issues = [];
    var host = String(row.address || '').replace(/:.*$/, '');
    var ip16 = /^\d+\.\d+\./.test(host) ? host.split('.').slice(0, 2).join('.') : null;
    market().rentals.forEach(function (r) {
      if (r.ended) return;
      if (row.payout && r.payout && row.payout.toLowerCase() === r.payout.toLowerCase()) issues.push('same payout address as an existing replica');
      var h2 = String(r.addr || '').replace(/:.*$/, '');
      if (host && h2 === host) issues.push('same host as an existing replica');
      if (ip16 && /^\d+\.\d+\./.test(h2) && h2.split('.').slice(0, 2).join('.') === ip16) issues.push('same /16 network as an existing replica');
    });
    return issues;
  }
  function rentOn(url, mb) {
    if (!ID) return Promise.resolve({ err: 'Unlock first' });
    var bytes = Math.round(Number(mb) * 1048576);
    if (!(bytes >= 1048576)) return Promise.resolve({ err: 'Minimum 1 MB' });
    if (market().rentals.filter(function (r) { return !r.ended; }).length >= 5) return Promise.resolve({ err: 'Max 5 replicas' });
    var payPriv = E().genPriv();
    var payAddr = E().addressOf(payPriv);
    return oneShot(url, ID.kp).then(function (api) {
      return api.rpc({ t: 'rent', bytes: bytes, payment_key: payAddr }, ['rent_ok'], 20000).then(function (m) {
        api.close();
        if (VAULT_ADDR && m.vault && String(m.vault).toLowerCase() !== VAULT_ADDR.toLowerCase()) {
          return { err: 'This relay names a different vault contract than the one compiled into this wallet — refusing to rent.' };
        }
        var r = {
          id: m.rental, url: normRelay(url), addr: advertiseOf(url), nodeId: metaOf(url).nodeId || '',
          bytes: m.bytes || bytes, priceEpochMicro: m.price_epoch_micro, epochDays: m.epoch_days || 31,
          paidUntil: (m.paid_until || 0) * (m.paid_until > 1e12 ? 1 : 1000),
          payout: m.payout || '', vault: m.vault || '', chainId: m.chain_id || null,
          payPriv: payPriv, payAddr: payAddr, bestCum: 0, rseq: 0, created: Date.now()
        };
        ST.market.rentals.push(r); save(); poke();
        setTimeout(function () { replicateTo(r); }, 500);
        return { ok: true, rental: r.id, priceEpochMicro: r.priceEpochMicro, vaultKnown: !!VAULT_ADDR };
      });
    }).catch(function (e) {
      var msg = String(e.message || e);
      if (/market_off/.test(msg)) msg = 'This relay does not sell storage';
      if (/market_full/.test(msg)) msg = 'This relay has no space left';
      return { err: msg };
    });
  }
  function rentalById(id) { return market().rentals.filter(function (r) { return r.id === id; })[0] || null; }
  function endRental(id) { var r = rentalById(id); if (r) { r.ended = true; save(); poke(); } }
  var _replT = null;
  function schedReplicate() { if (_replT) return; _replT = setTimeout(function () { _replT = null; market().rentals.forEach(function (r) { if (!r.ended) replicateTo(r); }); }, 5000); }
  function replicateTo(r) {
    // ferry my journal records (opaque ciphertext) from the primary to the rented replica
    var p = myPrimary(); if (!connReady(p) || r._busy) return Promise.resolve(0);
    r._busy = true;
    var copied = 0;
    var pull = function (since) {
      return req(p, { t: 'journal_read', since: since, max: 100 }, ['journal']).then(function (m) {
        var list = m.entries || [];
        if (!list.length) return { list: [], more: false };
        return { list: list, more: !!m.more };
      });
    };
    return oneShot(r.url, ID.kp).then(function (api) {
      var loop = function () {
        return pull(r.rseq | 0).then(function (d) {
          if (!d.list.length) return copied;
          var chain = Promise.resolve();
          d.list.forEach(function (it) {
            chain = chain.then(function () {
              return api.rpc({ t: 'journal_append', data: it.data }, ['journal_ok']).then(function () { r.rseq = it.seq | 0; copied++; });
            });
          });
          return chain.then(function () { save(); return d.more ? loop() : copied; });
        });
      };
      return loop().then(function (n) { api.close(); r._busy = false; r.lastReplicate = Date.now(); save(); poke(); return n; });
    }).catch(function () { r._busy = false; return copied; });
  }
  function auditRental(r) {
    // read a random sample back from the replica and verify it decrypts with MY journal key
    return oneShot(r.url, ID.kp).then(function (api) {
      var since = Math.max(0, Math.floor(Math.random() * Math.max(1, (r.rseq | 0) - 3)));
      return api.rpc({ t: 'journal_read', since: since, max: 3 }, ['journal'], 15000).then(function (m) {
        api.close();
        var list = m.entries || [];
        if (!list.length) return { ok: (r.rseq | 0) === 0, empty: true };
        var good = list.some(function (it) { return !!unsbox(it.data, jkey()); });
        return { ok: good };
      });
    }).catch(function (e) { return { ok: false, err: e.message || 'unreachable' }; });
  }
  function signAndSendVoucher(r) {
    if (!r.payout || !r.vault || !r.chainId) return Promise.resolve({ err: 'Rental is missing payout/vault/chain data' });
    var cum = (r.bestCum || 0) + (r.priceEpochMicro || 0);
    var hash = E().voucherHash(r.vault, r.chainId, r.payout, cum);
    if (!hash) return Promise.resolve({ err: 'Bad payout or vault address' });
    var sig = E().personalSign(hash, r.payPriv);
    return oneShot(r.url, ID.kp).then(function (api) {
      return api.rpc({ t: 'voucher', rental: r.id, payment_key: r.payAddr, payout: r.payout, cumulative_micro: cum, sig: sig }, ['voucher_ok'], 20000).then(function (m) {
        api.close();
        r.bestCum = m.cumulative_micro || cum;
        if (m.paid_until) r.paidUntil = m.paid_until * (m.paid_until > 1e12 ? 1 : 1000);
        r.lastVoucher = Date.now(); save(); poke();
        return { ok: true, paidUntil: r.paidUntil, cumulative: r.bestCum };
      });
    }).catch(function (e) { return { err: e.message || 'voucher refused' }; });
  }
  function runRentalCycle(force) {
    if (!ID || !ST) return Promise.resolve([]);
    var due = market().rentals.filter(function (r) {
      if (r.ended) return false;
      if (force) return true;
      var margin = 7 * 86400000;
      return !r.paidUntil || (r.paidUntil - Date.now()) < margin;
    });
    var results = [];
    var chain = Promise.resolve();
    market().rentals.forEach(function (r) { if (!r.ended) chain = chain.then(function () { return replicateTo(r); }); });
    due.forEach(function (r) {
      chain = chain.then(function () {
        return auditRental(r).then(function (a) {
          r.lastAudit = Date.now(); r.lastAuditOk = !!a.ok; save();
          if (!a.ok) { results.push({ rental: r.id, addr: r.addr, err: 'audit failed — do NOT pay; re-rent this replica elsewhere' }); poke(); return null; }
          return signAndSendVoucher(r).then(function (v) { results.push({ rental: r.id, addr: r.addr, ok: !v.err, err: v.err, paidUntil: v.paidUntil }); });
        });
      });
    });
    return chain.then(function () { poke(); return results; });
  }
  /* best-effort on-chain reads (registry age / lifetime earnings); needs an RPC url in settings */
  function chainInfo(payout) {
    var rpc = market().rpc;
    if (!rpc || !VAULT_ADDR || !payout) return Promise.resolve(null);
    var sel = E().selector('lifetimeEarned(address)');
    return E().ethCall(rpc, VAULT_ADDR, sel + E().encAddr(payout)).then(function (res) {
      return { lifetimeEarnedMicro: res && res !== '0x' ? Number(BigInt(res)) : 0 };
    }).catch(function () { return null; });
  }

  /* ---- QR / invites (contact invites, unchanged) ---- */
  function qrInto(el, text, size) { if (!el) return; el.innerHTML = ''; try { new QRCode(el, { text: text, width: size || 200, height: size || 200, correctLevel: QRCode.CorrectLevel.M }); } catch (e) { } }
  function invite() { var r = ST.relays[0] ? '?relay=' + encodeURIComponent(ST.relays[0]) : ''; return 'r2r:' + ID.addr + r; }
  function makeProtectedInvite(pin) {
    pin = String(pin || ''); if (pin.length < 6) return { err: 'Use at least 6 characters — two words are better' };
    var salt = nacl.randomBytes(16);
    return { ok: true, text: 'R2REI1:' + toHex(salt) + ':' + sbox(invite(), kdf(pin, salt)) };
  }
  function isProtectedInvite(t) { return /^R2REI1:[0-9a-fA-F]{32}:.+$/i.test(String(t || '').trim()); }
  function openProtectedInvite(text, pin) {
    var m = String(text || '').trim().match(/^R2REI1:([0-9a-fA-F]{32}):(.+)$/i); if (!m) return null;
    return unsbox(m[2], kdf(String(pin || ''), hexToBytes(m[1])));
  }
  var _scan = null;
  async function startScan(videoEl, onResult) {
    var getEl = typeof videoEl === 'function' ? videoEl : function () { return videoEl; };
    if (!window.isSecureContext && !(location.protocol === 'file:')) return { err: 'The camera needs a secure page (https:// or a local file). Paste the code instead.' };
    if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) return { err: 'This browser does not allow camera access here. Paste the code instead.' };
    var stream;
    try {
      stream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: { ideal: 'environment' }, width: { ideal: 1280 }, height: { ideal: 720 } } });
    } catch (e) {
      var n = e && e.name;
      if (n === 'NotAllowedError' || n === 'SecurityError') return { err: 'Camera permission was denied — allow it in the browser settings for this page, then try again.' };
      if (n === 'NotFoundError' || n === 'OverconstrainedError') { try { stream = await navigator.mediaDevices.getUserMedia({ video: true }); } catch (e2) { return { err: 'No usable camera found. Paste the code instead.' }; } }
      else if (n === 'NotReadableError') return { err: 'The camera is busy in another app — close it and try again.' };
      else return { err: 'Camera unavailable (' + (n || 'unknown') + '). Paste the code instead.' };
    }
    try {
      var det = null;
      if ('BarcodeDetector' in window) {
        try {
          var fmts = await Promise.race([BarcodeDetector.getSupportedFormats(), new Promise(function (r) { setTimeout(function () { r(null); }, 1200); })]);
          if (fmts && fmts.indexOf('qr_code') >= 0) det = new BarcodeDetector({ formats: ['qr_code'] });
        } catch (e) { det = null; }
      }
      if (!det && !window.jsQR) { stream.getTracks().forEach(function (t) { t.stop(); }); return { err: 'This browser cannot scan QR codes. Paste the code instead.' }; }
      var canvas = null, cctx = null;
      if (window.jsQR) { canvas = document.createElement('canvas'); cctx = canvas.getContext('2d', { willReadFrequently: true }); }
      var el = getEl(), tries = 0;
      while (!el && tries++ < 40) { await new Promise(function (r) { setTimeout(r, 50); }); el = getEl(); }
      if (!el) { stream.getTracks().forEach(function (t) { t.stop(); }); return { err: 'Camera view was not ready — try again.' }; }
      var attach = function (v) {
        if (!v) return;
        if (v.srcObject !== stream) { v.muted = true; v.setAttribute('muted', ''); v.setAttribute('playsinline', ''); v.setAttribute('autoplay', ''); v.srcObject = stream; }
        if (v.paused) v.play().catch(function () { });
      };
      attach(el);
      _scan = { stream: stream, busy: false, detBusy: false, frames: 0, vw: 0, vh: 0, native: !!det, detAnswers: 0, iv: setInterval(function () {
        var v = getEl(); attach(v); if (!v || !_scan || v.readyState < 2) return;
        _scan.vw = v.videoWidth; _scan.vh = v.videoHeight; _scan.native = !!det;
        if (det && !_scan.detBusy) {
          _scan.detBusy = true;
          try {
            det.detect(v).then(function (codes) {
              if (_scan) { _scan.detBusy = false; _scan.detAnswers++; }
              if (_scan && codes && codes.length && codes[0].rawValue) { var val = codes[0].rawValue; stopScan(); onResult(val); }
            }, function () { if (_scan) _scan.detBusy = false; });
          } catch (e) { if (_scan) _scan.detBusy = false; }
        }
        if (cctx && v.videoWidth && !_scan.busy) {
          _scan.busy = true; _scan.frames++;
          try {
            var sc = Math.min(1, 1024 / Math.max(v.videoWidth, v.videoHeight));
            var w = Math.round(v.videoWidth * sc), h = Math.round(v.videoHeight * sc);
            if (canvas.width !== w || canvas.height !== h) { canvas.width = w; canvas.height = h; }
            cctx.drawImage(v, 0, 0, w, h);
            var d = cctx.getImageData(0, 0, w, h);
            var code = window.jsQR(d.data, w, h, { inversionAttempts: 'attemptBoth' });
            if (code && code.data) { stopScan(); onResult(code.data); return; }
          } catch (e) { }
          if (_scan) _scan.busy = false;
        }
      }, 400) };
      return { ok: true };
    } catch (e) { try { stream.getTracks().forEach(function (t) { t.stop(); }); } catch (e2) { } return { err: 'Camera unavailable' }; }
  }
  function stopScan() { if (_scan) { try { clearInterval(_scan.iv); } catch (e) { } try { _scan.stream.getTracks().forEach(function (t) { t.stop(); }); } catch (e) { } _scan = null; } }

  /* ---- periodic ---- */
  var _iv2 = null;
  function setInterval2() {
    if (_iv2) return;
    _iv2 = setInterval(function () { if (ID) { poke(); refreshStats(); refreshUsage(); connectAll(); jFlush(); } }, 30000);
    setInterval(function () { if (ID) runRentalCycle(); }, 6 * 3600000);
  }

  function genKeyHex() { return toHex(nacl.randomBytes(32)); }

  return {
    on: on, toast: toast,
    hasVault: hasVault, createVault: createVault, unlock: unlock, lock: lock, forget: forget,
    genKeyHex: genKeyHex, seedFromInput: seedFromInput, pinCheck: pinCheck,
    me: function () { return ID ? { addr: ID.addr, pub: ID.pubHex, fp: ID.fp, name: ST.name || '' } : null; },
    setName: function (n) { ST.name = String(n || '').trim(); jrec({ k: 'name', name: ST.name }); save(); poke(); },
    exportKeyHex: function () { return ID ? toHex(ID.seed) : null; },
    fpOf: fpOf,
    contacts: function () { return ST ? ST.contacts.slice() : []; },
    addContact: addContact, removeContact: removeContact, renameContact: renameContact, nameOf: nameOf,
    parseContactInput: parseContactInput, shortAddr: shortAddr,
    thread: function (p) { return ST && ST.threads[p] ? ST.threads[p].slice() : []; },
    sendText: sendText, sendFile: sendFile, sendMedia: sendMedia, fetchAttachment: fetchAttachment, markRead: markRead, unreadOf: unreadOf,
    mails: function () { return (ST && ST.mails || []).slice(); },
    sendMail: sendMail, markMailRead: markMailRead, deleteMail: deleteMail, fetchMailAtt: fetchMailAtt,
    groups: function () { var g = groupsAll(), out = []; for (var k in g) out.push(g[k]); return out; },
    groupOf: groupOf, createGroup: createGroup, updateGroup: updateGroup, deleteGroup: deleteGroup,
    isGroupKey: isGKey, groupKey: gkey, myPub: function () { return ID ? ID.pubHex : null; },
    groupCallMax: GCALL_MAX, groupMax: GROUP_MAX,
    presenceOf: presenceOf, relayInfo: function () { return RELAYINFO; }, relays: relays, setRelays: setRelays, reconnect: connect, relayOfPub: relayOfPub, testRelay: testRelay,
    relayDownloadsUrl: relayDownloadsUrl, relayMetaOf: metaOf,
    locateNow: locateNow, gatherNow: gatherNow,
    claimInvite: claimInvite, setupWithInvite: setupWithInvite, parseInviteCode: parseInviteCode, myInvites: myInvites, inviteShareUrl: inviteShareUrl,
    inviteStatus: inviteStatus, refreshInviteStatus: refreshInviteStatus,
    call: callInfo, ring: ringInfo, startCall: startCall, answerCall: answerCall, declineCall: declineCall, endCall: endCall,
    toggleMute: toggleMute, toggleCam: toggleCam, toggleScreen: toggleScreen, listDevices: listDevices, switchDevice: switchDevice,
    hasRemoteVideo: hasRemoteVideo, callLog: function () { return ST ? ST.callLog.slice() : []; },
    backupPayload: backupPayload, restoreFromBackup: restoreFromBackup,
    parseSetupCard: parseSetupCard, setupFromCard: setupFromCard, migrateJournal: migrateJournal, changePin: changePin,
    cardKey: function () { try { return localStorage.getItem('r2r1_pepper') || null; } catch (e) { return null; } },
    syncEnabled: function () { return ST ? !ST.syncOff : true; }, setSyncEnabled: setSyncEnabled,
    onionEnabled: onionOn, setOnionEnabled: setOnionEnabled, onionLevel: onionLevel, setOnionLevel: setOnionLevel,
    onionInfo: function () { return { enabled: onionOn(), last: ONIONSTAT.last, relaysKnown: _onDir.list.length, waiting: ST ? ST.outbox.filter(function (o) { return o.via === 'onion'; }).length : 0 }; },
    _onion: { seal: onionSeal, sealMulti: onionSealMulti, build: onionBuild, gcm: aesGcmEncrypt, hkdf: hkdf32, scrypt: function (pw, salt, N, r, p, n) { return scrypt(pw, salt, N, r, p, n); } },
    syncNow: function () { return jPull().then(function (n) { jFlush(); refreshUsage(); return n; }); },
    adminAccounts: adminAccounts, adminSearchAccounts: adminSearchAccounts, adminSetQuota: adminSetQuota, adminSetTtl: adminSetTtl,
    adminDeleteAccount: adminDeleteAccount, adminMintInvites: adminMintInvites, adminListInvites: adminListInvites,
    adminRevokeInvite: adminRevokeInvite, adminSetAdvertise: adminSetAdvertise, adminListRentals: adminListRentals, adminListVouchers: adminListVouchers,
    market: function () { var m = market(); return { rpc: m.rpc, vaultAddr: VAULT_ADDR, rentals: m.rentals.map(function (r) { var c = {}; for (var k in r) if (k !== 'payPriv' && k.charAt(0) !== '_') c[k] = r[k]; return c; }) }; },
    setMarketRpc: setMarketRpc, marketDirectory: marketDirectory, diversityIssues: diversityIssues,
    rentOn: rentOn, endRental: endRental, runRentalCycle: runRentalCycle, chainInfo: chainInfo,
    qrInto: qrInto, invite: invite, startScan: startScan, stopScan: stopScan,
    scanStatus: function () { if (!_scan) return null; return { w: _scan.vw | 0, h: _scan.vh | 0, frames: _scan.frames | 0, native: !!_scan.native, detAnswers: _scan.detAnswers | 0, hasJsQR: !!window.jsQR }; },
    makeProtectedInvite: makeProtectedInvite, isProtectedInvite: isProtectedInvite, openProtectedInvite: openProtectedInvite
  };
})();
