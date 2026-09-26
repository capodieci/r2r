// Minimal R2R client for the OLD relay protocol: ed25519 auth + raw WebSocket.
// Used to test whether cross-relay delivery works without changing the server.
'use strict';
const crypto = require('crypto');
const http = require('http');

function newIdentity() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const der = publicKey.export({ format: 'der', type: 'spki' });
  const pub = der.subarray(der.length - 32).toString('hex');
  return { pub, privateKey };
}

function authQuery(id) {
  const ts = Math.floor(Date.now() / 1000);
  const sig = crypto.sign(null, Buffer.from('R2R-AUTH|' + ts), id.privateKey).toString('hex');
  return `pub=${id.pub}&ts=${ts}&sig=${sig}`;
}

function connect(port, id, onFrame) {
  return new Promise((resolve, reject) => {
    const key = crypto.randomBytes(16).toString('base64');
    const req = http.request({
      port, path: '/ws?' + authQuery(id), method: 'GET',
      headers: {
        Connection: 'Upgrade', Upgrade: 'websocket',
        'Sec-WebSocket-Key': key, 'Sec-WebSocket-Version': '13',
      },
    });
    req.on('upgrade', (res, sock) => {
      sock.setNoDelay(true);
      let buf = Buffer.alloc(0);
      sock.on('data', d => {
        buf = Buffer.concat([buf, d]);
        for (;;) {
          if (buf.length < 2) return;
          const op = buf[0] & 0x0f;
          let len = buf[1] & 0x7f, off = 2;
          if (len === 126) { if (buf.length < 4) return; len = buf.readUInt16BE(2); off = 4; }
          else if (len === 127) { if (buf.length < 10) return; len = Number(buf.readBigUInt64BE(2)); off = 10; }
          if (buf.length < off + len) return;
          const data = buf.subarray(off, off + len);
          buf = buf.subarray(off + len);
          if (op !== 1) continue;  // text frames only
          try { onFrame(JSON.parse(data.toString('utf8'))); } catch (e) { /* non-JSON */ }
        }
      });
      sock.on('error', () => {});
      resolve({
        send(obj) {
          const p = Buffer.from(JSON.stringify(obj));
          const mask = crypto.randomBytes(4);
          const n = p.length;
          let head;
          if (n < 126) head = Buffer.from([0x81, 0x80 | n]);
          else { head = Buffer.alloc(4); head[0] = 0x81; head[1] = 0x80 | 126; head.writeUInt16BE(n, 2); }
          const masked = Buffer.from(p);
          for (let i = 0; i < masked.length; i++) masked[i] ^= mask[i & 3];
          sock.write(Buffer.concat([head, mask, masked]));
        },
        close() { try { sock.destroy(); } catch (e) {} },
      });
    });
    req.on('response', r => reject(new Error('upgrade refused: HTTP ' + r.statusCode)));
    req.on('error', reject);
    req.end();
  });
}

module.exports = { newIdentity, authQuery, connect };
