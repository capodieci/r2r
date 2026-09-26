#!/usr/bin/env python3
# R2R relay - zero-dependency reference implementation of RELAY-SPEC.md (v1).
# Run:  python3 relay-server.py          (Python 3.8+, stdlib only)
# Env:  PORT=8787  DATA_DIR=./r2r-relay-data  BLOB_TTL_DAYS=30  QUEUE_TTL_DAYS=30
#       DEFAULT_QUOTA_MB=1  TURN_URL=turn:1.2.3.4:3478  TURN_USER=u  TURN_PASS=p
# Everything stored on disk is end-to-end ciphertext.
# Note: ed25519 auth is verified in pure Python (~50-150 ms per request) -
# perfectly fine for a personal relay, not for high traffic.
import base64, hashlib, json, os, re, secrets, socket, threading, time

PORT = int(os.environ.get('PORT', '8787'))
DATA = os.environ.get('DATA_DIR', './r2r-relay-data')
BLOB_TTL_DAYS = float(os.environ.get('BLOB_TTL_DAYS', '30'))
QUEUE_TTL = float(os.environ.get('QUEUE_TTL_DAYS', '30')) * 86400
DEFAULT_QUOTA_MB = float(os.environ.get('DEFAULT_QUOTA_MB', '1'))
MAX_BLOB = 17 * 1024 * 1024
MAX_PAYLOAD = 64 * 1024
MAX_EVENT = 600 * 1024
QUEUE_CAP = 500
SENDS_PER_MIN = 60
START = time.time()

for sub in ('queue', 'blobs', 'accounts'):
    os.makedirs(os.path.join(DATA, sub), exist_ok=True)
AK_FILE = os.path.join(DATA, 'admin.key')
ADMIN_KEY = ''
try:
    ADMIN_KEY = open(AK_FILE).read().strip()
except OSError:
    pass
if not re.fullmatch(r'[0-9a-f]{64}', ADMIN_KEY or ''):
    ADMIN_KEY = secrets.token_hex(32)
    with open(AK_FILE, 'w') as f:
        f.write(ADMIN_KEY + '\n')
    os.chmod(AK_FILE, 0o600)

# pre-auth per-IP limiter - checked BEFORE signature verification (the pure-Python
# ed25519 verify costs ~50-150 ms, so forged-signature floods are a cheap CPU DoS).
IP_REQS_PER_MIN = int(os.environ.get('IP_REQS_PER_MIN', '240'))
IPRATE = {}
IPRATE_LOCK = threading.Lock()
def ip_ok(sock):
    try: ip = sock.getpeername()[0]
    except OSError: return True
    if ip in ('127.0.0.1', '::1', '::ffff:127.0.0.1'): return True
    now = time.time()
    with IPRATE_LOCK:
        a = [t for t in IPRATE.get(ip, []) if now - t < 60]
        if len(a) >= IP_REQS_PER_MIN:
            IPRATE[ip] = a; return False
        a.append(now); IPRATE[ip] = a
    return True

# ---------- pure-python ed25519 verify (RFC 8032) ----------
P = 2**255 - 19
Q_ORD = 2**252 + 27742317777372353535851937790883648493
def _inv(x): return pow(x, P - 2, P)
D = -121665 * _inv(121666) % P
I = pow(2, (P - 1) // 4, P)
def _xrecover(y):
    xx = (y * y - 1) * _inv(D * y * y + 1)
    x = pow(xx, (P + 3) // 8, P)
    if (x * x - xx) % P: x = x * I % P
    if x % 2: x = P - x
    return x
B_PT = (_xrecover(4 * _inv(5) % P), 4 * _inv(5) % P)
def _add(a, b):
    (x1, y1), (x2, y2) = a, b
    den1 = _inv(1 + D * x1 * x2 * y1 * y2)
    den2 = _inv(1 - D * x1 * x2 * y1 * y2)
    return ((x1 * y2 + x2 * y1) * den1 % P, (y1 * y2 + x1 * x2) * den2 % P)
def _mul(pt, e):
    q = (0, 1)
    while e:
        if e & 1: q = _add(q, pt)
        pt = _add(pt, pt)
        e >>= 1
    return q
def _decode(s):
    y = int.from_bytes(s, 'little') & ((1 << 255) - 1)
    x = _xrecover(y)
    if x & 1 != s[31] >> 7: x = P - x
    if (-x * x + y * y - 1 - D * x * x * y * y) % P: raise ValueError
    return (x, y)
def ed25519_verify(pub_hex, msg, sig_hex):
    try:
        pub = bytes.fromhex(pub_hex); sig = bytes.fromhex(sig_hex)
        if len(pub) != 32 or len(sig) != 64: return False
        a = _decode(pub); r = _decode(sig[:32])
        s = int.from_bytes(sig[32:], 'little')
        if s >= Q_ORD: return False
        h = int.from_bytes(hashlib.sha512(sig[:32] + pub + msg).digest(), 'little') % Q_ORD
        return _mul(B_PT, s) == _add(r, _mul(a, h))
    except Exception:
        return False

def verify_auth(q):
    pub = (q.get('pub') or '').lower()
    if not re.fullmatch(r'[0-9a-f]{64}', pub): return None
    try: ts = int(q.get('ts') or '0')
    except ValueError: return None
    if not ts or abs(time.time() - ts) > 600: return None
    return pub if ed25519_verify(pub, b'R2R-AUTH|' + str(ts).encode(), q.get('sig') or '') else None

# ---------- accounts / quota / ttl ----------
def acct_dir(pub, sub=''): return os.path.join(DATA, 'accounts', pub, sub)
def acct_quota_bytes(pub):
    try:
        mb = float(open(acct_dir(pub, 'quota')).read())
        return -1 if mb < 0 else mb * 1048576
    except Exception:
        return DEFAULT_QUOTA_MB * 1048576
def acct_ttl_days(pub):
    try:
        d = float(open(acct_dir(pub, 'ttl')).read())
        return -1 if d < 0 else d
    except Exception:
        return BLOB_TTL_DAYS
def acct_used(pub):
    t = 0
    try:
        jd = acct_dir(pub, 'journal')
        for f in os.listdir(jd): t += os.path.getsize(os.path.join(jd, f))
    except OSError: pass
    return t
def next_seq(pub):
    jd = acct_dir(pub, 'journal'); os.makedirs(jd, exist_ok=True)
    mx = 0
    for f in os.listdir(jd):
        try: mx = max(mx, int(f))
        except ValueError: pass
    return mx + 1

# ---------- queue ----------
QLOCK = threading.Lock()
def q_file(pub): return os.path.join(DATA, 'queue', pub + '.json')
def q_load(pub):
    try: return json.load(open(q_file(pub)))
    except Exception: return []
def q_save(pub, lst):
    try:
        if not lst: os.path.exists(q_file(pub)) and os.remove(q_file(pub))
        else: json.dump(lst, open(q_file(pub), 'w'))
    except OSError: pass
def q_push(pub, item):
    with QLOCK:
        l = q_load(pub)
        if any(x['id'] == item['id'] for x in l): return
        l.append(item)
        while len(l) > QUEUE_CAP: l.pop(0)
        q_save(pub, l)
def q_drop(pub, mid):
    with QLOCK:
        l = q_load(pub)
        n = [x for x in l if x['id'] != mid]
        if len(n) != len(l): q_save(pub, n)
        return next((x for x in l if x['id'] == mid), None)

# ---------- live state ----------
G = threading.Lock()
SOCKS = {}      # pub -> WsConn
WATCHERS = {}   # watched pub -> set(watcher pubs)
LASTSEEN = {}
RATE = {}
STATS = {'msgs': 0, 'sigs': 0, 'in': 0, 'out': 0}

def rate_ok(pub):
    now = time.time()
    a = [t for t in RATE.get(pub, []) if now - t < 60]
    if len(a) >= SENDS_PER_MIN: return False
    a.append(now); RATE[pub] = a
    return True

def presence_of(pub):
    c = SOCKS.get(pub)
    return (c.pres if c else 'offline')
def push_presence(pub):
    with G:
        watchers = list(WATCHERS.get(pub, ()))
        frame = json.dumps({'type': 'presence', 'pub': pub, 'state': presence_of(pub), 'seen': LASTSEEN.get(pub, 0)})
        conns = [SOCKS[w] for w in watchers if w in SOCKS]
    for c in conns: c.send_raw(frame)

# ---------- WebSocket ----------
WS_GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11'
class WsConn:
    def __init__(self, sock, pub):
        self.sock = sock; self.pub = pub; self.pres = 'online'
        self.watching = set(); self.wlock = threading.Lock(); self.dead = False
    def send_raw(self, text):
        data = text.encode()
        n = len(data)
        if n < 126: head = bytes([0x81, n])
        elif n < 65536: head = bytes([0x81, 126]) + n.to_bytes(2, 'big')
        else: head = bytes([0x81, 127]) + n.to_bytes(8, 'big')
        try:
            with self.wlock: self.sock.sendall(head + data)
        except OSError: self.dead = True
    def send(self, obj): self.send_raw(json.dumps(obj))

def ws_serve(sock, pub, key):
    accept = base64.b64encode(hashlib.sha1((key + WS_GUID).encode()).digest()).decode()
    sock.sendall(('HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n'
                  'Sec-WebSocket-Accept: ' + accept + '\r\n\r\n').encode())
    conn = WsConn(sock, pub)
    with G:
        old = SOCKS.get(pub)
        SOCKS[pub] = conn
        LASTSEEN[pub] = int(time.time() * 1000)
    if old:
        try: old.sock.close()
        except OSError: pass
    push_presence(pub)
    for m in q_load(pub):
        conn.send({'type': 'msg', 'id': m['id'], 'from': m['from'], 'ts': m['ts'], 'payload': m['payload']})
    buf = b''
    try:
        while not conn.dead:
            need = 2
            while len(buf) < need:
                d = sock.recv(65536)
                if not d: raise OSError
                buf += d
            op = buf[0] & 0x0f; masked = buf[1] & 0x80; ln = buf[1] & 0x7f; off = 2
            if ln == 126:
                need = 4
                while len(buf) < need: buf += _recv1(sock)
                ln = int.from_bytes(buf[2:4], 'big'); off = 4
            elif ln == 127:
                need = 10
                while len(buf) < need: buf += _recv1(sock)
                ln = int.from_bytes(buf[2:10], 'big'); off = 10
            if ln > 1024 * 1024: raise OSError
            total = off + (4 if masked else 0) + ln
            while len(buf) < total: buf += _recv1(sock)
            if masked:
                mask = buf[off:off + 4]
                data = bytes(b ^ mask[i & 3] for i, b in enumerate(buf[off + 4:total]))
            else:
                data = buf[off:total]
            buf = buf[total:]
            if op == 8: break
            if op == 9:  # ping -> pong
                with conn.wlock:
                    sock.sendall(bytes([0x8a, len(data)]) + data)
                continue
            if op != 1: continue
            try: m = json.loads(data.decode())
            except Exception: continue
            handle_msg(conn, m)
    except OSError:
        pass
    finally:
        with G:
            if SOCKS.get(pub) is conn:
                del SOCKS[pub]
                LASTSEEN[pub] = int(time.time() * 1000)
            for w in conn.watching:
                s = WATCHERS.get(w)
                if s: s.discard(pub);  (not s) and WATCHERS.pop(w, None)
        push_presence(pub)
        try: sock.close()
        except OSError: pass

def _recv1(sock):
    d = sock.recv(65536)
    if not d: raise OSError
    return d

def handle_msg(conn, m):
    t = m.get('type')
    if t == 'ping': conn.send({'type': 'pong'}); return
    if t == 'presence':
        conn.pres = 'away' if m.get('state') == 'away' else 'online'
        push_presence(conn.pub); return
    if t == 'watch':
        with G:
            for w in conn.watching:
                s = WATCHERS.get(w)
                if s: s.discard(conn.pub)
            conn.watching = set()
            pubs = [str(p or '').lower() for p in (m.get('pubs') or [])][:5000]
            for p2 in pubs:
                if not re.fullmatch(r'[0-9a-f]{64}', p2): continue
                conn.watching.add(p2)
                WATCHERS.setdefault(p2, set()).add(conn.pub)
        for p2 in conn.watching:
            conn.send({'type': 'presence', 'pub': p2, 'state': presence_of(p2), 'seen': LASTSEEN.get(p2, 0)})
        return
    if t == 'send':
        to = str(m.get('to') or '').lower(); mid = str(m.get('id') or ''); pay = m.get('payload')
        if not re.fullmatch(r'[0-9a-f]{64}', to) or not re.fullmatch(r'[0-9a-f]{4,32}', mid): return
        if not isinstance(pay, str) or len(pay) > MAX_PAYLOAD: return
        if not rate_ok(conn.pub):
            conn.send({'type': 'sent', 'id': mid, 'queued': False, 'error': 'rate'}); return
        item = {'id': mid, 'from': conn.pub, 'to': to, 'ts': int(time.time() * 1000), 'payload': pay}
        rc = SOCKS.get(to)
        q_push(to, item)   # queue first - delete on ack, so delivery survives a drop
        if rc: rc.send({'type': 'msg', 'id': mid, 'from': conn.pub, 'ts': item['ts'], 'payload': pay})
        STATS['msgs'] += 1
        conn.send({'type': 'sent', 'id': mid, 'queued': not rc})
        return
    if t == 'ack':
        hit = q_drop(conn.pub, str(m.get('id') or ''))
        if hit:
            snd = SOCKS.get(hit['from'])
            if snd: snd.send({'type': 'delivered', 'id': hit['id']})
        return
    if t == 'sig':
        to = str(m.get('to') or '').lower(); pay = m.get('payload')
        if not re.fullmatch(r'[0-9a-f]{64}', to) or not isinstance(pay, str) or len(pay) > MAX_PAYLOAD: return
        rc = SOCKS.get(to)
        if rc: rc.send({'type': 'sig', 'from': conn.pub, 'payload': pay}); STATS['sigs'] += 1
        return

# ---------- HTTP ----------
CORS = 'Access-Control-Allow-Origin: *\r\nAccess-Control-Allow-Methods: GET,POST,OPTIONS\r\nAccess-Control-Allow-Headers: *\r\n'
def http_json(sock, code, obj):
    body = json.dumps(obj).encode()
    reason = {200: 'OK', 204: 'No Content', 400: 'Bad Request', 401: 'Unauthorized', 402: 'Payment Required', 404: 'Not Found', 413: 'Payload Too Large', 500: 'Internal Server Error'}.get(code, 'OK')
    head = 'HTTP/1.1 %d %s\r\n%sContent-Type: application/json\r\nContent-Length: %d\r\nConnection: close\r\n\r\n' % (code, reason, CORS, len(body))
    try: sock.sendall(head.encode() + body)
    except OSError: pass

def parse_query(url):
    q = {}
    if '?' in url:
        for part in url.split('?', 1)[1].split('&'):
            k, _, v = part.partition('=')
            try: q[k] = bytes(v.replace('+', ' '), 'utf8').decode()
            except Exception: q[k] = v
            import urllib.parse
            q[k] = urllib.parse.unquote(v)
    return q

def blob_write_exp(pub, blob_id):
    # per-blob expiry: TTL follows the uploading account (owner-adjustable); never shortened
    ttl = acct_ttl_days(pub)
    exp_f = os.path.join(DATA, 'blobs', blob_id + '.exp')
    prev = None
    try: prev = open(exp_f).read().strip()
    except OSError: pass
    new = -1 if ttl < 0 else int(time.time() * 1000 + ttl * 86400e3)
    if prev == '-1': return
    if prev is not None and new >= 0:
        try:
            if float(prev) >= new: return
        except ValueError: pass
    with open(exp_f, 'w') as f: f.write(str(new))

def handle_http(sock, req_head, body_reader):
    line = req_head.split('\r\n', 1)[0]
    parts = line.split(' ')
    if len(parts) < 2: sock.close(); return
    method, url = parts[0], parts[1]
    route = url.split('?', 1)[0]
    q = parse_query(url)
    if method == 'OPTIONS':
        try: sock.sendall(('HTTP/1.1 204 No Content\r\n' + CORS + 'Connection: close\r\n\r\n').encode())
        except OSError: pass
        sock.close(); return
    if route == '/info':
        try: queued = len(os.listdir(os.path.join(DATA, 'queue')))
        except OSError: queued = 0
        http_json(sock, 200, {'name': 'r2r-relay', 'version': 1, 'ws': '/ws', 'maxBlob': MAX_BLOB, 'queued': queued}); sock.close(); return
    if route == '/stats':
        bd = os.path.join(DATA, 'blobs')
        bb = bn = 0
        try:
            for f in os.listdir(bd):
                if f.endswith('.exp'): continue
                bn += 1; bb += os.path.getsize(os.path.join(bd, f))
        except OSError: pass
        try: qn = len(os.listdir(os.path.join(DATA, 'queue')))
        except OSError: qn = 0
        http_json(sock, 200, {'uptimeSec': int(time.time() - START), 'online': len(SOCKS), 'msgsRelayed': STATS['msgs'], 'sigsForwarded': STATS['sigs'], 'queuedMsgs': qn, 'blobs': bn, 'blobBytes': bb}); sock.close(); return
    pub = verify_auth(q)
    if route == '/credit':
        if not pub: http_json(sock, 401, {'error': 'auth'}); sock.close(); return
        http_json(sock, 200, {'mb': float(os.environ.get('CREDIT_MB', '999999'))}); sock.close(); return
    if route == '/ice':
        if not pub: http_json(sock, 401, {'error': 'auth'}); sock.close(); return
        ice = [{'urls': 'stun:stun.l.google.com:19302'}]
        if os.environ.get('TURN_URL'):
            ice.append({'urls': os.environ['TURN_URL'], 'username': os.environ.get('TURN_USER', ''), 'credential': os.environ.get('TURN_PASS', '')})
        http_json(sock, 200, {'iceServers': ice, 'ttl': 600}); sock.close(); return
    if route == '/blob' and method == 'POST':
        if not pub: http_json(sock, 401, {'error': 'auth'}); sock.close(); return
        body = body_reader(MAX_BLOB)
        if body is None: http_json(sock, 413, {'error': 'too_big'}); sock.close(); return
        blob_id = hashlib.sha256(body).hexdigest()[:32]
        with open(os.path.join(DATA, 'blobs', blob_id), 'wb') as f: f.write(body)
        blob_write_exp(pub, blob_id)
        http_json(sock, 200, {'id': blob_id}); sock.close(); return
    if route.startswith('/blob/') and method == 'GET':
        if not pub: http_json(sock, 401, {'error': 'auth'}); sock.close(); return
        blob_id = route[6:]
        if not re.fullmatch(r'[0-9a-f]{32}', blob_id): http_json(sock, 400, {'error': 'bad_id'}); sock.close(); return
        fpath = os.path.join(DATA, 'blobs', blob_id)
        if not os.path.exists(fpath): http_json(sock, 404, {'error': 'gone'}); sock.close(); return
        size = os.path.getsize(fpath)
        try:
            sock.sendall(('HTTP/1.1 200 OK\r\n' + CORS + 'Content-Type: application/octet-stream\r\nContent-Length: %d\r\nConnection: close\r\n\r\n' % size).encode())
            with open(fpath, 'rb') as f:
                while True:
                    chunk = f.read(65536)
                    if not chunk: break
                    sock.sendall(chunk)
        except OSError: pass
        sock.close(); return
    if route == '/journal' and method == 'POST':
        if not pub: http_json(sock, 401, {'error': 'auth'}); sock.close(); return
        body = body_reader(MAX_EVENT)
        if body is None: http_json(sock, 413, {'error': 'too_big'}); sock.close(); return
        if not re.fullmatch(rb'[\x20-\x7e]*', body): http_json(sock, 400, {'error': 'binary'}); sock.close(); return
        quota = acct_quota_bytes(pub)
        if quota >= 0 and acct_used(pub) + len(body) > quota:
            http_json(sock, 402, {'error': 'quota'}); sock.close(); return
        seq = next_seq(pub)
        with open(os.path.join(acct_dir(pub, 'journal'), str(seq).zfill(10)), 'wb') as f: f.write(body)
        http_json(sock, 200, {'seq': seq}); sock.close(); return
    if route == '/journal' and method == 'GET':
        if not pub: http_json(sock, 401, {'error': 'auth'}); sock.close(); return
        try: since = int(q.get('since') or '0')
        except ValueError: since = 0
        jd = acct_dir(pub, 'journal')
        try: names = os.listdir(jd)
        except OSError: names = []
        seqs = sorted(int(n) for n in names if n.isdigit() and int(n) > since)
        out, total = [], 0
        for s in seqs:
            if len(out) >= 200 or total > 2 * 1024 * 1024: break
            try:
                d = open(os.path.join(jd, str(s).zfill(10))).read()
                out.append({'seq': s, 'd': d}); total += len(d)
            except OSError: pass
        http_json(sock, 200, out); sock.close(); return
    if route == '/usage' and method == 'GET':
        if not pub: http_json(sock, 401, {'error': 'auth'}); sock.close(); return
        http_json(sock, 200, {'usedBytes': acct_used(pub), 'quotaBytes': acct_quota_bytes(pub), 'ttlDays': acct_ttl_days(pub)}); sock.close(); return
    if route.startswith('/admin/'):
        akm = re.search(r'(?im)^x-admin-key:[ \t]*(\S+)', req_head)
        if not ADMIN_KEY or not akm or akm.group(1) != ADMIN_KEY: http_json(sock, 401, {'error': 'admin'}); sock.close(); return
        if route == '/admin/accounts':
            try: pubs = [p for p in os.listdir(os.path.join(DATA, 'accounts')) if re.fullmatch(r'[0-9a-f]{64}', p)]
            except OSError: pubs = []
            http_json(sock, 200, [{'pub': p, 'usedBytes': acct_used(p), 'quotaBytes': acct_quota_bytes(p), 'ttlDays': acct_ttl_days(p)} for p in pubs]); sock.close(); return
        if route == '/admin/quota' and method == 'POST':
            p2 = (q.get('pub') or '').lower(); mb = q.get('mb') or ''
            if not re.fullmatch(r'[0-9a-f]{64}', p2) or mb == '': http_json(sock, 400, {'error': 'args'}); sock.close(); return
            os.makedirs(acct_dir(p2), exist_ok=True)
            open(acct_dir(p2, 'quota'), 'w').write(mb)
            http_json(sock, 200, {'ok': True}); sock.close(); return
        if route == '/admin/ttl' and method == 'POST':
            p2 = (q.get('pub') or '').lower(); days = q.get('days') or ''
            try: float(days)
            except ValueError: days = ''
            if not re.fullmatch(r'[0-9a-f]{64}', p2) or days == '': http_json(sock, 400, {'error': 'args'}); sock.close(); return
            os.makedirs(acct_dir(p2), exist_ok=True)
            open(acct_dir(p2, 'ttl'), 'w').write(days)
            http_json(sock, 200, {'ok': True}); sock.close(); return
        http_json(sock, 404, {'error': 'not_found'}); sock.close(); return
    http_json(sock, 404, {'error': 'not_found'}); sock.close()

def conn_thread(sock):
    sock.settimeout(30)
    buf = b''
    try:
        while b'\r\n\r\n' not in buf:
            d = sock.recv(65536)
            if not d: sock.close(); return
            buf += d
            if len(buf) > 32768: sock.close(); return
    except OSError:
        sock.close(); return
    head, _, rest = buf.partition(b'\r\n\r\n')
    head_s = head.decode('latin1')
    line = head_s.split('\r\n', 1)[0]
    url = line.split(' ')[1] if len(line.split(' ')) > 1 else '/'
    route = url.split('?', 1)[0]
    if not ip_ok(sock):
        try: sock.sendall(b'HTTP/1.1 429 Too Many Requests\r\nContent-Length: 0\r\n\r\n')
        except OSError: pass
        sock.close(); return
    m = re.search(r'(?i)upgrade:\s*websocket', head_s)
    if route == '/ws' and m:
        pub = verify_auth(parse_query(url))
        km = re.search(r'(?i)sec-websocket-key:\s*(\S+)', head_s)
        if not pub or not km:
            try: sock.sendall(b'HTTP/1.1 401 Unauthorized\r\n\r\n')
            except OSError: pass
            sock.close(); return
        sock.settimeout(None)
        ws_serve(sock, pub, km.group(1))
        return
    cl = re.search(r'(?i)content-length:\s*(\d+)', head_s)
    length = int(cl.group(1)) if cl else 0
    body_buf = [rest]
    def body_reader(cap):
        if length <= 0 or length > cap: return None if length > cap else b''
        have = body_buf[0]
        try:
            while len(have) < length:
                d = sock.recv(65536)
                if not d: return None
                have += d
        except OSError:
            return None
        return have[:length]
    handle_http(sock, head_s, body_reader)

def sweeper():
    while True:
        time.sleep(3600)
        now = time.time() * 1000
        with IPRATE_LOCK:
            cut = time.time() - 60
            for k in [k for k, a in list(IPRATE.items()) if not any(t > cut for t in a)]: del IPRATE[k]
        bd = os.path.join(DATA, 'blobs')
        try:
            for f in os.listdir(bd):
                if f.endswith('.exp'): continue
                p = os.path.join(bd, f); xf = p + '.exp'
                exp = None
                try: exp = float(open(xf).read())
                except Exception: pass
                try:
                    if exp is not None:
                        if exp >= 0 and now > exp:
                            os.remove(p); os.path.exists(xf) and os.remove(xf)
                    elif now - os.path.getmtime(p) * 1000 > BLOB_TTL_DAYS * 86400e3:
                        os.remove(p); os.path.exists(xf) and os.remove(xf)
                except OSError: pass
        except OSError: pass
        try:
            for f in os.listdir(os.path.join(DATA, 'queue')):
                pub = f[:-5]
                with QLOCK:
                    q_save(pub, [x for x in q_load(pub) if now / 1000 - x['ts'] / 1000 < QUEUE_TTL])
        except OSError: pass

def main():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(('0.0.0.0', PORT)); srv.listen(64)
    print('R2R relay listening on :%d  (data: %s)' % (PORT, DATA))
    print('ADMIN KEY — copy this into the wallet (Settings → Relay owner) to manage per-identity storage & file lifetimes:')
    print('  %s' % ADMIN_KEY)
    print('  (kept in %s/admin.key — printed at every start; delete that file + restart for a new one. Default quota: %g MB/account)' % (DATA, DEFAULT_QUOTA_MB))
    threading.Thread(target=sweeper, daemon=True).start()
    while True:
        try: c, _ = srv.accept()
        except OSError: continue
        threading.Thread(target=conn_thread, args=(c,), daemon=True).start()

if __name__ == '__main__':
    main()
