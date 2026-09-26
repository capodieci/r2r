<?php
/* R2R relay - zero-dependency reference implementation of RELAY-SPEC.md (v1).
 * Run:  php relay-server.php            (PHP 8.0+ CLI, bundled sodium extension)
 * Env:  PORT=8787  DATA_DIR=./r2r-relay-data  BLOB_TTL_DAYS=30  QUEUE_TTL_DAYS=30
 *       DEFAULT_QUOTA_MB=1  TURN_URL=turn:1.2.3.4:3478  TURN_USER=u  TURN_PASS=p
 *       IP_REQS_PER_MIN=240  (pre-auth per-IP limiter; loopback exempt)
 * Everything stored on disk is end-to-end ciphertext.
 * Single-process stream_select() event loop: HTTP + WebSocket on one port. */
error_reporting(E_ALL & ~E_DEPRECATED);
if (!function_exists('sodium_crypto_sign_verify_detached')) { fwrite(STDERR, "PHP sodium extension required (bundled since PHP 7.2)\n"); exit(1); }

$PORT = (int)(getenv('PORT') ?: 8787);
$DATA = getenv('DATA_DIR') ?: './r2r-relay-data';
$BLOB_TTL_DAYS = (float)(getenv('BLOB_TTL_DAYS') ?: 30);
$QUEUE_TTL = (float)(getenv('QUEUE_TTL_DAYS') ?: 30) * 86400;
$DEFAULT_QUOTA_MB = (float)(getenv('DEFAULT_QUOTA_MB') ?: 1);
const MAX_BLOB = 17825792; const MAX_PAYLOAD = 65536; const MAX_EVENT = 614400;
const QUEUE_CAP = 500; const SENDS_PER_MIN = 60;
$IP_REQS_PER_MIN = (int)(getenv('IP_REQS_PER_MIN') ?: 240); $IPRATE = [];
$START = time();

foreach (['queue', 'blobs', 'accounts'] as $sub) @mkdir("$DATA/$sub", 0755, true);
$AK_FILE = "$DATA/admin.key";
$ADMIN_KEY = trim(@file_get_contents($AK_FILE) ?: '');
if (!preg_match('/^[0-9a-f]{64}$/', $ADMIN_KEY)) {
  $ADMIN_KEY = bin2hex(random_bytes(32));
  file_put_contents($AK_FILE, $ADMIN_KEY . "\n"); @chmod($AK_FILE, 0600);
}

/* pre-auth per-IP limiter - checked BEFORE signature verification (anti CPU-flood) */
function ip_ok($sock) {
  global $IPRATE, $IP_REQS_PER_MIN;
  $peer = @stream_socket_get_name($sock, true) ?: '';
  $ip = ($p = strrpos($peer, ':')) !== false ? substr($peer, 0, $p) : $peer;
  if ($ip === '' || $ip === '127.0.0.1' || $ip === '::1' || $ip === '[::1]') return true;
  if (count($IPRATE) > 4096) $IPRATE = [];   /* crude cap so the table can't grow unbounded */
  $now = time();
  $a = array_values(array_filter($IPRATE[$ip] ?? [], fn($t) => $now - $t < 60));
  if (count($a) >= $IP_REQS_PER_MIN) { $IPRATE[$ip] = $a; return false; }
  $a[] = $now; $IPRATE[$ip] = $a; return true;
}

/* ---------- auth ---------- */
function verify_auth($q) {
  $pub = strtolower($q['pub'] ?? '');
  if (!preg_match('/^[0-9a-f]{64}$/', $pub)) return null;
  $ts = (int)($q['ts'] ?? 0);
  if (!$ts || abs(time() - $ts) > 600) return null;
  $sig = @hex2bin($q['sig'] ?? '');
  if ($sig === false || strlen($sig) !== 64) return null;
  try { return sodium_crypto_sign_verify_detached($sig, 'R2R-AUTH|' . $ts, hex2bin($pub)) ? $pub : null; }
  catch (Throwable $e) { return null; }
}
function parse_query($url) {
  $q = []; $i = strpos($url, '?');
  if ($i !== false) parse_str(substr($url, $i + 1), $q);
  return $q;
}

/* ---------- accounts / quota / ttl ---------- */
function acct_dir($pub, $sub = '') { global $DATA; return "$DATA/accounts/$pub" . ($sub !== '' ? "/$sub" : ''); }
function acct_quota_bytes($pub) {
  global $DEFAULT_QUOTA_MB;
  $v = @file_get_contents(acct_dir($pub, 'quota'));
  if ($v !== false && is_numeric(trim($v))) { $mb = (float)$v; return $mb < 0 ? -1 : $mb * 1048576; }
  return $DEFAULT_QUOTA_MB * 1048576;
}
function acct_ttl_days($pub) {
  global $BLOB_TTL_DAYS;
  $v = @file_get_contents(acct_dir($pub, 'ttl'));
  if ($v !== false && is_numeric(trim($v))) { $d = (float)$v; return $d < 0 ? -1 : $d; }
  return $BLOB_TTL_DAYS;
}
function acct_used($pub) {
  $t = 0;
  foreach (@scandir(acct_dir($pub, 'journal')) ?: [] as $f)
    if ($f[0] !== '.') $t += @filesize(acct_dir($pub, 'journal') . "/$f");
  return $t;
}
function next_seq($pub) {
  @mkdir(acct_dir($pub, 'journal'), 0755, true);
  $mx = 0;
  foreach (@scandir(acct_dir($pub, 'journal')) ?: [] as $f)
    if ($f[0] !== '.' && (int)$f > $mx) $mx = (int)$f;
  return $mx + 1;
}

/* ---------- queue ---------- */
function q_file($pub) { global $DATA; return "$DATA/queue/$pub.json"; }
function q_load($pub) { $j = @json_decode(@file_get_contents(q_file($pub)) ?: '', true); return is_array($j) ? $j : []; }
function q_save($pub, $l) { if (!$l) @unlink(q_file($pub)); else @file_put_contents(q_file($pub), json_encode($l)); }
function q_push($pub, $item) {
  $l = q_load($pub);
  foreach ($l as $x) if ($x['id'] === $item['id']) return;
  $l[] = $item;
  while (count($l) > QUEUE_CAP) array_shift($l);
  q_save($pub, $l);
}

/* ---------- live state ---------- */
$CLIENTS = [];   // id => ['sock','buf','mode'=>'http'|'ws','pub','pres','watching'=>[],'need'=>N]
$SOCKS = [];     // pub => client id
$WATCHERS = [];  // watched pub => [watcher pub => true]
$LASTSEEN = [];
$RATE = [];
$STATS = ['msgs' => 0, 'sigs' => 0];

function rate_ok($pub) {
  global $RATE;
  $now = time();
  $a = array_values(array_filter($RATE[$pub] ?? [], fn($t) => $now - $t < 60));
  if (count($a) >= SENDS_PER_MIN) return false;
  $a[] = $now; $RATE[$pub] = $a;
  return true;
}
function presence_of($pub) { global $SOCKS, $CLIENTS; $id = $SOCKS[$pub] ?? null; return $id !== null ? ($CLIENTS[$id]['pres'] ?? 'online') : 'offline'; }
function push_presence($pub) {
  global $WATCHERS, $SOCKS, $CLIENTS, $LASTSEEN;
  $frame = json_encode(['type' => 'presence', 'pub' => $pub, 'state' => presence_of($pub), 'seen' => $LASTSEEN[$pub] ?? 0]);
  foreach (array_keys($WATCHERS[$pub] ?? []) as $w) {
    $id = $SOCKS[$w] ?? null;
    if ($id !== null) ws_send_raw($CLIENTS[$id]['sock'], $frame);
  }
}

/* ---------- WebSocket framing ---------- */
function ws_send_raw($sock, $text) {
  $n = strlen($text);
  if ($n < 126) $head = chr(0x81) . chr($n);
  elseif ($n < 65536) $head = chr(0x81) . chr(126) . pack('n', $n);
  else $head = chr(0x81) . chr(127) . pack('J', $n);
  @fwrite($sock, $head . $text);
}
function ws_send($sock, $obj) { ws_send_raw($sock, json_encode($obj)); }
function ws_read_frame(&$buf, &$err) {
  $err = false;
  $len = strlen($buf);
  if ($len < 2) return null;
  $op = ord($buf[0]) & 0x0f;
  $masked = (ord($buf[1]) & 0x80) !== 0;
  $ln = ord($buf[1]) & 0x7f; $off = 2;
  if ($ln === 126) { if ($len < 4) return null; $ln = unpack('n', substr($buf, 2, 2))[1]; $off = 4; }
  elseif ($ln === 127) { if ($len < 10) return null; $ln = unpack('J', substr($buf, 2, 8))[1]; $off = 10; }
  if ($ln > 1048576) { $err = true; return null; }
  $total = $off + ($masked ? 4 : 0) + $ln;
  if ($len < $total) return null;
  $data = substr($buf, $off + ($masked ? 4 : 0), $ln);
  if ($masked) {
    $mask = substr($buf, $off, 4);
    $data = $data ^ str_pad('', $ln, $mask);
  }
  $buf = substr($buf, $total);
  return ['op' => $op, 'data' => $data];
}

/* ---------- WS protocol ---------- */
function handle_ws_msg($id, $m) {
  global $CLIENTS, $SOCKS, $WATCHERS, $LASTSEEN, $STATS;
  $c = &$CLIENTS[$id];
  $sock = $c['sock']; $pub = $c['pub'];
  $t = $m['type'] ?? '';
  if ($t === 'ping') { ws_send($sock, ['type' => 'pong']); return; }
  if ($t === 'presence') { $c['pres'] = ($m['state'] ?? '') === 'away' ? 'away' : 'online'; push_presence($pub); return; }
  if ($t === 'watch') {
    foreach ($c['watching'] as $w => $_) unset($WATCHERS[$w][$pub]);
    $c['watching'] = [];
    foreach (array_slice((array)($m['pubs'] ?? []), 0, 5000) as $p2) {
      $p2 = strtolower((string)$p2);
      if (!preg_match('/^[0-9a-f]{64}$/', $p2)) continue;
      $c['watching'][$p2] = true;
      $WATCHERS[$p2][$pub] = true;
      ws_send($sock, ['type' => 'presence', 'pub' => $p2, 'state' => presence_of($p2), 'seen' => $LASTSEEN[$p2] ?? 0]);
    }
    return;
  }
  if ($t === 'send') {
    $to = strtolower((string)($m['to'] ?? '')); $mid = (string)($m['id'] ?? ''); $pay = $m['payload'] ?? null;
    if (!preg_match('/^[0-9a-f]{64}$/', $to) || !preg_match('/^[0-9a-f]{4,32}$/', $mid)) return;
    if (!is_string($pay) || strlen($pay) > MAX_PAYLOAD) return;
    if (!rate_ok($pub)) { ws_send($sock, ['type' => 'sent', 'id' => $mid, 'queued' => false, 'error' => 'rate']); return; }
    $item = ['id' => $mid, 'from' => $pub, 'to' => $to, 'ts' => (int)(microtime(true) * 1000), 'payload' => $pay];
    q_push($to, $item);   /* queue first - delete on ack, so delivery survives a drop */
    $rcId = $SOCKS[$to] ?? null;
    if ($rcId !== null) ws_send($CLIENTS[$rcId]['sock'], ['type' => 'msg', 'id' => $mid, 'from' => $pub, 'ts' => $item['ts'], 'payload' => $pay]);
    $STATS['msgs']++;
    ws_send($sock, ['type' => 'sent', 'id' => $mid, 'queued' => $rcId === null]);
    return;
  }
  if ($t === 'ack') {
    $mid = (string)($m['id'] ?? '');
    $l = q_load($pub); $hit = null;
    foreach ($l as $x) if ($x['id'] === $mid) { $hit = $x; break; }
    if ($hit) {
      q_save($pub, array_values(array_filter($l, fn($x) => $x['id'] !== $mid)));
      $sndId = $SOCKS[$hit['from']] ?? null;
      if ($sndId !== null) ws_send($CLIENTS[$sndId]['sock'], ['type' => 'delivered', 'id' => $mid]);
    }
    return;
  }
  if ($t === 'sig') {
    $to = strtolower((string)($m['to'] ?? '')); $pay = $m['payload'] ?? null;
    if (!preg_match('/^[0-9a-f]{64}$/', $to) || !is_string($pay) || strlen($pay) > MAX_PAYLOAD) return;
    $rcId = $SOCKS[$to] ?? null;
    if ($rcId !== null) { ws_send($CLIENTS[$rcId]['sock'], ['type' => 'sig', 'from' => $pub, 'payload' => $pay]); $STATS['sigs']++; }
    return;
  }
}

/* ---------- HTTP ---------- */
const CORS = "Access-Control-Allow-Origin: *\r\nAccess-Control-Allow-Methods: GET,POST,OPTIONS\r\nAccess-Control-Allow-Headers: *\r\n";
function http_json($sock, $code, $obj) {
  $reasons = [200 => 'OK', 204 => 'No Content', 400 => 'Bad Request', 401 => 'Unauthorized', 402 => 'Payment Required', 404 => 'Not Found', 413 => 'Payload Too Large', 500 => 'Internal Server Error'];
  $body = json_encode($obj);
  @fwrite($sock, "HTTP/1.1 $code " . ($reasons[$code] ?? 'OK') . "\r\n" . CORS . "Content-Type: application/json\r\nContent-Length: " . strlen($body) . "\r\nConnection: close\r\n\r\n" . $body);
}
function blob_write_exp($pub, $id) {
  global $DATA;
  /* per-blob expiry: TTL follows the uploading account (owner-adjustable); never shortened */
  $ttl = acct_ttl_days($pub);
  $xf = "$DATA/blobs/$id.exp";
  $prev = @file_get_contents($xf);
  $prev = $prev === false ? null : trim($prev);
  $new = $ttl < 0 ? -1 : (int)(microtime(true) * 1000 + $ttl * 86400000);
  if ($prev === '-1') return;
  if ($prev !== null && $new >= 0 && is_numeric($prev) && (float)$prev >= $new) return;
  @file_put_contents($xf, (string)$new);
}
function handle_http($id, $method, $url, $body, $head) {
  global $CLIENTS, $DATA, $ADMIN_KEY, $START, $SOCKS, $STATS;
  $sock = $CLIENTS[$id]['sock'];
  $route = explode('?', $url)[0];
  $q = parse_query($url);
  if ($method === 'OPTIONS') { @fwrite($sock, "HTTP/1.1 204 No Content\r\n" . CORS . "Connection: close\r\n\r\n"); return;
  }
  if ($route === '/info') {
    $queued = count(array_diff(@scandir("$DATA/queue") ?: [], ['.', '..']));
    http_json($sock, 200, ['name' => 'r2r-relay', 'version' => 1, 'ws' => '/ws', 'maxBlob' => MAX_BLOB, 'queued' => $queued]); return;
  }
  if ($route === '/stats') {
    $bn = 0; $bb = 0;
    foreach (@scandir("$DATA/blobs") ?: [] as $f) {
      if ($f[0] === '.' || str_ends_with($f, '.exp')) continue;
      $bn++; $bb += @filesize("$DATA/blobs/$f");
    }
    $qn = count(array_diff(@scandir("$DATA/queue") ?: [], ['.', '..']));
    http_json($sock, 200, ['uptimeSec' => time() - $START, 'online' => count($SOCKS), 'msgsRelayed' => $STATS['msgs'], 'sigsForwarded' => $STATS['sigs'], 'queuedMsgs' => $qn, 'blobs' => $bn, 'blobBytes' => $bb]); return;
  }
  $pub = verify_auth($q);
  if ($route === '/credit') {
    if (!$pub) { http_json($sock, 401, ['error' => 'auth']); return; }
    http_json($sock, 200, ['mb' => (float)(getenv('CREDIT_MB') ?: 999999)]); return;
  }
  if ($route === '/ice') {
    if (!$pub) { http_json($sock, 401, ['error' => 'auth']); return; }
    $ice = [['urls' => 'stun:stun.l.google.com:19302']];
    if (getenv('TURN_URL')) $ice[] = ['urls' => getenv('TURN_URL'), 'username' => getenv('TURN_USER') ?: '', 'credential' => getenv('TURN_PASS') ?: ''];
    http_json($sock, 200, ['iceServers' => $ice, 'ttl' => 600]); return;
  }
  if ($route === '/blob' && $method === 'POST') {
    if (!$pub) { http_json($sock, 401, ['error' => 'auth']); return; }
    $id2 = substr(hash('sha256', $body), 0, 32);
    file_put_contents("$DATA/blobs/$id2", $body);
    blob_write_exp($pub, $id2);
    http_json($sock, 200, ['id' => $id2]); return;
  }
  if (str_starts_with($route, '/blob/') && $method === 'GET') {
    if (!$pub) { http_json($sock, 401, ['error' => 'auth']); return; }
    $id2 = substr($route, 6);
    if (!preg_match('/^[0-9a-f]{32}$/', $id2)) { http_json($sock, 400, ['error' => 'bad_id']); return; }
    $f = "$DATA/blobs/$id2";
    if (!file_exists($f)) { http_json($sock, 404, ['error' => 'gone']); return; }
    @fwrite($sock, "HTTP/1.1 200 OK\r\n" . CORS . "Content-Type: application/octet-stream\r\nContent-Length: " . filesize($f) . "\r\nConnection: close\r\n\r\n");
    $fp = fopen($f, 'rb');
    while (!feof($fp)) { $chunk = fread($fp, 65536); if ($chunk === false || @fwrite($sock, $chunk) === false) break; }
    fclose($fp); return;
  }
  if ($route === '/journal' && $method === 'POST') {
    if (!$pub) { http_json($sock, 401, ['error' => 'auth']); return; }
    if (!preg_match('/^[\x20-\x7e]*$/', $body)) { http_json($sock, 400, ['error' => 'binary']); return; }
    $quota = acct_quota_bytes($pub);
    if ($quota >= 0 && acct_used($pub) + strlen($body) > $quota) { http_json($sock, 402, ['error' => 'quota']); return; }
    $seq = next_seq($pub);
    file_put_contents(acct_dir($pub, 'journal') . '/' . str_pad((string)$seq, 10, '0', STR_PAD_LEFT), $body);
    http_json($sock, 200, ['seq' => $seq]); return;
  }
  if ($route === '/journal' && $method === 'GET') {
    if (!$pub) { http_json($sock, 401, ['error' => 'auth']); return; }
    $since = (int)($q['since'] ?? 0);
    $seqs = [];
    foreach (@scandir(acct_dir($pub, 'journal')) ?: [] as $f)
      if ($f[0] !== '.' && (int)$f > $since) $seqs[] = (int)$f;
    sort($seqs);
    $out = []; $total = 0;
    foreach ($seqs as $s) {
      if (count($out) >= 200 || $total > 2097152) break;
      $d = @file_get_contents(acct_dir($pub, 'journal') . '/' . str_pad((string)$s, 10, '0', STR_PAD_LEFT));
      if ($d !== false) { $out[] = ['seq' => $s, 'd' => $d]; $total += strlen($d); }
    }
    http_json($sock, 200, $out); return;
  }
  if ($route === '/usage' && $method === 'GET') {
    if (!$pub) { http_json($sock, 401, ['error' => 'auth']); return; }
    http_json($sock, 200, ['usedBytes' => acct_used($pub), 'quotaBytes' => acct_quota_bytes($pub), 'ttlDays' => acct_ttl_days($pub)]); return;
  }
  if (str_starts_with($route, '/admin/')) {
    $ak = preg_match('/^x-admin-key:[ \t]*(\S+)/im', $head, $akm) ? $akm[1] : '';
    if (!$ADMIN_KEY || $ak !== $ADMIN_KEY) { http_json($sock, 401, ['error' => 'admin']); return; }
    if ($route === '/admin/accounts') {
      $out = [];
      foreach (@scandir("$DATA/accounts") ?: [] as $p)
        if (preg_match('/^[0-9a-f]{64}$/', $p)) $out[] = ['pub' => $p, 'usedBytes' => acct_used($p), 'quotaBytes' => acct_quota_bytes($p), 'ttlDays' => acct_ttl_days($p)];
      http_json($sock, 200, $out); return;
    }
    if ($route === '/admin/quota' && $method === 'POST') {
      $p2 = strtolower($q['pub'] ?? ''); $mb = $q['mb'] ?? '';
      if (!preg_match('/^[0-9a-f]{64}$/', $p2) || $mb === '' || !is_numeric($mb)) { http_json($sock, 400, ['error' => 'args']); return; }
      @mkdir(acct_dir($p2), 0755, true);
      file_put_contents(acct_dir($p2, 'quota'), $mb);
      http_json($sock, 200, ['ok' => true]); return;
    }
    if ($route === '/admin/ttl' && $method === 'POST') {
      $p2 = strtolower($q['pub'] ?? ''); $days = $q['days'] ?? '';
      if (!preg_match('/^[0-9a-f]{64}$/', $p2) || $days === '' || !is_numeric($days)) { http_json($sock, 400, ['error' => 'args']); return; }
      @mkdir(acct_dir($p2), 0755, true);
      file_put_contents(acct_dir($p2, 'ttl'), $days);
      http_json($sock, 200, ['ok' => true]); return;
    }
    http_json($sock, 404, ['error' => 'not_found']); return;
  }
  http_json($sock, 404, ['error' => 'not_found']);
}

/* ---------- event loop ---------- */
function drop_client($id) {
  global $CLIENTS, $SOCKS, $WATCHERS, $LASTSEEN;
  if (!isset($CLIENTS[$id])) return;
  $c = $CLIENTS[$id];
  if (($c['mode'] ?? '') === 'ws' && isset($c['pub'])) {
    $pub = $c['pub'];
    if (($SOCKS[$pub] ?? null) === $id) {
      unset($SOCKS[$pub]);
      $LASTSEEN[$pub] = (int)(microtime(true) * 1000);
      foreach ($c['watching'] ?? [] as $w => $_) { unset($WATCHERS[$w][$id]); unset($WATCHERS[$w][$pub]); if (empty($WATCHERS[$w])) unset($WATCHERS[$w]); }
      push_presence($pub);
    }
  }
  @fclose($c['sock']);
  unset($CLIENTS[$id]);
}

$srv = stream_socket_server("tcp://0.0.0.0:$PORT", $errno, $errstr);
if (!$srv) { fwrite(STDERR, "bind failed: $errstr\n"); exit(1); }
echo "R2R relay listening on :$PORT  (data: $DATA)\n";
echo "ADMIN KEY — copy this into the wallet (Settings → Relay owner) to manage per-identity storage & file lifetimes:\n";
echo "  $ADMIN_KEY\n";
echo "  (kept in $DATA/admin.key — printed at every start; delete that file + restart for a new one. Default quota: {$DEFAULT_QUOTA_MB} MB/account)\n";
$nextId = 1; $lastSweep = time();

while (true) {
  $read = [$srv];
  foreach ($CLIENTS as $c) $read[] = $c['sock'];
  $write = null; $except = null;
  if (@stream_select($read, $write, $except, 5) === false) continue;

  foreach ($read as $sock) {
    if ($sock === $srv) {
      $c = @stream_socket_accept($srv, 0);
      if ($c) { stream_set_blocking($c, false); $CLIENTS[$nextId] = ['sock' => $c, 'buf' => '', 'mode' => 'http', 'watching' => []]; $nextId++; }
      continue;
    }
    $id = null;
    foreach ($CLIENTS as $cid => $c) if ($c['sock'] === $sock) { $id = $cid; break; }
    if ($id === null) continue;
    $data = @fread($sock, 262144);
    if ($data === '' || $data === false) {
      if (feof($sock)) drop_client($id);
      continue;
    }
    $CLIENTS[$id]['buf'] .= $data;
    $c = &$CLIENTS[$id];

    if ($c['mode'] === 'ws') {
      while (true) {
        $err = false;
        $fr = ws_read_frame($c['buf'], $err);
        if ($err) { drop_client($id); break; }
        if ($fr === null) break;
        if ($fr['op'] === 8) { drop_client($id); break; }
        if ($fr['op'] === 9) { @fwrite($c['sock'], chr(0x8a) . chr(strlen($fr['data'])) . $fr['data']); continue; }
        if ($fr['op'] !== 1) continue;
        $m = json_decode($fr['data'], true);
        if (is_array($m)) handle_ws_msg($id, $m);
        if (!isset($CLIENTS[$id])) break;
      }
      continue;
    }

    /* HTTP mode: wait for full head, then full body */
    if (strlen($c['buf']) > MAX_BLOB + 65536) { drop_client($id); continue; }
    $he = strpos($c['buf'], "\r\n\r\n");
    if ($he === false) { if (strlen($c['buf']) > 32768) drop_client($id); continue; }
    $head = substr($c['buf'], 0, $he);
    if (!ip_ok($sock)) { @fwrite($sock, "HTTP/1.1 429 Too Many Requests\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"); drop_client($id); continue; }
    $line = explode("\r\n", $head)[0];
    $parts = explode(' ', $line);
    if (count($parts) < 2) { drop_client($id); continue; }
    [$method, $url] = $parts;
    $route = explode('?', $url)[0];

    if ($route === '/ws' && preg_match('/upgrade:\s*websocket/i', $head)) {
      $pub = verify_auth(parse_query($url));
      if (!$pub || !preg_match('/sec-websocket-key:\s*(\S+)/i', $head, $km)) {
        @fwrite($sock, "HTTP/1.1 401 Unauthorized\r\n\r\n"); drop_client($id); continue;
      }
      $accept = base64_encode(sha1($km[1] . '258EAFA5-E914-47DA-95CA-C5AB0DC85B11', true));
      @fwrite($sock, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: $accept\r\n\r\n");
      $old = $SOCKS[$pub] ?? null;
      if ($old !== null && $old !== $id) drop_client($old);
      $c['mode'] = 'ws'; $c['pub'] = $pub; $c['pres'] = 'online'; $c['buf'] = substr($c['buf'], $he + 4);
      $SOCKS[$pub] = $id;
      $LASTSEEN[$pub] = (int)(microtime(true) * 1000);
      push_presence($pub);
      foreach (q_load($pub) as $m) ws_send($sock, ['type' => 'msg', 'id' => $m['id'], 'from' => $m['from'], 'ts' => $m['ts'], 'payload' => $m['payload']]);
      continue;
    }

    $clen = preg_match('/content-length:\s*(\d+)/i', $head, $cm) ? (int)$cm[1] : 0;
    $cap = $route === '/blob' ? MAX_BLOB : MAX_EVENT;
    if ($clen > $cap) { http_json($sock, 413, ['error' => 'too_big']); drop_client($id); continue; }
    if (strlen($c['buf']) < $he + 4 + $clen) continue;   /* body not complete yet */
    $body = substr($c['buf'], $he + 4, $clen);
    handle_http($id, $method, $url, $body, $head);
    drop_client($id);
  }

  /* hourly TTL sweep */
  if (time() - $lastSweep >= 3600) {
    $lastSweep = time(); $now = microtime(true) * 1000;
    foreach (@scandir("$DATA/blobs") ?: [] as $f) {
      if ($f[0] === '.' || str_ends_with($f, '.exp')) continue;
      $p = "$DATA/blobs/$f"; $xf = "$p.exp";
      $exp = @file_get_contents($xf);
      if ($exp !== false && is_numeric(trim($exp))) {
        $e = (float)$exp;
        if ($e >= 0 && $now > $e) { @unlink($p); @unlink($xf); }
      } elseif ($now - @filemtime($p) * 1000 > $BLOB_TTL_DAYS * 86400000) { @unlink($p); @unlink($xf); }
    }
    foreach (@scandir("$DATA/queue") ?: [] as $f) {
      if ($f[0] === '.') continue;
      $pub = substr($f, 0, -5);
      q_save($pub, array_values(array_filter(q_load($pub), fn($x) => $now / 1000 - $x['ts'] / 1000 < $QUEUE_TTL)));
    }
  }
}
