<?php
// /admin.php — R2R.help operator console.
// Gated on Sippis session; only emails in bot_config.admin_emails may enter.
// Actions:
//   mint  — issue N fresh root invite codes
//   revoke — mark a code (and its descendants) as revoked
//   view   — default: recent codes + stats + identities

require_once __DIR__ . '/lib/session.php';
require_once __DIR__ . '/lib/branding.php';
require_once __DIR__ . '/lib/i18n.php';
require_once __DIR__ . '/lib/db.php';
require_once __DIR__ . '/lib/card.php';

$GLOBALS['_sippis_lang'] = sippis_lang_resolve_or_redirect();
$lang_code = $GLOBALS['_sippis_lang'];   // required in scope for _topbar.php's selector
$state = sippis_session_state();

// If not signed in, punt to the login page and come back here.
if (!$state['signed_in']) {
    $return = urlencode('/admin.php');
    header('Location: /auth/login.php?next=' . $return);
    exit;
}
$user  = $state['user'];
$email = strtolower($user['email'] ?? '');

$db  = r2r_db();
$bot = r2r_bot_config();
$admin_emails = array_filter(array_map(fn($e) => strtolower(trim($e)),
                                       explode(',', $bot['admin_emails'] ?? '')));

// Authorization: preferred signal is v1's isAppOwner/appRole (the shell's
// canonical "app super-user" bit — see lib/session.php::sippis_is_app_owner).
// Email allowlist stays as an escape hatch for co-admins or when running
// pre-owner (before the first owner has been claimed on v1's side).
$is_owner = sippis_is_app_owner($state);
$is_allowlisted = $email !== '' && in_array($email, $admin_emails, true);
if (!$is_owner && !$is_allowlisted) {
    $h = fn($s) => htmlspecialchars((string)$s, ENT_QUOTES, 'UTF-8');
    $fqdn_403 = $h($_SERVER['HTTP_HOST'] ?? 'r2r.help');
    $user_403 = $h($email !== '' ? $email : ($user['fullName'] ?? t('admin.user_unknown')));
    $brand     = sippis_branding();
    $primary   = $brand['primaryColor']   ?? '#0EADB5';
    $secondary = $brand['secondaryColor'] ?? '#F26430';
    $bg_tint   = sippis_color_darken($primary, 0.7);
    http_response_code(403);
    ?><!DOCTYPE html>
    <html lang="<?= $h($GLOBALS['_sippis_lang']) ?>">
    <head>
      <meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
      <title><?= $h(t('admin.forbidden.title', ['HOST' => $fqdn_403])) ?></title>
<link rel="icon" type="image/svg+xml" href="/favicon.svg">
      <link rel="stylesheet" href="/sippis-shell.css?v=<?= (int)@filemtime(__DIR__ . '/sippis-shell.css') ?>">
      <style>:root { --primary: <?= $h($primary) ?>; --secondary: <?= $h($secondary) ?>; --bg-tint: <?= $h($bg_tint) ?>; }</style>
    </head>
    <body>
    <?php include __DIR__ . '/auth/_topbar.php'; ?>
    <main class="hero">
      <img class="logo" src="/sippis-logo.svg" alt="R2R">
      <h1><?= $h(t('admin.forbidden.h1')) ?></h1>
      <p class="tagline">
        <?= t('admin.forbidden.signed_in_html', ['USER' => $user_403]) ?>
      </p>
      <p class="tagline">
        <?= t('admin.forbidden.limits_html', ['HOST' => $fqdn_403]) ?>
      </p>
      <a class="cta" href="/"><?= t('admin.forbidden.back_html', ['HOST' => $fqdn_403]) ?></a>
    </main>
    </body></html>
    <?php
    exit;
}

$h    = fn($s) => htmlspecialchars((string)$s, ENT_QUOTES, 'UTF-8');
$fqdn = $h($_SERVER['HTTP_HOST'] ?? 'r2r.help');
$note = null;

// ------- GET action: download a ZIP of card PNGs for the N most recent unused codes.
// Must run BEFORE any HTML output. Requires ZipArchive (PHP core).
if (($_GET['action'] ?? '') === 'download_zip' && class_exists('ZipArchive')) {
    $limit = max(1, min(50, (int)($_GET['n'] ?? 20)));
    $r = $db->query(
        "SELECT code FROM invites WHERE status = 'unused' ORDER BY issued_at DESC LIMIT $limit"
    );
    $codes = [];
    while ($r && ($row = $r->fetch_assoc())) $codes[] = $row['code'];
    if (!$codes) {
        http_response_code(404);
        header('Content-Type: text/plain');
        echo t('admin.err.no_unused');
        exit;
    }
    $scheme = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http';
    $host   = $_SERVER['HTTP_HOST'] ?? 'r2r.help';
    $tmpZip = tempnam(sys_get_temp_dir(), 'r2rz_') . '.zip';
    $zip = new ZipArchive();
    if ($zip->open($tmpZip, ZipArchive::CREATE | ZipArchive::OVERWRITE) !== true) {
        http_response_code(500);
        echo t('admin.err.zip_open_failed');
        exit;
    }
    foreach ($codes as $code) {
        $redeem = $scheme . '://' . $host . '/redeem.php?code=' . rawurlencode($code);
        $png = r2r_card_render($code, $redeem);
        if ($png && is_file($png)) $zip->addFile($png, $code . '.png');
    }
    $zip->close();
    header('Content-Type: application/zip');
    header('Content-Length: ' . filesize($tmpZip));
    header('Content-Disposition: attachment; filename="r2r-cards-' . date('Ymd-His') . '.zip"');
    readfile($tmpZip);
    @unlink($tmpZip);
    exit;
}

function mint_code_string(string $prefix): string {
    $alph = 'ABCDEFGHJKMNPQRSTUVWXYZ23456789';
    $a = strlen($alph);
    $out = $prefix;
    for ($g = 0; $g < 3; $g++) {
        if ($g) $out .= '-';
        for ($i = 0; $i < 4; $i++) $out .= $alph[random_int(0, $a - 1)];
    }
    return $out;
}

// ------- POST actions
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $action = $_POST['action'] ?? '';
    if ($action === 'mint') {
        $n = max(1, min(50, (int)($_POST['n'] ?? 1)));
        $tag = trim($_POST['note'] ?? '') ?: null;
        $minted = [];
        for ($i = 0; $i < $n; $i++) {
            for ($try = 0; $try < 5; $try++) {
                $c = mint_code_string($bot['code_prefix']);
                $s = $db->prepare(
                    "INSERT INTO invites (code, status, depth, note) VALUES (?, 'unused', 0, ?)"
                );
                $s->bind_param('ss', $c, $tag);
                if ($s->execute()) { $minted[] = $c; $s->close(); break; }
                $s->close();
            }
        }
        foreach ($minted as $c) {
            $db->query("INSERT INTO events (kind, code, detail) VALUES
                ('mint_root', '" . $db->real_escape_string($c) . "',
                 JSON_OBJECT('by','" . $db->real_escape_string($email) . "'))");
        }
        $note = t('admin.notes.minted', ['N' => count($minted)]);
    }
    elseif ($action === 'revoke') {
        $code = strtoupper(trim($_POST['code'] ?? ''));
        if (preg_match('/^[A-Z0-9-]{6,32}$/', $code)) {
            // Revoke this code AND all descendants (unused/locked ones only —
            // don't try to unbind claimed identities).
            $db->query("START TRANSACTION");
            $stmt = $db->prepare(
                "UPDATE invites SET status='revoked' WHERE code = ? AND status IN ('unused','locked')"
            );
            $stmt->bind_param('s', $code);
            $stmt->execute();
            $count = $stmt->affected_rows;
            $stmt->close();

            // Cascade: any descendant tree of this code that is not yet claimed.
            // Do BFS on parent_code so we don't need recursive CTE.
            $frontier = [$code];
            $cascaded = 0;
            while ($frontier) {
                $placeholders = implode(',', array_fill(0, count($frontier), '?'));
                $q = $db->prepare(
                    "SELECT code FROM invites WHERE parent_code IN ($placeholders) AND status IN ('unused','locked')"
                );
                $q->bind_param(str_repeat('s', count($frontier)), ...$frontier);
                $q->execute();
                $res = $q->get_result();
                $next = [];
                while ($row = $res->fetch_assoc()) $next[] = $row['code'];
                $q->close();
                if (!$next) break;
                $placeholders2 = implode(',', array_fill(0, count($next), '?'));
                $u = $db->prepare(
                    "UPDATE invites SET status='revoked' WHERE code IN ($placeholders2)"
                );
                $u->bind_param(str_repeat('s', count($next)), ...$next);
                $u->execute();
                $cascaded += $u->affected_rows;
                $u->close();
                $frontier = $next;
            }
            $db->query("COMMIT");
            $db->query("INSERT INTO events (kind, code, detail) VALUES
                ('revoke', '" . $db->real_escape_string($code) . "',
                 JSON_OBJECT('by','" . $db->real_escape_string($email)
                 . "','direct',$count,'cascaded',$cascaded))");
            $note = t('admin.notes.revoked', ['DIRECT' => $count, 'CASCADE' => $cascaded]);
        } else $note = t('admin.notes.bad_format');
    }
}

// ------- Stats
$stats = [];
$r = $db->query("SELECT status, COUNT(*) c FROM invites GROUP BY status");
while ($row = $r->fetch_assoc()) $stats[$row['status']] = (int)$row['c'];

$ident_count = (int)$db->query("SELECT COUNT(*) c FROM identities")->fetch_assoc()['c'];

// Recent codes for the table
$recent = [];
$r = $db->query(
    "SELECT code, parent_code, status, depth, note, issued_at, redeemed_at,
            LEFT(redeemed_by_identity_pub, 16) AS pub16
       FROM invites
       ORDER BY issued_at DESC
       LIMIT 200"
);
while ($row = $r->fetch_assoc()) $recent[] = $row;

$brand     = sippis_branding();
$primary   = $brand['primaryColor']   ?? '#0EADB5';
$secondary = $brand['secondaryColor'] ?? '#F26430';
$bg_tint   = sippis_color_darken($primary, 0.7);
?><!DOCTYPE html>
<html lang="<?= $h($GLOBALS['_sippis_lang']) ?>" dir="ltr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow">
<title><?= $h(t('admin.meta.title', ['HOST' => $fqdn])) ?></title>
<link rel="icon" type="image/svg+xml" href="/favicon.svg">
<link rel="stylesheet" href="/sippis-shell.css?v=<?= (int)@filemtime(__DIR__ . '/sippis-shell.css') ?>">
<style>
  :root { --primary: <?= $h($primary) ?>; --secondary: <?= $h($secondary) ?>; --bg-tint: <?= $h($bg_tint) ?>; }
  main.admin { max-width: 1100px; margin: 32px auto; padding: 0 20px; }
  .stats { display: flex; gap: 16px; flex-wrap: wrap; margin: 16px 0 24px; }
  .stat  { flex: 1 1 140px; padding: 16px; background: rgba(0,0,0,0.15); border-radius: 10px; text-align: center; }
  .stat b { font-size: 28px; display: block; color: var(--primary); }
  form.card { background: rgba(0,0,0,0.15); padding: 16px; border-radius: 10px; margin: 12px 0; }
  form.card input, form.card select {
    padding: 8px; margin: 0 4px; border: 1px solid #666; background: transparent;
    color: inherit; border-radius: 4px; font-family: inherit;
  }
  form.card button {
    padding: 8px 18px; background: var(--primary); color: #fff; border: 0;
    border-radius: 4px; cursor: pointer; margin-left: 8px;
  }
  table.codes { width: 100%; border-collapse: collapse; margin-top: 12px; font-size: 13px; font-family: monospace; }
  table.codes th, table.codes td { padding: 6px 8px; text-align: left; border-bottom: 1px solid rgba(255,255,255,0.1); }
  table.codes th { background: rgba(0,0,0,0.2); font-weight: bold; }
  .st-unused  { color: #cf9; }
  .st-locked  { color: #fc9; }
  .st-claimed { color: #9cf; }
  .st-revoked { color: #f88; text-decoration: line-through; }
  .note { padding: 10px; background: rgba(0,150,0,0.2); border-radius: 6px; margin: 10px 0; }
</style>
</head>
<body>
<?php include __DIR__ . '/auth/_topbar.php'; ?>

<main class="admin">
  <?php $user_display = $h($email !== '' ? $email : ($user['fullName'] ?? t('admin.user_unknown'))); ?>
  <h1><?= $h(t('admin.h1', ['HOST' => $fqdn])) ?></h1>
  <p><?= t('admin.signed_in_html', ['USER' => $user_display]) ?><?php
    if ($is_owner) echo ' <em>' . $h(t('admin.role.owner')) . '</em>';
    elseif ($is_allowlisted) echo ' <em>' . $h(t('admin.role.allowlisted')) . '</em>';
  ?></p>

  <?php if ($note): ?><div class="note"><?= $h($note) ?></div><?php endif; ?>

  <div class="stats">
    <div class="stat"><b><?= (int)($stats['unused'] ?? 0) ?></b><?= $h(t('admin.stats.unused')) ?></div>
    <div class="stat"><b><?= (int)($stats['locked'] ?? 0) ?></b><?= $h(t('admin.stats.locked')) ?></div>
    <div class="stat"><b><?= (int)($stats['claimed'] ?? 0) ?></b><?= $h(t('admin.stats.claimed')) ?></div>
    <div class="stat"><b><?= (int)($stats['revoked'] ?? 0) ?></b><?= $h(t('admin.stats.revoked')) ?></div>
    <div class="stat"><b><?= (int)$ident_count ?></b><?= $h(t('admin.stats.identities')) ?></div>
  </div>

  <form class="card" method="post">
    <input type="hidden" name="action" value="mint">
    <label><?= $h(t('admin.form.mint.label_start')) ?> <input type="number" name="n" value="5" min="1" max="50" style="width:60px"> <?= $h(t('admin.form.mint.label_end')) ?></label>
    <input type="text" name="note" placeholder="<?= $h(t('admin.form.mint.note_placeholder')) ?>" style="width:200px">
    <button type="submit"><?= $h(t('admin.form.mint.button')) ?></button>
  </form>

  <form class="card" method="post" onsubmit="return confirm('<?= $h(t('admin.form.revoke.confirm')) ?>')">
    <input type="hidden" name="action" value="revoke">
    <label><?= $h(t('admin.form.revoke.label_start')) ?> <input type="text" name="code" placeholder="<?= $h(t('admin.form.revoke.placeholder')) ?>" style="width:220px; font-family:monospace"></label>
    <button type="submit" style="background:#c33"><?= $h(t('admin.form.revoke.button')) ?></button>
  </form>

  <h2><?= $h(t('admin.recent.h2')) ?></h2>
  <p style="margin:6px 0 12px; font-size:14px">
    <a class="cta" style="padding:8px 16px;font-size:14px" href="/admin.php?action=download_zip&amp;n=20"><?= $h(t('admin.recent.download_zip')) ?></a>
    <?= t('admin.recent.cached_html') ?>
  </p>
  <table class="codes">
    <thead>
      <tr>
        <th><?= $h(t('admin.tbl.code')) ?></th>
        <th><?= $h(t('admin.tbl.card')) ?></th>
        <th><?= $h(t('admin.tbl.status')) ?></th>
        <th><?= $h(t('admin.tbl.parent')) ?></th>
        <th><?= $h(t('admin.tbl.depth')) ?></th>
        <th><?= $h(t('admin.tbl.note')) ?></th>
        <th><?= $h(t('admin.tbl.issued')) ?></th>
        <th><?= $h(t('admin.tbl.redeemed')) ?></th>
        <th><?= $h(t('admin.tbl.identity')) ?></th>
      </tr>
    </thead>
    <tbody>
    <?php foreach ($recent as $row): ?>
      <tr>
        <td><?= $h($row['code']) ?></td>
        <td>
          <?php if ($row['status'] === 'unused' || $row['status'] === 'locked'): ?>
            <a href="/card.php?code=<?= $h($row['code']) ?>" target="_blank" title="<?= $h(t('admin.tbl.png_title')) ?>"><?= $h(t('admin.tbl.png')) ?></a>
          <?php else: ?>—<?php endif; ?>
        </td>
        <td class="st-<?= $h($row['status']) ?>"><?= $h(t('admin.status.' . $row['status'])) ?></td>
        <td><?= $h($row['parent_code'] ?? '—') ?></td>
        <td><?= (int)$row['depth'] ?></td>
        <td><?= $h($row['note'] ?? '') ?></td>
        <td><?= $h($row['issued_at']) ?></td>
        <td><?= $h($row['redeemed_at'] ?? '—') ?></td>
        <td><?= $h($row['pub16'] ? $row['pub16'] . '…' : '—') ?></td>
      </tr>
    <?php endforeach; ?>
    </tbody>
  </table>
</main>
</body>
</html>
