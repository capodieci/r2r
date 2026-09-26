<?php
// /m.php?token=…  (exposed as /m/<token> via .htaccess)
// Resolves an opaque contact token back to the issuing identity's pubkey +
// bot relay, and renders a page that either:
//   - auto-forwards to the R2R wallet with a #addContact= hash (if the
//     wallet URL is set + reachable), or
//   - shows the pubkey/relay with a Copy button and paste-in instructions.
//
// The token itself is the credential: anyone who has it can look up the
// issuer's pubkey. Revoking the parent invite (admin → revoke) tears the
// mapping down so old cards go dead.

require_once __DIR__ . '/lib/session.php';
require_once __DIR__ . '/lib/branding.php';
require_once __DIR__ . '/lib/i18n.php';
require_once __DIR__ . '/lib/db.php';

$GLOBALS['_sippis_lang'] = sippis_lang_resolve_or_redirect();
$lang_code = $GLOBALS['_sippis_lang'];

$state = sippis_session_state();   // required in scope for _topbar.php to render
$user  = $state['user'];

$h    = fn($s) => htmlspecialchars((string)$s, ENT_QUOTES, 'UTF-8');
$fqdn = $h($_SERVER['HTTP_HOST'] ?? 'r2r.help');

$brand     = sippis_branding();
$primary   = $brand['primaryColor']   ?? '#0EADB5';
$secondary = $brand['secondaryColor'] ?? '#F26430';
$bg_tint   = sippis_color_darken($primary, 0.7);

$token = trim($_GET['token'] ?? '');
$pubkey = null;
$relay  = null;
$err    = null;

if (!preg_match('/^[A-Za-z0-9]{6,16}$/', $token)) {
    $err = t('m.err.malformed');
} else {
    $db = r2r_db();
    $stmt = $db->prepare(
        "SELECT i.issued_by_identity_pub, i.status
           FROM invites i
          WHERE i.contact_token = ?
          LIMIT 1"
    );
    $stmt->bind_param('s', $token);
    $stmt->execute();
    $stmt->bind_result($pub, $status);
    $found = $stmt->fetch();
    $stmt->close();

    if (!$found) {
        $err = t('m.err.unknown');
    } elseif ($status === 'revoked') {
        $err = t('m.err.revoked');
    } elseif (!$pub) {
        $err = t('m.err.no_contact');
    } else {
        $pubkey = $pub;
        // For now: contact relay = the bot's relay. When identities carry
        // their own preferred relay (future enhancement), read that instead.
        $bot = r2r_bot_config();
        $relay = $bot['relay_ws_url'];
    }
}
?><!DOCTYPE html>
<html lang="<?= $h($lang_code) ?>">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow">
<title><?= $h(t('m.meta.title', ['HOST' => $fqdn])) ?></title>
<link rel="icon" type="image/svg+xml" href="/favicon.svg">
<link rel="stylesheet" href="/sippis-shell.css?v=<?= (int)@filemtime(__DIR__ . '/sippis-shell.css') ?>">
<style>
  :root { --primary: <?= $h($primary) ?>; --secondary: <?= $h($secondary) ?>; --bg-tint: <?= $h($bg_tint) ?>; }
  .contact-box {
    max-width: 620px; margin: 24px auto; padding: 20px; text-align: center;
    background: rgba(0,0,0,0.15); border-radius: 12px;
  }
  .fld { text-align: left; margin: 14px 0; }
  .fld label { display: block; font-size: 12px; color: rgba(255,255,255,0.55); margin-bottom: 4px; text-transform: uppercase; letter-spacing: 1px; }
  .fld code {
    display: block; word-break: break-all; font-family: monospace; font-size: 13px;
    background: rgba(0,0,0,0.35); padding: 10px; border-radius: 6px; user-select: all;
  }
  .cp {
    padding: 10px 18px; background: var(--primary); color: #fff; border: 0;
    border-radius: 6px; cursor: pointer; font-size: 14px; margin-top: 6px;
  }
  .cp:hover { filter: brightness(1.1); }
  .err { color: #f88; text-align: center; font-size: 18px; margin: 32px auto; max-width: 480px; }
  ol.steps { max-width: 620px; margin: 20px auto; text-align: left; }
  ol.steps li { margin: 8px 0; }
</style>
</head>
<body>
<?php include __DIR__ . '/auth/_topbar.php'; ?>

<main class="hero">
  <img class="logo" src="/sippis-logo.svg" alt="R2R">

  <?php if ($err): ?>
    <h1><?= $h(t('m.err.h1')) ?></h1>
    <p class="err"><?= $h($err) ?></p>
    <a class="cta" href="/"><?= t('m.err.back_html', ['HOST' => $fqdn]) ?></a>

  <?php else: ?>
    <h1><?= $h(t('m.ok.h1')) ?></h1>
    <p class="tagline"><?= $h(t('m.ok.tagline')) ?></p>

    <?php $copied = $h(t('m.ok.copied')); ?>
    <div class="contact-box">
      <div class="fld">
        <label><?= $h(t('m.ok.pubkey_label')) ?></label>
        <code id="pubkey"><?= $h($pubkey) ?></code>
        <button class="cp" onclick="navigator.clipboard.writeText(document.getElementById('pubkey').textContent);this.textContent='<?= $copied ?>'"><?= $h(t('m.ok.copy_pubkey')) ?></button>
      </div>
      <div class="fld">
        <label><?= $h(t('m.ok.relay_label')) ?></label>
        <code id="relay"><?= $h($relay) ?></code>
        <button class="cp" onclick="navigator.clipboard.writeText(document.getElementById('relay').textContent);this.textContent='<?= $copied ?>'"><?= $h(t('m.ok.copy_relay')) ?></button>
      </div>
    </div>

    <ol class="steps">
      <li><?= $h(t('m.ok.step1')) ?></li>
      <li><?= t('m.ok.step2_html') ?></li>
      <li><?= $h(t('m.ok.step3')) ?></li>
      <li><?= $h(t('m.ok.step4')) ?></li>
    </ol>

    <p style="text-align:center;font-size:14px;color:rgba(255,255,255,0.5);margin-top:24px">
      <?= t('m.ok.no_wallet_html') ?>
    </p>
  <?php endif; ?>
</main>

<footer>
  <?= str_replace('Sippis', '<a href="https://sippis.com/">Sippis</a>', $h(t('topbar.powered_by'))) ?>
</footer>
</body>
</html>
