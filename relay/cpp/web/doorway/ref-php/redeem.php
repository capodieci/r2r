<?php
// /redeem.php  — invite-code redemption
//
// Three states in one file:
//   GET  /redeem                → landing form (enter code)
//   GET  /redeem?code=CODE      → CONFIRM screen ("this will consume the code, continue?")
//   POST /redeem  code=CODE     → actually lock the code, mint the setup card, show it once.
//
// The GET-with-code path used to auto-mint; that meant an accidental
// phone-camera scan of a card burned the code. Now it just previews the
// code's status (unused / already used / revoked / unknown) with a big
// "Redeem now" button that POSTs.

require_once __DIR__ . '/lib/session.php';
require_once __DIR__ . '/lib/branding.php';
require_once __DIR__ . '/lib/i18n.php';
require_once __DIR__ . '/lib/db.php';

$GLOBALS['_sippis_lang'] = sippis_lang_resolve_or_redirect();
$lang_code = $GLOBALS['_sippis_lang'];
$lang_dir  = 'ltr';
foreach (sippis_supported_languages() as $L) {
    if (strcasecmp($L['code'], $lang_code) === 0) { $lang_dir = $L['dir'] ?? 'ltr'; break; }
}

$state     = sippis_session_state();   // required in scope for _topbar.php to render
$user      = $state['user'];
$brand     = sippis_branding();
$primary   = $brand['primaryColor']   ?? '#0EADB5';
$secondary = $brand['secondaryColor'] ?? '#F26430';
$bg_tint   = sippis_color_darken($primary, 0.7);
$h         = fn($s) => htmlspecialchars((string)$s, ENT_QUOTES, 'UTF-8');
$fqdn      = $h($_SERVER['HTTP_HOST'] ?? 'r2r.help');

$code = strtoupper(trim($_POST['code'] ?? $_GET['code'] ?? ''));
$is_post = ($_SERVER['REQUEST_METHOD'] === 'POST');

// The contact_token, if any, becomes the second QR on the branded card (the
// "message me" side). Pulled after a successful mint below.
$contact_url = null;

// View state: one of 'form' (no code entered), 'confirm', 'done', 'err'
$view      = 'form';
$err       = null;
$card_str  = null;                 // R2RSC1 string, only set on 'done'
$code_status = null;               // current DB status when we're on 'confirm'

if ($code !== '') {
    if (!preg_match('/^[A-Z0-9-]{6,32}$/', $code)) {
        $err  = t('redeem.err.malformed');
        $view = 'err';
    } else {
        $db  = r2r_db();

        // Peek at the current status (read only) before doing anything destructive.
        $q = $db->prepare("SELECT status FROM invites WHERE code = ? LIMIT 1");
        $q->bind_param('s', $code);
        $q->execute();
        $q->bind_result($status);
        $found = $q->fetch();
        $q->close();

        if (!$found) {
            $err  = t('redeem.err.unknown');
            $view = 'err';
        } elseif ($status === 'revoked') {
            $err  = t('redeem.err.revoked');
            $view = 'err';
        } elseif ($status === 'claimed') {
            $err  = t('redeem.err.claimed');
            $view = 'err';
        } elseif ($status === 'locked') {
            $err  = t('redeem.err.locked');
            $view = 'err';
        } elseif ($status === 'unused') {
            if (!$is_post) {
                // GET → show confirmation page, do NOT touch the DB.
                $view        = 'confirm';
                $code_status = $status;
            } else {
                // POST → actually redeem.
                $bot = r2r_bot_config();
                $stmt = $db->prepare(
                    "UPDATE invites SET status='locked', locked_at=NOW()
                     WHERE code = ? AND status = 'unused'"
                );
                $stmt->bind_param('s', $code);
                $stmt->execute();
                $locked = $stmt->affected_rows > 0;
                $stmt->close();

                if (!$locked) {
                    $err  = t('redeem.err.race');
                    $view = 'err';
                } else {
                    $cardKey  = random_bytes(32);
                    $cardKeyH = bin2hex($cardKey);
                    $cardHash = hash('sha256', $cardKey);

                    $ins = $db->prepare(
                        "INSERT INTO cards (card_key_hash, invite_code) VALUES (?, ?)"
                    );
                    $ins->bind_param('ss', $cardHash, $code);
                    if (!$ins->execute()) {
                        // Roll back the lock so the code stays usable.
                        $db->query("UPDATE invites SET status='unused', locked_at=NULL
                                      WHERE code = '" . $db->real_escape_string($code)
                                    . "' AND status='locked'");
                        $err  = t('redeem.err.mint_failed');
                        $view = 'err';
                    } else {
                        $card_str = 'R2RSC1:' . $cardKeyH . ':' . $bot['relay_ws_url']
                                  . ':' . $bot['bot_pub_hex'];
                        $db->query("INSERT INTO events (kind, code, detail) VALUES
                            ('redeem', '" . $db->real_escape_string($code) . "',
                             JSON_OBJECT('card_hash','" . $db->real_escape_string($cardHash) . "'))");
                        // Look up the invite's contact_token so the branded card
                        // can carry a second QR ("message me"). Root-minted codes
                        // have no token → single-QR variant.
                        $ct = $db->prepare("SELECT contact_token FROM invites WHERE code = ? LIMIT 1");
                        $ct->bind_param('s', $code);
                        $ct->execute();
                        $ct->bind_result($tok);
                        $ct->fetch();
                        $ct->close();
                        if ($tok) {
                            $scheme = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http';
                            $host_r = $_SERVER['HTTP_HOST'] ?? 'r2r.help';
                            $contact_url = $scheme . '://' . $host_r . '/m/' . $tok;
                        }
                        $view = 'done';
                    }
                    $ins->close();
                }
            }
        } else {
            $err  = t('redeem.err.not_available');
            $view = 'err';
        }
    }
}
?><!DOCTYPE html>
<html lang="<?= $h($lang_code) ?>" dir="<?= $h($lang_dir) ?>">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow">
<title><?= $h(t('redeem.meta.title', ['HOST' => $fqdn])) ?></title>
<link rel="icon" type="image/svg+xml" href="/favicon.svg">
<link rel="stylesheet" href="/sippis-shell.css?v=<?= (int)@filemtime(__DIR__ . '/sippis-shell.css') ?>">
<style>
  :root { --primary: <?= $h($primary) ?>; --secondary: <?= $h($secondary) ?>; --bg-tint: <?= $h($bg_tint) ?>; }
  .r2r-mesh-frame { max-width: 100%; margin: 0 auto; text-align: center; }
  .r2r-mesh-frame svg { display: block; margin: 0 auto; width: 100%; max-width: 460px; height: auto; }
  .redeem-form {
    /* Escape the flex-column body's align-items:center shrink-to-fit trap:
       give the form a concrete target width so the input inside can actually
       reach its own max-width. `max-width:100%` keeps it responsive. */
    width: 310px; max-width: 100%;
    margin: 24px auto; text-align: center;
  }
  .redeem-form input[type=text] {
    width: 100%; box-sizing: border-box;
    padding: 14px 16px; font-size: 20px;
    letter-spacing: 2px; text-align: center; text-transform: uppercase;
    border: 2px solid var(--primary); border-radius: 8px; background: transparent;
    color: inherit; font-family: monospace;
  }
  .redeem-form button, .redeem-form .cta {
    margin-top: 16px; padding: 12px 28px; font-size: 18px;
    background: var(--primary); color: #fff; border: 0; border-radius: 8px; cursor: pointer;
    text-decoration: none; display: inline-block;
  }
  .confirm-code {
    display: inline-block; padding: 14px 24px; font-family: monospace; font-size: 26px;
    letter-spacing: 2px; background: rgba(0,0,0,0.35); border: 1px solid var(--primary);
    border-radius: 8px; margin: 12px 0;
  }
  .card-box {
    max-width: 640px; margin: 24px auto; padding: 20px; text-align: center;
    background: rgba(0,0,0,0.15); border-radius: 12px;
  }
  #card-canvas { display: block; width: 100%; max-width: 360px; height: auto; margin: 0 auto; border-radius: 12px; box-shadow: 0 8px 24px rgba(0,0,0,0.35); }
  .card-download { margin-top: 12px; padding: 10px 20px; background: var(--primary); color: #fff; border: 0; border-radius: 8px; cursor: pointer; font-size: 14px; }
  .card-str {
    display: block; word-break: break-all; font-family: monospace; font-size: 13px;
    background: rgba(0,0,0,0.35); padding: 12px; border-radius: 6px; margin-top: 12px; user-select: all;
  }
  .warn { color: #ff9; margin: 12px 0; }
  .err  { color: #f88; margin: 24px auto; max-width: 480px; text-align: center; font-size: 18px; }
  .steps { max-width: 640px; margin: 24px auto; text-align: left; }
  .steps li { margin: 8px 0; }
  .cancel-link { display: block; margin-top: 12px; color: rgba(255,255,255,0.6); font-size: 14px; }
</style>
</head>
<body>
<?php include __DIR__ . '/auth/_topbar.php'; ?>

<main class="hero">
  <div class="r2r-mesh-frame"><?php include __DIR__ . '/lib/_mesh.php'; ?></div>

  <?php if ($view === 'done'): ?>
    <h1><?= $h(t('redeem.done.h1')) ?></h1>
    <p class="tagline"><?= $h(t('redeem.done.tagline')) ?></p>

    <div class="card-box">
      <canvas id="card-canvas" aria-label="Setup card"></canvas>
      <button type="button" class="card-download" onclick="R2R.downloadCardPNG(document.getElementById('card-canvas'), 'r2r-setup-card.png')">Download card PNG</button>
      <code class="card-str"><?= $h($card_str) ?></code>
      <p class="warn"><?= $h(t('redeem.done.warn')) ?></p>
    </div>

    <ol class="steps">
      <li><?= $h(t('redeem.done.step1')) ?></li>
      <li><?= $h(t('redeem.done.step2')) ?></li>
      <li><?= t('redeem.done.step3_html') ?></li>
      <li><?= t('redeem.done.step4_html', ['HOST' => $fqdn]) ?></li>
    </ol>

    <script src="/js/qrcode.min.js?v=<?= (int)@filemtime(__DIR__ . '/js/qrcode.min.js') ?>"></script>
    <script src="/js/card.js?v=<?= (int)@filemtime(__DIR__ . '/js/card.js') ?>"></script>
    <script>
      // The QR on the redeem card carries the setup-card string itself — the
      // wallet's setup-card scanner is what parses R2RSC1:… The optional second
      // QR ("message me") carries the /m/<token> URL, if this invite had one.
      R2R.renderCard(document.getElementById('card-canvas'), {
        code:       <?= json_encode($code) ?>,
        redeemUrl:  <?= json_encode($card_str) ?>,
        contactUrl: <?= json_encode($contact_url) ?>,
        host:       <?= json_encode($_SERVER['HTTP_HOST'] ?? 'r2r.help') ?>,
        primaryColor: <?= json_encode($primary) ?>
      });
    </script>

  <?php elseif ($view === 'confirm'): ?>
    <h1><?= $h(t('redeem.confirm.h1')) ?></h1>
    <p class="tagline">
      <?= t('redeem.confirm.tagline_html') ?>
    </p>
    <div class="confirm-code"><?= $h($code) ?></div>
    <form class="redeem-form" method="post" action="/redeem.php">
      <input type="hidden" name="code" value="<?= $h($code) ?>">
      <br><button type="submit"><?= $h(t('redeem.confirm.button')) ?></button>
      <a class="cancel-link" href="/"><?= t('redeem.confirm.cancel_html', ['HOST' => $fqdn]) ?></a>
    </form>
    <p class="steps" style="text-align:center">
      <?= t('redeem.confirm.accidental_html') ?>
    </p>

  <?php elseif ($view === 'err'): ?>
    <h1><?= $h(t('redeem.err_view.h1')) ?></h1>
    <p class="err"><?= $h($err) ?></p>
    <form class="redeem-form" method="get" action="/redeem.php">
      <input type="text" name="code" value="<?= $h($code) ?>" placeholder="<?= $h(t('redeem.form.placeholder')) ?>" autocomplete="off" autofocus>
      <br><button type="submit"><?= $h(t('redeem.err_view.try_again')) ?></button>
    </form>

  <?php else: ?>
    <h1><?= $h(t('redeem.form.h1')) ?></h1>
    <p class="tagline"><?= $h(t('redeem.form.tagline')) ?></p>
    <form class="redeem-form" method="get" action="/redeem.php">
      <input type="text" name="code" placeholder="<?= $h(t('redeem.form.placeholder')) ?>" autocomplete="off" autofocus>
      <br><button type="submit"><?= $h(t('redeem.form.button')) ?></button>
    </form>
    <p class="steps">
      <?= t('redeem.form.no_code_html') ?>
    </p>
  <?php endif; ?>
</main>

<footer>
  <?= str_replace('Sippis', '<a href="https://sippis.com/">Sippis</a>', $h(t('topbar.powered_by'))) ?>
</footer>
</body>
</html>
