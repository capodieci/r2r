<?php
// /card.php?code=R2R-XXXX-XXXX-XXXX[&fmt=json]
//
// Public endpoint that streams the invite-card for a given code. Anyone can
// render a card for any code — the code itself is the secret, and having it
// means the visitor is already able to redeem it. Rendering does not consume
// the code.
//
// Two response formats:
//   fmt=png  (default) — image/png, cached client-side for a day
//   fmt=json           — {code, redeem_url, contact_url?, host} for client-side
//                         rendering via /js/card.js
//
// The JSON form is what the relay-embedded doorway will use (no ImageMagick
// available); the PNG form stays for admin's ZIP export on this PHP box.

require_once __DIR__ . '/lib/card.php';
require_once __DIR__ . '/lib/db.php';

$code = strtoupper(trim($_GET['code'] ?? ''));
$fmt  = strtolower(trim($_GET['fmt'] ?? 'png'));
if (!preg_match('/^[A-Z0-9-]{6,32}$/', $code)) {
    http_response_code(400);
    header('Content-Type: text/plain');
    echo "bad code";
    exit;
}

// Short URL — keeps the QR code small (fewer modules = larger, easier to scan).
// /i/CODE resolves to the redeem-confirmation page (no auto-consume on scan).
$scheme = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http';
$host   = $_SERVER['HTTP_HOST'] ?? 'r2r.help';
$redeem = $scheme . '://' . $host . '/i/' . $code;

if ($fmt === 'json') {
    // Look up contact_token so the client can render the two-QR variant.
    $db = r2r_db();
    $st = $db->prepare("SELECT contact_token FROM invites WHERE code = ? LIMIT 1");
    $st->bind_param('s', $code);
    $st->execute();
    $st->bind_result($tok);
    $found = $st->fetch();
    $st->close();

    $contact_url = ($found && $tok) ? ($scheme . '://' . $host . '/m/' . $tok) : null;

    header('Content-Type: application/json; charset=utf-8');
    header('Cache-Control: private, max-age=60');
    echo json_encode([
        'code'        => $code,
        'redeem_url'  => $redeem,
        'contact_url' => $contact_url,
        'host'        => $host,
    ]);
    exit;
}

$png = r2r_card_render($code, $redeem);
if (!$png || !is_file($png)) {
    http_response_code(500);
    header('Content-Type: text/plain');
    echo "card render failed";
    exit;
}

// Serve.
header('Content-Type: image/png');
header('Content-Length: ' . filesize($png));
header('Cache-Control: public, max-age=86400, immutable');
header('Content-Disposition: inline; filename="' . $code . '.png"');
readfile($png);
