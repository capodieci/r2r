<?php
// R2R invite-card compositor.
//
// Two templates share the 600×1050 canvas, chosen by whether the invite
// carries a contact_token:
//
//   cards/template.png      — single-QR (root-minted codes, no known sender)
//     QR frame   (207..393, 644..823)
//     Code frame ( 78..522, 872..991)
//
//   cards/template-2qr.png  — two-QR (bot-minted codes; contact_token set)
//     QR1 (redeem)  ( 45..225, 680..860)
//     QR2 (message) (375..555, 680..860)
//     Code frame    ( 70..530, 890..1010)
//
// Rendered per-code PNGs are cached under card-cache/<code>.png.

const CARD_W        = 600;
const CARD_H        = 1050;
const CARD_CACHE    = '/usr/local/lsws/home/r2r.help/card-cache';
const CARD_TEMPLATE_1QR = '/usr/local/lsws/home/r2r.help/cards/template.png';
const CARD_TEMPLATE_2QR = '/usr/local/lsws/home/r2r.help/cards/template-2qr.png';
const FONT_MONO     = '/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf';
const FONT_SANS     = '/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf';
const FONT_SANS_B   = '/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf';

// Frame geometry per template.
const QR_BOX_1QR  = ['x1' => 207, 'y1' => 644, 'x2' => 393, 'y2' => 823];
const CODE_BOX_1QR= ['x1' =>  78, 'y1' => 872, 'x2' => 522, 'y2' => 991];
const QR1_BOX_2QR = ['x1' =>  45, 'y1' => 680, 'x2' => 225, 'y2' => 860];
const QR2_BOX_2QR = ['x1' => 375, 'y1' => 680, 'x2' => 555, 'y2' => 860];
const CODE_BOX_2QR= ['x1' =>  70, 'y1' => 890, 'x2' => 530, 'y2' => 1010];
const WORDMARK_Y  = 60;

// Encode $url into a temp PNG via qrencode. Returns file path or '' on error.
function _r2r_qr_tmp(string $url): string {
    $out = tempnam(sys_get_temp_dir(), 'qr_') . '.png';
    $cmd = 'qrencode -t PNG -s 12 -m 1 -l Q -o ' . escapeshellarg($out) . ' ' . escapeshellarg($url);
    exec($cmd . ' 2>&1', $_, $rc);
    if ($rc !== 0 || !is_file($out)) return '';
    return $out;
}

// Center a $inner-sized square in a box; returns [x,y] top-left offsets.
function _r2r_center_in_box(array $box, int $inner): array {
    $x = (int)($box['x1'] + (($box['x2'] - $box['x1']) - $inner) / 2);
    $y = (int)($box['y1'] + (($box['y2'] - $box['y1']) - $inner) / 2);
    return [$x, $y];
}

// Render a single-QR card.
function _r2r_card_render_1qr(string $code, string $redeemUrl, string $cached): bool {
    $qr = _r2r_qr_tmp($redeemUrl);
    if (!$qr) return false;

    $qr_size = 170;
    [$qr_x, $qr_y] = _r2r_center_in_box(QR_BOX_1QR, $qr_size);
    $code_pt = 30;
    $code_cy = (int)((CODE_BOX_1QR['y1'] + CODE_BOX_1QR['y2']) / 2);
    $code_baseline_y = $code_cy + (int)($code_pt * 0.35);
    $qr_label_y = QR_BOX_1QR['y2'] + 18;

    $cmd =
        "convert " . escapeshellarg(CARD_TEMPLATE_1QR) . " " .
        "-font " . escapeshellarg(FONT_SANS_B) . " -pointsize 84 -fill white " .
        "-gravity North -annotate +0+" . WORDMARK_Y . " 'R2Я' " .
        "-font " . escapeshellarg(FONT_SANS) . " -pointsize 15 -fill 'rgba(255,255,255,0.65)' " .
        "-gravity North -annotate +0+" . (WORDMARK_Y + 96) . " 'invite-only. peer-to-peer.' " .
        "-gravity NorthWest " .
        "\\( " . escapeshellarg($qr) . " -resize {$qr_size}x{$qr_size} \\) -geometry +{$qr_x}+{$qr_y} -composite " .
        "-font " . escapeshellarg(FONT_SANS) . " -pointsize 14 -fill 'rgba(255,255,255,0.6)' " .
        "-gravity North -annotate +0+{$qr_label_y} 'scan to redeem' " .
        "-font " . escapeshellarg(FONT_MONO) . " -pointsize $code_pt -fill white " .
        "-gravity North -annotate +0+{$code_baseline_y} " . escapeshellarg($code) . " " .
        "-font " . escapeshellarg(FONT_SANS) . " -pointsize 13 -fill 'rgba(255,255,255,0.55)' " .
        "-gravity South -annotate +0+22 'r2r.help' " .
        escapeshellarg($cached);

    exec($cmd . ' 2>&1', $co, $rc);
    @unlink($qr);
    if ($rc !== 0) { error_log('1qr composite failed: ' . implode("\n", $co)); return false; }
    @chmod($cached, 0644);
    return true;
}

// Render a two-QR card (invite + contact).
function _r2r_card_render_2qr(string $code, string $redeemUrl, string $contactUrl, string $cached): bool {
    $qr1 = _r2r_qr_tmp($redeemUrl);
    $qr2 = _r2r_qr_tmp($contactUrl);
    if (!$qr1 || !$qr2) { if($qr1)@unlink($qr1); if($qr2)@unlink($qr2); return false; }

    $qr_size = 170;
    [$q1x, $q1y] = _r2r_center_in_box(QR1_BOX_2QR, $qr_size);
    [$q2x, $q2y] = _r2r_center_in_box(QR2_BOX_2QR, $qr_size);
    $code_pt = 30;
    $code_cy = (int)((CODE_BOX_2QR['y1'] + CODE_BOX_2QR['y2']) / 2);
    $code_baseline_y = $code_cy + (int)($code_pt * 0.35);
    $label_y = QR1_BOX_2QR['y2'] + 8;

    // Two labels under the two QRs. We use two annotate calls positioned by absolute x.
    // With gravity=NorthWest, annotate +x+y draws at (x,y) top-left. To center a label
    // horizontally around a target column, ImageMagick's `label:` primitive is easier.
    $q1_cx = (QR1_BOX_2QR['x1'] + QR1_BOX_2QR['x2']) / 2;
    $q2_cx = (QR2_BOX_2QR['x1'] + QR2_BOX_2QR['x2']) / 2;

    $cmd =
        "convert " . escapeshellarg(CARD_TEMPLATE_2QR) . " " .
        // Wordmark + tagline
        "-font " . escapeshellarg(FONT_SANS_B) . " -pointsize 84 -fill white " .
        "-gravity North -annotate +0+" . WORDMARK_Y . " 'R2Я' " .
        "-font " . escapeshellarg(FONT_SANS) . " -pointsize 15 -fill 'rgba(255,255,255,0.65)' " .
        "-gravity North -annotate +0+" . (WORDMARK_Y + 96) . " 'invite. connect. talk.' " .
        // Two QRs
        "-gravity NorthWest " .
        "\\( " . escapeshellarg($qr1) . " -resize {$qr_size}x{$qr_size} \\) -geometry +{$q1x}+{$q1y} -composite " .
        "\\( " . escapeshellarg($qr2) . " -resize {$qr_size}x{$qr_size} \\) -geometry +{$q2x}+{$q2y} -composite " .
        // Labels under each QR — use label: to render, position with -geometry
        "-font " . escapeshellarg(FONT_SANS_B) . " -pointsize 13 -fill 'rgba(140,220,255,0.9)' -background none " .
        "\\( label:'REDEEM' \\) -geometry +" . ($q1_cx - 30) . "+{$label_y} -composite " .
        "\\( label:'MESSAGE ME' \\) -geometry +" . ($q2_cx - 50) . "+{$label_y} -composite " .
        // Invite code centered
        "-font " . escapeshellarg(FONT_MONO) . " -pointsize $code_pt -fill white " .
        "-gravity North -annotate +0+{$code_baseline_y} " . escapeshellarg($code) . " " .
        // Footer
        "-font " . escapeshellarg(FONT_SANS) . " -pointsize 13 -fill 'rgba(255,255,255,0.55)' " .
        "-gravity South -annotate +0+18 'r2r.help' " .
        escapeshellarg($cached);

    exec($cmd . ' 2>&1', $co, $rc);
    @unlink($qr1);
    @unlink($qr2);
    if ($rc !== 0) { error_log('2qr composite failed: ' . implode("\n", $co)); return false; }
    @chmod($cached, 0644);
    return true;
}

// Public entry. Returns the path to the (cached) rendered PNG.
// Look up contact_token from DB to decide which template to use.
function r2r_card_render(string $code, string $redeemUrl): string {
    if (!preg_match('/^[A-Z0-9-]{6,32}$/', $code)) return '';
    $cached = CARD_CACHE . '/' . $code . '.png';
    if (is_file($cached) && filesize($cached) > 0) return $cached;

    // Look up the contact_token for this code (DB helper lives in lib/db.php)
    require_once __DIR__ . '/db.php';
    $db = r2r_db();
    $stmt = $db->prepare("SELECT contact_token FROM invites WHERE code = ? LIMIT 1");
    $stmt->bind_param('s', $code);
    $stmt->execute();
    $stmt->bind_result($contact_token);
    $stmt->fetch();
    $stmt->close();

    $ok = false;
    if ($contact_token && is_file(CARD_TEMPLATE_2QR)) {
        $scheme = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http';
        $host   = $_SERVER['HTTP_HOST'] ?? 'r2r.help';
        $contactUrl = $scheme . '://' . $host . '/m/' . $contact_token;
        $ok = _r2r_card_render_2qr($code, $redeemUrl, $contactUrl, $cached);
    } elseif (is_file(CARD_TEMPLATE_1QR)) {
        $ok = _r2r_card_render_1qr($code, $redeemUrl, $cached);
    } else {
        error_log('no card template found');
    }
    return $ok ? $cached : '';
}

function r2r_card_flush_cache(): int {
    $n = 0;
    foreach (glob(CARD_CACHE . '/*.png') ?: [] as $f) { if (@unlink($f)) $n++; }
    return $n;
}
