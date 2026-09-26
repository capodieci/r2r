<?php
// Shared <head> + CSS for the docs pages (run-a-relay, network, privacy, faq).
// Include AFTER these vars are in scope:
//   $lang_code, $lang_dir, $primary, $secondary, $bg_tint
//   $docs_title       — <title> for the browser tab
//   $docs_description — meta description
// Emits <!DOCTYPE html> ... up to and including <body>.

$_h = fn($s) => htmlspecialchars((string)$s, ENT_QUOTES, 'UTF-8');
?><!DOCTYPE html>
<html lang="<?= $_h($lang_code) ?>" dir="<?= $_h($lang_dir) ?>">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="description" content="<?= $_h($docs_description ?? '') ?>">
<meta name="robots" content="index,follow">
<title><?= $_h($docs_title ?? 'R2R docs') ?></title>
<link rel="icon" type="image/svg+xml" href="/favicon.svg">
<link rel="stylesheet" href="/sippis-shell.css?v=<?= (int)@filemtime(__DIR__ . '/../sippis-shell.css') ?>">
<style>
  :root {
    --primary: <?= $_h($primary) ?>;
    --secondary: <?= $_h($secondary) ?>;
    --bg-tint: <?= $_h($bg_tint) ?>;
    --pane: rgba(0,0,0,0.20);
    --pane-border: rgba(255,255,255,0.08);
    --text: #f4f7f8;
    --muted: rgba(255,255,255,0.7);
    --dim: rgba(255,255,255,0.55);
    --code-bg: #0b1a22;
    --code-fg: #e5f5f7;
    --token: #f6c26b;
    --token-bg: rgba(246,194,107,0.14);
    --info-bg: rgba(255,255,255,0.06);
    --info-bd: rgba(255,255,255,0.15);
    --imp-bg: rgba(14,173,181,0.10);
    --imp-bd: var(--primary);
    --warn-bg: rgba(226,120,60,0.10);
    --warn-bd: #e2783c;
  }
  @media (prefers-color-scheme: light) {
    :root:not([data-theme="dark"]) {
      --text: #16232a;
      --muted: rgba(20,30,40,0.75);
      --dim: rgba(20,30,40,0.55);
      --pane: rgba(0,0,0,0.04);
      --pane-border: rgba(0,0,0,0.10);
      --info-bg: rgba(20,40,60,0.05);
      --info-bd: rgba(20,40,60,0.15);
    }
  }
  :root[data-theme="dark"] {
    --text: #f4f7f8; --muted: rgba(255,255,255,0.7); --dim: rgba(255,255,255,0.55);
    --pane: rgba(0,0,0,0.20); --pane-border: rgba(255,255,255,0.08);
  }
  body { color: var(--text); background: radial-gradient(ellipse at top, var(--bg-tint,#0A7B83) 0%, #11313e 55%, #1A2B3C 100%); }
  @media (prefers-color-scheme: light) {
    body:not([data-theme="dark"] body) { background: linear-gradient(180deg, #f6fafb 0%, #e6eff2 100%); color: #16232a; }
  }

  .layout {
    display: grid; grid-template-columns: 240px minmax(0,1fr); gap: 32px;
    max-width: 1140px; margin: 0 auto; padding: 24px 20px 80px; align-items: start;
    text-align: left;      /* docs pages left-align body, not center */
  }
  @media (max-width: 860px) {
    .layout { grid-template-columns: 1fr; }
    nav.toc { position: static !important; margin-bottom: 24px; }
  }

  /* Sticky TOC — top offset accounts for the sticky topbar height so the two
     don't overlap. Bump if the topbar height changes. */
  nav.toc {
    position: sticky; top: 96px; padding: 16px; background: var(--pane);
    border: 1px solid var(--pane-border); border-radius: 10px; font-size: 14px;
  }
  nav.toc h2 { color: var(--primary); font-size: 13px; text-transform: uppercase; letter-spacing: 1px; margin: 0 0 10px; }
  nav.toc ol { list-style: none; padding: 0; margin: 0; counter-reset: toc; }
  nav.toc ol li { counter-increment: toc; padding: 4px 0; }
  nav.toc ol li::before { content: counter(toc, decimal-leading-zero) ". "; color: var(--dim); font-family: monospace; font-size: 12px; }
  nav.toc a { color: var(--text); text-decoration: none; }
  nav.toc a:hover { color: var(--primary); }

  /* min-width:0 lets minmax(0,1fr) actually clamp the article column — without
     it, long inline content (URLs, code) can force the whole page wider. */
  .layout > article { min-width: 0; }

  article { text-align: left; }
  article h1 {
    font-size: clamp(28px, 4.5vw, 40px); margin: 0 0 8px;
    letter-spacing: -0.5px; text-align: center;    /* only the title is centered */
  }
  article h1 .accent { color: var(--primary); }
  article h1 .h1-sub {
    display: block; margin-top: 4px;
    font-size: 0.72em; font-weight: 500; letter-spacing: -0.3px;
    color: var(--muted, rgba(255,255,255,0.72));
  }
  article h2 {
    color: var(--primary); font-size: 22px; margin: 44px 0 12px;
    padding-top: 20px; border-top: 1px solid var(--pane-border);
    scroll-margin-top: 108px;                       /* space below sticky topbar */
  }
  article h2 a.anchor { color: inherit; text-decoration: none; }
  article h2 a.anchor:hover::after { content: " #"; color: var(--dim); font-weight: 400; }
  article h3 { color: var(--primary); font-size: 16px; margin: 24px 0 8px; text-transform: uppercase; letter-spacing: 1px; }
  article p, article li { line-height: 1.6; color: var(--text); }
  article a { color: var(--primary); }

  .lede { font-size: 18px; color: var(--muted); text-align: left; }

  /* Code blocks with copy button */
  .code {
    position: relative; background: var(--code-bg); color: var(--code-fg);
    border-radius: 10px; padding: 14px 16px; padding-right: 100px;
    font-family: "SFMono-Regular", Menlo, Consolas, "DejaVu Sans Mono", monospace;
    font-size: 13.5px; line-height: 1.55; overflow-x: auto; margin: 12px 0;
    border: 1px solid rgba(255,255,255,0.08);
    text-align: left;
  }
  .code pre { margin: 0; white-space: pre; }
  .code .copy {
    position: absolute; top: 8px; right: 8px;
    background: rgba(255,255,255,0.08); color: var(--code-fg);
    border: 1px solid rgba(255,255,255,0.14); padding: 4px 10px;
    font: inherit; font-size: 12px; border-radius: 6px; cursor: pointer;
  }
  .code .copy:hover { background: rgba(255,255,255,0.16); }
  .code .copy.ok { background: rgba(80,200,120,0.25); color: #cff5db; }

  .tok {
    display: inline; padding: 1px 6px; border-radius: 4px;
    background: var(--token-bg); color: var(--token); font-weight: 600;
  }
  .hero-code { font-size: 15px; padding: 18px 18px; padding-right: 110px; }

  /* Callouts */
  .callout {
    padding: 12px 16px; border-left: 3px solid; border-radius: 6px;
    margin: 16px 0; font-size: 15px; line-height: 1.55; text-align: left;
  }
  .callout.info { background: var(--info-bg); border-left-color: var(--info-bd); }
  .callout.important { background: var(--imp-bg); border-left-color: var(--imp-bd); }
  .callout.warn { background: var(--warn-bg); border-left-color: var(--warn-bd); }
  .callout b { display: block; margin-bottom: 4px; }

  /* Tables */
  table.compact { width: 100%; border-collapse: collapse; font-size: 14px; margin: 12px 0; }
  table.compact th, table.compact td { text-align: left; padding: 8px 10px; border-bottom: 1px solid var(--pane-border); }
  table.compact th { background: var(--pane); color: var(--primary); font-weight: 700; }
  table.compact td code { background: var(--pane); padding: 1px 6px; border-radius: 4px; }

  /* Two-column knows/doesn't-know layout */
  .knows-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 20px; margin-top: 12px; }
  .knows-grid .col { padding: 16px 18px; border-radius: 10px; background: var(--pane); border-top: 3px solid var(--primary); }
  .knows-grid .col.warn { border-top-color: var(--warn-bd); }
  .knows-grid h4 { margin: 0 0 8px; font-size: 15px; }
  .knows-grid ul { margin: 8px 0 0; padding-left: 18px; }
  .knows-grid li { margin: 6px 0; font-size: 14px; }

  /* FAQ accordion */
  details.faq {
    background: var(--pane); border: 1px solid var(--pane-border); border-radius: 8px;
    padding: 12px 16px; margin: 8px 0;
    width: 100%; box-sizing: border-box;                /* full column width, always */
  }
  details.faq summary {
    cursor: pointer; font-weight: 600; color: var(--text);
    list-style: none;
    display: block; width: 100%;                        /* summary bar is full-width regardless of open/closed */
  }
  details.faq summary::-webkit-details-marker { display: none; }
  details.faq summary::before { content: "▸ "; color: var(--primary); display: inline-block; width: 1.1em; }
  details.faq[open] summary::before { content: "▾ "; }
  details.faq[open] { padding-bottom: 16px; }
  details.faq p, details.faq li {
    margin: 8px 0; font-size: 14.5px;
    overflow-wrap: anywhere;                            /* long strings wrap inside the box, don't push it wider */
  }

  /* Mesh diagram (network page) */
  .mesh-svg { display: block; max-width: 520px; width: 100%; height: auto; margin: 12px auto 0; background: var(--pane); border: 1px solid var(--pane-border); border-radius: 10px; padding: 16px; }

  /* footer */
  .page-footer { color: var(--dim); font-size: 13px; text-align: center; padding: 24px 0 0; margin-top: 40px; border-top: 1px solid var(--pane-border); }
</style>
</head>
<body>
<?php
// _topbar.php early-exits unless both $state and $h are in scope. Expose $h
// here (the docs pages already set $state above) so the topbar always renders.
$h = $_h;
include __DIR__ . '/../auth/_topbar.php';
?>
