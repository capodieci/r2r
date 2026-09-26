#!/usr/bin/env python3
"""Render ../protocol/R2R-WHITEPAPER.md into the doorway's /paper page.

    python3 tools/build-paper-page.py            # writes web/doorway/templates/en/paper.html

The page is pre-rendered here rather than in the browser so it works under the
doorway's CSP (no CDN scripts) and reads fine without JavaScript. Re-run it
whenever the white paper changes, then rebuild the bundle
(scripts/build-doorway-bundle.py).

Layout follows the specification sites (sticky contents sidebar with download
button, hero card, abstract callout, inline paper, download card with SHA-256),
in the doorway's own palette and shell (site topbar lifted from index.html).
"""
import hashlib, html, os, re, sys
from markdown_it import MarkdownIt

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MD_PATH = os.path.join(ROOT, '..', 'protocol', 'R2R-WHITEPAPER.md')
PDF_PATH = os.path.join(ROOT, '..', 'protocol', 'R2R-WHITEPAPER.pdf')
INDEX_TPL = os.path.join(ROOT, 'web', 'doorway', 'templates', 'en', 'index.html')
OUT = os.path.join(ROOT, 'web', 'doorway', 'templates', 'en', 'paper.html')

PDF_NAME = 'R2R-WHITEPAPER.pdf'
MD_NAME = 'R2R-WHITEPAPER.md'

SUBTITLE = ('The complete white paper: wallet, vault and setup cards, the wire protocol, '
            'dead-drop storage, onion routing, the relay mesh, the invite tree and the storage '
            'market. Written to the byte level so a second implementation can interoperate.')
KEYWORDS = ['End-to-end encryption', 'Ed25519', 'X25519', 'AES-256-GCM', 'Onion routing',
            'Dead drops', 'Relay mesh', 'Invite tree', 'Storage market', 'WebSocket', 'SQLite',
            'scrypt', 'USDC vouchers']
DESCRIPTION = ('R2R protocol white paper and complete specification: identities, the wallet, '
               'the wire protocol, relay storage, onion routing, the relay mesh, invites and the '
               'storage market. Read online or download as PDF or Markdown.')


def sha256(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(1 << 20), b''):
            h.update(chunk)
    return h.hexdigest()


def fmt_size(n):
    if n < 1024 * 1024:
        return '%d KB' % round(n / 1024)
    return '%.1f MB' % (n / (1024 * 1024))


def pdf_pages(path):
    """Page count without a PDF library: the /Count of the root /Pages node
    (the largest one; intermediate nodes carry partial counts)."""
    data = open(path, 'rb').read()
    counts = [int(c) for c in re.findall(rb'/Type\s*/Pages\b[^>]*?/Count\s+(\d+)', data, re.S)]
    counts += [int(c) for c in re.findall(rb'/Count\s+(\d+)[^>]*?/Type\s*/Pages\b', data, re.S)]
    return max(counts) if counts else None


def slugify(text, seen):
    s = text.strip().lower()
    s = re.sub(r'[^\w\s-]', '', s, flags=re.UNICODE)  # GitHub: drop punctuation
    s = re.sub(r'\s', '-', s)
    base = s
    i = 1
    while s in seen:
        s = '%s-%d' % (base, i)
        i += 1
    seen.add(s)
    return s


def main():
    src = open(MD_PATH, encoding='utf-8').read()

    # --- lift the pieces the hero shows, out of the body ---------------------
    m_title = re.match(r'# (.+)\n', src)
    title = m_title.group(1).strip()
    src = src[m_title.end():]
    src = re.sub(r'^\s*## White paper and complete protocol specification\s*\n', '', src, count=1)
    m_meta = re.search(r'^\*\*Protocol:\*\*.*$', src, re.M)
    meta_md = m_meta.group(0)
    src = src[:m_meta.start()] + src[m_meta.end():]
    m_date = re.search(r'\*\*Document date:\*\*\s*([0-9]{1,2} \w+ [0-9]{4})', meta_md)
    doc_date = m_date.group(1) if m_date else ''
    m_abs = re.search(r'^## Abstract\s*\n(.*?)\n---\s*\n', src, re.S | re.M)
    abstract_md = m_abs.group(1).strip()
    src = src[:m_abs.start()] + src[m_abs.end():]
    m_toc = re.search(r'^## Table of contents\s*\n(.*?)\n---\s*\n', src, re.S | re.M)
    src = src[:m_toc.start()] + src[m_toc.end():]
    src = re.sub(r'^\s*---\s*\n', '', src, count=1)  # leading rule left behind

    md = MarkdownIt('commonmark', {'html': False, 'linkify': False, 'typographer': False})
    md.enable('table').enable('strikethrough')

    # --- renderer tweaks: heading ids, table wrappers, no rule before a section
    tokens = md.parse(src)
    seen = set()
    toc = []
    for i, t in enumerate(tokens):
        if t.type == 'heading_open' and t.tag in ('h2', 'h3'):
            text = tokens[i + 1].content
            sid = slugify(text, seen)
            t.attrSet('id', sid)
            toc.append((t.tag, sid, text))
    # drop the "---" that precedes every section; the h2 draws its own rule
    for i, t in enumerate(tokens):
        if t.type == 'hr' and i + 1 < len(tokens) and tokens[i + 1].type == 'heading_open':
            t.hidden = True
            t.type = 'hidden_hr'
    r = md.renderer

    def render_table_open(self, toks, idx, options, env):
        return '<div class="table-wrap"><table>'

    def render_table_close(self, toks, idx, options, env):
        return '</table></div>\n'

    def render_hidden(self, toks, idx, options, env):
        return ''

    def render_link_open(self, toks, idx, options, env):
        href = toks[idx].attrGet('href') or ''
        if href.startswith('http://') or href.startswith('https://'):
            toks[idx].attrSet('target', '_blank')
            toks[idx].attrSet('rel', 'noopener')
        return self.renderToken(toks, idx, options, env)

    r.rules['table_open'] = render_table_open.__get__(r)
    r.rules['table_close'] = render_table_close.__get__(r)
    r.rules['hidden_hr'] = render_hidden.__get__(r)
    r.rules['link_open'] = render_link_open.__get__(r)
    body_html = r.render(tokens, md.options, {})

    # every internal link in the paper must land on a heading we emitted
    ids = {sid for _, sid, _ in toc}
    missing = sorted({h for h in re.findall(r'href="#([^"]+)"', body_html) if h not in ids})
    if missing:
        sys.exit('internal links with no target: %s' % ', '.join(missing))

    abstract_html = md.render(abstract_md)
    meta_html = md.renderInline(meta_md)

    # --- files, hashes, sizes -------------------------------------------------
    pdf_size = os.path.getsize(PDF_PATH)
    md_size = os.path.getsize(MD_PATH)
    pdf_sha = sha256(PDF_PATH)
    md_sha = sha256(MD_PATH)
    pages = pdf_pages(PDF_PATH)
    n_sections = sum(1 for tag, sid, _ in toc if tag == 'h2' and not sid.startswith('appendix'))
    n_appendix = sum(1 for tag, sid, _ in toc if tag == 'h2' and sid.startswith('appendix'))

    # --- the site topbar, lifted from the home template -----------------------
    idx_html = open(INDEX_TPL, encoding='utf-8').read()
    hs = idx_html.find('<header class="topbar">')
    he = idx_html.find('</header>', hs) + len('</header>')
    topbar = idx_html[hs:he]
    topbar = topbar.replace('class="site-nav-item active"', 'class="site-nav-item"')
    topbar = topbar.replace('href="{{BASE}}/paper"\n         class="site-nav-item"',
                            'href="{{BASE}}/paper"\n         class="site-nav-item active"')
    topbar = topbar.replace('class="intent-pill active"', 'class="intent-pill"')
    assert 'site-nav-item active' in topbar, 'Paper nav item missing from index.html'

    # --- sidebar + print contents ----------------------------------------------
    side_nav = []
    print_toc = []
    for tag, sid, text in toc:
        cls = 'l0' if tag == 'h2' else 'l2'
        side_nav.append('<a href="#%s" class="nav-link %s">%s</a>' % (sid, cls, html.escape(text)))
        print_toc.append('<li class="%s">%s</li>' % (cls, html.escape(text)))

    chips = ['<span>%s</span>' % html.escape(doc_date)] if doc_date else []
    chips.append('<span>%d sections + %d appendices</span>' % (n_sections, n_appendix))
    if pages:
        chips.append('<span>%d pages (A4 PDF)</span>' % pages)
    chips.append('<span>Test vectors checked against the reference code</span>')

    dl_icon = ('<svg width="16" height="16" viewBox="0 0 16 16" fill="none" stroke="currentColor" '
               'stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">'
               '<path d="M8 2v9m0 0l-3-3m3 3l3-3"/><path d="M2 12v1a2 2 0 002 2h8a2 2 0 002-2v-1"/></svg>')

    page = TEMPLATE
    page = page.replace('@@TITLE@@', html.escape(title))
    page = page.replace('@@DESCRIPTION@@', html.escape(DESCRIPTION))
    page = page.replace('@@SUBTITLE@@', html.escape(SUBTITLE))
    page = page.replace('@@META@@', meta_html)
    page = page.replace('@@CHIPS@@', ''.join(chips))
    page = page.replace('@@KEYWORDS@@', ''.join('<span>%s</span>' % html.escape(k) for k in KEYWORDS))
    page = page.replace('@@ABSTRACT@@', abstract_html)
    page = page.replace('@@TOPBAR@@', topbar)
    page = page.replace('@@SIDENAV@@', '\n    '.join(side_nav))
    page = page.replace('@@PRINTTOC@@', '\n'.join(print_toc))
    page = page.replace('@@BODY@@', body_html)
    page = page.replace('@@PDF_NAME@@', PDF_NAME).replace('@@MD_NAME@@', MD_NAME)
    page = page.replace('@@PDF_SIZE@@', fmt_size(pdf_size)).replace('@@MD_SIZE@@', fmt_size(md_size))
    page = page.replace('@@PDF_SHA@@', pdf_sha).replace('@@MD_SHA@@', md_sha)
    page = page.replace('@@DATE@@', html.escape(doc_date))
    page = page.replace('@@ICON@@', dl_icon)

    with open(OUT, 'w', encoding='utf-8') as f:
        f.write(page)
    print('wrote %s (%d bytes): %d sections, %d subsections, %d internal links ok, pdf %s, md %s'
          % (os.path.relpath(OUT, ROOT), len(page), sum(1 for t in toc if t[0] == 'h2'),
             sum(1 for t in toc if t[0] == 'h3'), len(re.findall(r'href="#', body_html)),
             fmt_size(pdf_size), fmt_size(md_size)))


TEMPLATE = r'''<!DOCTYPE html>
<html lang="en" dir="ltr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="description" content="@@DESCRIPTION@@">
<meta name="robots" content="index,follow">
<meta property="og:type" content="article">
<meta property="og:title" content="@@TITLE@@">
<meta property="og:description" content="@@DESCRIPTION@@">
<meta name="twitter:card" content="summary">
<title>R2R white paper — @@TITLE@@</title>
<link rel="icon" type="image/svg+xml" href="/favicon.svg">
<link rel="stylesheet" href="/sippis-shell.css">
<style>
  :root {
    --primary: #0EADB5;
    --secondary: #F26430;
    --bg-tint: #09797E;
    --pane: rgba(0,0,0,0.20);
    --pane-strong: rgba(0,0,0,0.30);
    --pane-border: rgba(255,255,255,0.08);
    --text: #f4f7f8;
    --muted: rgba(255,255,255,0.72);
    --dim: rgba(255,255,255,0.55);
    --code-bg: #0b1a22;
    --code-fg: #e5f5f7;
    --inline-code-bg: rgba(0,0,0,0.30);
    --inline-code-fg: #dff6f8;
    --glow: rgba(14,173,181,0.12);
    --table-head: rgba(14,173,181,0.12);
    --stripe: rgba(255,255,255,0.03);
    --note-bg: rgba(242,100,48,0.10);
    --side-w: 290px;
    --topbar-h: 96px;
  }
  @media (prefers-color-scheme: light) {
    :root:not([data-theme="dark"]) {
      --text: #16232a;
      --muted: rgba(20,30,40,0.75);
      --dim: rgba(20,30,40,0.55);
      --pane: rgba(0,0,0,0.04);
      --pane-strong: rgba(0,0,0,0.07);
      --pane-border: rgba(0,0,0,0.10);
      --inline-code-bg: rgba(14,173,181,0.10);
      --inline-code-fg: #0b3a3e;
      --table-head: rgba(14,173,181,0.12);
      --stripe: rgba(0,0,0,0.025);
    }
  }
  :root[data-theme="dark"] {
    --text: #f4f7f8; --muted: rgba(255,255,255,0.72); --dim: rgba(255,255,255,0.55);
    --pane: rgba(0,0,0,0.20); --pane-strong: rgba(0,0,0,0.30); --pane-border: rgba(255,255,255,0.08);
  }
  html { scroll-behavior: smooth; }
  @media (prefers-reduced-motion: reduce) { html { scroll-behavior: auto; } }
  body { color: var(--text); background: radial-gradient(ellipse at top, var(--bg-tint,#0A7B83) 0%, #11313e 55%, #1A2B3C 100%); }
  @media (prefers-color-scheme: light) {
    body:not([data-theme="dark"]) { background: linear-gradient(180deg, #f6fafb 0%, #e6eff2 100%); color: #16232a; }
  }

  /* Reading progress, pinned to the bottom edge of the sticky topbar */
  #progress { position: fixed; top: var(--topbar-h); left: 0; height: 3px; width: 0; background: var(--primary); z-index: 99; transition: width .1s linear; }

  /* Two columns: sticky contents on the left, the paper on the right */
  .paper {
    width: 100%; max-width: 1240px; margin: 0 auto; padding: 20px 20px 60px;
    display: grid; grid-template-columns: var(--side-w) minmax(0,1fr); gap: 32px;
    align-items: start; text-align: left;
  }
  .paper-side {
    position: sticky; top: calc(var(--topbar-h) + 12px);
    max-height: calc(100vh - var(--topbar-h) - 24px);
    display: flex; flex-direction: column;
    background: var(--pane); border: 1px solid var(--pane-border); border-radius: 12px;
    overflow: hidden;
  }
  .side-head { padding: 16px 16px 12px; border-bottom: 1px solid var(--pane-border); display: grid; gap: 8px; }
  .side-kicker { font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: .1em; color: var(--primary); }
  .side-dl {
    display: inline-flex; align-items: center; justify-content: center; gap: 8px;
    padding: 9px 14px; border-radius: 999px; text-decoration: none; font-size: 14px; font-weight: 600;
    background: var(--primary); color: #fff; border: 1px solid transparent; transition: filter .15s, background .15s;
  }
  .side-dl:hover { filter: brightness(1.1); }
  .side-dl.alt { background: rgba(14,173,181,0.08); color: var(--text); border-color: rgba(14,173,181,0.55); }
  .side-dl.alt:hover { background: rgba(14,173,181,0.18); }
  .side-dl small { font-weight: 400; opacity: .8; font-size: 12px; }
  .side-verify {
    margin-top: 2px; padding: 9px 10px; border: 1.5px dashed rgba(14,173,181,0.45); border-radius: 8px;
    font-size: 12px; line-height: 1.35; color: var(--dim); text-align: center; cursor: pointer;
    transition: border-color .15s, background .15s;
  }
  .side-verify:hover, .side-verify.over { border-color: var(--primary); background: var(--glow); color: var(--text); }
  .side-verify b { color: var(--text); font-weight: 600; }
  .side-verify input { display: none; }
  .side-verify-status { font-size: 12px; line-height: 1.4; margin-top: 6px; overflow-wrap: anywhere; }
  .side-verify-status.ok { color: #86efac; } .side-verify-status.bad { color: #fab088; } .side-verify-status.err { color: #f88; }
  @media (prefers-color-scheme: light) { :root:not([data-theme="dark"]) .side-verify-status.ok { color: #15803d; } :root:not([data-theme="dark"]) .side-verify-status.bad { color: #b45309; } }
  .side-nav { flex: 1 1 auto; overflow-y: auto; padding: 8px 0; scrollbar-width: thin; }
  .nav-link {
    display: block; padding: 5px 16px; font-size: 13px; line-height: 1.35; color: var(--muted);
    text-decoration: none; border-left: 2px solid transparent; transition: background .12s, color .12s;
  }
  .nav-link:hover { color: var(--text); background: var(--glow); }
  .nav-link.active { color: var(--primary); border-left-color: var(--primary); background: var(--glow); font-weight: 600; }
  .nav-link.l0 { font-weight: 600; color: var(--text); padding-top: 9px; }
  .nav-link.l0.active { color: var(--primary); }
  .nav-link.l2 { padding-left: 30px; font-size: 12.5px; }
  .side-foot { padding: 10px 16px; border-top: 1px solid var(--pane-border); font-size: 11.5px; color: var(--dim); }

  .side-toggle, .overlay { display: none; }
  @media (max-width: 900px) {
    .paper { grid-template-columns: 1fr; padding: 16px 16px 60px; }
    .paper-side {
      position: fixed; top: 0; left: 0; bottom: 0; width: min(var(--side-w), 86vw); max-height: none;
      border-radius: 0 12px 12px 0; z-index: 1000; transform: translateX(-102%); transition: transform .25s ease;
      background: #11313e;
    }
    .paper-side.open { transform: translateX(0); }
    .overlay.open { display: block; position: fixed; inset: 0; background: rgba(0,0,0,.5); z-index: 999; }
    .side-toggle {
      display: inline-flex; align-items: center; gap: 8px; position: fixed; left: 16px; bottom: 20px; z-index: 900;
      padding: 10px 16px; border-radius: 999px; border: 1px solid rgba(14,173,181,0.55);
      background: #11313e; color: #f4f7f8; font: inherit; font-size: 14px; font-weight: 600; cursor: pointer;
      box-shadow: 0 8px 24px rgba(0,0,0,0.35);
    }
  }
  @media (prefers-color-scheme: light) {
    @media (max-width: 900px) {
      :root:not([data-theme="dark"]) .paper-side { background: #f6fafb; }
      :root:not([data-theme="dark"]) .side-toggle { background: #ffffff; color: #16232a; }
    }
  }

  /* The paper itself */
  .paper-main { min-width: 0; }
  .hero-card {
    position: relative; overflow: hidden; padding: 32px 32px 28px; border-radius: 16px;
    background: var(--pane); border: 1px solid var(--pane-border);
  }
  .hero-card::after {
    content: ""; position: absolute; top: -40%; right: -10%; width: 320px; height: 320px; pointer-events: none;
    background: radial-gradient(circle, rgba(14,173,181,0.22) 0%, transparent 70%);
  }
  .hero-label {
    display: inline-block; font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: .1em;
    color: var(--primary); background: var(--glow); padding: 4px 10px; border-radius: 4px; margin-bottom: 14px;
  }
  .hero-card h1 { font-size: clamp(24px, 3.4vw, 38px); line-height: 1.15; font-weight: 800; letter-spacing: -0.02em; margin: 0 0 10px; }
  .hero-sub { font-size: 16px; color: var(--muted); max-width: 66ch; line-height: 1.6; margin: 0 0 16px; }
  .hero-meta { display: flex; flex-wrap: wrap; gap: 8px; margin-bottom: 18px; }
  .hero-meta span {
    font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 12px;
    background: var(--glow); color: var(--text); padding: 6px 10px; border-radius: 4px;
  }
  .hero-actions { display: flex; flex-wrap: wrap; gap: 10px; align-items: center; }
  .btn {
    display: inline-flex; align-items: center; gap: 8px; padding: 10px 18px; border-radius: 999px;
    font-size: 14.5px; font-weight: 600; text-decoration: none; background: var(--primary); color: #fff;
    border: 1px solid transparent; transition: filter .15s, transform .15s;
  }
  .btn:hover { filter: brightness(1.1); transform: translateY(-1px); }
  .btn small { font-weight: 400; opacity: .85; font-size: 12px; }
  .hero-actions .cta { font-size: 14.5px; }
  .hero-spec { margin: 18px 0 0; font-size: 13px; color: var(--dim); line-height: 1.6; }
  .hero-spec code { font-size: 12px; }

  .keywords { margin: 18px 0 22px; display: flex; flex-wrap: wrap; gap: 6px; }
  .keywords span { font-size: 12px; padding: 4px 10px; border-radius: 999px; background: var(--glow); color: var(--primary); border: 1px solid rgba(14,173,181,0.25); }

  .abstract {
    border-left: 3px solid var(--primary); background: var(--pane); border-radius: 0 12px 12px 0;
    padding: 18px 24px; margin: 0 0 8px; font-size: 15.5px; line-height: 1.75; color: var(--muted);
  }
  .abstract h2 { margin: 0 0 8px; padding: 0; border: 0; font-size: 13px; text-transform: uppercase; letter-spacing: .1em; color: var(--primary); }
  .abstract p:last-child { margin-bottom: 0; }

  article { font-size: 16px; line-height: 1.7; }
  article > h2 {
    color: var(--primary); font-size: 25px; font-weight: 700; letter-spacing: -0.01em;
    margin: 52px 0 14px; padding-top: 22px; border-top: 1px solid var(--pane-border);
    scroll-margin-top: calc(var(--topbar-h) + 20px);
  }
  article > h3 { font-size: 18px; font-weight: 600; margin: 32px 0 10px; scroll-margin-top: calc(var(--topbar-h) + 20px); }
  article > h4 { font-size: 15.5px; font-weight: 700; margin: 24px 0 8px; font-style: italic; }
  article p { margin: 0 0 16px; }
  article a { color: var(--primary); }
  article ul, article ol { margin: 0 0 16px; padding-left: 26px; }
  article li { margin-bottom: 6px; }
  article li::marker { color: var(--primary); }
  article strong { color: var(--text); }
  article hr { border: 0; border-top: 1px solid var(--pane-border); margin: 32px 0; }
  article blockquote {
    margin: 0 0 18px; padding: 12px 18px; border-left: 3px solid var(--secondary);
    background: var(--note-bg); border-radius: 0 10px 10px 0; color: var(--muted);
  }
  article blockquote p:last-child { margin: 0; }
  article code {
    font-family: "SFMono-Regular", Menlo, Consolas, "DejaVu Sans Mono", monospace;
    font-size: .86em; background: var(--inline-code-bg); color: var(--inline-code-fg);
    padding: 2px 6px; border-radius: 4px; overflow-wrap: anywhere;
  }
  article pre {
    background: var(--code-bg); color: var(--code-fg); border: 1px solid rgba(255,255,255,0.08);
    border-radius: 10px; padding: 14px 16px; margin: 0 0 18px; overflow-x: auto;
    font-size: 13px; line-height: 1.55; text-align: left;
  }
  article pre code { background: none; color: inherit; padding: 0; font-size: inherit; overflow-wrap: normal; }
  .table-wrap { overflow-x: auto; margin: 0 0 20px; border: 1px solid var(--pane-border); border-radius: 10px; background: var(--pane); }
  .table-wrap table { width: 100%; border-collapse: collapse; font-size: 14px; }
  .table-wrap thead { background: var(--table-head); }
  .table-wrap th { text-align: left; padding: 10px 12px; font-weight: 700; border-bottom: 1px solid var(--pane-border); white-space: nowrap; color: var(--text); }
  .table-wrap td { padding: 8px 12px; border-bottom: 1px solid var(--pane-border); vertical-align: top; }
  .table-wrap tbody tr:nth-child(even) { background: var(--stripe); }
  .table-wrap tbody tr:last-child td { border-bottom: 0; }
  .table-wrap td code, .table-wrap th code { font-size: .82em; padding: 1px 5px; }

  .download-card { margin: 48px 0 0; padding: 22px 26px; border-radius: 14px; background: var(--pane); border: 1px solid var(--pane-border); }
  .download-card h3 { margin: 0 0 8px; font-size: 18px; color: var(--primary); }
  .download-card p { margin: 0 0 14px; color: var(--muted); font-size: 14.5px; }
  .download-card .row { display: flex; flex-wrap: wrap; gap: 10px; margin-bottom: 14px; }
  .sha { font-size: 12px; color: var(--dim); margin: 6px 0 0; }
  .sha code { font-size: 11.5px; overflow-wrap: anywhere; background: var(--inline-code-bg); }
  .sha code.live::after { content: " ✓ as served by this relay"; color: #86efac; font-family: inherit; }

  .back-top {
    position: fixed; right: 20px; bottom: 20px; width: 42px; height: 42px; border-radius: 50%; border: 0;
    background: var(--primary); color: #fff; cursor: pointer; display: flex; align-items: center; justify-content: center;
    opacity: 0; transform: translateY(10px); transition: opacity .25s, transform .25s; z-index: 900;
    box-shadow: 0 8px 24px rgba(0,0,0,0.35);
  }
  .back-top.visible { opacity: 1; transform: translateY(0); }

  #print-toc { display: none; }
  footer { padding: 24px; color: rgba(255,255,255,0.5); font-size: 13px; }
  @media print {
    .topbar, .paper-side, .side-toggle, .overlay, .back-top, #progress, .hero-actions, .download-card, footer { display: none !important; }
    body { background: #fff; color: #000; display: block; }
    .paper { display: block; max-width: none; padding: 0; }
    .hero-card { border: 1px solid #ccc; background: none; }
    .hero-card::after { display: none; }
    #print-toc { display: block; break-after: page; }
    #print-toc ol { list-style: none; padding: 0; columns: 2; column-gap: 32px; font-size: 12px; }
    #print-toc li.l2 { padding-left: 14px; }
    article a { color: #000; text-decoration: none; }
    article pre, .table-wrap, .abstract, blockquote { break-inside: avoid; }
    article > h2, article > h3 { break-after: avoid; color: #000; }
  }
</style>
</head>
<body>
@@TOPBAR@@

<div id="progress" aria-hidden="true"></div>

<div class="paper">

<aside class="paper-side" id="sidebar" aria-label="Contents">
  <div class="side-head">
    <span class="side-kicker">White paper · protocol specification</span>
    <a class="side-dl" href="{{BASE}}/assets/@@PDF_NAME@@" download="@@PDF_NAME@@">@@ICON@@ Download PDF <small>@@PDF_SIZE@@</small></a>
    <a class="side-dl alt" href="{{BASE}}/assets/@@MD_NAME@@" download="@@MD_NAME@@">@@ICON@@ Markdown source <small>@@MD_SIZE@@</small></a>
    <label class="side-verify" id="sideVerify" title="Check a downloaded copy against the hashes this relay serves">
      <b>Verify a download</b><br>drop the PDF or .md here, or click
      <input type="file" id="sideVerifyInput">
    </label>
    <div class="side-verify-status" id="sideVerifyStatus" role="status"></div>
  </div>
  <nav class="side-nav" id="nav">
    @@SIDENAV@@
  </nav>
  <div class="side-foot">R2R v2 · @@DATE@@</div>
</aside>
<div class="overlay" id="overlay"></div>

<article class="paper-main" id="top">

<div class="hero-card">
  <span class="hero-label">White paper · R2R v2 · wire proto 1</span>
  <h1>@@TITLE@@</h1>
  <p class="hero-sub">@@SUBTITLE@@</p>
  <div class="hero-meta">@@CHIPS@@</div>
  <div class="hero-actions">
    <a class="btn" href="{{BASE}}/assets/@@PDF_NAME@@" download="@@PDF_NAME@@">@@ICON@@ Download PDF <small>@@PDF_SIZE@@</small></a>
    <a class="cta" href="{{BASE}}/assets/@@MD_NAME@@" download="@@MD_NAME@@">Markdown source</a>
    <a class="cta" href="#abstract">Read it here</a>
  </div>
  <p class="hero-spec">@@META@@</p>
</div>

<div class="keywords">@@KEYWORDS@@</div>

<div class="abstract" id="abstract">
  <h2>Abstract</h2>
  @@ABSTRACT@@
</div>

<nav id="print-toc" aria-hidden="true">
  <h2>Contents</h2>
  <ol>
@@PRINTTOC@@
  </ol>
</nav>

@@BODY@@

<div class="download-card" id="download">
  <h3>Download the white paper</h3>
  <p>The complete paper as a typeset PDF, and the same text in Markdown for machine reading. Every relay serves its own copy under <code>/assets/</code> with its SHA-256; check a downloaded file on the <a href="{{BASE}}/downloads#verify">Downloads page</a>, and cross-check the hashes against other relays there.</p>
  <div class="row">
    <a class="btn" href="{{BASE}}/assets/@@PDF_NAME@@" download="@@PDF_NAME@@">@@ICON@@ Download PDF <small>@@PDF_SIZE@@</small></a>
    <a class="cta" href="{{BASE}}/assets/@@MD_NAME@@" download="@@MD_NAME@@">Markdown source <small>@@MD_SIZE@@</small></a>
  </div>
  <p class="sha"><strong>SHA-256 · PDF:</strong> <code data-sha-for="@@PDF_NAME@@">@@PDF_SHA@@</code></p>
  <p class="sha"><strong>SHA-256 · Markdown:</strong> <code data-sha-for="@@MD_NAME@@">@@MD_SHA@@</code></p>
</div>

</article>
</div>

<button type="button" class="side-toggle" id="sideToggle" aria-controls="sidebar" aria-expanded="false">&#9776; Contents</button>
<button type="button" class="back-top" id="backTop" aria-label="Back to top">
  <svg width="18" height="18" viewBox="0 0 18 18" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M9 14V4m0 0L5 8m4-4l4 4"/></svg>
</button>

<footer>
  Powered by <a href="https://sippis.com/">Sippis</a></footer>

<script>
(function () {
  'use strict';
  var B = '{{BASE}}';
  var root = document.documentElement;
  var topbar = document.querySelector('.topbar');
  function measure() { root.style.setProperty('--topbar-h', (topbar ? topbar.offsetHeight : 0) + 'px'); }
  measure();
  window.addEventListener('resize', measure);
  window.addEventListener('load', measure);

  // Off-canvas contents on small screens
  var side = document.getElementById('sidebar');
  var overlay = document.getElementById('overlay');
  var toggle = document.getElementById('sideToggle');
  function setOpen(open) {
    side.classList.toggle('open', open);
    overlay.classList.toggle('open', open);
    toggle.setAttribute('aria-expanded', open ? 'true' : 'false');
  }
  toggle.addEventListener('click', function () { setOpen(!side.classList.contains('open')); });
  overlay.addEventListener('click', function () { setOpen(false); });

  // Scroll spy, reading progress, back to top
  var links = Array.prototype.slice.call(document.querySelectorAll('#nav .nav-link'));
  var sections = [];
  links.forEach(function (l) {
    var el = document.getElementById((l.getAttribute('href') || '').slice(1));
    if (el) sections.push({ el: el, link: l });
    l.addEventListener('click', function () { if (side.classList.contains('open')) setOpen(false); });
  });
  var nav = document.getElementById('nav');
  var progress = document.getElementById('progress');
  var backTop = document.getElementById('backTop');
  var current = null, ticking = false;
  function update() {
    ticking = false;
    var offset = (topbar ? topbar.offsetHeight : 0) + 28;
    var y = window.scrollY + offset, active = null;
    for (var i = sections.length - 1; i >= 0; i--) {
      if (sections[i].el.getBoundingClientRect().top + window.scrollY <= y) { active = sections[i]; break; }
    }
    if (active !== current) {
      if (current) current.link.classList.remove('active');
      current = active;
      if (current) {
        current.link.classList.add('active');
        var r = current.link.getBoundingClientRect(), nr = nav.getBoundingClientRect();
        if (r.top < nr.top || r.bottom > nr.bottom) current.link.scrollIntoView({ block: 'nearest' });
      }
    }
    var max = root.scrollHeight - window.innerHeight;
    progress.style.width = (max > 0 ? Math.min(100, window.scrollY / max * 100) : 0) + '%';
    backTop.classList.toggle('visible', window.scrollY > 600);
  }
  window.addEventListener('scroll', function () { if (!ticking) { ticking = true; requestAnimationFrame(update); } }, { passive: true });
  window.addEventListener('load', update);
  update();
  backTop.addEventListener('click', function () { window.scrollTo({ top: 0, behavior: 'smooth' }); });

  // The hashes printed above were computed when this page was built; confirm
  // them against what this relay actually serves right now, and keep the list
  // for the verifier in the sidebar.
  var served = [];
  fetch(B + '/assets/', { headers: { 'Accept': 'application/json' } })
    .then(function (r) { return r.ok ? r.json() : null; })
    .then(function (j) {
      if (!j) return;
      served = Array.isArray(j) ? j : (j.assets || j.files || []);
      served.forEach(function (f) {
        var el = document.querySelector('[data-sha-for="' + f.name + '"]');
        if (el && f.sha256) { el.textContent = f.sha256; el.classList.add('live'); }
      });
    }).catch(function () {});

  // Drop a downloaded file on the sidebar: SHA-256 in the browser, compared
  // with every file this relay serves (the paper, the wallet, the binaries).
  var vz = document.getElementById('sideVerify');
  var vin = document.getElementById('sideVerifyInput');
  var vst = document.getElementById('sideVerifyStatus');
  function vsay(cls, html) { vst.className = 'side-verify-status ' + cls; vst.innerHTML = html; }
  function esc(t) { return String(t).replace(/[&<>"]/g, function (c) { return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]; }); }
  function verify(file) {
    if (!file) return;
    if (!(window.crypto && crypto.subtle)) { vsay('err', 'This browser cannot hash files here (needs https).'); return; }
    vsay('', 'Hashing <b>' + esc(file.name) + '</b>\u2026');
    file.arrayBuffer().then(function (buf) { return crypto.subtle.digest('SHA-256', buf); }).then(function (d) {
      var hex = Array.prototype.map.call(new Uint8Array(d), function (b) { return ('0' + b.toString(16)).slice(-2); }).join('');
      var hit = served.filter(function (f) { return (f.sha256 || '').toLowerCase() === hex; })[0];
      if (hit) vsay('ok', '\u2713 Matches <b>' + esc(hit.name) + '</b> as served by this relay.');
      else if (!served.length) vsay('err', 'Could not load this relay\u2019s file list; SHA-256 of your file is <code>' + hex.slice(0, 16) + '\u2026</code>.');
      else vsay('bad', '\u2717 No file on this relay has this hash (<code>' + hex.slice(0, 16) + '\u2026</code>). Expected for a file from elsewhere; otherwise it was altered.');
    }).catch(function () { vsay('err', 'Could not read that file.'); });
  }
  ['dragenter', 'dragover'].forEach(function (ev) { vz.addEventListener(ev, function (e) { e.preventDefault(); vz.classList.add('over'); }); });
  ['dragleave', 'drop'].forEach(function (ev) { vz.addEventListener(ev, function (e) { e.preventDefault(); vz.classList.remove('over'); }); });
  vz.addEventListener('drop', function (e) { if (e.dataTransfer && e.dataTransfer.files.length) verify(e.dataTransfer.files[0]); });
  vin.addEventListener('change', function () { if (vin.files.length) verify(vin.files[0]); vin.value = ''; });
})();
</script>
</body>
</html>
'''

if __name__ == '__main__':
    main()
