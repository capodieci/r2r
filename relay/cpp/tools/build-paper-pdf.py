#!/usr/bin/env python3
"""Render ../protocol/R2R-WHITEPAPER.md into ../protocol/R2R-WHITEPAPER.pdf.

    ~/.local/venvs/paper/bin/python tools/build-paper-pdf.py

Needs WeasyPrint and markdown-it-py, which on this build host live in a
private virtualenv (python3 -m venv ~/.local/venvs/paper &&
~/.local/venvs/paper/bin/pip install weasyprint markdown-it-py). Run it
whenever the white paper changes, before tools/build-paper-page.py, since the
paper page shows the PDF's size, hash and page count.

A4, numbered pages, PDF outline from the headings (WeasyPrint builds it from
h1-h3), internal links that land on the right heading, tables and code that
wrap instead of running off the page.
"""
import os, re, sys

try:
    from markdown_it import MarkdownIt
    from weasyprint import HTML
except ImportError as e:
    sys.exit('%s -- run this with ~/.local/venvs/paper/bin/python (see the docstring)' % e)

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MD_PATH = os.path.join(ROOT, '..', 'protocol', 'R2R-WHITEPAPER.md')
PDF_PATH = os.path.join(ROOT, '..', 'protocol', 'R2R-WHITEPAPER.pdf')

CSS = '''
@page { size: A4; margin: 20mm 18mm 22mm 18mm;
  @bottom-center { content: counter(page) " / " counter(pages); font: 9pt "DejaVu Sans", sans-serif; color: #666; }
  @top-right { content: "R2R white paper"; font: 8pt "DejaVu Sans", sans-serif; color: #999; } }
@page :first { @top-right { content: none; } }
html { font-family: "DejaVu Serif", Georgia, serif; font-size: 10.5pt; line-height: 1.45; color: #111; }
h1 { font-family: "DejaVu Sans", sans-serif; font-size: 22pt; line-height: 1.2; margin: 0 0 6pt; }
h2 { font-family: "DejaVu Sans", sans-serif; font-size: 15pt; margin: 22pt 0 8pt; padding-top: 6pt;
     border-top: 1.5pt solid #222; page-break-after: avoid; }
h3 { font-family: "DejaVu Sans", sans-serif; font-size: 12pt; margin: 14pt 0 6pt; page-break-after: avoid; }
h4 { font-family: "DejaVu Sans", sans-serif; font-size: 10.5pt; margin: 10pt 0 4pt; page-break-after: avoid; }
p { margin: 0 0 7pt; orphans: 3; widows: 3; }
ul, ol { margin: 0 0 7pt 0; padding-left: 18pt; }
li { margin-bottom: 2pt; }
li > p { margin-bottom: 3pt; }
code, pre { font-family: "DejaVu Sans Mono", monospace; }
code { font-size: 8.8pt; background: #f2f2f2; padding: 0 2pt; border-radius: 2pt; }
pre { font-size: 8.3pt; line-height: 1.35; background: #f4f4f4; border: 0.5pt solid #ccc; border-radius: 3pt;
      padding: 6pt 8pt; margin: 4pt 0 9pt; white-space: pre-wrap; word-wrap: break-word; overflow-wrap: anywhere; }
pre code { background: none; padding: 0; font-size: inherit; }
table { border-collapse: collapse; width: 100%; margin: 4pt 0 10pt; font-size: 8.8pt; page-break-inside: auto; }
th, td { border: 0.5pt solid #bbb; padding: 3pt 5pt; vertical-align: top; text-align: left; overflow-wrap: break-word; }
th { background: #eaeaea; font-family: "DejaVu Sans", sans-serif; font-weight: bold; }
tr { page-break-inside: avoid; }
blockquote { margin: 0 0 8pt; padding: 2pt 10pt; border-left: 2.5pt solid #999; color: #333; }
hr { border: 0; border-top: 0.5pt solid #bbb; margin: 12pt 0; }
a { color: #0b4f8a; text-decoration: none; }
strong { font-weight: bold; }
.meta { font-family: "DejaVu Sans", sans-serif; font-size: 9pt; color: #444; margin-bottom: 14pt; }
'''


def slugify(text, seen):
    s = text.strip().lower()
    s = re.sub(r'[^\w\s-]', '', s, flags=re.UNICODE)
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
    md = MarkdownIt('commonmark', {'html': False, 'linkify': False, 'typographer': False})
    md.enable('table').enable('strikethrough')
    tokens = md.parse(src)

    seen = set()
    ids = set()
    for i, t in enumerate(tokens):
        if t.type == 'heading_open':
            sid = slugify(tokens[i + 1].content, seen)
            t.attrSet('id', sid)
            ids.add(sid)
        # the metadata line right under the title gets its own style
        if t.type == 'paragraph_open' and i + 1 < len(tokens) and \
                tokens[i + 1].content.startswith('**Protocol:**'):
            t.attrSet('class', 'meta')

    body = md.renderer.render(tokens, md.options, {})
    missing = sorted({h for h in re.findall(r'href="#([^"]+)"', body) if h not in ids})
    if missing:
        sys.exit('internal links with no target: %s' % ', '.join(missing))

    m = re.match(r'# (.+)\n', src)
    title = m.group(1).strip() if m else 'R2R white paper'
    html = ('<!doctype html><html><head><meta charset="utf-8"><title>%s</title>'
            '<style>%s</style></head><body>%s</body></html>' % (title, CSS, body))
    doc = HTML(string=html, base_url=os.path.dirname(MD_PATH)).render()
    doc.write_pdf(PDF_PATH)
    print('wrote %s: %d pages, %d bytes' % (os.path.relpath(PDF_PATH, ROOT), len(doc.pages),
                                            os.path.getsize(PDF_PATH)))


if __name__ == '__main__':
    main()
