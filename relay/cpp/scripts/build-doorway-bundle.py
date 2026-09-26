#!/usr/bin/env python3
"""Package web/doorway/ into the doorway bundle the relay serves and install.sh fetches.

    python3 scripts/build-doorway-bundle.py [--install]

Regenerates manifest.json (SHA-256 of every file), writes
deploy/r2r-doorway-bundle.zip (root folder r2r-doorway/) and refreshes
docs/translations.zip from web/doorway/i18n. With --install it also copies the
bundle into /var/lib/r2r/doorway and the zip into the relay's assets directory
(needs root); the running relay picks the new bundle up on restart.

The manifest hash is what versions every asset URL (?v=…), so any change here
rolls CDN and browser caches automatically.
"""
import datetime, hashlib, json, os, shutil, subprocess, sys, zipfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(ROOT, 'web', 'doorway')
BUNDLE = os.path.join(ROOT, 'deploy', 'r2r-doorway-bundle.zip')
TRANSLATIONS = os.path.join(ROOT, 'docs', 'translations.zip')
DOORWAY_DIR = '/var/lib/r2r/doorway'
ASSETS_DIR = '/var/lib/r2r/assets'
VERSION = '1.1.0'


def sha256(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(1 << 20), b''):
            h.update(chunk)
    return h.hexdigest()


def main():
    install = '--install' in sys.argv
    files = {}
    for dirpath, dirnames, filenames in os.walk(SRC):
        dirnames[:] = sorted(d for d in dirnames if not d.startswith('.'))
        for fn in sorted(filenames):
            if fn.startswith('.') or fn == 'manifest.json':
                continue
            full = os.path.join(dirpath, fn)
            rel = os.path.relpath(full, SRC).replace(os.sep, '/')
            files[rel] = {'sha256': sha256(full), 'size': os.path.getsize(full)}
    manifest = {
        'built_at': datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
        'files': files,
        'source': 'r2r-relay repo, web/doorway (scripts/build-doorway-bundle.py)',
        'version': VERSION,
    }
    with open(os.path.join(SRC, 'manifest.json'), 'w', encoding='utf-8') as f:
        json.dump(manifest, f, indent=2, sort_keys=True, ensure_ascii=False)
        f.write('\n')

    with zipfile.ZipFile(BUNDLE, 'w', zipfile.ZIP_DEFLATED) as z:
        z.write(os.path.join(SRC, 'manifest.json'), 'r2r-doorway/manifest.json')
        for rel in files:
            z.write(os.path.join(SRC, rel), 'r2r-doorway/' + rel)
    with zipfile.ZipFile(TRANSLATIONS, 'w', zipfile.ZIP_DEFLATED) as z:
        for rel in files:
            if rel.startswith('i18n/'):
                z.write(os.path.join(SRC, rel), rel[len('i18n/'):])
    mh = sha256(os.path.join(SRC, 'manifest.json'))[:8]
    print('manifest: %d files, asset version %s' % (len(files), mh))
    print('bundle:   %s (%d bytes)' % (os.path.relpath(BUNDLE, ROOT), os.path.getsize(BUNDLE)))
    print('i18n:     %s (%d bytes)' % (os.path.relpath(TRANSLATIONS, ROOT), os.path.getsize(TRANSLATIONS)))

    if install:
        if os.geteuid() != 0:
            sys.exit('--install needs root (sudo)')
        # Replace the served copy wholesale except ref-php, which is reference
        # material the manifest also covers; keep ownership as the relay expects.
        for sub in ('templates', 'assets', 'i18n', 'partials', 'ref-php'):
            dst = os.path.join(DOORWAY_DIR, sub)
            if os.path.isdir(dst):
                shutil.rmtree(dst)
            src = os.path.join(SRC, sub)
            if os.path.isdir(src):
                shutil.copytree(src, dst)
        for fn in ('manifest.json', 'HANDOFF.md'):
            shutil.copy2(os.path.join(SRC, fn), os.path.join(DOORWAY_DIR, fn))
        subprocess.check_call(['chown', '-R', 'r2r:r2r', DOORWAY_DIR])
        subprocess.check_call(['chmod', '-R', 'u+rwX,go+rX', DOORWAY_DIR])
        if os.path.isdir(ASSETS_DIR):
            shutil.copy2(BUNDLE, os.path.join(ASSETS_DIR, 'r2r-doorway-bundle.zip'))
            subprocess.check_call(['chown', 'r2r:r2r', os.path.join(ASSETS_DIR, 'r2r-doorway-bundle.zip')])
        print('installed to %s and %s (restart r2r-relay to serve it)' % (DOORWAY_DIR, ASSETS_DIR))


if __name__ == '__main__':
    main()
