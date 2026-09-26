// /js/card.js — client-side R2R setup card renderer.
//
// Produces a 600x1050 branded card on a <canvas> from {code, redeemUrl,
// contactUrl?, host}. Composites: gradient background → R2Я wordmark →
// tagline → 1 or 2 QRs → labels under each QR → invite code (monospace) →
// host watermark. Two-QR variant renders when contactUrl is supplied.
//
// Depends on qrcode.js being loaded first (David Shim's qrcodejs API).
//
// Public API:
//   R2R.renderCard(canvasEl, opts)          — draw in place, returns Promise
//   R2R.exportCardBlob(canvasEl)            — return PNG Blob for download
//   R2R.renderCardOffscreen(opts)           — draw on a fresh offscreen canvas, return it (Promise)

(function (root) {
  'use strict';
  var R2R = root.R2R || (root.R2R = {});

  var W = 600, H = 1050;

  var COLORS = {
    bgTop:    '#0A7B83',
    bgMid:    '#11313e',
    bgBottom: '#1A2B3C',
    accent:   '#0EADB5',
    white:    '#ffffff',
    dim:      'rgba(255,255,255,0.65)',
    faint:    'rgba(255,255,255,0.55)',
    label:    'rgba(140,220,255,0.9)',
  };

  // Font stack matches the mesh SVG wordmark and existing docs headings.
  var FONT_SANS = '-apple-system, "Segoe UI", system-ui, sans-serif';
  var FONT_MONO = 'ui-monospace, SFMono-Regular, Menlo, Consolas, monospace';

  function fillGradientBg(ctx, primary, secondary) {
    var top = primary || COLORS.bgTop;
    var g = ctx.createRadialGradient(W / 2, 0, 50, W / 2, H / 2, H);
    g.addColorStop(0, top);
    g.addColorStop(0.55, COLORS.bgMid);
    g.addColorStop(1, COLORS.bgBottom);
    ctx.fillStyle = g;
    ctx.fillRect(0, 0, W, H);
  }

  function drawText(ctx, text, x, y, opts) {
    var o = opts || {};
    ctx.save();
    ctx.fillStyle = o.color || COLORS.white;
    ctx.font = (o.weight || 'normal') + ' ' + o.size + 'px ' + (o.family || FONT_SANS);
    ctx.textAlign = o.align || 'center';
    ctx.textBaseline = o.baseline || 'alphabetic';
    ctx.fillText(text, x, y);
    ctx.restore();
  }

  // qrcode.js writes into an element (usually a <canvas> child). This wrapper
  // creates a detached div, mints the QR into it, extracts the canvas, and
  // returns it. Falls back to the <img> case some browser branches use.
  function makeQRCanvas(text, size) {
    if (typeof QRCode === 'undefined') {
      throw new Error('qrcode.js not loaded — <script src="/js/qrcode.min.js"> must come before card.js');
    }
    var holder = document.createElement('div');
    holder.style.position = 'absolute';
    holder.style.left = '-9999px';
    holder.style.top = '-9999px';
    holder.style.width = size + 'px';
    holder.style.height = size + 'px';
    document.body.appendChild(holder);
    new QRCode(holder, {
      text: text,
      width: size,
      height: size,
      correctLevel: QRCode.CorrectLevel.Q,
      colorDark: '#000000',
      colorLight: '#ffffff'
    });
    var canvas = holder.querySelector('canvas');
    if (canvas) {
      holder.remove();
      return Promise.resolve(canvas);
    }
    // Some browser branches use an <img> data-URL. Wait for it to load, then draw to canvas.
    var img = holder.querySelector('img');
    if (!img) {
      holder.remove();
      return Promise.reject(new Error('qrcode.js produced neither canvas nor img'));
    }
    return new Promise(function (resolve, reject) {
      function done() {
        var c = document.createElement('canvas');
        c.width = size; c.height = size;
        c.getContext('2d').drawImage(img, 0, 0, size, size);
        holder.remove();
        resolve(c);
      }
      if (img.complete && img.naturalWidth > 0) done();
      else {
        img.addEventListener('load', done, { once: true });
        img.addEventListener('error', function () { holder.remove(); reject(new Error('QR img load failed')); }, { once: true });
      }
    });
  }

  // QRs get a subtle white padded frame so they read well against the dark bg.
  function drawFramedQR(ctx, qrCanvas, cx, cy, size) {
    var pad = 8;
    var half = size / 2 + pad;
    ctx.save();
    ctx.fillStyle = COLORS.white;
    ctx.beginPath();
    // Rounded rect (fallback if roundRect not available)
    var r = 8, x = cx - half, y = cy - half, w = half * 2, h = half * 2;
    if (typeof ctx.roundRect === 'function') {
      ctx.roundRect(x, y, w, h, r);
    } else {
      ctx.moveTo(x + r, y);
      ctx.arcTo(x + w, y,     x + w, y + h, r);
      ctx.arcTo(x + w, y + h, x,     y + h, r);
      ctx.arcTo(x,     y + h, x,     y,     r);
      ctx.arcTo(x,     y,     x + w, y,     r);
    }
    ctx.fill();
    ctx.drawImage(qrCanvas, cx - size / 2, cy - size / 2, size, size);
    ctx.restore();
  }

  function drawHeader(ctx, tagline) {
    // R2Я wordmark — the "2" is accent-teal to match the mesh
    ctx.save();
    ctx.textAlign = 'center';
    ctx.textBaseline = 'alphabetic';
    ctx.font = '800 84px ' + FONT_SANS;
    // Draw "R", "2" (accent), "Я" separately so the middle character can be colored
    var y = 130;
    var r = 'R', two = '2', ya = 'Я';
    // Measure widths for a proper centered layout
    var wR  = ctx.measureText(r).width;
    var w2  = ctx.measureText(two).width;
    var wYa = ctx.measureText(ya).width;
    var kerning = -6;
    var total = wR + w2 + wYa + kerning * 2;
    var x0 = (W - total) / 2;
    ctx.fillStyle = COLORS.white;
    ctx.textAlign = 'left';
    ctx.fillText(r, x0, y);
    ctx.fillStyle = COLORS.accent;
    ctx.fillText(two, x0 + wR + kerning, y);
    ctx.fillStyle = COLORS.white;
    ctx.fillText(ya, x0 + wR + w2 + kerning * 2, y);
    ctx.restore();

    drawText(ctx, tagline, W / 2, 172, { size: 15, color: COLORS.dim });
  }

  function drawFooter(ctx, host) {
    drawText(ctx, host, W / 2, H - 32, { size: 13, color: COLORS.faint });
  }

  function drawCode(ctx, code, yBaseline) {
    drawText(ctx, code, W / 2, yBaseline, {
      size: 30, weight: 'bold', family: FONT_MONO, color: COLORS.white
    });
  }

  async function render1QR(ctx, opts) {
    fillGradientBg(ctx, opts.primaryColor);
    drawHeader(ctx, opts.tagline1 || 'invite-only. peer-to-peer.');

    var qrSize = 200;
    var qr = await makeQRCanvas(opts.redeemUrl, qrSize);
    var cx = W / 2, cy = 730;
    drawFramedQR(ctx, qr, cx, cy, qrSize);

    drawText(ctx, opts.labelRedeem || 'scan to redeem', W / 2, cy + qrSize / 2 + 34, {
      size: 14, color: COLORS.faint
    });

    drawCode(ctx, opts.code, 940);
    drawFooter(ctx, opts.host);
  }

  async function render2QR(ctx, opts) {
    fillGradientBg(ctx, opts.primaryColor);
    drawHeader(ctx, opts.tagline2 || 'invite. connect. talk.');

    var qrSize = 200;
    var qr1 = await makeQRCanvas(opts.redeemUrl, qrSize);
    var qr2 = await makeQRCanvas(opts.contactUrl, qrSize);
    var cy = 770;
    var cx1 = 165, cx2 = W - 165;
    drawFramedQR(ctx, qr1, cx1, cy, qrSize);
    drawFramedQR(ctx, qr2, cx2, cy, qrSize);

    var labelY = cy + qrSize / 2 + 30;
    drawText(ctx, opts.labelRedeem || 'REDEEM',      cx1, labelY, { size: 14, weight: 'bold', color: COLORS.label });
    drawText(ctx, opts.labelContact || 'MESSAGE ME', cx2, labelY, { size: 14, weight: 'bold', color: COLORS.label });

    drawCode(ctx, opts.code, 970);
    drawFooter(ctx, opts.host);
  }

  R2R.renderCard = function (canvas, opts) {
    canvas.width = W;
    canvas.height = H;
    var ctx = canvas.getContext('2d');
    if (!ctx) return Promise.reject(new Error('canvas 2d context unavailable'));

    var host = opts.host || (typeof location !== 'undefined' ? location.hostname : '');
    var full = Object.assign({ host: host }, opts);

    return opts.contactUrl ? render2QR(ctx, full) : render1QR(ctx, full);
  };

  R2R.renderCardOffscreen = function (opts) {
    var c = document.createElement('canvas');
    return R2R.renderCard(c, opts).then(function () { return c; });
  };

  R2R.exportCardBlob = function (canvas) {
    return new Promise(function (resolve, reject) {
      canvas.toBlob(function (b) {
        if (b) resolve(b); else reject(new Error('canvas toBlob failed'));
      }, 'image/png');
    });
  };

  R2R.downloadCardPNG = function (canvas, filename) {
    return R2R.exportCardBlob(canvas).then(function (blob) {
      var url = URL.createObjectURL(blob);
      var a = document.createElement('a');
      a.href = url;
      a.download = filename || 'r2r-card.png';
      document.body.appendChild(a);
      a.click();
      setTimeout(function () { a.remove(); URL.revokeObjectURL(url); }, 500);
    });
  };
})(typeof window !== 'undefined' ? window : this);
