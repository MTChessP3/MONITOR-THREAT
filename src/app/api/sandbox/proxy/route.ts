// Sandbox Proxy — fetches the target URL server-side, injects the
// monitoring script, and serves the modified HTML from our own origin.
// This makes the popup SAME-ORIGIN with MONITOR-THREAT, so all the
// monitoring hooks (console, errors, popups, eval, crypto, etc.) work
// without cross-origin restrictions.
//
// For NON-HTML responses (images, CSS, JS, fonts) it passes through
// the bytes with CORS headers — this allows html2canvas (running in
// the parent) to render the popup's <img> elements as same-origin
// resources, so the canvas is not tainted and toDataURL works.

import { NextResponse } from "next/server";

const MONITOR_SCRIPT = `
<script>
(function() {
  var origLog = console.log, origWarn = console.warn, origError = console.error, origInfo = console.info;
  console.log = function() { parent.postMessage({type:'console', level:'log', msg: Array.from(arguments).map(String).join(' ').slice(0,500)}, '*'); origLog.apply(console, arguments); };
  console.warn = function() { parent.postMessage({type:'console', level:'warn', msg: Array.from(arguments).map(String).join(' ').slice(0,500)}, '*'); origWarn.apply(console, arguments); };
  console.error = function() { parent.postMessage({type:'console', level:'error', msg: Array.from(arguments).map(String).join(' ').slice(0,500)}, '*'); origError.apply(console, arguments); };
  console.info = function() { parent.postMessage({type:'console', level:'info', msg: Array.from(arguments).map(String).join(' ').slice(0,500)}, '*'); origInfo.apply(console, arguments); };
  window.onerror = function(msg, src, line, col) { parent.postMessage({type:'error', msg: String(msg).slice(0,300) + ' (' + src + ':' + line + ':' + col + ')'}, '*'); return false; };
  window.onunhandledrejection = function(e) { parent.postMessage({type:'error', msg: 'Unhandled rejection: ' + String(e.reason).slice(0,300)}, '*'); };
  var origOpen = window.open; window.open = function(u) { parent.postMessage({type:'popup', url: u || '(unknown)'}, '*'); try { return origOpen.call(window, u); } catch(e) { return null; } };
  var origEval = window.eval; window.eval = function(code) { parent.postMessage({type:'eval', code: String(code).slice(0,300)}, '*'); try { return origEval.call(window, code); } catch(e) {} };
  var origFunc = Function; try { window.Function = function() { parent.postMessage({type:'eval', code: 'Function(' + Array.from(arguments).map(String).join(',').slice(0,300) + ')'}, '*'); return new origFunc(...arguments); }; window.Function.prototype = origFunc.prototype; } catch(e) {}
  var observer = new MutationObserver(function(muts) {
    for (var m of muts) {
      var added = [];
      m.addedNodes.forEach(function(n) { added.push(n.nodeName + (n.attributes ? '[' + Array.from(n.attributes).map(function(a) { return a.name; }).join(',') + ']' : '')); });
      if (added.length > 0 || m.type === 'attributes') { parent.postMessage({type:'mutation', mtype: m.type, target: m.target.nodeName, added: added.slice(0,5)}, '*'); }
    }
  });
  observer.observe(document, {childList:true, subtree:true, attributes:true});
  // Crypto mining detection
  var scripts = document.querySelectorAll('script[src]');
  for (var s of scripts) {
    var src = s.src.toLowerCase();
    if (src.indexOf('coinhive') >= 0 || src.indexOf('coin-hive') >= 0 || src.indexOf('cryptonight') >= 0 || src.indexOf('webminer') >= 0 || src.indexOf('monero') >= 0 || src.indexOf('crypto-loot') >= 0 || src.indexOf('deepminer') >= 0) {
      parent.postMessage({type:'crypto', script: s.src, miner: 'CoinHive/CryptoNight'}, '*');
    }
  }
  // REWRITE IMAGE URLs to go through our proxy (so they get CORS headers
  // and html2canvas can render them without tainting the canvas)
  function rewriteResourceUrls() {
    try {
      document.querySelectorAll('img[src]').forEach(function(img) {
        var s = img.getAttribute('src');
        if (!s || s.startsWith('data:') || s.startsWith('blob:') || s.startsWith('/api/')) return;
        try {
          var abs = new URL(s, document.baseURI).href;
          if (abs.startsWith('http:') || abs.startsWith('https:')) {
            img.setAttribute('src', '/api/sandbox/proxy?url=' + encodeURIComponent(abs));
            img.setAttribute('crossorigin', 'anonymous');
          }
        } catch(e) {}
      });
      // Rewrite <source> in <picture>
      document.querySelectorAll('source[src]').forEach(function(src) {
        var s = src.getAttribute('src');
        if (!s || s.startsWith('data:') || s.startsWith('blob:') || s.startsWith('/api/')) return;
        try {
          var abs = new URL(s, document.baseURI).href;
          if (abs.startsWith('http:') || abs.startsWith('https:')) {
            src.setAttribute('src', '/api/sandbox/proxy?url=' + encodeURIComponent(abs));
          }
        } catch(e) {}
      });
      // Rewrite inline style background-image url(...)
      document.querySelectorAll('[style*="url("]').forEach(function(el) {
        var st = el.getAttribute('style') || '';
        var newSt = st.replace(/url\\(\\s*(['"]?)(https?:\\/\\/[^'")\\s]+)\\1\\s*\\)/g, function(m, q, u) {
          return 'url(' + q + '/api/sandbox/proxy?url=' + encodeURIComponent(u) + q + ')';
        });
        if (newSt !== st) el.setAttribute('style', newSt);
      });
      // Rewrite CSS <link> hrefs (stylesheets) through proxy
      document.querySelectorAll('link[rel="stylesheet"]').forEach(function(link) {
        var s = link.getAttribute('href');
        if (!s || s.startsWith('data:') || s.startsWith('blob:') || s.startsWith('/api/')) return;
        try {
          var abs = new URL(s, document.baseURI).href;
          if (abs.startsWith('http:') || abs.startsWith('https:')) {
            link.setAttribute('href', '/api/sandbox/proxy?url=' + encodeURIComponent(abs));
          }
        } catch(e) {}
      });
    } catch(e) {}
  }
  // Form auto-submit
  document.addEventListener('DOMContentLoaded', function() {
    rewriteResourceUrls();
    var forms = document.querySelectorAll('form');
    for (var f of forms) {
      if (f.hasAttribute('onload') || f.querySelector('input[type=submit][autofocus]')) {
        parent.postMessage({type:'formAutoSubmit'}, '*');
      }
    }
    // External links
    var links = document.querySelectorAll('a[href]');
    var baseUrl = window.location.href;
    var originHost = location.hostname;
    var seen = {};
    for (var a of links) {
      var href = a.href;
      if (!href || href.startsWith('#') || href.startsWith('javascript:') || href.startsWith('mailto:')) continue;
      if (seen[href]) continue; seen[href] = true;
      try {
        var u = new URL(href);
        var sameDomain = u.hostname === originHost;
        parent.postMessage({type:'link', href: href, text: (a.textContent || '').trim().slice(0,80), domain: u.hostname, sameDomain: sameDomain}, '*');
      } catch(e) {}
    }
    // Send final DOM (the parent uses this for the finalDom panel/PDF only)
    parent.postMessage({type:'finalDom', html: document.documentElement.outerHTML.slice(0, 50000), title: document.title}, '*');
    // Run html2canvas on our own body and post the data URL back to parent.
    // The parent exposed its html2canvas onto our window (popup.html2canvas = ...)
    // so we can call it from inside our context — this ensures the rendering
    // sandbox iframe uses our window, and the rewritten images load
    // through our proxy with CORS headers.
    function shoot(delay) {
      setTimeout(function() {
        try {
          if (typeof window.html2canvas !== 'function') {
            parent.postMessage({type:'screenshotError', delay: delay, error: 'html2canvas not exposed on popup window'}, '*');
            return;
          }
          window.html2canvas(document.body, {
            useCORS: true,
            allowTaint: false,
            backgroundColor: '#ffffff',
            scale: 1,
            width: 1280,
            height: 720,
            windowWidth: 1280,
            windowHeight: 720,
            imageTimeout: 3000,
            logging: false,
            foreignObjectRendering: false
          }).then(function(canvas) {
            try {
              var dataUrl = canvas.toDataURL('image/png');
              parent.postMessage({type:'screenshot', delay: delay, dataUrl: dataUrl}, '*');
            } catch(e) {
              // tainted canvas — extract what we can
              parent.postMessage({type:'screenshotError', delay: delay, error: 'toDataURL failed: ' + String(e).slice(0,200)}, '*');
            }
          }).catch(function(err) {
            parent.postMessage({type:'screenshotError', delay: delay, error: 'html2canvas rejected: ' + String(err).slice(0,200)}, '*');
          });
        } catch(e) {
          parent.postMessage({type:'screenshotError', delay: delay, error: 'shoot: ' + String(e).slice(0,200)}, '*');
        }
      }, delay);
    }
    // Take screenshots at 2s, 6s, 10s, 14s after DOMContentLoaded
    // (the parent has a 20s total recording window — these all fit)
    shoot(2000);
    shoot(6000);
    shoot(10000);
    shoot(14000);
    // Re-run URL rewriting periodically to catch dynamically added images
    setInterval(rewriteResourceUrls, 2000);
  });
  // WebGL fingerprinting
  try {
    var c = document.createElement('canvas'); var gl = c.getContext('webgl') || c.getContext('experimental-webgl');
    if (gl) { var origGP = gl.getParameter; gl.getParameter = function(p) { if (p==0x9245||p==0x9246||p==0x9247||p==0x9248) { parent.postMessage({type:'webglFp'}, '*'); } return origGP.call(gl, p); }; }
  } catch(e) {}
  // Canvas fingerprinting
  try {
    var c2 = document.createElement('canvas'); var ctx2 = c2.getContext('2d');
    if (ctx2) { var origID = ctx2.getImageData; ctx2.getImageData = function() { parent.postMessage({type:'canvasFp'}, '*'); return origID.apply(ctx2, arguments); }; var origTD = c2.toDataURL; c2.toDataURL = function() { parent.postMessage({type:'canvasFp'}, '*'); return origTD.apply(c2, arguments); }; }
  } catch(e) {}
  // Service worker
  if (navigator.serviceWorker && navigator.serviceWorker.controller) { parent.postMessage({type:'serviceWorker'}, '*'); }
  // Storage
  try { for (var i=0; i<localStorage.length; i++) { var k=localStorage.key(i); parent.postMessage({type:'storage', stype:'localStorage', key:k, value:(localStorage.getItem(k)||'').slice(0,200)}, '*'); } } catch(e) {}
  try { for (var i=0; i<sessionStorage.length; i++) { var k=sessionStorage.key(i); parent.postMessage({type:'storage', stype:'sessionStorage', key:k, value:(sessionStorage.getItem(k)||'').slice(0,200)}, '*'); } } catch(e) {}
  // Cookies
  parent.postMessage({type:'cookies', cookies: document.cookie || ''}, '*');
  // Meta refresh redirect
  var meta = document.querySelector('meta[http-equiv="refresh"]');
  if (meta) { parent.postMessage({type:'hiddenRedirect', url: (meta.getAttribute('content')||'').match(/url=(.+)/i) ? RegExp.$1 : ''}, '*'); }
  // Notify parent that monitoring is active
  parent.postMessage({type:'sandboxReady'}, '*');
})();
</script>
`;

export async function GET(request: Request) {
  const { searchParams } = new URL(request.url);
  const targetUrl = (searchParams.get("url") || "").trim();

  if (!targetUrl) {
    return NextResponse.json({ error: "missing_url" }, { status: 400 });
  }

  // Common CORS + cache headers for pass-through responses
  const corsHeaders: Record<string, string> = {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, OPTIONS",
    "Access-Control-Allow-Headers": "*",
    "Cache-Control": "public, max-age=3600, immutable",
  };

  try {
    // Fetch the target URL server-side
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 15000);
    const res = await fetch(targetUrl, {
      signal: controller.signal,
      redirect: "follow",
      headers: {
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        Accept: "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
      },
    });
    clearTimeout(timeout);

    const contentType = res.headers.get("content-type") || "";

    // NON-HTML pass-through: images, CSS, JS, fonts, JSON, etc.
    // Returns the bytes with CORS headers so the browser can use them
    // in same-origin contexts (and html2canvas can render them without
    // tainting the canvas).
    if (!contentType.includes("text/html") && !contentType.includes("application/xhtml")) {
      const bodyBuffer = await res.arrayBuffer();
      const passHeaders: Record<string, string> = {
        ...corsHeaders,
        "Content-Type": contentType || "application/octet-stream",
      };
      // Preserve content-length if present
      const cl = res.headers.get("content-length");
      if (cl) passHeaders["Content-Length"] = cl;
      return new NextResponse(bodyBuffer, { status: 200, headers: passHeaders });
    }

    if (!res.ok) {
      return new NextResponse(
        `<html><body><h1>Sandbox: HTTP ${res.status}</h1><p>Could not load ${targetUrl}</p></body></html>`,
        { status: 200, headers: { "Content-Type": "text/html" } }
      );
    }

    let html = await res.text();
    const finalUrl = res.url || targetUrl;

    // Inject the monitor script right after <head> or at the top of <body>
    // We also inject a <base> tag so relative URLs resolve to the original site
    const baseTag = `<base href="${finalUrl}">`;

    if (html.includes("<head>")) {
      html = html.replace("<head>", `<head>${baseTag}${MONITOR_SCRIPT}`);
    } else if (html.includes("<head ")) {
      html = html.replace(/<head\s/i, `<head ${baseTag}${MONITOR_SCRIPT}`);
    } else if (html.includes("<body>")) {
      html = html.replace("<body>", `<body>${baseTag}${MONITOR_SCRIPT}`);
    } else if (html.includes("<html")) {
      html = html.replace(/<html/i, `<html><head>${baseTag}${MONITOR_SCRIPT}</head>`);
    } else {
      html = `<head>${baseTag}${MONITOR_SCRIPT}</head>${html}`;
    }

    return new NextResponse(html, {
      status: 200,
      headers: {
        "Content-Type": "text/html; charset=utf-8",
        "X-Sandbox-Origin": finalUrl,
      },
    });
  } catch (err: any) {
    return new NextResponse(
      `<html><body><h1>Sandbox Error</h1><p>${err.message}</p><p>URL: ${targetUrl}</p></body></html>`,
      { status: 200, headers: { "Content-Type": "text/html" } }
    );
  }
}

export async function OPTIONS() {
  return new NextResponse(null, {
    status: 204,
    headers: {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET, OPTIONS",
      "Access-Control-Allow-Headers": "*",
    },
  });
}
