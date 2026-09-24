// Sandbox Proxy — fetches the target URL server-side, injects the
// monitoring script, and serves the modified HTML from our own origin.
// This makes the popup SAME-ORIGIN with MONITOR-THREAT, so all the
// monitoring hooks (console, errors, popups, eval, crypto, etc.) work
// without cross-origin restrictions.

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
  // Form auto-submit
  document.addEventListener('DOMContentLoaded', function() {
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
    // Send final DOM
    parent.postMessage({type:'finalDom', html: document.documentElement.outerHTML.slice(0, 50000), title: document.title}, '*');
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

  // SELF-SCREENSHOT: load html2canvas from CDN and capture screenshots
  // The popup captures ITSELF (same-origin = no CORS issues) and sends
  // the PNG data to the parent via postMessage.
  function loadScript(src) {
    return new Promise(function(resolve, reject) {
      var s = document.createElement('script');
      s.src = src; s.onload = resolve; s.onerror = reject;
      document.head.appendChild(s);
    });
  }

  loadScript('https://cdnjs.cloudflare.com/ajax/libs/html2canvas/1.4.1/html2canvas.min.js')
    .then(function() {
      // html2canvas loaded — capture screenshots at 6s, 12s, 18s
      var times = [6000, 12000, 18000];
      times.forEach(function(delay) {
        setTimeout(function() {
          try {
            html2canvas(document.body, {
              width: 1280, height: 720, windowWidth: 1280, windowHeight: 720,
              useCORS: true, allowTaint: true, logging: false, scale: 1,
              backgroundColor: '#ffffff'
            }).then(function(canvas) {
              parent.postMessage({type:'screenshot', dataUrl: canvas.toDataURL('image/png'), delay: delay}, '*');
            }).catch(function(e) {
              parent.postMessage({type:'screenshotError', delay: delay, error: String(e).slice(0,200)}, '*');
            });
          } catch(e) {
            parent.postMessage({type:'screenshotError', delay: delay, error: String(e).slice(0,200)}, '*');
          }
        }, delay);
      });
    })
    .catch(function(e) {
      parent.postMessage({type:'screenshotError', delay: 0, error: 'Failed to load html2canvas: ' + String(e).slice(0,200)}, '*');
    });
})();
</script>
`;

export async function GET(request: Request) {
  const { searchParams } = new URL(request.url);
  const targetUrl = (searchParams.get("url") || "").trim();

  if (!targetUrl) {
    return NextResponse.json({ error: "missing_url" }, { status: 400 });
  }

  try {
    // Fetch the target URL server-side
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 10000);
    const res = await fetch(targetUrl, {
      signal: controller.signal,
      redirect: "follow",
      headers: {
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        Accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
      },
    });
    clearTimeout(timeout);

    if (!res.ok) {
      return new NextResponse(
        `<html><body><h1>Sandbox: HTTP ${res.status}</h1><p>Could not load ${targetUrl}</p></body></html>`,
        { status: 200, headers: { "Content-Type": "text/html" } }
      );
    }

    const contentType = res.headers.get("content-type") || "";
    if (!contentType.includes("text/html") && !contentType.includes("application/xhtml")) {
      return new NextResponse(
        `<html><body><h1>Sandbox: Non-HTML content</h1><p>Content-Type: ${contentType}</p></body></html>`,
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

    // Remove X-Frame-Options and CSP so the page can be loaded in a popup
    // (we're serving from our own origin, so these headers would be ours anyway)
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
