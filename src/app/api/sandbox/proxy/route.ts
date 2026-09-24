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

  // SELF-SCREENSHOT: capture screenshots using native browser APIs.
  // No external libraries needed — uses SVG foreignObject to render the
  // popup's own HTML as an image. Works even with strict CSP.
  function captureSelf() {
    try {
      // Get the full rendered HTML of the page
      var clone = document.documentElement.cloneNode(true);
      // Remove our injected monitoring script from the clone (avoid infinite loop)
      var scripts = clone.querySelectorAll('script');
      scripts.forEach(function(s) { s.remove(); });
      
      // Serialize to SVG with foreignObject
      var width = Math.min(window.innerWidth || 1280, 1280);
      var height = Math.min(window.innerHeight || 720, 720);
      var svg = '<svg xmlns="http://www.w3.org/2000/svg" width="' + width + '" height="' + height + '">'
        + '<foreignObject width="100%" height="100%">'
        + '<div xmlns="http://www.w3.org/1999/xhtml" style="width:' + width + 'px;height:' + height + 'px;overflow:hidden;">'
        + new XMLSerializer().serializeToString(clone)
        + '</div></foreignObject></svg>';
      
      var svgBlob = new Blob([svg], {type: 'image/svg+xml;charset=utf-8'});
      var url = URL.createObjectURL(svgBlob);
      var img = new Image();
      img.onload = function() {
        var canvas = document.createElement('canvas');
        canvas.width = width;
        canvas.height = height;
        var ctx = canvas.getContext('2d');
        ctx.fillStyle = '#ffffff';
        ctx.fillRect(0, 0, width, height);
        ctx.drawImage(img, 0, 0, width, height);
        URL.revokeObjectURL(url);
        try {
          var dataUrl = canvas.toDataURL('image/png');
          parent.postMessage({type:'screenshot', dataUrl: dataUrl}, '*');
        } catch(e) {
          // canvas.toDataURL might throw if the SVG contains cross-origin images
          // Fallback: send the SVG itself as the screenshot
          parent.postMessage({type:'screenshot', dataUrl: 'data:image/svg+xml;base64,' + btoa(unescape(encodeURIComponent(svg))).slice(0, 100000)}, '*');
        }
      };
      img.onerror = function() {
        URL.revokeObjectURL(url);
        // SVG foreignObject failed — try a simpler approach
        // Just capture the text content as a basic representation
        var bodyText = document.body ? document.body.innerText.slice(0, 5000) : '';
        var titleText = document.title || '';
        var canvas2 = document.createElement('canvas');
        canvas2.width = 1280; canvas2.height = 720;
        var ctx2 = canvas2.getContext('2d');
        ctx2.fillStyle = '#ffffff'; ctx2.fillRect(0, 0, 1280, 720);
        ctx2.fillStyle = '#333333'; ctx2.font = 'bold 24px sans-serif';
        ctx2.fillText(titleText.slice(0, 80), 20, 40);
        ctx2.font = '14px monospace';
        var lines = bodyText.split('\\n').slice(0, 40);
        for (var i = 0; i < lines.length; i++) {
          ctx2.fillText(lines[i].slice(0, 150), 20, 80 + i * 20);
        }
        parent.postMessage({type:'screenshot', dataUrl: canvas2.toDataURL('image/png')}, '*');
      };
      img.src = url;
    } catch(e) {
      parent.postMessage({type:'screenshotError', error: String(e).slice(0,200)}, '*');
    }
  }

  // Capture at 6s, 12s, 18s
  [6000, 12000, 18000].forEach(function(delay) {
    setTimeout(function() {
      captureSelf();
    }, delay);
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
