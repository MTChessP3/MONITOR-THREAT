---
Task ID: sandbox-video-fix
Agent: main
Task: Fix URL Sandbox video showing black screen / MONITOR-THREAT text instead of target page

Work Log:
- Diagnosed root cause: the `domSnapshot` postMessage handler in url-sandbox-view.tsx was creating a hidden iframe with `src=/api/sandbox/proxy?url=...` — that's the SAME proxy URL, so the proxy re-injected the monitor script into the iframe, which sent ANOTHER `domSnapshot` back to the parent, which created ANOTHER iframe → cascading iframe explosion. The html2canvas on the iframe body also failed because cross-origin images from the target site tainted the iframe canvas.
- Redesigned the screenshot pipeline: the popup's own monitor script now takes screenshots itself via `window.html2canvas(document.body, ...)`. The parent exposes its imported html2canvas to the popup via `popup.html2canvas = html2canvas` (works because popup is same-origin via the proxy). The popup then posts the data URL back to the parent via `postMessage({type:'screenshot', ...})`.
- Added image/CSS URL rewriting in the proxy's monitor script: all `<img>`, `<source>`, `<link rel=stylesheet>`, and inline `style="url(...)"` references pointing to absolute http(s) URLs are rewritten to go through `/api/sandbox/proxy?url=...`. This way html2canvas's rendering sandbox loads those resources from our same-origin proxy, which returns them with CORS headers — the canvas is NOT tainted and `toDataURL()` works.
- Updated the proxy route `/api/sandbox/proxy/route.ts` to pass through non-HTML responses (images, CSS, JS, fonts, JSON) with `Access-Control-Allow-Origin: *` and `Cache-Control: public, max-age=3600, immutable` so the browser treats them as same-origin-CORS-enabled resources.
- Added an `OPTIONS` handler to the proxy route to respond to preflight CORS requests.
- Removed the `domSnapshot` sender from the proxy monitor script (was the source of the iframe cascade).
- Removed the iframe-based `domSnapshot` handler in url-sandbox-view.tsx (kept only a no-op case for backward compat).
- Updated screenshot schedule: 4 screenshots at 2s, 6s, 10s, 14s after DOMContentLoaded (all fit within the 20s recording window).
- Added a parent-side text-only fallback at 12s: if zero screenshots have arrived, the parent reads `popup.document.body.innerText` and `popup.document.title` directly (same-origin via proxy) and draws them on a 1280×720 canvas. This guarantees the video always shows SOMETHING from the target page, even when html2canvas throws on every attempt.
- Updated the initial-frame progress text from "Waiting for first screenshot at 6s..." to "Waiting for first screenshot at 2s..." to match the new schedule.
- Verified `npx next build` succeeds (no TypeScript/compile errors).

Stage Summary:
- Files modified: `src/app/api/sandbox/proxy/route.ts`, `src/components/views/url-sandbox-view.tsx`
- Root cause of the black screen: iframe cascade from the `domSnapshot` handler, plus cross-origin image tainting
- New pipeline: popup takes its own screenshots via parent-exposed html2canvas, with all images routed through our CORS-enabled proxy
- Fallback: text-only canvas at 12s if html2canvas never returns
- Build passes — ready to commit and push, Vercel will auto-deploy
