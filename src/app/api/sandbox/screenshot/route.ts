// Screenshot Proxy — fetches a REAL visual screenshot of the target
// URL by trying multiple free external screenshot services in parallel.
// The first one that returns a valid image wins; the others are
// aborted. Returns the PNG/JPEG bytes with CORS headers so the parent
// (running in the browser) can use the image in a canvas without
// tainting it.
//
// Services tried (in parallel, first valid one wins):
//   1. WordPress mshots  — https://s.wordpress.com/mshots/v1/<url>?w=1280
//      Free, no API key, returns PNG directly. On first request may
//      return a small placeholder while the screenshot is generated;
//      we skip responses under 5KB to avoid the placeholder.
//   2. thum.io           — https://image.thum.io/get/width/1280/crop/720/<url>
//      Free for personal use, returns PNG directly.
//   3. microlink.io      — https://api.microlink.io/?url=<url>&screenshot=true
//      Free 50 req/day per IP. Returns JSON with a screenshot URL,
//      which we then fetch to get the actual image.

import { NextResponse } from "next/server";

const corsHeaders: Record<string, string> = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, OPTIONS",
  "Access-Control-Allow-Headers": "*",
  "Cache-Control": "public, max-age=3600, immutable",
};

type ShotResult = { buf: ArrayBuffer; ct: string; src: string };

export async function GET(request: Request) {
  const { searchParams } = new URL(request.url);
  const targetUrl = (searchParams.get("url") || "").trim();
  if (!targetUrl) {
    return NextResponse.json({ error: "missing_url" }, { status: 400 });
  }

  const services: Promise<ShotResult | null>[] = [
    // 1. WordPress mshots
    (async (): Promise<ShotResult | null> => {
      try {
        const r = await fetch(
          `https://s.wordpress.com/mshots/v1/${encodeURIComponent(targetUrl)}?w=1280`,
          {
            signal: AbortSignal.timeout(12000),
            headers: { "User-Agent": "Mozilla/5.0 (compatible; MONITOR-THREAT/1.0)" },
          }
        );
        if (!r.ok) return null;
        const ct = r.headers.get("content-type") || "";
        if (!ct.startsWith("image/")) return null;
        const buf = await r.arrayBuffer();
        if (buf.byteLength < 5000) return null; // skip placeholder
        return { buf, ct, src: "wordpress-mshots" };
      } catch {
        return null;
      }
    })(),

    // 2. thum.io
    (async (): Promise<ShotResult | null> => {
      try {
        const r = await fetch(
          `https://image.thum.io/get/width/1280/crop/720/${targetUrl}`,
          {
            signal: AbortSignal.timeout(12000),
            headers: { "User-Agent": "Mozilla/5.0 (compatible; MONITOR-THREAT/1.0)" },
          }
        );
        if (!r.ok) return null;
        const ct = r.headers.get("content-type") || "";
        if (!ct.startsWith("image/")) return null;
        const buf = await r.arrayBuffer();
        if (buf.byteLength < 5000) return null;
        return { buf, ct, src: "thum-io" };
      } catch {
        return null;
      }
    })(),

    // 3. microlink.io (2-step: JSON → fetch image URL)
    (async (): Promise<ShotResult | null> => {
      try {
        const r = await fetch(
          `https://api.microlink.io/?url=${encodeURIComponent(targetUrl)}&screenshot=true&meta=false`,
          {
            signal: AbortSignal.timeout(12000),
            headers: { "User-Agent": "Mozilla/5.0 (compatible; MONITOR-THREAT/1.0)" },
          }
        );
        if (!r.ok) return null;
        const j: any = await r.json();
        const ssUrl: string | undefined = j?.data?.screenshot?.url;
        if (!ssUrl) return null;
        const ir = await fetch(ssUrl, {
          signal: AbortSignal.timeout(8000),
        });
        if (!ir.ok) return null;
        const ct = ir.headers.get("content-type") || "image/png";
        if (!ct.startsWith("image/")) return null;
        const buf = await ir.arrayBuffer();
        if (buf.byteLength < 5000) return null;
        return { buf, ct, src: "microlink" };
      } catch {
        return null;
      }
    })(),
  ];

  // Race — first non-null wins. After all settle with null, return 502.
  return new Promise<NextResponse>((resolve) => {
    let done = false;
    let pending = services.length;
    services.forEach((p) =>
      p.then((result) => {
        if (done) return;
        if (result) {
          done = true;
          resolve(
            new NextResponse(result.buf, {
              status: 200,
              headers: {
                ...corsHeaders,
                "Content-Type": result.ct,
                "X-Screenshot-Source": result.src,
              },
            })
          );
        } else {
          pending--;
          if (pending === 0 && !done) {
            done = true;
            resolve(
              new NextResponse(
                JSON.stringify({ error: "all_screenshot_services_failed", url: targetUrl }),
                {
                  status: 502,
                  headers: { ...corsHeaders, "Content-Type": "application/json" },
                }
              )
            );
          }
        }
      })
    );
    // Safety: 20s absolute timeout
    setTimeout(() => {
      if (!done) {
        done = true;
        resolve(
          new NextResponse(
            JSON.stringify({ error: "timeout", url: targetUrl }),
            {
              status: 504,
              headers: { ...corsHeaders, "Content-Type": "application/json" },
            }
          )
        );
      }
    }, 20000);
  });
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
