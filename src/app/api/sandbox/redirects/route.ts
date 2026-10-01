// Redirect Chain — fetches the target URL with redirect: "manual"
// and follows each redirect step manually, recording the status code
// and URL of each hop. Returns the full chain as JSON.
//
// This gives the parent the exact redirect chain (including HTTP 301,
// 302, 303, 307, 308 status codes and the Location header for each
// hop) WITHOUT relying on the popup's navigation tracking (which can
// miss server-side redirects that happen before the popup loads).

import { NextResponse } from "next/server";

interface RedirectStep {
  url: string;
  status: number;
  location?: string | null;
  contentType?: string | null;
  error?: string;
}

interface RedirectResponse {
  original: string;
  final: string;
  redirectCount: number;
  crossDomainRedirects: number;
  chain: RedirectStep[];
}

export async function GET(request: Request) {
  const { searchParams } = new URL(request.url);
  const targetUrl = (searchParams.get("url") || "").trim();
  if (!targetUrl) {
    return NextResponse.json({ error: "missing_url" }, { status: 400 });
  }

  const chain: RedirectStep[] = [];
  let currentUrl = targetUrl;
  const maxSteps = 10;

  for (let i = 0; i < maxSteps; i++) {
    try {
      const res = await fetch(currentUrl, {
        redirect: "manual",
        signal: AbortSignal.timeout(8000),
        headers: {
          "User-Agent":
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
          Accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        },
      });

      chain.push({
        url: currentUrl,
        status: res.status,
        location: res.headers.get("location"),
        contentType: res.headers.get("content-type"),
      });

      // 3xx = redirect
      if (res.status >= 300 && res.status < 400) {
        const location = res.headers.get("location");
        if (!location) break;
        try {
          currentUrl = new URL(location, currentUrl).href;
        } catch {
          break;
        }
      } else {
        // Not a redirect — this is the final URL
        break;
      }
    } catch (e: any) {
      chain.push({
        url: currentUrl,
        status: 0,
        error: String(e?.message || e),
      });
      break;
    }
  }

  // Compute cross-domain redirect count
  let crossDomain = 0;
  try {
    const originalHost = new URL(targetUrl).hostname;
    for (const step of chain) {
      try {
        if (new URL(step.url).hostname !== originalHost) {
          crossDomain++;
        }
      } catch {}
    }
  } catch {}

  const final = chain.length > 0 ? chain[chain.length - 1].url : targetUrl;
  const redirectCount = chain.filter(
    (c) => c.status >= 300 && c.status < 400
  ).length;

  const response: RedirectResponse = {
    original: targetUrl,
    final,
    redirectCount,
    crossDomainRedirects: crossDomain,
    chain,
  };

  return NextResponse.json(response, {
    headers: {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET, OPTIONS",
      "Access-Control-Allow-Headers": "*",
      "Cache-Control": "public, max-age=300, immutable",
    },
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
