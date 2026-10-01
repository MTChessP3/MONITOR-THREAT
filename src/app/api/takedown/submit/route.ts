// TakeDown Submit — auto-submits a URL to platforms that expose a
// public submission API:
//   - VirusTotal          — POST https://www.virustotal.com/api/v3/urls
//     Required: x-apikey header, body url=<url> (URL-encoded)
//   - Clean-MX            — POST http://support.clean-mx.de/clean-mx/xmlCursors
//     (XML-based, no auth)
//   - URLscan.io         — POST https://urlscan.io/api/v1/scan/
//     No auth required for basic usage (rate-limited). Creates a PUBLIC
//     scan report that anyone can view.

import { NextResponse } from "next/server";

// Read an API key from the user's session cookie first, then fall
// back to the environment variable. This allows the user to set keys
// from the dashboard UI without redeploying Vercel.
function getKey(request: Request, id: string): string {
  const cookieHeader = request.headers.get("cookie") || "";
  const cookies = Object.fromEntries(
    cookieHeader.split(";").map(c => {
      const [k, ...v] = c.trim().split("=");
      return [k, v.join("=")];
    })
  );
  if (cookies[id]) {
    try { return decodeURIComponent(cookies[id]); } catch { return cookies[id]; }
  }
  return process.env[id] || "";
}

// Note: these now become functions of `request` — they're called per-request.
const getVirustotalKey = (req: Request) => getKey(req, "VIRUSTOTAL_API_KEY");
const getUrlscanKey = (req: Request) => getKey(req, "URLSCAN_API_KEY");

interface SubmitRequest {
  platform: "virustotal" | "cleanmx" | "urlscan";
  url: string;
  threatType?: "phishing_url" | "malware_url" | "scam_url";
  tags?: string;
}

export async function POST(request: Request) {
  let body: SubmitRequest;
  try {
    body = await request.json();
  } catch {
    return NextResponse.json({ error: "invalid_json" }, { status: 400 });
  }

  const { platform, url, threatType, tags } = body;
  if (!url || !platform) {
    return NextResponse.json({ error: "missing_url_or_platform" }, { status: 400 });
  }

  const tType = threatType || "phishing_url";

  switch (platform) {
    case "virustotal": {
      const VIRUSTOTAL_API_KEY = getVirustotalKey(request);
      if (!VIRUSTOTAL_API_KEY) {
        return NextResponse.json({ platform, url, status: "skipped", message: "VIRUSTOTAL_API_KEY no configurada" }, { status: 200 });
      }
      try {
        const r = await fetch("https://www.virustotal.com/api/v3/urls", {
          method: "POST",
          headers: {
            "x-apikey": VIRUSTOTAL_API_KEY,
            "Content-Type": "application/x-www-form-urlencoded",
          },
          body: `url=${encodeURIComponent(url)}`,
          signal: AbortSignal.timeout(15000),
        });
        const j: any = await r.json();
        const id = j?.data?.id || "";
        return NextResponse.json({
          platform,
          url,
          status: r.status === 200 ? "success" : "failed",
          responseStatus: r.status,
          permalink: id ? `https://www.virustotal.com/gui/url/${id.replace(/-/g, "")}` : null,
          response: j,
        });
      } catch (e: any) {
        return NextResponse.json({ platform, url, status: "error", error: String(e?.message || e) }, { status: 200 });
      }
    }
    case "cleanmx": {
      try {
        // Clean-MX submission via XML (legacy but works)
        const escapedUrl = url.split("<").join("&lt;").split(">").join("&gt;");
        const xml = `<?xml version="1.0" encoding="UTF-8"?>
<cursor>
  <id>monitor-threat-${Date.now()}</id>
  <url>${escapedUrl}</url>
  <type>${tType === "phishing_url" ? "phishing" : tType === "malware_url" ? "malware" : "scam"}</type>
  <tag>monitor-threat</tag>
</cursor>`;
        const r = await fetch("http://support.clean-mx.de/clean-mx/xmlCursors?mode=0", {
          method: "POST",
          body: xml,
          headers: { "Content-Type": "application/xml" },
          signal: AbortSignal.timeout(15000),
        });
        const text = await r.text();
        return NextResponse.json({
          platform,
          url,
          status: r.ok ? "success" : "failed",
          responseStatus: r.status,
          response: text.slice(0, 500),
        });
      } catch (e: any) {
        return NextResponse.json({ platform, url, status: "error", error: String(e?.message || e) }, { status: 200 });
      }
    }
    case "urlscan": {
      // URLscan.io — free scan API. Creates a PUBLIC report that anyone
      // can view. No auth required for basic usage (rate-limited to ~100
      // scans/day anonymous, 1000/day with free API key).
      try {
        const headers: Record<string, string> = { "Content-Type": "application/json" };
        const URLSCAN_API_KEY = getUrlscanKey(request);
        if (URLSCAN_API_KEY) headers["API-Key"] = URLSCAN_API_KEY;
        const payload: any = {
          url,
          public: "on",  // makes the report public
          tags: [tags || "monitor-threat"],
        };
        const r = await fetch("https://urlscan.io/api/v1/scan/", {
          method: "POST",
          headers,
          body: JSON.stringify(payload),
          signal: AbortSignal.timeout(15000),
        });
        const j: any = await r.json();
        // urlscan returns {message: "Submission successful", uuid, result, ...}
        const permalink = j?.result || `https://urlscan.io/result/${j?.uuid || ""}/`;
        return NextResponse.json({
          platform,
          url,
          status: r.status === 200 && j?.message === "Submission successful" ? "success" : "failed",
          responseStatus: r.status,
          permalink,
          response: j,
        });
      } catch (e: any) {
        return NextResponse.json({ platform, url, status: "error", error: String(e?.message || e) }, { status: 200 });
      }
    }
    default:
      return NextResponse.json({ error: `unknown_platform: ${platform}` }, { status: 400 });
  }
}

export async function OPTIONS() {
  return new NextResponse(null, {
    status: 204,
    headers: {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "POST, OPTIONS",
      "Access-Control-Allow-Headers": "*",
    },
  });
}
