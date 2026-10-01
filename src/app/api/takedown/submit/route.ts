// TakeDown Submit — auto-submits a URL to platforms that expose a
// public submission API:
//   - URLhaus (abuse.ch)  — POST https://urlhaus-api.abuse.ch/api/v1/
//     Required fields: token, action=insert-url, url, threat_type,
//     tags, payload (optional), anonymous (optional)
//   - VirusTotal          — POST https://www.virustotal.com/api/v3/urls
//     Required: x-apikey header, body url=<url> (URL-encoded)
//   - Clean-MX            — POST http://support.clean-mx.de/clean-mx/xmlCursors
//     (XML-based, no auth)
//
// PhishTank requires a registered application with an API key — the
// user needs to register at phishtank.com and provide the key. The
// module will surface this requirement in the UI.

import { NextResponse } from "next/server";

const VIRUSTOTAL_API_KEY = process.env.VIRUSTOTAL_API_KEY || "";
const URLHAUS_API_KEY = process.env.URLHAUS_API_KEY || "";

interface SubmitRequest {
  platform: "urlhaus" | "virustotal" | "cleanmx" | "phishtank";
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
    case "urlhaus": {
      if (!URLHAUS_API_KEY) {
        return NextResponse.json({
          platform,
          url,
          status: "skipped",
          message: "URLHAUS_API_KEY environment variable not set. Register at https://auth.abuse.ch to get a token.",
        }, { status: 200 });
      }
      try {
        const fd = new URLSearchParams();
        fd.append("token", URLHAUS_API_KEY);
        fd.append("action", "insert-url");
        fd.append("url", url);
        fd.append("threat_type", tType);
        if (tags) fd.append("tags", tags);
        fd.append("anonymous", "1");
        const r = await fetch("https://urlhaus-api.abuse.ch/api/v1/", {
          method: "POST",
          body: fd,
          signal: AbortSignal.timeout(15000),
        });
        const text = await r.text();
        let j: any;
        try { j = JSON.parse(text); } catch { j = { raw: text.slice(0, 500) }; }
        return NextResponse.json({
          platform,
          url,
          status: j.query_status === "url_added" || j.query_status === "ok" ? "success" : "failed",
          responseStatus: r.status,
          response: j,
        });
      } catch (e: any) {
        return NextResponse.json({ platform, url, status: "error", error: String(e?.message || e) }, { status: 200 });
      }
    }
    case "virustotal": {
      if (!VIRUSTOTAL_API_KEY) {
        return NextResponse.json({ platform, url, status: "skipped", message: "VIRUSTOTAL_API_KEY not set" }, { status: 200 });
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
    case "phishtank": {
      const PHISHTANK_API_KEY = process.env.PHISHTANK_API_KEY || "";
      const PHISHTANK_APP_ID = process.env.PHISHTANK_APP_ID || "";
      if (!PHISHTANK_API_KEY || !PHISHTANK_APP_ID) {
        return NextResponse.json({
          platform,
          url,
          status: "skipped",
          message: "PHISHTANK_API_KEY or PHISHTANK_APP_ID not set. Register an application at https://www.phishtank.com/developer.php",
        }, { status: 200 });
      }
      try {
        const fd = new URLSearchParams();
        fd.append("url", url);
        fd.append("phish_detail_id", "0");
        fd.append("format", "json");
        fd.append("app_key", PHISHTANK_API_KEY);
        fd.append("app_id", PHISHTANK_APP_ID);
        const r = await fetch("https://checkurl.phishtank.com/checkurl/", {
          method: "POST",
          body: fd,
          signal: AbortSignal.timeout(15000),
        });
        const text = await r.text();
        let j: any;
        try { j = JSON.parse(text); } catch { j = { raw: text.slice(0, 500) }; }
        return NextResponse.json({
          platform,
          url,
          status: j?.results?.in_database ? "success" : "submitted",
          responseStatus: r.status,
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
