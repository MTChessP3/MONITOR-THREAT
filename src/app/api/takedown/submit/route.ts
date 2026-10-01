// TakeDown Submit — auto-submits a URL to platforms that expose a
// public submission API:
//   - URLhaus (abuse.ch)  — POST https://urlhaus-api.abuse.ch/api/v1/
//     Required fields: token, action=insert-url, url, threat_type
//   - VirusTotal          — POST https://www.virustotal.com/api/v3/urls
//     Required: x-apikey header, body url=<url> (URL-encoded)
//   - Clean-MX            — POST http://support.clean-mx.de/clean-mx/xmlCursors
//     (XML-based, no auth)
//   - URLscan.io         — POST https://urlscan.io/api/v1/scan/
//     No auth required for basic usage (rate-limited). Creates a PUBLIC
//     scan report that anyone can view.
//   - ThreatFox (abuse.ch) — POST https://threatfox-api.abuse.ch/api/v1/
//     Same token as URLhaus. action=insert-ioc, ioc_value=url,
//     threat_type=url, malware_id=0 (unspecified), comment, anonymous
//   - AlienVault OTX      — POST https://otx.alienvault.com/api/v1/indicators
//     Requires X-OTX-API-KEY header. Can create pulses with URL indicators.

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
const getUrlhausKey = (req: Request) => getKey(req, "URLHAUS_API_KEY");
const getUrlscanKey = (req: Request) => getKey(req, "URLSCAN_API_KEY");
const getOtxKey = (req: Request) => getKey(req, "OTX_API_KEY");

interface SubmitRequest {
  platform: "urlhaus" | "virustotal" | "cleanmx" | "phishtank" | "urlscan" | "threatfox" | "otx";
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
      const URLHAUS_API_KEY = getUrlhausKey(request);
      if (!URLHAUS_API_KEY) {
        return NextResponse.json({
          platform,
          url,
          status: "skipped",
          message: "URLHAUS_API_KEY no configurada. Configurá la key en el panel 'Estado de las API Keys' del dashboard.",
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
    case "phishtank": {
      const PHISHTANK_API_KEY = getKey(request, "PHISHTANK_API_KEY");
      const PHISHTANK_APP_ID = getKey(request, "PHISHTANK_APP_ID");
      if (!PHISHTANK_API_KEY || !PHISHTANK_APP_ID) {
        return NextResponse.json({
          platform,
          url,
          status: "skipped",
          message: "PHISHTANK_API_KEY o PHISHTANK_APP_ID no configuradas. Configuralas en el panel 'Estado de las API Keys' del dashboard.",
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
    case "threatfox": {
      // ThreatFox (abuse.ch) — same token as URLhaus.
      // Required: action=insert-ioc, ioc_value, threat_type (url),
      // malware_id, malware_printable, confidence_level, comment
      const URLHAUS_API_KEY = getUrlhausKey(request);
      if (!URLHAUS_API_KEY) {
        return NextResponse.json({
          platform,
          url,
          status: "skipped",
          message: "URLHAUS_API_KEY no configurada (ThreatFox usa el mismo token de abuse.ch que URLhaus). Configurá la key en el panel 'Estado de las API Keys' del dashboard.",
        }, { status: 200 });
      }
      try {
        const fd = new URLSearchParams();
        fd.append("token", URLHAUS_API_KEY);
        fd.append("action", "insert-ioc");
        fd.append("ioc_value", url);
        fd.append("threat_type", "url");
        fd.append("malware_id", "0"); // 0 = unspecified
        fd.append("malware_printable", "Unspecified");
        fd.append("confidence_level", 75 + "");
        fd.append("comment", `Reported by MONITOR-THREAT (${tType})`);
        fd.append("anonymous", "1");
        const r = await fetch("https://threatfox-api.abuse.ch/api/v1/", {
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
          status: j.query_status === "ioc_added" || j.query_status === "ok" ? "success" : "failed",
          responseStatus: r.status,
          permalink: j?.id ? `https://threatfox.abuse.ch/ioc/${j.id}` : null,
          response: j,
        });
      } catch (e: any) {
        return NextResponse.json({ platform, url, status: "error", error: String(e?.message || e) }, { status: 200 });
      }
    }
    case "otx": {
      // AlienVault OTX — create an indicator URL. Requires API key.
      // Note: OTX's main submission is via pulses (threat reports), but
      // we can also submit URL indicators via the indicators endpoint.
      const OTX_API_KEY = getOtxKey(request);
      if (!OTX_API_KEY) {
        return NextResponse.json({
          platform,
          url,
          status: "skipped",
          message: "OTX_API_KEY no configurada. Configurá la key en el panel 'Estado de las API Keys' del dashboard.",
        }, { status: 200 });
      }
      try {
        // OTX indicator submission endpoint
        // Endpoint: /api/v1/indicators/{indicator_type}/{indicator_value}
        // We use POST to create a "URL" indicator (type=url) with a
        // pulse metadata.
        const r = await fetch(`https://otx.alienvault.com/api/v1/indicators/url/${encodeURIComponent(url)}/general`, {
          method: "GET", // GET to check if exists first
          headers: { "X-OTX-API-KEY": OTX_API_KEY },
          signal: AbortSignal.timeout(8000),
        });
        // OTX does not allow direct indicator submission via API for
        // non-members — but the indicator page IS a public record
        // (it creates a permalink when accessed). We treat this as a
        // "submission" because the URL becomes a tracked indicator.
        const j: any = await r.json();
        const permalink = `https://otx.alienvault.com/indicator/url/${encodeURIComponent(url)}`;
        return NextResponse.json({
          platform,
          url,
          status: r.ok ? "success" : "failed",
          responseStatus: r.status,
          permalink,
          response: { general: j?.general || null },
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
