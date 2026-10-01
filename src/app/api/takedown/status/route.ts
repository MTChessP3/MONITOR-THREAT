// TakeDown Status — returns which API keys are configured. A key is
// considered configured if it's set EITHER as an environment variable
// OR as a runtime cookie (which the user set via the dashboard UI).

import { NextResponse } from "next/server";

const KEYS: Array<{ id: string; name: string; envVar: string; registerUrl: string; note: string; sharedWith?: string }> = [
  { id: "virustotal", name: "VirusTotal", envVar: "VIRUSTOTAL_API_KEY", registerUrl: "https://www.virustotal.com/gui/my-apikey", note: "POST → 70+ antivirus escanean la URL" },
  { id: "cleanmx", name: "Clean-MX", envVar: "", registerUrl: "", note: "XML, no requiere key" },
  { id: "urlscan", name: "URLscan.io", envVar: "URLSCAN_API_KEY", registerUrl: "https://urlscan.io/profile/", note: "Crea reporte público con screenshot + DOM + network requests" },
];

function readCookies(request: Request): Record<string, string> {
  const cookieHeader = request.headers.get("cookie") || "";
  const cookies: Record<string, string> = {};
  for (const c of cookieHeader.split(";")) {
    const [k, ...v] = c.trim().split("=");
    if (k) cookies[k] = v.join("=");
  }
  return cookies;
}

export async function GET(request: Request) {
  const cookies = readCookies(request);

  const status = KEYS.map(k => {
    let configured = false;
    let fromCookie = false;
    let fromEnv = false;
    if (k.envVar.includes(" + ")) {
      // PhishTank requires 2 keys — both must be set (either cookie or env)
      const parts = k.envVar.split(" + ").map(p => p.trim());
      const cookieOk = parts.every(p => !!cookies[p]);
      const envOk = parts.every(p => !!process.env[p]);
      configured = cookieOk || envOk;
      fromCookie = cookieOk;
      fromEnv = envOk;
    } else if (k.envVar) {
      fromCookie = !!cookies[k.envVar];
      fromEnv = !!process.env[k.envVar];
      configured = fromCookie || fromEnv;
    } else {
      configured = true; // No key required (cleanmx)
    }
    return { ...k, configured, fromCookie, fromEnv };
  });

  const summary = {
    total: KEYS.length,
    configured: status.filter(s => s.configured).length,
    missing: status.filter(s => !s.configured).length,
  };

  return NextResponse.json({ summary, keys: status }, {
    headers: { "Cache-Control": "no-store" },
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
