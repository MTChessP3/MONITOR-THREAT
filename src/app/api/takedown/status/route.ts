// TakeDown Status — returns which API keys are configured on the
// backend. The frontend uses this to show the user a clear status
// panel: ✓ configured / ✗ missing, with setup links for the missing
// ones.

import { NextResponse } from "next/server";

const KEYS: Array<{ id: string; name: string; envVar: string; registerUrl: string; note: string; sharedWith?: string }> = [
  { id: "virustotal", name: "VirusTotal", envVar: "VIRUSTOTAL_API_KEY", registerUrl: "https://www.virustotal.com/gui/my-apikey", note: "POST → 70+ antivirus escanean la URL" },
  { id: "urlhaus", name: "URLhaus (abuse.ch)", envVar: "URLHAUS_API_KEY", registerUrl: "https://auth.abuse.ch/register", note: "POST directo a la base pública de URLs maliciosas", sharedWith: "threatfox" },
  { id: "cleanmx", name: "Clean-MX", envVar: "", registerUrl: "", note: "XML, no requiere key" },
  { id: "phishtank", name: "PhishTank", envVar: "PHISHTANK_API_KEY + PHISHTANK_APP_ID", registerUrl: "https://www.phishtank.com/developer.php", note: "Base de phishing de la comunidad" },
  { id: "urlscan", name: "URLscan.io", envVar: "URLSCAN_API_KEY", registerUrl: "https://urlscan.io/profile/", note: "Crea reporte público con screenshot + DOM + network requests", },
  { id: "threatfox", name: "ThreatFox (abuse.ch)", envVar: "URLHAUS_API_KEY", registerUrl: "https://auth.abuse.ch/register", note: "Base de IOCs pública (mismo token que URLhaus)", sharedWith: "urlhaus" },
  { id: "otx", name: "AlienVault OTX", envVar: "OTX_API_KEY", registerUrl: "https://otx.alienvault.com/", note: "Crea indicator URL con permalink público" },
];

export async function GET() {
  const status = KEYS.map(k => {
    let configured = false;
    if (k.envVar.includes(" + ")) {
      // PhishTank requires 2 keys — both must be set
      const parts = k.envVar.split(" + ");
      configured = parts.every(p => !!process.env[p.trim()]);
    } else if (k.envVar) {
      configured = !!process.env[k.envVar];
    } else {
      configured = true; // No key required (cleanmx)
    }
    return { ...k, configured };
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
