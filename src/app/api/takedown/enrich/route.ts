// TakeDown Enrich — given a URL, returns a complete enrichment bundle:
//   - Visual screenshot (via /api/sandbox/screenshot, which races
//     WordPress mshots / thum.io / microlink.io)
//   - VirusTotal URL reputation (number of malicious verdicts)
//   - WHOIS data (registrar + abuse email) for the domain
//   - Hosting provider (ASN organization from Shodan InternetDB)
//   - Cloudflare detection (CF-Ray / CF-Cache-Status headers)
//   - Auto-classification (phishing / malware / scam / unknown)
//     based on URL keyword patterns
//
// The frontend calls this endpoint in parallel for each URL the user
// loads, and uses the result to fill the enrichment table and to
// decide which abuse email template to use.

import { NextResponse } from "next/server";

const VIRUSTOTAL_API_KEY = process.env.VIRUSTOTAL_API_KEY || "";

interface EnrichResult {
  url: string;
  hostname: string;
  screenshotUrl: string;
  vt: {
    malicious: number;
    suspicious: number;
    harmless: number;
    undetected: number;
    lastAnalysisDate: string | null;
    permalink: string | null;
    error?: string;
  };
  whois: {
    registrar: string | null;
    abuseEmail: string | null;
    createdDate: string | null;
    error?: string;
  };
  hosting: {
    asn: string | null;
    asnOrg: string | null;
    isp: string | null;
    abuseEmail: string | null;
    error?: string;
  };
  cloudflare: boolean;
  classification: "phishing" | "malware" | "scam" | "unknown";
  classificationReason: string;
  redirectChain: Array<{ url: string; status: number }>;
  finalUrl: string;
  error?: string;
}

// Phishing URL keyword patterns (case-insensitive substring match)
const PHISHING_PATTERNS = [
  "login", "signin", "account", "verify", "secure", "update", "confirm",
  "bank", "paypal", "apple", "amazon", "microsoft", "google", "facebook",
  "netflix", "instagram", "twitter", "linkedin", "github", "dropbox",
  "wallet", "crypto", "metamask", "coinbase", "binance",
  "password", "credential", "reactivate", "suspended", "limited",
  "cancelar", "compra", "pago", "factura", "banco", "cuenta",
];

const MALWARE_PATTERNS = [
  "download", "crack", "keygen", "patch", "serial", "warez", "torrent",
  "exe", "msi", "apk", "dmg", "scr", "bat",
  "free-", "full-version", "nulled", "pirated",
];

const SCAM_PATTERNS = [
  "prize", "winner", "lottery", "claim", "free", "gift", "reward",
  "investment", "bitcoin-doubler", "get-rich", "easy-money",
  "premio", "ganador", "sorteo", "regalo", "inversion",
];

function classifyUrl(url: string): { type: "phishing" | "malware" | "scam" | "unknown"; reason: string } {
  const lower = url.toLowerCase();
  for (const p of PHISHING_PATTERNS) if (lower.includes(p)) {
    return { type: "phishing", reason: `patrón de phishing: "${p}"` };
  }
  for (const p of MALWARE_PATTERNS) if (lower.includes(p)) {
    return { type: "malware", reason: `patrón de malware: "${p}"` };
  }
  for (const p of SCAM_PATTERNS) if (lower.includes(p)) {
    return { type: "scam", reason: `patrón de scam: "${p}"` };
  }
  return { type: "unknown", reason: "no se detectaron patrones — clasificación manual" };
}

async function fetchVirusTotal(url: string) {
  if (!VIRUSTOTAL_API_KEY) {
    return { malicious: 0, suspicious: 0, harmless: 0, undetected: 0, lastAnalysisDate: null, permalink: null, error: "missing API key" };
  }
  try {
    // VT requires URL to be base64url-encoded (no padding)
    const urlId = Buffer.from(url).toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
    const r = await fetch(`https://www.virustotal.com/api/v3/urls/${urlId}`, {
      headers: { "x-apikey": VIRUSTOTAL_API_KEY },
      signal: AbortSignal.timeout(10000),
    });
    if (r.status === 404) {
      // URL not yet analyzed — submit it for analysis
      const submitRes = await fetch("https://www.virustotal.com/api/v3/urls", {
        method: "POST",
        headers: {
          "x-apikey": VIRUSTOTAL_API_KEY,
          "Content-Type": "application/x-www-form-urlencoded",
        },
        body: `url=${encodeURIComponent(url)}`,
        signal: AbortSignal.timeout(10000),
      });
      if (!submitRes.ok) {
        return { malicious: 0, suspicious: 0, harmless: 0, undetected: 0, lastAnalysisDate: null, permalink: null, error: `VT submit failed: ${submitRes.status}` };
      }
      return { malicious: 0, suspicious: 0, harmless: 0, undetected: 0, lastAnalysisDate: null, permalink: `https://www.virustotal.com/gui/url/${urlId}`, error: "submitted for analysis (no verdicts yet)" };
    }
    if (!r.ok) {
      return { malicious: 0, suspicious: 0, harmless: 0, undetected: 0, lastAnalysisDate: null, permalink: null, error: `VT API ${r.status}` };
    }
    const j: any = await r.json();
    const stats = j?.data?.attributes?.last_analysis_stats || {};
    const lastAnalysis = j?.data?.attributes?.last_analysis_date;
    const permalink = `https://www.virustotal.com/gui/url/${urlId}`;
    return {
      malicious: stats.malicious || 0,
      suspicious: stats.suspicious || 0,
      harmless: stats.harmless || 0,
      undetected: stats.undetected || 0,
      lastAnalysisDate: lastAnalysis ? new Date(lastAnalysis * 1000).toISOString() : null,
      permalink,
    };
  } catch (e: any) {
    return { malicious: 0, suspicious: 0, harmless: 0, undetected: 0, lastAnalysisDate: null, permalink: null, error: String(e?.message || e) };
  }
}

async function fetchWhois(hostname: string) {
  try {
    // RDAP is the modern WHOIS protocol. Most TLDs have RDAP servers.
    // We try the IANA bootstrap first.
    const rdapRes = await fetch(`https://rdap.org/domain/${hostname}`, {
      signal: AbortSignal.timeout(8000),
      headers: { Accept: "application/rdap+json" },
    });
    if (!rdapRes.ok) {
      return { registrar: null, abuseEmail: null, createdDate: null, error: `RDAP ${rdapRes.status}` };
    }
    const j: any = await rdapRes.json();
    // Find registrar
    let registrar: string | null = null;
    for (const e of j.entities || []) {
      for (const role of e.roles || []) {
        if (role === "registrar") {
          registrar = e.vcardArray?.[1]?.find((v: any[]) => v[0] === "fn")?.[3] || null;
        }
      }
    }
    // Find abuse email in remarks or vCard
    let abuseEmail: string | null = null;
    for (const e of j.entities || []) {
      for (const role of e.roles || []) {
        if (role === "abuse") {
          // vCard may have email
          const vcard = e.vcardArray?.[1] || [];
          for (const field of vcard) {
            if (field[0] === "email") {
              abuseEmail = field[3];
            }
          }
        }
      }
    }
    // If no abuse email in entities, look in remarks
    if (!abuseEmail && j.remarks) {
      for (const r of j.remarks) {
        if (r.title && /abuse/i.test(r.title)) {
          const m = (r.description || []).join(" ").match(/[\w.+-]+@[\w.-]+\.[a-z]+/i);
          if (m) abuseEmail = m[0];
        }
      }
    }
    // Created date
    let createdDate: string | null = null;
    for (const e of j.events || []) {
      if (e.eventAction === "registration") {
        createdDate = e.eventDate || null;
      }
    }
    return { registrar, abuseEmail, createdDate };
  } catch (e: any) {
    return { registrar: null, abuseEmail: null, createdDate: null, error: String(e?.message || e) };
  }
}

async function fetchHosting(ip: string) {
  try {
    // Shodan InternetDB — free, no API key
    const r = await fetch(`https://internetdb.shodan.io/${ip}`, {
      signal: AbortSignal.timeout(8000),
    });
    if (!r.ok) {
      return { asn: null, asnOrg: null, isp: null, abuseEmail: null, error: `Shodan ${r.status}` };
    }
    const j: any = await r.json();
    // j has: cpes, hostnames, ip, ports, vulns, tags
    // We can also query AbuseIPDB for the abuse contact
    const ABUSEIPDB_API_KEY = process.env.ABUSEIPDB_API_KEY || "";
    let abuseEmail: string | null = null;
    let isp: string | null = null;
    if (ABUSEIPDB_API_KEY) {
      try {
        const ar = await fetch(`https://api.abuseipdb.com/api/v2/check?ipAddress=${ip}&maxAgeInDays=30`, {
          headers: { Key: ABUSEIPDB_API_KEY, Accept: "application/json" },
          signal: AbortSignal.timeout(8000),
        });
        if (ar.ok) {
          const aj: any = await ar.json();
          isp = aj?.data?.isp || null;
          abuseEmail = aj?.data?.abuseConfidenceScore !== undefined ? null : null;
          // AbuseIPDB doesn't return abuse email directly — use the ISP + hostname heuristic
          // We'll generate a generic abuse@<isp-domain> from the hostname
        }
      } catch {}
    }
    return {
      asn: j.asn ? `AS${j.asn}` : null,
      asnOrg: j.org || isp || null,
      isp,
      abuseEmail,
    };
  } catch (e: any) {
    return { asn: null, asnOrg: null, isp: null, abuseEmail: null, error: String(e?.message || e) };
  }
}

async function checkCloudflareAndRedirects(url: string): Promise<{ cloudflare: boolean; redirectChain: Array<{ url: string; status: number }>; finalUrl: string }> {
  try {
    const r = await fetch(url, {
      redirect: "manual",
      signal: AbortSignal.timeout(8000),
      headers: {
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        Accept: "text/html,application/xhtml+xml,*/*;q=0.8",
      },
    });
    const cfRay = r.headers.get("cf-ray") || r.headers.get("server") === "cloudflare";
    const cfCache = r.headers.get("cf-cache-status");
    const isCF = !!(cfRay || cfCache || r.headers.get("server")?.toLowerCase().includes("cloudflare"));
    const chain: Array<{ url: string; status: number }> = [{ url, status: r.status }];
    let current = url;
    if (r.status >= 300 && r.status < 400) {
      const loc = r.headers.get("location");
      if (loc) {
        try {
          current = new URL(loc, url).href;
          chain.push({ url: current, status: 0 });
        } catch {}
      }
    }
    return { cloudflare: isCF, redirectChain: chain, finalUrl: current };
  } catch {
    return { cloudflare: false, redirectChain: [], finalUrl: url };
  }
}

export async function GET(request: Request) {
  const { searchParams } = new URL(request.url);
  const targetUrl = (searchParams.get("url") || "").trim();
  if (!targetUrl) {
    return NextResponse.json({ error: "missing_url" }, { status: 400 });
  }

  let hostname: string;
  let ip: string | null = null;
  try {
    hostname = new URL(targetUrl).hostname;
  } catch {
    return NextResponse.json({ error: "invalid_url" }, { status: 400 });
  }

  // Resolve hostname → IP (for hosting lookup)
  try {
    const dnsRes = await fetch(`https://cloudflare-dns.com/dns-query?name=${hostname}&type=A`, {
      headers: { Accept: "application/dns-json" },
      signal: AbortSignal.timeout(5000),
    });
    if (dnsRes.ok) {
      const dj: any = await dnsRes.json();
      const aRecord = (dj.Answer || []).find((a: any) => a.type === 1);
      if (aRecord) ip = aRecord.data;
    }
  } catch {}

  // Run all enrichments in parallel
  const [vt, whois, hosting, cfInfo] = await Promise.all([
    fetchVirusTotal(targetUrl),
    fetchWhois(hostname),
    ip ? fetchHosting(ip) : Promise.resolve({ asn: null, asnOrg: null, isp: null, abuseEmail: null }),
    checkCloudflareAndRedirects(targetUrl),
  ]);

  const classification = classifyUrl(targetUrl);

  const result: EnrichResult = {
    url: targetUrl,
    hostname,
    screenshotUrl: `/api/sandbox/screenshot?url=${encodeURIComponent(targetUrl)}`,
    vt,
    whois,
    hosting,
    cloudflare: cfInfo.cloudflare,
    classification: classification.type,
    classificationReason: classification.reason,
    redirectChain: cfInfo.redirectChain,
    finalUrl: cfInfo.finalUrl,
  };

  return NextResponse.json(result, {
    headers: { "Cache-Control": "public, max-age=300" },
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
