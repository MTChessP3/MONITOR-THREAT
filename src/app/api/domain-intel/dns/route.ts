// Domain Intel — DNS records via Cloudflare DoH (DNS-over-HTTPS)
//
// Cloudflare's public DNS-over-HTTPS endpoint is free, fast, supports all
// record types, and doesn't rate-limit reasonable usage. We use it to
// fetch A, AAAA, MX, NS, TXT, CNAME, SOA, SRV, CAA, DNSKEY, DS, and TLSA
// records in parallel.
//
// We also derive email-infra signals (SPF, DKIM, DMARC) from TXT lookups
// on the apex domain and on _dmarc.<domain>.

import { NextResponse } from "next/server";
import { getCached, setCached, cacheKey } from "@/lib/cache";

const DOH_URL = "https://cloudflare-dns.com/dns-query";

const TYPE_MAP: Record<string, number> = {
  A: 1,
  NS: 2,
  CNAME: 5,
  SOA: 6,
  MX: 15,
  TXT: 16,
  AAAA: 28,
  SRV: 33,
  CAA: 257,
  DNSKEY: 48,
  DS: 43,
  TLSA: 52,
  // DMARC lives in TXT of _dmarc.domain
  DMARC: 16,
  // DKIM lives in TXT of selector._domainkey.domain — we use a few common selectors
  DKIM: 16,
  // MTA-STS lives in TXT of _mta-sts.domain
  MTASTS: 16,
  // BIMI lives in TXT of default._bimi.domain
  BIMI: 16,
};

interface DnsRecord {
  type: string;
  name: string;
  ttl: number;
  data: string;
}

interface DnsResult {
  domain: string;
  available: boolean;
  records: {
    A: DnsRecord[];
    AAAA: DnsRecord[];
    MX: DnsRecord[];
    NS: DnsRecord[];
    TXT: DnsRecord[];
    CNAME: DnsRecord[];
    SOA: DnsRecord[];
    SRV: DnsRecord[];
    CAA: DnsRecord[];
    DNSKEY: DnsRecord[];
    DS: DnsRecord[];
    TLSA: DnsRecord[];
  };
  // Email-infra derived signals
  email: {
    spf?: { record: string; mechanism: string[] };
    dkim?: { selector: string; record: string; keyType?: string };
    dmarc?: { record: string; policy: "none" | "quarantine" | "reject" | "missing"; pct?: number };
    mtaSts?: { record: string; id: string };
    bimi?: { record: string };
    mxCount: number;
    mxProviders: string[];
  };
  // DNSSEC
  dnssec: boolean;
  // Anti-spoofing
  hasSpf: boolean;
  hasDmarc: boolean;
  hasDkim: boolean;
  emailSecurityScore: 0 | 1 | 2 | 3 | 4; // 0=none, 4=full SPF+DKIM+DMARC reject+MTA-STS
  error?: string;
}

async function fetchDoh(domain: string, type: string): Promise<DnsRecord[]> {
  const typeNum = TYPE_MAP[type];
  if (!typeNum) return [];
  try {
    const url = `${DOH_URL}?name=${encodeURIComponent(domain)}&type=${typeNum}`;
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 4000);
    const res = await fetch(url, {
      signal: controller.signal,
      headers: { accept: "application/dns-json", "User-Agent": "MONITOR-THREAT/2.0" },
    });
    clearTimeout(timeout);
    if (!res.ok) return [];
    const data = await res.json();
    return (data.Answer || []).map((a: any) => ({
      type: type,
      name: a.name,
      ttl: a.TTL,
      data: a.data,
    }));
  } catch {
    return [];
  }
}

// Try common DKIM selectors — these are the most common across providers
const DKIM_SELECTORS = ["default", "google", "selector1", "selector2", "k1", "s1", "s2", "mail", "smtp", "dkim"];

async function findDkim(domain: string): Promise<{ selector: string; record: string; keyType?: string } | undefined> {
  for (const selector of DKIM_SELECTORS) {
    const records = await fetchDoh(`${selector}._domainkey.${domain}`, "TXT");
    for (const r of records) {
      const data = r.data.replace(/"/g, "");
      if (data.startsWith("v=DKIM1") || data.includes("k=") || data.includes("p=")) {
        let keyType: string | undefined;
        const kMatch = data.match(/k=([a-z0-9]+)/i);
        if (kMatch) keyType = kMatch[1].toLowerCase();
        return { selector, record: data, keyType };
      }
    }
  }
  return undefined;
}

function parseSpf(records: DnsRecord[]): { record: string; mechanism: string[] } | undefined {
  for (const r of records) {
    const data = r.data.replace(/"/g, "");
    if (data.startsWith("v=spf1")) {
      const mechanism = data.split(/\s+/).filter((m) => m !== "v=spf1");
      return { record: data, mechanism };
    }
  }
  return undefined;
}

async function parseDmarc(domain: string): Promise<{ record: string; policy: "none" | "quarantine" | "reject" | "missing"; pct?: number } | undefined> {
  const records = await fetchDoh(`_dmarc.${domain}`, "TXT");
  for (const r of records) {
    const data = r.data.replace(/"/g, "");
    if (data.startsWith("v=DMARC1")) {
      const policyMatch = data.match(/p=(none|quarantine|reject)/i);
      const pctMatch = data.match(/pct=(\d+)/i);
      return {
        record: data,
        policy: policyMatch ? (policyMatch[1].toLowerCase() as any) : "none",
        pct: pctMatch ? parseInt(pctMatch[1]) : undefined,
      };
    }
  }
  return { record: "", policy: "missing" };
}

async function parseMtaSts(domain: string): Promise<{ record: string; id: string } | undefined> {
  const records = await fetchDoh(`_mta-sts.${domain}`, "TXT");
  for (const r of records) {
    const data = r.data.replace(/"/g, "");
    if (data.startsWith("v=STSv1")) {
      const idMatch = data.match(/id=([^\s;]+)/);
      return { record: data, id: idMatch ? idMatch[1] : "" };
    }
  }
  return undefined;
}

async function parseBimi(domain: string): Promise<{ record: string } | undefined> {
  const records = await fetchDoh(`default._bimi.${domain}`, "TXT");
  for (const r of records) {
    const data = r.data.replace(/"/g, "");
    if (data.startsWith("v=BIMI1")) {
      return { record: data };
    }
  }
  return undefined;
}

// Detect MX provider from MX records
function detectMxProviders(mxRecords: DnsRecord[]): string[] {
  const providers: string[] = [];
  for (const r of mxRecords) {
    const data = r.data.toLowerCase();
    if (data.includes("google.com") || data.includes("googlemail.com")) {
      if (!providers.includes("Google Workspace")) providers.push("Google Workspace");
    } else if (data.includes("outlook") || data.includes("microsoft") || data.includes("office365")) {
      if (!providers.includes("Microsoft 365")) providers.push("Microsoft 365");
    } else if (data.includes("protonmail") || data.includes("proton")) {
      if (!providers.includes("ProtonMail")) providers.push("ProtonMail");
    } else if (data.includes("zoho")) {
      if (!providers.includes("Zoho Mail")) providers.push("Zoho Mail");
    } else if (data.includes("yahoodns")) {
      if (!providers.includes("Yahoo")) providers.push("Yahoo");
    } else if (data.includes("mailgun")) {
      if (!providers.includes("Mailgun")) providers.push("Mailgun");
    } else if (data.includes("sendgrid")) {
      if (!providers.includes("SendGrid")) providers.push("SendGrid");
    } else if (data.includes("ses.amazon")) {
      if (!providers.includes("Amazon SES")) providers.push("Amazon SES");
    } else if (data.includes("mailchimp")) {
      if (!providers.includes("Mailchimp")) providers.push("Mailchimp");
    } else if (data.includes("postmark")) {
      if (!providers.includes("Postmark")) providers.push("Postmark");
    } else {
      // Generic — extract the MX hostname
      const m = data.match(/(\S+\.\S+)/);
      if (m && !providers.includes(m[1])) providers.push(m[1]);
    }
  }
  return providers;
}

export async function GET(request: Request) {
  const { searchParams } = new URL(request.url);
  const domain = (searchParams.get("domain") || "").trim().toLowerCase();

  if (!domain) {
    return NextResponse.json(
      { error: "missing_params", hint: "Provide a 'domain' query parameter." },
      { status: 400 }
    );
  }

  if (!/^[a-z0-9.-]+\.[a-z]{2,}$/i.test(domain) || domain.includes("..")) {
    return NextResponse.json(
      { error: "invalid_domain", hint: `Not a valid domain: ${domain}` },
      { status: 400 }
    );
  }

  const cacheK = cacheKey("dns", domain);
  const cached = getCached<DnsResult>(cacheK);
  if (cached) return NextResponse.json({ ...cached, cached: true });

  // Fetch all record types in parallel
  const types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "SRV", "CAA", "DNSKEY", "DS", "TLSA"];
  const results = await Promise.all(types.map((t) => fetchDoh(domain, t)));

  const recordsByType: DnsResult["records"] = {
    A: results[0],
    AAAA: results[1],
    MX: results[2],
    NS: results[3],
    TXT: results[4],
    CNAME: results[5],
    SOA: results[6],
    SRV: results[7],
    CAA: results[8],
    DNSKEY: results[9],
    DS: results[10],
    TLSA: results[11],
  };

  // Email infra — derived from TXT records + special-domain lookups
  const spf = parseSpf(recordsByType.TXT);
  const dmarc = await parseDmarc(domain);
  const mtaSts = await parseMtaSts(domain);
  const bimi = await parseBimi(domain);
  const dkim = await findDkim(domain);

  // Detect MX providers
  const mxProviders = detectMxProviders(recordsByType.MX);

  // DNSSEC: DS or DNSKEY records present
  const dnssec = recordsByType.DS.length > 0 || recordsByType.DNSKEY.length > 0;

  // Email security score (0-4)
  let emailSecurityScore: 0 | 1 | 2 | 3 | 4 = 0;
  if (spf) emailSecurityScore = 1;
  if (spf && dkim) emailSecurityScore = 2;
  if (spf && dkim && dmarc && dmarc.policy !== "missing") emailSecurityScore = 3;
  if (spf && dkim && dmarc && (dmarc.policy === "quarantine" || dmarc.policy === "reject") && mtaSts) {
    emailSecurityScore = 4;
  }

  const result: DnsResult = {
    domain,
    available: true,
    records: recordsByType,
    email: {
      spf,
      dkim,
      dmarc,
      mtaSts,
      bimi,
      mxCount: recordsByType.MX.length,
      mxProviders,
    },
    dnssec,
    hasSpf: !!spf,
    hasDmarc: dmarc?.policy !== "missing" && !!dmarc,
    hasDkim: !!dkim,
    emailSecurityScore,
  };

  setCached(cacheK, result, 30 * 60 * 1000); // 30 min TTL
  return NextResponse.json(result);
}
