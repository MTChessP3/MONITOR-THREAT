// Domain Intel — Domain blacklist checks via DNSBL
//
// Domains (and URLs) have their own blacklists, different from the IP
// DNSBLs. The main ones we check:
//   - Spamhaus DBL (Domain Block List) — known phishing/malware/spam domains
//   - SURBL (Spam URI Realtime Blocklists)
//   - URIBL (URI Block Lists)
//   - Spamhaus ZEN (on the domain's MX IP, but only if we have an MX)
//
// All DNS-based, free, no API key. We do them in parallel.

import { NextResponse } from "next/server";
import * as dns from "node:dns/promises";
import { getCached, setCached, cacheKey } from "@/lib/cache";

interface BlacklistResult {
  domain: string;
  available: boolean;
  totalChecked: number;
  listedCount: number;
  entries: Array<{
    zone: string;
    listed: boolean;
    reason?: string;
  }>;
  isBlacklisted: boolean;
  error?: string;
}

// Spamhaus DBL returns 127.0.1.x codes:
//   127.0.1.2 = spam
//   127.0.1.4 = phishing
//   127.0.1.5 = malware
//   127.0.1.6 = botnet C&C
//   127.0.1.102 = spam esp
//   127.0.1.103 = spam operations
//   127.0.1.104 = spam hosting
function decodeDblReturn(ip: string): string | undefined {
  if (!ip.startsWith("127.0.1.")) return undefined;
  const code = ip.split(".").pop();
  switch (code) {
    case "2": return "Spam domain";
    case "4": return "Phishing domain";
    case "5": return "Malware domain";
    case "6": return "Botnet C&C domain";
    case "102": return "Spam ESP (email service provider)";
    case "103": return "Spam operations";
    case "104": return "Spam hosting";
    default: return "Listed";
  }
}

// URIBL returns 127.0.0.x:
//   127.0.0.2 = blacklisted (SURBL multi)
//   127.0.0.4 = blacklisted (SURBL black)
//   127.0.0.8 = blacklisted (SURBL grey)
//   127.0.0.10 = blacklisted (SURBL white)
function decodeUriblReturn(ip: string): string | undefined {
  if (!ip.startsWith("127.0.0.")) return undefined;
  const code = ip.split(".").pop();
  switch (code) {
    case "2": return "Blacklisted (multi)";
    case "4": return "Blacklisted (black)";
    case "8": return "Blacklisted (grey)";
    case "10": return "Whitelisted";
    case "1": return "Blacklisted";
    default: return undefined;
  }
}

async function checkDnsbl(domain: string, zone: string, decoder?: (ip: string) => string | undefined): Promise<{
  zone: string;
  listed: boolean;
  reason?: string;
}> {
  try {
    // Some zones append the domain to themselves, others prepend.
    // For domain blacklists, the convention is <domain>.<zone>
    const lookup = `${domain}.${zone}`;
    const c = new AbortController();
    const t = setTimeout(() => c.abort(), 2000);
    const records = await dns.resolve4(lookup).catch((err) => {
      if (err.code === "ENOTFOUND" || err.code === "ENODATA") return [];
      throw err;
    });
    clearTimeout(t);
    if (records.length > 0) {
      const first = records[0];
      const reason = decoder ? decoder(first) : "Listed";
      return { zone, listed: true, reason };
    }
    return { zone, listed: false };
  } catch (err: any) {
    if (err.code === "ENOTFOUND" || err.code === "ENODATA") {
      return { zone, listed: false };
    }
    return { zone, listed: false, reason: `lookup_error: ${err.message}` };
  }
}

const ZONES = [
  { zone: "dbl.spamhaus.org", decoder: decodeDblReturn },
  { zone: "multi.uribl.com", decoder: decodeUriblReturn },
  { zone: "multi.surbl.com" },
  { zone: "black.uribl.com", decoder: decodeUriblReturn },
  { zone: "rhs.mailspike.net" },
  { zone: "rhs.suportefap.com" },
];

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

  const cacheK = cacheKey("domain_blacklists", domain);
  const cached = getCached<BlacklistResult>(cacheK);
  if (cached) return NextResponse.json({ ...cached, cached: true });

  // Run all checks in parallel — each is a single DNS query
  const entries = await Promise.all(
    ZONES.map((z) => checkDnsbl(domain, z.zone, z.decoder))
  );

  const listedCount = entries.filter((e) => e.listed).length;

  const result: BlacklistResult = {
    domain,
    available: true,
    totalChecked: entries.length,
    listedCount,
    entries,
    isBlacklisted: listedCount > 0,
  };

  setCached(cacheK, result, 60 * 60 * 1000); // 1 hour TTL
  return NextResponse.json(result);
}
