// Domain Intel — SSL Certificate Transparency history via crt.sh
//
// Returns all the SSL/TLS certificates ever issued for this domain (or any
// subdomain), with issuer, validity window, and the full SAN list. The
// SAN list reveals other domains sharing the same cert — a strong pivot
// for discovering related infrastructure owned by the same actor.

import { NextResponse } from "next/server";
import { getCached, setCached, cacheKey } from "@/lib/cache";

interface CertEntry {
  id: number;
  issuer: string;
  commonName: string;
  sanNames: string[]; // Subject Alternative Names — could include *.example.com, www.example.com, etc.
  notBefore: string; // ISO date
  notAfter: string; // ISO date — expiry
  serialNumber: string;
  isWildcard: boolean;
  isExpired: boolean;
  isCurrentlyValid: boolean;
}

interface CertsResult {
  domain: string;
  available: boolean;
  totalCerts: number;
  currentlyValidCerts: number;
  expiredCerts: number;
  wildcardCerts: number;
  uniqueIssuers: Array<{ name: string; count: number }>;
  uniqueSanDomains: string[]; // unique domains that share certs with this domain — pivots!
  certs: CertEntry[]; // sorted by notBefore desc, capped at 50
  crtShOk: boolean;
  error?: string;
}

async function fetchCrtShCerts(domain: string): Promise<{ raw: any[]; ok: boolean }> {
  try {
    const url = `https://crt.sh/?q=${encodeURIComponent(domain)}&output=json`;
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 20000);
    const res = await fetch(url, {
      signal: controller.signal,
      headers: {
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        Accept: "application/json",
      },
    });
    clearTimeout(timeout);
    if (!res.ok) return { raw: [], ok: false };
    const data = await res.json();
    return { raw: data, ok: true };
  } catch {
    return { raw: [], ok: false };
  }
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

  const cacheK = cacheKey("certs", domain);
  const cached = getCached<CertsResult>(cacheK);
  if (cached) return NextResponse.json({ ...cached, cached: true });

  const { raw, ok } = await fetchCrtShCerts(domain);

  if (!ok || raw.length === 0) {
    return NextResponse.json({
      domain,
      available: false,
      totalCerts: 0,
      currentlyValidCerts: 0,
      expiredCerts: 0,
      wildcardCerts: 0,
      uniqueIssuers: [],
      uniqueSanDomains: [],
      certs: [],
      crtShOk: ok,
      error: ok ? "no_certs_found" : "crt_sh_unreachable",
    });
  }

  const now = Date.now();
  const issuerCounts = new Map<string, number>();
  const sanDomainSet = new Set<string>();
  const certEntries: CertEntry[] = [];

  for (const c of raw) {
    const notBefore = c.not_before ? new Date(c.not_before) : null;
    const notAfter = c.not_after ? new Date(c.not_after) : null;
    const isExpired = notAfter ? notAfter.getTime() < now : false;
    const isCurrentlyValid =
      notBefore && notAfter ? notBefore.getTime() <= now && notAfter.getTime() >= now : false;

    // Sanitize SAN list
    const sanNames: string[] = (c.name_value || "")
      .split("\n")
      .map((s: string) => s.trim().toLowerCase())
      .filter(Boolean);

    // Track pivot domains (SAN entries that don't match the target domain)
    for (const s of sanNames) {
      const clean = s.replace(/^\*\./, "");
      if (clean !== domain && !clean.endsWith(`.${domain}`)) {
        sanDomainSet.add(s);
      }
    }

    // Track issuers
    const issuerName = c.issuer_name || "Unknown";
    issuerCounts.set(issuerName, (issuerCounts.get(issuerName) || 0) + 1);

    certEntries.push({
      id: c.id,
      issuer: issuerName,
      commonName: (c.common_name || "").toLowerCase(),
      sanNames,
      notBefore: c.not_before,
      notAfter: c.not_after,
      serialNumber: c.serial_number,
      isWildcard: sanNames.some((n: string) => n.startsWith("*.")),
      isExpired,
      isCurrentlyValid,
    });
  }

  // Sort by notBefore desc
  certEntries.sort((a, b) => {
    const aT = a.notBefore ? new Date(a.notBefore).getTime() : 0;
    const bT = b.notBefore ? new Date(b.notBefore).getTime() : 0;
    return bT - aT;
  });

  const result: CertsResult = {
    domain,
    available: true,
    totalCerts: certEntries.length,
    currentlyValidCerts: certEntries.filter((c) => c.isCurrentlyValid).length,
    expiredCerts: certEntries.filter((c) => c.isExpired).length,
    wildcardCerts: certEntries.filter((c) => c.isWildcard).length,
    uniqueIssuers: Array.from(issuerCounts.entries())
      .map(([name, count]) => ({ name, count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 10),
    uniqueSanDomains: Array.from(sanDomainSet).sort().slice(0, 50),
    certs: certEntries.slice(0, 50),
    crtShOk: ok,
  };

  setCached(cacheK, result, 30 * 60 * 1000); // 30 min TTL
  return NextResponse.json(result);
}
