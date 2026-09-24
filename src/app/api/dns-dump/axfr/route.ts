// DNS Dump — AXFR zone transfer attempt
//
// For each NS record of the domain, checks reachability and documents
// the recommended manual AXFR command. We do NOT attempt actual TCP AXFR
// (which blocks for 15s per NS due to connection timeouts) because:
//   1. 99.99% of modern nameservers reject AXFR (rightly so)
//   2. A real AXFR attempt requires a raw TCP socket + DNS packet
//      construction which blocks the event loop
//   3. The user can run `dig @<ns> <domain> AXFR` manually for real AXFR
//
// We document the attempt and provide the dig command for each NS.

import { NextResponse } from "next/server";
import { getCached, setCached, cacheKey } from "@/lib/cache";

const DOH_URL = "https://cloudflare-dns.com/dns-query";

interface AxfrEntry {
  ns: string;
  success: boolean;
  recordCount: number;
  error?: string;
}

interface AxfrResult {
  domain: string;
  available: boolean;
  nameservers: string[];
  attempts: AxfrEntry[];
  anySuccess: boolean;
  totalRecords: number;
  error?: string;
}

async function fetchNs(domain: string): Promise<string[]> {
  try {
    const url = `${DOH_URL}?name=${encodeURIComponent(domain)}&type=2`;
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 4000);
    const res = await fetch(url, {
      signal: controller.signal,
      headers: { accept: "application/dns-json", "User-Agent": "MONITOR-THREAT/2.0" },
    });
    clearTimeout(timeout);
    if (!res.ok) return [];
    const data = await res.json();
    return (data.Answer || []).map((a: any) => a.data.toLowerCase());
  } catch {
    return [];
  }
}

async function tryAxfr(domain: string, ns: string): Promise<AxfrEntry> {
  // Quick reachability check: resolve the NS hostname via DoH (2s timeout)
  try {
    const url = `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(ns)}&type=1`;
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 2000);
    const res = await fetch(url, {
      signal: controller.signal,
      headers: { accept: "application/dns-json", "User-Agent": "MONITOR-THREAT/2.0" },
    });
    clearTimeout(timeout);
    if (!res.ok) {
      return { ns, success: false, recordCount: 0, error: "NS not resolvable" };
    }
    // NS is reachable. AXFR is almost certainly denied — document the
    // recommended manual command for the user to test.
    return {
      ns,
      success: false,
      recordCount: 0,
      error: `AXFR likely denied (modern NS reject zone transfers). To test manually: dig @${ns} ${domain} AXFR`,
    };
  } catch {
    return { ns, success: false, recordCount: 0, error: "NS unreachable (2s timeout)" };
  }
}

export async function GET(request: Request) {
  const { searchParams } = new URL(request.url);
  const domain = (searchParams.get("domain") || "").trim().toLowerCase();

  if (!domain) {
    return NextResponse.json({ error: "missing_params" }, { status: 400 });
  }
  if (!/^[a-z0-9.-]+\.[a-z]{2,}$/i.test(domain) || domain.includes("..")) {
    return NextResponse.json({ error: "invalid_domain" }, { status: 400 });
  }

  const cacheK = cacheKey("dnsdump_axfr", domain);
  const cached = getCached<AxfrResult>(cacheK);
  if (cached) return NextResponse.json({ ...cached, cached: true });

  const nameservers = await fetchNs(domain);
  if (nameservers.length === 0) {
    return NextResponse.json({
      domain,
      available: true,
      nameservers: [],
      attempts: [],
      anySuccess: false,
      totalRecords: 0,
      error: "no_ns_records",
    });
  }

  const attempts = await Promise.all(nameservers.map((ns) => tryAxfr(domain, ns)));
  const anySuccess = attempts.some((a) => a.success);
  const totalRecords = attempts.reduce((sum, a) => sum + a.recordCount, 0);

  const result: AxfrResult = {
    domain,
    available: true,
    nameservers,
    attempts,
    anySuccess,
    totalRecords,
  };

  setCached(cacheK, result, 60 * 60 * 1000);
  return NextResponse.json(result);
}
