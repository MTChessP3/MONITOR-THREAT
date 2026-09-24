// DNS Dump — Cross-resolver comparison
//
// Queries the same A record against 4 public DNS resolvers and compares
// the responses. If they differ, it could indicate split-horizon DNS
// (different responses based on geolocation or client identity) or
// DNS-level blocking by one of the resolvers.

import { NextResponse } from "next/server";
import { getCached, setCached, cacheKey } from "@/lib/cache";

const RESOLVERS = [
  { name: "Cloudflare", doh: "https://cloudflare-dns.com/dns-query" },
  { name: "Google", doh: "https://dns.google/resolve" },
  { name: "Quad9", doh: "https://dns.quad9.net/dns-query" },
  { name: "OpenDNS", doh: "https://doh.opendns.com/dns-query" },
];

interface ResolverEntry {
  name: string;
  ips: string[];
  status: number;
  responseTimeMs: number;
  error?: string;
}

interface CrossResolverResult {
  domain: string;
  available: boolean;
  results: ResolverEntry[];
  allAgree: boolean;
  uniqueIpSets: number;
  splitHorizon: boolean;
  error?: string;
}

async function queryResolver(domain: string, resolver: { name: string; doh: string }): Promise<ResolverEntry> {
  const start = Date.now();
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 5000);
    const res = await fetch(`${resolver.doh}?name=${encodeURIComponent(domain)}&type=1`, {
      signal: controller.signal,
      headers: { accept: "application/dns-json", "User-Agent": "MONITOR-THREAT/2.0" },
    });
    clearTimeout(timeout);
    const elapsed = Date.now() - start;
    if (!res.ok) {
      return { name: resolver.name, ips: [], status: res.status, responseTimeMs: elapsed, error: `HTTP ${res.status}` };
    }
    const data = await res.json();
    const ips = (data.Answer || []).filter((a: any) => a.type === 1).map((a: any) => a.data);
    return { name: resolver.name, ips, status: data.Status || 0, responseTimeMs: elapsed };
  } catch (err: any) {
    return { name: resolver.name, ips: [], status: 0, responseTimeMs: Date.now() - start, error: err.message };
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

  const cacheK = cacheKey("dnsdump_crossresolver", domain);
  const cached = getCached<CrossResolverResult>(cacheK);
  if (cached) return NextResponse.json({ ...cached, cached: true });

  const results = await Promise.all(RESOLVERS.map((r) => queryResolver(domain, r)));

  // Compare IP sets
  const ipSets = results.map((r) => r.ips.sort().join(","));
  const uniqueIpSets = Array.from(new Set(ipSets.filter(Boolean)));
  const allAgree = uniqueIpSets.length <= 1;
  const splitHorizon = !allAgree && uniqueIpSets.length > 1;

  const result: CrossResolverResult = {
    domain,
    available: true,
    results,
    allAgree,
    uniqueIpSets: uniqueIpSets.length,
    splitHorizon,
  };

  setCached(cacheK, result, 15 * 60 * 1000);
  return NextResponse.json(result);
}
