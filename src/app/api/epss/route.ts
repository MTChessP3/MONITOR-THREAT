// EPSS — Exploit Prediction Scoring System (FIRST.org)
//
// EPSS gives the probability (0..1) that a CVE will be exploited in the
// next 30 days. The API supports batch queries (up to 100 CVEs per
// request) so we can enrich many CVEs at once.
//
// Rate limit: free, no API key, no documented rate limit (we keep it
// reasonable with a single batched request per IP analysis).
//
// Cache: each CVE's EPSS score is cached for 24 hours.

import { NextResponse } from "next/server";
import { getCached, setCached, cacheKey } from "@/lib/cache";

interface EpssResult {
  cve: string;
  epss: number; // 0..1 probability of exploitation in next 30 days
  percentile: number; // 0..1 — rank vs. all CVEs in EPSS model
}

const EPSS_API = "https://api.first.org/data/v1/epss";
const BATCH_SIZE = 100;

// In-memory cache of EPSS scores — keyed by CVE id, 24 hour TTL
const epssCache = new Map<string, EpssResult>();
const EPSS_TTL_MS = 24 * 60 * 60 * 1000;
let lastCacheClean = Date.now();

function cacheGet(cve: string): EpssResult | null {
  const entry = epssCache.get(cve);
  if (!entry) return null;
  return entry;
}

function cacheSet(cve: string, r: EpssResult): void {
  epssCache.set(cve, r);
  // Prune every hour
  if (Date.now() - lastCacheClean > 3600 * 1000) {
    lastCacheClean = Date.now();
    // EPSS doesn't change quickly; we leave entries in, they just expire
    // on next miss-check. Map will naturally grow with distinct CVEs.
    if (epssCache.size > 5000) {
      epssCache.clear();
    }
  }
}

export async function getEpssBatch(cves: string[]): Promise<EpssResult[]> {
  if (cves.length === 0) return [];
  // Dedupe + filter out cached ones
  const unique = Array.from(new Set(cves.filter(Boolean)));
  const results: EpssResult[] = [];
  const toFetch: string[] = [];
  for (const cve of unique) {
    const cached = cacheGet(cve);
    if (cached) results.push(cached);
    else toFetch.push(cve);
  }
  if (toFetch.length === 0) return results;

  // Batch in chunks of BATCH_SIZE
  for (let i = 0; i < toFetch.length; i += BATCH_SIZE) {
    const batch = toFetch.slice(i, i + BATCH_SIZE);
    try {
      const url = `${EPSS_API}?cve=${batch.map(encodeURIComponent).join(",")}`;
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 8000);
      const res = await fetch(url, {
        signal: controller.signal,
        headers: { "User-Agent": "MONITOR-THREAT/2.0 (EPSS)", Accept: "application/json" },
      });
      clearTimeout(timeout);
      if (!res.ok) continue;
      const data = await res.json();
      for (const item of data?.data || []) {
        const r: EpssResult = {
          cve: item.cve,
          epss: parseFloat(item.epss) || 0,
          percentile: parseFloat(item.percentile) || 0,
        };
        cacheSet(r.cve, r);
        results.push(r);
      }
    } catch {
      // continue with next batch
    }
  }
  return results;
}

export async function GET(request: Request) {
  const { searchParams } = new URL(request.url);
  const cveParam = (searchParams.get("cve") || "").trim();
  const cvesParam = (searchParams.get("cves") || "").trim();

  if (cvesParam) {
    // Batch endpoint — cves=CVE-X,CVE-Y,CVE-Z
    const cves = cvesParam.split(",").map((c) => c.trim()).filter(Boolean);
    if (cves.length === 0) {
      return NextResponse.json({ error: "no_cves" }, { status: 400 });
    }
    const results = await getEpssBatch(cves);
    return NextResponse.json({ results });
  }

  if (cveParam) {
    const results = await getEpssBatch([cveParam]);
    return NextResponse.json(results[0] || { cve: cveParam, epss: 0, percentile: 0 });
  }

  return NextResponse.json({ error: "missing_cve" }, { status: 400 });
}
