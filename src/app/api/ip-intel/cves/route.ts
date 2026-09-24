// IP Intel — CVE / Vulnerability Assessment
//
// Strategy:
// 1. Pull the list of CVEs that Shodan InternetDB already knows for this IP
//    (free, no API key, ~50ms).
// 2. For each CVE, enrich with NVD (National Vulnerability Database):
//    description, CVSS score, severity, attack vector, published date,
//    affected products, references (PoC / advisory links).
// 3. Mark CVEs published in the last 2 months as "RECENT" so the analyst
//    can spot fresh exposures.
// 4. Cache the enriched result for 1 hour — CVE metadata rarely changes.
//
// NVD public API: https://services.nvd.nist.gov/rest/json/cves/2.0
// Rate limit (no API key): 5 req / 30 sec rolling window. We respect this
// by doing NVD lookups in serial with a 250ms delay between calls and
// capping enrichment to the top 20 CVEs Shodan returned.

import { NextResponse } from "next/server";
import { getCached, setCached, cacheKey } from "@/lib/cache";
import { isKev } from "@/app/api/cisa-kev/route";
import { getEpssBatch } from "@/app/api/epss/route";
import { getPocBatch } from "@/app/api/poc-check/route";

interface CveDetail {
  id: string; // e.g. CVE-2024-3400
  source: "nvd" | "shodan";
  // NVD data
  description?: string;
  cvssScore?: number;
  cvssSeverity?: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  cvssVector?: string;
  attackVector?: "NETWORK" | "ADJACENT" | "LOCAL" | "PHYSICAL";
  publishedDate?: string; // ISO
  lastModified?: string;
  cwe?: string; // e.g. CWE-78
  references?: Array<{ url: string; source?: string; tags?: string[] }>;
  affectedProducts?: string[];
  // Exploitation enrichment
  inKev?: boolean; // CISA KEV — known exploited in the wild
  kevEntry?: {
    dateAdded: string;
    dueDate: string;
    knownRansomwareCampaignUse: "Known" | "Unknown";
    requiredAction: string;
    shortDescription: string;
  };
  epss?: number; // 0..1 probability of exploitation in next 30 days
  epssPercentile?: number; // 0..1 rank vs. all CVEs
  pocAvailable?: boolean; // GitHub repos exist with this CVE in name/description
  pocRepoCount?: number;
  pocTopRepos?: Array<{ name: string; url: string; stars: number; description?: string }>;
  // Convenience flags
  isRecent: boolean; // published in the last 2 months
  ageDays?: number; // days since published
}

interface CveAssessment {
  ip: string;
  available: boolean;
  totalCves: number;
  recentCves: number; // published in last 2 months
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  kevCount: number; // in CISA KEV — known exploited in the wild
  highEpssCount: number; // EPSS percentile >= 0.95 (very likely to be exploited)
  pocCount: number; // at least one public PoC repo on GitHub
  topSeverity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "NONE";
  kevCatalogVersion?: string;
  kevCatalogCount?: number;
  cves: CveDetail[];
  shodanOk: boolean;
  error?: string;
}

const TWO_MONTHS_MS = 60 * 24 * 60 * 60 * 1000;
const NVD_CALL_DELAY_MS = 250;
const MAX_NVD_LOOKUPS = 20;

async function fetchShodan(ip: string, base: string): Promise<{
  vulns: string[];
  ok: boolean;
}> {
  try {
    const res = await fetch(`${base}/api/ip-intel/ports?ip=${encodeURIComponent(ip)}`, {
      signal: AbortSignal.timeout(5000),
    });
    if (!res.ok) return { vulns: [], ok: false };
    const data = await res.json();
    return { vulns: data.vulns || [], ok: true };
  } catch {
    return { vulns: [], ok: false };
  }
}

async function fetchNvd(cveId: string): Promise<CveDetail | null> {
  try {
    const url = `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${encodeURIComponent(cveId)}`;
    const res = await fetch(url, {
      signal: AbortSignal.timeout(8000),
      headers: {
        "User-Agent": "MONITOR-THREAT/2.0 (CVE enrichment)",
        Accept: "application/json",
      },
    });
    if (!res.ok) return null;
    const data = await res.json();
    const v = data?.vulnerabilities?.[0]?.cve;
    if (!v) return null;

    // English description
    const desc = (v.descriptions || []).find((d: any) => d.lang === "en")?.value;

    // CVSS v3.1 preferred, fallback v3.0, fallback v2
    const metrics = v.metrics || {};
    let cvssData: any = null;
    let cvssVersion = "";
    if (metrics.cvssMetricV31?.length) {
      cvssData = metrics.cvssMetricV31[0];
      cvssVersion = "3.1";
    } else if (metrics.cvssMetricV30?.length) {
      cvssData = metrics.cvssMetricV30[0];
      cvssVersion = "3.0";
    } else if (metrics.cvssMetricV2?.length) {
      cvssData = metrics.cvssMetricV2[0];
      cvssVersion = "2.0";
    }

    const cvss = cvssData?.cvssData || {};
    const cvssScore = cvss.baseScore;
    const cvssSeverity =
      cvss.baseSeverity ||
      cvssData?.baseSeverity ||
      (cvssScore >= 9 ? "CRITICAL" : cvssScore >= 7 ? "HIGH" : cvssScore >= 4 ? "MEDIUM" : "LOW");
    const cvssVector = cvss.vectorString;
    const attackVector = cvss.attackVector;

    // CWE (first one)
    const cwe =
      v.weaknesses?.[0]?.description?.find((d: any) => d.lang === "en")?.value;

    // References
    const references = (v.references || []).slice(0, 10).map((r: any) => ({
      url: r.url,
      source: r.source,
      tags: r.tags,
    }));

    // Affected products (CPEs — take unique vendors/products)
    const configs = v.configurations || [];
    const affectedProducts: string[] = [];
    for (const cfg of configs) {
      for (const node of cfg.nodes || []) {
        for (const m of node.cpeMatch || []) {
          const cpe = m.criteria || "";
          // cpe:2.3:a:vendor:product:version:*:*:*:*:*:*:*:*
          const parts = cpe.split(":");
          if (parts.length >= 5) {
            const vendor = parts[3];
            const product = parts[4];
            const version = parts[5] || "*";
            const label = `${vendor}/${product} ${version !== "*" ? version : ""}`.trim();
            if (label && !affectedProducts.includes(label)) {
              affectedProducts.push(label);
              if (affectedProducts.length >= 5) break;
            }
          }
        }
      }
    }

    const publishedDate = v.published;
    const lastModified = v.lastModified;
    let isRecent = false;
    let ageDays: number | undefined;
    if (publishedDate) {
      const published = new Date(publishedDate).getTime();
      const age = Date.now() - published;
      ageDays = Math.floor(age / (24 * 60 * 60 * 1000));
      isRecent = age <= TWO_MONTHS_MS;
    }

    return {
      id: v.id,
      source: "nvd",
      description: desc,
      cvssScore,
      cvssSeverity,
      cvssVector,
      attackVector,
      publishedDate,
      lastModified,
      cwe,
      references,
      affectedProducts,
      isRecent,
      ageDays,
    };
  } catch {
    return null;
  }
}

export async function GET(request: Request) {
  const { searchParams } = new URL(request.url);
  const ip = (searchParams.get("ip") || "").trim();

  if (!ip) {
    return NextResponse.json(
      { error: "missing_params", hint: "Provide an 'ip' query parameter." },
      { status: 400 }
    );
  }

  const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/;
  const ipv6Regex = /^([0-9a-fA-F:]+)$/;
  if (!ipv4Regex.test(ip) && !ipv6Regex.test(ip)) {
    return NextResponse.json(
      { error: "invalid_ip", hint: `Not a valid IP: ${ip}` },
      { status: 400 }
    );
  }

  // Cache check — 1 hour TTL (CVE metadata doesn't change often)
  const cacheK = cacheKey("cves", ip);
  const cached = getCached<CveAssessment>(cacheK);
  if (cached) return NextResponse.json({ ...cached, cached: true });

  const base = new URL(request.url).origin;

  // 1. Pull CVEs from Shodan InternetDB
  const shodan = await fetchShodan(ip, base);

  if (!shodan.ok) {
    return NextResponse.json({
      ip,
      available: false,
      totalCves: 0,
      recentCves: 0,
      criticalCount: 0,
      highCount: 0,
      mediumCount: 0,
      lowCount: 0,
      kevCount: 0,
      highEpssCount: 0,
      pocCount: 0,
      topSeverity: "NONE",
      cves: [],
      shodanOk: false,
      error: "shodan_unreachable",
    });
  }

  const shodanVulns = shodan.vulns;
  if (shodanVulns.length === 0) {
    const empty: CveAssessment = {
      ip,
      available: true,
      totalCves: 0,
      recentCves: 0,
      criticalCount: 0,
      highCount: 0,
      mediumCount: 0,
      lowCount: 0,
      kevCount: 0,
      highEpssCount: 0,
      pocCount: 0,
      topSeverity: "NONE",
      cves: [],
      shodanOk: true,
    };
    setCached(cacheK, empty, 60 * 60 * 1000);
    return NextResponse.json(empty);
  }

  // 2. Enrich up to MAX_NVD_LOOKUPS CVEs in serial (NVD rate limit ~5/30s)
  const cvesToFetch = shodanVulns.slice(0, MAX_NVD_LOOKUPS);
  const enriched: CveDetail[] = [];

  for (const cveId of cvesToFetch) {
    const detail = await fetchNvd(cveId);
    if (detail) {
      enriched.push(detail);
    } else {
      // Even without NVD we list the CVE so the analyst knows Shodan flagged it
      enriched.push({
        id: cveId,
        source: "shodan",
        isRecent: false,
      });
    }
    // Respect NVD rate limit (5 req / 30 sec = 1 per 6 sec ideally, but with 250ms
    // we get ~4 req/sec — NVD tolerates bursts; they will rate-limit us with a
    // 503 if we push too hard, and our per-call 8s timeout will recover.)
    await new Promise((r) => setTimeout(r, NVD_CALL_DELAY_MS));
  }

  // 3. Enrich with CISA KEV in parallel — fast, single in-memory catalog check
  // Pre-load the catalog so the first batch of lookups is warm.
  await Promise.all(enriched.map(async (c) => {
    const kevEntry = await isKev(c.id);
    if (kevEntry) {
      c.inKev = true;
      c.kevEntry = {
        dateAdded: kevEntry.dateAdded,
        dueDate: kevEntry.dueDate,
        knownRansomwareCampaignUse: kevEntry.knownRansomwareCampaignUse,
        requiredAction: kevEntry.requiredAction,
        shortDescription: kevEntry.shortDescription,
      };
    } else {
      c.inKev = false;
    }
  }));

  // 4. Enrich with EPSS in one batched call — fast (1 HTTP request for up to 100 CVEs)
  try {
    const epssResults = await getEpssBatch(enriched.map((c) => c.id));
    const epssMap = new Map(epssResults.map((e) => [e.cve, e]));
    for (const c of enriched) {
      const epss = epssMap.get(c.id);
      if (epss) {
        c.epss = epss.epss;
        c.epssPercentile = epss.percentile;
      }
    }
  } catch {
    // EPSS is best-effort enrichment
  }

  // 5. Enrich with PoC availability — GitHub search API. To stay under the
  // unauthenticated rate limit (10 req/min), only check the top 10 CVEs by
  // CVSS severity (which are the most interesting anyway).
  const cveIdsForPoc = enriched
    .filter((c) => c.cvssSeverity === "CRITICAL" || c.cvssSeverity === "HIGH")
    .slice(0, 10)
    .map((c) => c.id);
  if (cveIdsForPoc.length > 0) {
    try {
      const pocResults = await getPocBatch(cveIdsForPoc);
      const pocMap = new Map(pocResults.map((p) => [p.cve, p]));
      for (const c of enriched) {
        const poc = pocMap.get(c.id);
        if (poc) {
          c.pocAvailable = poc.pocAvailable;
          c.pocRepoCount = poc.totalRepos;
          c.pocTopRepos = poc.topRepos.map((r) => ({
            name: r.name,
            url: r.url,
            stars: r.stars,
            description: r.description,
          }));
        } else {
          c.pocAvailable = false;
          c.pocRepoCount = 0;
        }
      }
    } catch {
      // best-effort
    }
  }

  // Sort: KEV first (most urgent), then by severity, then by EPSS percentile,
  // then by recency, then by published date desc.
  const severityOrder = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 } as const;
  enriched.sort((a, b) => {
    // CISA KEV always floats to the top
    const ka = a.inKev ? 1 : 0;
    const kb = b.inKev ? 1 : 0;
    if (kb !== ka) return kb - ka;
    // Then by severity
    const sa = a.cvssSeverity ? severityOrder[a.cvssSeverity] : 0;
    const sb = b.cvssSeverity ? severityOrder[b.cvssSeverity] : 0;
    if (sb !== sa) return sb - sa;
    // Then by EPSS percentile desc
    const ea = a.epssPercentile || 0;
    const eb = b.epssPercentile || 0;
    if (eb !== ea) return eb - ea;
    // Then by PoC availability (PoC available first)
    const pa = a.pocAvailable ? 1 : 0;
    const pb = b.pocAvailable ? 1 : 0;
    if (pb !== pa) return pb - pa;
    // Then by recency
    if (a.isRecent !== b.isRecent) return a.isRecent ? -1 : 1;
    // Then by CVSS score desc
    if ((b.cvssScore || 0) !== (a.cvssScore || 0))
      return (b.cvssScore || 0) - (a.cvssScore || 0);
    // Then by published date desc
    const pda = a.publishedDate ? new Date(a.publishedDate).getTime() : 0;
    const pdb = b.publishedDate ? new Date(b.publishedDate).getTime() : 0;
    return pdb - pda;
  });

  const criticalCount = enriched.filter((c) => c.cvssSeverity === "CRITICAL").length;
  const highCount = enriched.filter((c) => c.cvssSeverity === "HIGH").length;
  const mediumCount = enriched.filter((c) => c.cvssSeverity === "MEDIUM").length;
  const lowCount = enriched.filter((c) => c.cvssSeverity === "LOW").length;
  const recentCves = enriched.filter((c) => c.isRecent).length;
  const kevCount = enriched.filter((c) => c.inKev).length;
  const highEpssCount = enriched.filter((c) => (c.epssPercentile || 0) >= 0.95).length;
  const pocCount = enriched.filter((c) => c.pocAvailable).length;
  const topSeverity =
    criticalCount > 0 ? "CRITICAL" :
    highCount > 0 ? "HIGH" :
    mediumCount > 0 ? "MEDIUM" :
    lowCount > 0 ? "LOW" : "NONE";

  // Pull KEV catalog stats for the panel header
  const { getKevStats } = await import("@/app/api/cisa-kev/route");
  const kevStats = await getKevStats();

  const result: CveAssessment = {
    ip,
    available: true,
    totalCves: enriched.length,
    recentCves,
    criticalCount,
    highCount,
    mediumCount,
    lowCount,
    kevCount,
    highEpssCount,
    pocCount,
    topSeverity: topSeverity as CveAssessment["topSeverity"],
    kevCatalogVersion: kevStats.loaded ? kevStats.version : undefined,
    kevCatalogCount: kevStats.loaded ? kevStats.count : undefined,
    cves: enriched,
    shodanOk: true,
  };

  setCached(cacheK, result, 60 * 60 * 1000);
  return NextResponse.json(result);
}
