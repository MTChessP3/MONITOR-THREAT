// CISA KEV — Known Exploited Vulnerabilities catalog
//
// CISA publishes a catalog of CVEs that are known to be actively exploited
// in the wild. We use the GitHub mirror of cisagov/kev-data because the
// direct cisa.gov endpoint is fronted by Akamai and 403s server-to-server
// requests. The GitHub raw URL is fully open.
//
// We cache the whole catalog (id -> entry) for 6 hours, since CISA
// updates it at most once a day.

import { NextResponse } from "next/server";

interface KevEntry {
  cveID: string;
  vendorProject: string;
  product: string;
  vulnName: string;
  shortDescription: string;
  dateAdded: string;
  dueDate: string;
  requiredAction: string;
  knownRansomwareCampaignUse: "Known" | "Unknown";
  notes: string;
}

interface KevCache {
  loadedAt: number;
  version: string;
  count: number;
  entries: Map<string, KevEntry>;
}

let kevCache: KevCache | null = null;
const KEV_TTL_MS = 6 * 60 * 60 * 1000; // 6 hours
const KEV_SOURCE_URL =
  "https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json";

async function loadKev(): Promise<KevCache | null> {
  if (kevCache && Date.now() - kevCache.loadedAt < KEV_TTL_MS) {
    return kevCache;
  }
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 10000);
    const res = await fetch(KEV_SOURCE_URL, {
      signal: controller.signal,
      headers: {
        "User-Agent": "MONITOR-THREAT/2.0 (CISA KEV)",
        Accept: "application/json",
      },
    });
    clearTimeout(timeout);
    if (!res.ok) return kevCache;
    const data = await res.json();
    const entries = new Map<string, KevEntry>();
    for (const v of data.vulnerabilities || []) {
      entries.set(v.cveID, v as KevEntry);
    }
    kevCache = {
      loadedAt: Date.now(),
      version: data.catalogVersion || "?",
      count: data.count || entries.size,
      entries,
    };
    return kevCache;
  } catch {
    return kevCache;
  }
}

export async function isKev(cveId: string): Promise<KevEntry | null> {
  const cache = await loadKev();
  if (!cache) return null;
  return cache.entries.get(cveId) || null;
}

export async function getKevStats(): Promise<{
  loaded: boolean;
  version: string;
  count: number;
  cacheAgeMin: number;
}> {
  const cache = await loadKev();
  if (!cache) {
    return { loaded: false, version: "?", count: 0, cacheAgeMin: 0 };
  }
  return {
    loaded: true,
    version: cache.version,
    count: cache.count,
    cacheAgeMin: Math.floor((Date.now() - cache.loadedAt) / 60000),
  };
}

export async function GET(request: Request) {
  const { searchParams } = new URL(request.url);
  const cve = (searchParams.get("cve") || "").trim();

  if (cve) {
    const entry = await isKev(cve);
    if (!entry) {
      return NextResponse.json({ cve, inKev: false });
    }
    return NextResponse.json({ cve, inKev: true, entry });
  }

  const stats = await getKevStats();
  return NextResponse.json(stats);
}
