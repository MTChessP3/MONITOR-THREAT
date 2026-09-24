// PoC check — search GitHub for public PoC/exploit repositories per CVE
//
// Uses GitHub's public search API (no auth needed, 10 req/min unauthenticated,
// 30 req/min authenticated). We make one search per CVE and return:
//   - total_count: how many public repos mention this CVE
//   - top_repos: top 3 by stars (with url, stars, description)
//
// Cache: per-CVE for 24 hours (repos don't move around much).

import { NextResponse } from "next/server";

interface PocRepo {
  name: string;
  url: string;
  stars: number;
  description?: string;
  pushedAt: string;
}

interface PocResult {
  cve: string;
  pocAvailable: boolean;
  totalRepos: number;
  topRepos: PocRepo[];
}

const pocCache = new Map<string, PocResult>();
const POC_TTL_MS = 24 * 60 * 60 * 1000;

async function searchPocFor(cve: string): Promise<PocResult> {
  const cached = pocCache.get(cve);
  if (cached) return cached;
  try {
    const url = `https://api.github.com/search/repositories?q=${encodeURIComponent(cve)}&sort=stars&order=desc&per_page=5`;
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 8000);
    const res = await fetch(url, {
      signal: controller.signal,
      headers: {
        "User-Agent": "MONITOR-THREAT/2.0 (PoC check)",
        Accept: "application/vnd.github+json",
      },
    });
    clearTimeout(timeout);
    if (!res.ok) {
      const empty: PocResult = { cve, pocAvailable: false, totalRepos: 0, topRepos: [] };
      pocCache.set(cve, empty);
      return empty;
    }
    const data = await res.json();
    const totalRepos = data.total_count || 0;
    const topRepos: PocRepo[] = (data.items || []).slice(0, 3).map((r: any) => ({
      name: r.full_name,
      url: r.html_url,
      stars: r.stargazers_count || 0,
      description: r.description || "",
      pushedAt: r.pushed_at,
    }));
    const result: PocResult = {
      cve,
      pocAvailable: totalRepos > 0,
      totalRepos,
      topRepos,
    };
    pocCache.set(cve, result);
    return result;
  } catch {
    return { cve, pocAvailable: false, totalRepos: 0, topRepos: [] };
  }
}

export async function getPocBatch(cves: string[]): Promise<PocResult[]> {
  // GitHub search API is unauthenticated-limited to 10 req/min, so we
  // do them serially with a small delay to stay under the limit.
  const results: PocResult[] = [];
  for (let i = 0; i < cves.length; i++) {
    results.push(await searchPocFor(cves[i]));
    if (i < cves.length - 1) await new Promise((r) => setTimeout(r, 100));
  }
  return results;
}

export async function GET(request: Request) {
  const { searchParams } = new URL(request.url);
  const cve = (searchParams.get("cve") || "").trim();
  const cvesParam = (searchParams.get("cves") || "").trim();

  if (cvesParam) {
    const cves = cvesParam.split(",").map((c) => c.trim()).filter(Boolean);
    const results = await getPocBatch(cves);
    return NextResponse.json({ results });
  }
  if (cve) {
    const result = await searchPocFor(cve);
    return NextResponse.json(result);
  }
  return NextResponse.json({ error: "missing_cve" }, { status: 400 });
}
