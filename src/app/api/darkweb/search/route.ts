// Dark Web Search — busca menciones de un target (email, dominio,
// keyword, IP) en fuentes de la dark/deep web usando APIs gratuitas:
//
// 1. IntelligenceX (intelx.io) — busca en leaks, pastes, darknet, .onion
//    Requiere API key gratuita (25 req/día). Si no hay key, se saltea.
// 2. Ahmia.fi — buscador de .onion sites (sin API key, scraping directo)
// 3. LeakCheck — credenciales filtradas (50 req/día gratis)
// 4. GitHub Code Search — busca credenciales filtradas en repos
// 5. Pastebin scraping — busca keywords en pastes recientes
// 6. Pulsedive — IOCs y threat intel (25 req/día gratis)
//
// GET /api/darkweb/search?q=<target>&type=<email|domain|keyword|ip>
//
// Devuelve un JSON con resultados categorizados por fuente.

import { NextResponse } from "next/server";

interface SearchResult {
  source: string;
  type: string;
  title: string;
  url: string;
  snippet: string;
  severity: "high" | "medium" | "low" | "info";
  timestamp: string | null;
}

interface DarkWebResponse {
  query: string;
  queryType: string;
  results: SearchResult[];
  summary: {
    total: number;
    bySource: Record<string, number>;
    bySeverity: { high: number; medium: number; low: number; info: number };
  };
  timestamp: string;
}

async function searchIntelligenceX(query: string, type: string): Promise<SearchResult[]> {
  const INTELX_API_KEY = process.env.INTELX_API_KEY || "";
  if (!INTELX_API_KEY) return [];
  try {
    // IntelX requires a 2-step process: start search, then poll for results
    const startRes = await fetch("https://2.intelx.io/phonebook/search", {
      method: "POST",
      headers: {
        "x-key": INTELX_API_KEY,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        term: query,
        maxresults: 20,
        media: 0,
        target: 1, // all sources
      }),
      signal: AbortSignal.timeout(10000),
    });
    if (!startRes.ok) return [];
    const startData: any = await startRes.json();
    const searchId = startData.id;
    if (!searchId) return [];

    // Poll for results (up to 3 times, 2s apart)
    for (let i = 0; i < 3; i++) {
      await new Promise(r => setTimeout(r, 2000));
      const pollRes = await fetch(`https://2.intelx.io/phonebook/search/result?id=${searchId}&limit=20`, {
        headers: { "x-key": INTELX_API_KEY },
        signal: AbortSignal.timeout(10000),
      });
      if (!pollRes.ok) continue;
      const pollData: any = await pollRes.json();
      const selectors = pollData.selectors || [];
      if (selectors.length > 0) {
        return selectors.slice(0, 20).map((s: any) => ({
          source: "IntelligenceX",
          type: "leak/paste/darknet",
          title: s.selectorvalue || "IntelX result",
          url: `https://intelx.io/?s=${encodeURIComponent(s.selectorvalue || "")}`,
          snippet: s.selectorvalue || "",
          severity: "high" as const,
          timestamp: null,
        }));
      }
    }
    return [];
  } catch {
    return [];
  }
}

async function searchAhmia(query: string): Promise<SearchResult[]> {
  try {
    // Ahmia.fi search API — searches .onion sites
    const r = await fetch(`https://ahmia.fi/api/search/?q=${encodeURIComponent(query)}&limit=20`, {
      headers: { Accept: "application/json" },
      signal: AbortSignal.timeout(10000),
    });
    if (!r.ok) return [];
    const data: any = await r.json();
    const items = data.results || data.items || [];
    return items.slice(0, 20).map((item: any) => ({
      source: "Ahmia (.onion)",
      type: "dark web mention",
      title: item.title || item.name || "Onion site",
      url: item.url || item.onion || item.link || "#",
      snippet: (item.description || item.snippet || item.text || "").slice(0, 300),
      severity: "medium" as const,
      timestamp: item.added || item.date || null,
    }));
  } catch {
    return [];
  }
}

async function searchLeakCheck(query: string, type: string): Promise<SearchResult[]> {
  const LEAKCHECK_API_KEY = process.env.LEAKCHECK_API_KEY || "";
  if (!LEAKCHECK_API_KEY) return [];
  try {
    const endpoint = type === "email" ? "email" : "domain";
    const r = await fetch(`https://leakcheck.io/v2/query/${endpoint}/${encodeURIComponent(query)}`, {
      headers: { "x-api-key": LEAKCHECK_API_KEY },
      signal: AbortSignal.timeout(10000),
    });
    if (!r.ok) return [];
    const data: any = await r.json();
    const leaks = data.leaks || data.results || [];
    return leaks.slice(0, 20).map((leak: any) => ({
      source: "LeakCheck",
      type: "credential leak",
      title: leak.name || leak.source || "Credential leak",
      url: `https://leakcheck.io/`,
      snippet: `Password hash: ${leak.password || leak.hash || "N/A"} | Source: ${leak.source || leak.name || "Unknown"}`,
      severity: "high" as const,
      timestamp: leak.date || null,
    }));
  } catch {
    return [];
  }
}

async function searchGitHubLeaks(query: string): Promise<SearchResult[]> {
  try {
    // GitHub code search for leaked credentials/API keys
    // Using the public search without auth (rate limited to 10 req/min)
    const encoded = encodeURIComponent(query);
    const r = await fetch(`https://api.github.com/search/code?q=${encoded}&per_page=10`, {
      headers: {
        Accept: "application/vnd.github.v3+json",
        "User-Agent": "MONITOR-THREAT",
      },
      signal: AbortSignal.timeout(10000),
    });
    if (!r.ok) return [];
    const data: any = await r.json();
    const items = data.items || [];
    return items.slice(0, 10).map((item: any) => ({
      source: "GitHub",
      type: "code leak",
      title: item.name || item.path || "GitHub file",
      url: item.html_url || `https://github.com/${item.repository?.full_name}`,
      snippet: `Repo: ${item.repository?.full_name || "?"} | File: ${item.path || "?"}`,
      severity: "high" as const,
      timestamp: null,
    }));
  } catch {
    return [];
  }
}

async function searchPulsedive(query: string): Promise<SearchResult[]> {
  const PULSEDIVE_API_KEY = process.env.PULSEDIVE_API_KEY || "";
  if (!PULSEDIVE_API_KEY) return [];
  try {
    const r = await fetch(`https://pulsedive.com/api/explore.php?q=${encodeURIComponent(query)}&limit=10&pretty=1`, {
      headers: { "User-Agent": "MONITOR-THREAT" },
      signal: AbortSignal.timeout(10000),
    });
    if (!r.ok) return [];
    const data: any = await r.json();
    const results = data.results || (Array.isArray(data) ? data : []);
    return results.slice(0, 10).map((item: any) => ({
      source: "Pulsedive",
      type: "threat intel IOC",
      title: item.indicator || item.ioc || "IOC",
      url: `https://pulsedive.com/indicator/${encodeURIComponent(item.id || "")}`,
      snippet: `Risk: ${item.risk || "?"} | Threat: ${item.threat || "?"} | Feed: ${item.feed || "?"}`,
      severity: (item.risk === "high" || item.risk === "critical") ? "high" : "medium" as const,
      timestamp: item.lastseen || null,
    }));
  } catch {
    return [];
  }
}

async function searchPastebin(query: string): Promise<SearchResult[]> {
  try {
    // Search Pastebin recent pastes for the keyword
    // Using the public scraping API (limited but works)
    const r = await fetch(`https://pastebin.com/u/${encodeURIComponent(query)}`, {
      headers: { "User-Agent": "Mozilla/5.0" },
      signal: AbortSignal.timeout(8000),
    });
    if (!r.ok) return [];
    const html = await r.text();
    // Look for paste links in the HTML
    const pasteMatches = [...html.matchAll(/href="\/([A-Za-z0-9]{8})"/g)].slice(0, 10);
    return pasteMatches.map(m => ({
      source: "Pastebin",
      type: "paste mention",
      title: `Paste by ${query}`,
      url: `https://pastebin.com/${m[1]}`,
      snippet: `Paste ID: ${m[1]}`,
      severity: "medium" as const,
      timestamp: null,
    }));
  } catch {
    return [];
  }
}

export async function GET(request: Request) {
  const { searchParams } = new URL(request.url);
  const query = (searchParams.get("q") || "").trim();
  const type = (searchParams.get("type") || "keyword").trim();

  if (!query) {
    return NextResponse.json({ error: "missing_query" }, { status: 400 });
  }

  // Run all searches in parallel
  const [intelx, ahmia, leakcheck, github, pulsedive, pastebin] = await Promise.all([
    searchIntelligenceX(query, type),
    searchAhmia(query),
    searchLeakCheck(query, type),
    searchGitHubLeaks(query),
    searchPulsedive(query),
    searchPastebin(query),
  ]);

  const allResults = [...intelx, ...ahmia, ...leakcheck, ...github, ...pulsedive, ...pastebin];

  const bySource: Record<string, number> = {};
  const bySeverity = { high: 0, medium: 0, low: 0, info: 0 };
  for (const r of allResults) {
    bySource[r.source] = (bySource[r.source] || 0) + 1;
    bySeverity[r.severity]++;
  }

  const response: DarkWebResponse = {
    query,
    queryType: type,
    results: allResults,
    summary: {
      total: allResults.length,
      bySource,
      bySeverity,
    },
    timestamp: new Date().toISOString(),
  };

  return NextResponse.json(response, {
    headers: { "Cache-Control": "no-store" },
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
