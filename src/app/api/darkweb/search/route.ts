// Dark Web Search — busca menciones de un target en fuentes de la
// dark/deep web usando múltiples estrategias:
//
// 1. Google Dorks (via Google Custom Search API o scraping) — busca
//    exposed credentials, .env files, config leaks en sites específicos
// 2. Pastebin scraping (via Google site:pastebin.com)
// 3. GitHub Search (via GitHub API con token opcional)
// 4. Ahmia .onion search (via HTTP scraping, no API)
// 5. Censys/Shodan exposed services
// 6. URLscan.io public scans
// 7. crt.sh certificate transparency
// 8. Wayback Machine (web.archive.org)
//
// Las búsquedas usan DORKS pre-configurados según el tipo de target:
// - email: busca el email en pastes, leaks, .env files
// - domain: busca subdominios, credenciales, config expuesta
// - keyword: busca menciones generales
// - ip: busca exposición, servicios abiertos, reputation

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
  dorks: string[];
  results: SearchResult[];
  summary: {
    total: number;
    bySource: Record<string, number>;
    bySeverity: { high: number; medium: number; low: number; info: number };
  };
  timestamp: string;
}

// Generate Google dorks based on target type
function generateDorks(query: string, type: string): string[] {
  const dorks: string[] = [];
  if (type === "email") {
    dorks.push(`"${query}" site:pastebin.com`);
    dorks.push(`"${query}" site:github.com filetype:env OR filetype:txt OR filetype:json`);
    dorks.push(`"${query}" "password" OR "credential" OR "token" OR "api_key"`);
    dorks.push(`"${query}" site:ghostbin.com OR site:hastebin.com OR site:dpaste.com`);
    dorks.push(`"${query}" site:telegra.ph`);
  } else if (type === "domain") {
    dorks.push(`site:${query}`);
    dorks.push(`"${query}" site:pastebin.com`);
    dorks.push(`"${query}" filetype:env OR filetype:sql OR filetype:config`);
    dorks.push(`"${query}" "password" OR "credential" OR "api_key" OR "secret" site:github.com`);
    dorks.push(`"${query}" site:ghostbin.com OR site:hastebin.com`);
    dorks.push(`"${query}" "leaked" OR "breach" OR "dump"`);
    dorks.push(`site:${query} filetype:pdf "confidential" OR "internal"`);
    dorks.push(`"${query}" "index of" OR "directory listing"`);
  } else if (type === "ip") {
    dorks.push(`"${query}" "open port" OR "vulnerable" OR "exploit"`);
    dorks.push(`"${query}" "shodan" OR "censys"`);
    dorks.push(`"${query}" site:urlscan.io`);
  } else {
    // keyword
    dorks.push(`"${query}" site:pastebin.com`);
    dorks.push(`"${query}" "leaked" OR "breach" OR "dump" OR "hack"`);
    dorks.push(`"${query}" "password" OR "credential" OR "token"`);
    dorks.push(`"${query}" site:github.com filetype:env OR filetype:txt`);
    dorks.push(`"${query}" "dark web" OR "onion" OR "marketplace"`);
    dorks.push(`"${query}" site:ghostbin.com OR site:hastebin.com`);
  }
  return dorks;
}

// Search via Google Custom Search API (requires API key + CX)
async function searchGoogleCSE(dork: string): Promise<SearchResult[]> {
  const GOOGLE_API_KEY = process.env.GOOGLE_CSE_API_KEY || "";
  const GOOGLE_CX = process.env.GOOGLE_CSE_CX || "";
  if (!GOOGLE_API_KEY || !GOOGLE_CX) return [];
  try {
    const r = await fetch(`https://www.googleapis.com/customsearch/v1?key=${GOOGLE_API_KEY}&cx=${GOOGLE_CX}&q=${encodeURIComponent(dork)}&num=10`, {
      signal: AbortSignal.timeout(10000),
    });
    if (!r.ok) return [];
    const data: any = await r.json();
    return (data.items || []).map((item: any) => ({
      source: "Google Dork",
      type: "search result",
      title: item.title || "",
      url: item.link || "",
      snippet: (item.snippet || "").slice(0, 300),
      severity: "medium" as const,
      timestamp: null,
    }));
  } catch {
    return [];
  }
}

// Search via DuckDuckGo HTML (no API key needed, scraping)
async function searchDuckDuckGo(query: string): Promise<SearchResult[]> {
  try {
    const r = await fetch(`https://html.duckduckgo.com/html/?q=${encodeURIComponent(query)}`, {
      headers: { "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36" },
      signal: AbortSignal.timeout(10000),
    });
    if (!r.ok) return [];
    const html = await r.text();
    // Parse results from DDG HTML
    const results: SearchResult[] = [];
    const matches = [...html.matchAll(/<a rel="nofollow" class="result__a" href="([^"]+)">(.*?)<\/a>.*?<a class="result__snippet"[^>]*>(.*?)<\/a>/gs)];
    for (const m of matches.slice(0, 10)) {
      const url = m[1] || "";
      const title = m[2]?.replace(/<[^>]*>/g, "").trim() || "";
      const snippet = m[3]?.replace(/<[^>]*>/g, "").trim().slice(0, 300) || "";
      results.push({
        source: "DuckDuckGo",
        type: "search result",
        title,
        url,
        snippet,
        severity: "medium" as const,
        timestamp: null,
      });
    }
    return results;
  } catch {
    return [];
  }
}

// Search GitHub with optional token (higher rate limit with token)
async function searchGitHub(query: string, type: string): Promise<SearchResult[]> {
  try {
    const GITHUB_TOKEN = process.env.GITHUB_TOKEN || process.env.GH_PAT || "";
    const headers: Record<string, string> = {
      Accept: "application/vnd.github.v3+json",
      "User-Agent": "MONITOR-THREAT",
    };
    if (GITHUB_TOKEN) headers["Authorization"] = `token ${GITHUB_TOKEN}`;

    // Search code for the query
    const codeQuery = type === "email"
      ? `"${query}" filename:.env OR filename:.env.local OR filename:config OR filename:credentials`
      : type === "domain"
      ? `"${query}" filename:.env OR filename:.env.local OR filename:config OR filename:.sql OR filename:backup`
      : `"${query}"`;

    const r = await fetch(`https://api.github.com/search/code?q=${encodeURIComponent(codeQuery)}&per_page=10`, {
      headers,
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

// Search crt.sh (certificate transparency — finds subdomains)
async function searchCrtSh(domain: string): Promise<SearchResult[]> {
  try {
    const r = await fetch(`https://crt.sh/?q=${encodeURIComponent(domain)}&output=json`, {
      headers: { "User-Agent": "Mozilla/5.0" },
      signal: AbortSignal.timeout(10000),
    });
    if (!r.ok) return [];
    const data: any[] = await r.json();
    // Deduplicate by name
    const seen = new Set<string>();
    return data.slice(0, 20).filter((c: any) => {
      const name = c.name_value || c.common_name || "";
      if (seen.has(name)) return false;
      seen.add(name);
      return true;
    }).map((c: any) => ({
      source: "crt.sh",
      type: "certificate / subdomain",
      title: c.name_value || c.common_name || "Certificate",
      url: `https://crt.sh/?q=${encodeURIComponent(c.name_value || domain)}`,
      snippet: `Issuer: ${c.issuer_name || "?"} | Entry: ${c.entry_timestamp || "?"}`,
      severity: "info" as const,
      timestamp: c.entry_timestamp || null,
    }));
  } catch {
    return [];
  }
}

// Search Wayback Machine (web.archive.org)
async function searchWayback(url: string): Promise<SearchResult[]> {
  try {
    const r = await fetch(`https://web.archive.org/cdx/search/cdx?url=${encodeURIComponent(url)}/*&output=json&limit=10&collapse=urlkey`, {
      signal: AbortSignal.timeout(10000),
    });
    if (!r.ok) return [];
    const data: any[] = await r.json();
    if (data.length < 2) return []; // first row is headers
    return data.slice(1, 11).map((row: any) => ({
      source: "Wayback Machine",
      type: "archived snapshot",
      title: row[2] || url,
      url: `https://web.archive.org/web/${row[1]}/${row[2]}`,
      snippet: `Snapshot: ${row[1]} | Status: ${row[4] || "?"} | MIME: ${row[3] || "?"}`,
      severity: "low" as const,
      timestamp: row[1] || null,
    }));
  } catch {
    return [];
  }
}

// Search URLscan.io (public scans of the domain)
async function searchUrlscan(domain: string): Promise<SearchResult[]> {
  try {
    const r = await fetch(`https://urlscan.io/api/v1/search/?q=domain:${encodeURIComponent(domain)}&size=10`, {
      signal: AbortSignal.timeout(10000),
    });
    if (!r.ok) return [];
    const data: any = await r.json();
    const results = data.results || [];
    return results.slice(0, 10).map((item: any) => ({
      source: "URLscan.io",
      type: "public scan",
      title: item.page?.url || item.task?.url || "Scan",
      url: `https://urlscan.io/result/${item._id || item.task?.uuid}/`,
      snippet: `Page: ${item.page?.title || "?"} | IP: ${item.page?.ip || "?"} | Score: ${item.lists?.urls?.length || 0} URLs`,
      severity: "low" as const,
      timestamp: item.task?.time || null,
    }));
  } catch {
    return [];
  }
}

// Search Ahmia via HTML scraping (the API changed, use the HTML search)
async function searchAhmiaHtml(query: string): Promise<SearchResult[]> {
  try {
    const r = await fetch(`https://ahmia.fi/search/?q=${encodeURIComponent(query)}`, {
      headers: { "User-Agent": "Mozilla/5.0" },
      signal: AbortSignal.timeout(10000),
    });
    if (!r.ok) return [];
    const html = await r.text();
    const results: SearchResult[] = [];
    // Parse onion links from the HTML results
    const matches = [...html.matchAll(/<li[^>]*>.*?<h4[^>]*>(.*?)<\/h4>.*?<a[^>]*href="([^"]*\.onion[^"]*)"[^>]*>(.*?)<\/a>.*?<p[^>]*>(.*?)<\/p>/gs)];
    for (const m of matches.slice(0, 10)) {
      results.push({
        source: "Ahmia (.onion)",
        type: "dark web mention",
        title: (m[1] || m[5] || "Onion site").replace(/<[^>]*>/g, "").trim(),
        url: m[2] || "",
        snippet: (m[4] || "").replace(/<[^>]*>/g, "").trim().slice(0, 300),
        severity: "medium" as const,
        timestamp: null,
      });
    }
    // Fallback: just extract any .onion links
    if (results.length === 0) {
      const onionMatches = [...html.matchAll(/https?:\/\/[a-z0-9]{16,56}\.onion/g)];
      for (const m of onionMatches.slice(0, 10)) {
        results.push({
          source: "Ahmia (.onion)",
          type: "dark web mention",
          title: m[0],
          url: m[0],
          snippet: "Onion site found via Ahmia search",
          severity: "medium" as const,
          timestamp: null,
        });
      }
    }
    return results;
  } catch {
    return [];
  }
}

// Search Pastebin via Google site: search (DDG fallback)
async function searchPastebinViaDDG(query: string): Promise<SearchResult[]> {
  try {
    const dork = `site:pastebin.com "${query}"`;
    const r = await fetch(`https://html.duckduckgo.com/html/?q=${encodeURIComponent(dork)}`, {
      headers: { "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36" },
      signal: AbortSignal.timeout(10000),
    });
    if (!r.ok) return [];
    const html = await r.text();
    const results: SearchResult[] = [];
    const matches = [...html.matchAll(/<a rel="nofollow" class="result__a" href="([^"]*pastebin\.com[^"]*)">(.*?)<\/a>.*?<a class="result__snippet"[^>]*>(.*?)<\/a>/gs)];
    for (const m of matches.slice(0, 10)) {
      results.push({
        source: "Pastebin (via DDG)",
        type: "paste mention",
        title: m[2]?.replace(/<[^>]*>/g, "").trim() || "Paste",
        url: m[1] || "",
        snippet: m[3]?.replace(/<[^>]*>/g, "").trim().slice(0, 300) || "",
        severity: "high" as const,
        timestamp: null,
      });
    }
    return results;
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

  const dorks = generateDorks(query, type);

  // Build the full list of search queries to run
  const ddgQueries = type === "domain"
    ? [dorks[0], dorks[1], dorks[5], `"${query}" "leaked" OR "breach"`]
    : type === "email"
    ? [dorks[0], dorks[2], `"${query}" "password" OR "credential"`]
    : [dorks[0], dorks[1], `"${query}" "leaked" OR "breach" OR "hack"`];

  // Run all searches in parallel
  const [ddg1, ddg2, ddg3, github, crtsh, wayback, urlscan, ahmia, pastebinDDG] = await Promise.all([
    searchDuckDuckGo(ddgQueries[0] || query),
    searchDuckDuckGo(ddgQueries[1] || query),
    ddgQueries[2] ? searchDuckDuckGo(ddgQueries[2]) : Promise.resolve([]),
    searchGitHub(query, type),
    type === "domain" ? searchCrtSh(query) : Promise.resolve([]),
    type === "domain" || type === "ip" ? searchWayback(query) : Promise.resolve([]),
    type === "domain" ? searchUrlscan(query) : Promise.resolve([]),
    searchAhmiaHtml(query),
    searchPastebinViaDDG(query),
  ]);

  // Combine all results, deduplicate by URL
  const allResults = [...ddg1, ...ddg2, ...ddg3, ...github, ...crtsh, ...wayback, ...urlscan, ...ahmia, ...pastebinDDG];
  const seenUrls = new Set<string>();
  const deduped = allResults.filter(r => {
    if (seenUrls.has(r.url)) return false;
    seenUrls.add(r.url);
    return true;
  });

  const bySource: Record<string, number> = {};
  const bySeverity = { high: 0, medium: 0, low: 0, info: 0 };
  for (const r of deduped) {
    bySource[r.source] = (bySource[r.source] || 0) + 1;
    bySeverity[r.severity]++;
  }

  const response: DarkWebResponse = {
    query,
    queryType: type,
    dorks,
    results: deduped,
    summary: {
      total: deduped.length,
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
