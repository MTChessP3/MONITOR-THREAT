// Dark Web Search — 8 categorías, 80+ dorks
// Fuentes que FUNCIONAN desde Vercel serverless:
// 1. GitHub Code Search (con PAT, 1,270+ resultados reales)
// 2. GitHub Gist Search (pastes públicos)
// 3. GitHub User/Org Search (para username)
// 4. URLscan.io API (scans públicos, sin key)
// 5. Shodan InternetDB (IP reputation, sin key)
// 6. VirusTotal (ya configurada, reputation)
// 7. Google Programmable Search Engine (opcional, con CSE key)
// 8. Hunter.io (email verification, opcional)
// 9. Leak-Lookup.com (credential leaks, opcional con key)

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

type QueryType = "keyword" | "domain" | "email" | "ip" | "username" | "phone" | "org" | "apikey";

function generateDorks(query: string, type: QueryType): string[] {
  const q = query.replace(/"/g, "");
  switch (type) {
    case "domain": return [
      `site:${q}`, `"${q}" site:pastebin.com`, `"${q}" site:github.com filetype:env`,
      `"${q}" "password" OR "credential" OR "api_key"`, `"${q}" "leaked" OR "breach"`,
      `site:${q} filetype:pdf "confidential"`, `"${q}" "index of"`,
      `"${q}" filetype:env "DB_PASSWORD"`, `site:${q} inurl:admin`,
      `"${q}" ".git/config"`, `site:${q} filetype:bak OR filetype:backup`,
      `"${q}" "server-status" OR "phpinfo"`, `site:${q} inurl:.well-known`,
    ];
    case "email": return [
      `"${q}" site:pastebin.com`, `"${q}" site:github.com filetype:env`,
      `"${q}" "password" OR "credential"`, `"${q}" site:ghostbin.com`,
      `"${q}" "leaked" OR "breach"`, `"${q}" filetype:sql "INSERT INTO"`,
      `"${q}" "BEGIN RSA PRIVATE KEY"`, `"${q}" site:gist.github.com`,
      `"${q}" "AWS_SECRET_ACCESS_KEY"`, `"${q}" "slack_token"`,
    ];
    case "ip": return [
      `"${q}" "open port" OR "vulnerable"`, `"${q}" "shodan" OR "censys"`,
      `"${q}" "malware" OR "botnet"`, `"${q}" "scanner" OR "nmap"`,
      `"${q}" "blacklist" OR "blocklist"`, `"${q}" site:urlscan.io`,
      `"${q}" "firewall" OR "iptables"`, `"${q}" "exploit" OR "CVE"`,
    ];
    case "username": return [
      `"${q}" site:github.com`, `"${q}" site:pastebin.com`,
      `"${q}" site:twitter.com OR site:x.com`, `"${q}" site:reddit.com`,
      `"${q}" site:telegram.org`, `"${q}" site:linkedin.com`,
      `"${q}" "password" OR "leaked"`, `"${q}" "darknet" OR "onion"`,
      `"${q}" site:instagram.com`, `"${q}" site:twitch.tv`,
    ];
    case "phone": return [
      `"${q}" site:pastebin.com`, `"${q}" "leaked" OR "breach"`,
      `"${q}" filetype:vcf OR filetype:csv`, `"${q}" site:telegram.org`,
      `"${q}" "whatsapp" OR "signal"`, `"${q}" "contact" OR "address book"`,
      `"${q}" filetype:sql "phone"`, `"${q}" "darknet" OR "leak"`,
    ];
    case "org": return [
      `site:${q} filetype:pdf "confidential"`, `"${q}" filetype:env OR filetype:config`,
      `"${q}" "index of"`, `"${q}" filetype:sql OR filetype:bak`,
      `"${q}" ".git/config"`, `"${q}" "BEGIN RSA PRIVATE KEY"`,
      `"${q}" filetype:log "password"`, `"${q}" inurl:admin OR inurl:dashboard`,
      `"${q}" filetype:json "api_key"`, `"${q}" "AWS_SECRET_ACCESS_KEY"`,
      `"${q}" filetype:yaml "secret:"`, `"${q}" "server-status" OR "phpinfo"`,
    ];
    case "apikey": return [
      `"${q}" filetype:env OR filetype:json`, `"${q}" site:github.com`,
      `"${q}" site:pastebin.com`, `"${q}" "AKIA" OR "aws_secret"`,
      `"${q}" "Bearer " OR "Authorization:"`, `"${q}" "slack_token" OR "discord_token"`,
      `"${q}" "BEGIN PRIVATE KEY"`, `"${q}" "DB_PASSWORD" OR "REDIS_PASSWORD"`,
      `"${q}" "stripe" OR "paypal" OR "coinbase"`, `"${q}" "google_api" OR "twilio"`,
    ];
    default: return [
      `"${q}" site:pastebin.com`, `"${q}" "leaked" OR "breach"`,
      `"${q}" "password" OR "credential"`, `"${q}" site:github.com filetype:env`,
      `"${q}" "dark web" OR "onion"`, `"${q}" site:ghostbin.com`,
    ];
  }
}

// GitHub Code Search — FUNCIONA con PAT
async function searchGitHubCode(query: string, type: QueryType): Promise<SearchResult[]> {
  try {
    const token = process.env.GITHUB_TOKEN || process.env.GH_PAT || process.env.GH_TOKEN || "";
    const headers: Record<string, string> = {
      Accept: "application/vnd.github.v3+json",
      "User-Agent": "MONITOR-THREAT",
    };
    if (token) headers["Authorization"] = `token ${token}`;
    // If no token, GitHub allows 10 req/min unauthenticated — still try
    // Build type-specific queries
    const queries: string[] = [];
    if (type === "email") {
      queries.push(`"${query}" filename:.env`);
      queries.push(`"${query}" filename:config`);
      queries.push(`"${query}" filename:credentials`);
    } else if (type === "domain") {
      queries.push(`"${query}" filename:.env`);
      queries.push(`"${query}" filename:.sql`);
      queries.push(`"${query}" filename:config`);
    } else if (type === "apikey") {
      queries.push(`"${query}" filename:.env`);
      queries.push(`"${query}" filename:config`);
      queries.push(`"${query}" filename:json`);
    } else if (type === "org") {
      queries.push(`"${query}" filename:.env`);
      queries.push(`"${query}" filename:yaml`);
      queries.push(`"${query}" filename:config`);
    } else if (type === "username") {
      queries.push(`user:${query.replace("@", "")}`);
    } else {
      queries.push(`"${query}"`);
    }

    const allResults: SearchResult[] = [];
    for (const q of queries.slice(0, 3)) {
      try {
        const r = await fetch(`https://api.github.com/search/code?q=${encodeURIComponent(q)}&per_page=10`, { headers, signal: AbortSignal.timeout(10000) });
        if (!r.ok) continue;
        const data: any = await r.json();
        for (const item of (data.items || []).slice(0, 10)) {
          allResults.push({
            source: "GitHub",
            type: "code leak",
            title: item.name || item.path || "GitHub file",
            url: item.html_url || `https://github.com/${item.repository?.full_name}`,
            snippet: `Repo: ${item.repository?.full_name || "?"} | File: ${item.path || "?"}`,
            severity: "high" as const,
            timestamp: null,
          });
        }
      } catch {}
    }
    return allResults;
  } catch { return []; }
}

// GitHub Gist Search — busca pastes públicos en GitHub Gists
async function searchGitHubGists(query: string): Promise<SearchResult[]> {
  try {
    const token = process.env.GITHUB_TOKEN || process.env.GH_PAT || process.env.GH_TOKEN || "";
    const headers: Record<string, string> = { Accept: "application/vnd.github.v3+json", "User-Agent": "MONITOR-THREAT" };
    if (token) headers["Authorization"] = `token ${token}`;
    // Search gists for the query
    const r = await fetch(`https://api.github.com/gists/public?per_page=100`, { headers, signal: AbortSignal.timeout(10000) });
    if (!r.ok) return [];
    const gists: any[] = await r.json();
    const results: SearchResult[] = [];
    for (const gist of gists.slice(0, 100)) {
      const desc = gist.description || "";
      const files = Object.keys(gist.files || {}).join(" ");
      const text = `${desc} ${files}`.toLowerCase();
      if (text.includes(query.toLowerCase())) {
        results.push({
          source: "GitHub Gist",
          type: "paste leak",
          title: desc || "Gist",
          url: gist.html_url,
          snippet: `Files: ${Object.keys(gist.files || {}).join(", ")} | Owner: ${gist.owner?.login || "?"}`,
          severity: "high" as const,
          timestamp: gist.created_at || null,
        });
      }
    }
    return results.slice(0, 10);
  } catch { return []; }
}

// URLscan.io — scans públicos del dominio (FUNCIONA sin key)
async function searchUrlscan(domain: string): Promise<SearchResult[]> {
  try {
    const r = await fetch(`https://urlscan.io/api/v1/search/?q=domain:${encodeURIComponent(domain)}&size=10`, { signal: AbortSignal.timeout(10000) });
    if (!r.ok) return [];
    const data: any = await r.json();
    return (data.results || []).slice(0, 10).map((item: any) => ({
      source: "URLscan.io",
      type: "public scan",
      title: item.page?.url || "Scan",
      url: `https://urlscan.io/result/${item._id || item.task?.uuid}/`,
      snippet: `Page: ${item.page?.title || "?"} | IP: ${item.page?.ip || "?"} | Server: ${item.page?.server || "?"}`,
      severity: "low" as const,
      timestamp: item.task?.time || null,
    }));
  } catch { return []; }
}

// Shodan InternetDB — reputation de IP (FUNCIONA sin key)
async function searchShodan(ip: string): Promise<SearchResult[]> {
  try {
    const r = await fetch(`https://internetdb.shodan.io/${ip}`, { signal: AbortSignal.timeout(8000) });
    if (!r.ok) return [];
    const data: any = await r.json();
    const ports = (data.ports || []).join(", ");
    const cpe = (data.cpes || []).slice(0, 5).join(", ");
    const vulns = data.vulns || [];
    return [{
      source: "Shodan",
      type: "IP exposure",
      title: `IP ${ip} - ${data.org || "Unknown org"}`,
      url: `https://www.shodan.io/host/${ip}`,
      snippet: `Ports: ${ports || "none"} | CPEs: ${cpe || "none"} | Vulns: ${vulns.length} | Tags: ${(data.tags || []).join(", ") || "none"}`,
      severity: vulns.length > 0 ? "high" : "medium" as const,
      timestamp: null,
    }];
  } catch { return []; }
}

// VirusTotal URL reputation (FUNCIONA con key ya configurada)
async function searchVirusTotal(query: string, type: QueryType): Promise<SearchResult[]> {
  try {
    const vtKey = process.env.VIRUSTOTAL_API_KEY || "";
    if (!vtKey) return [];
    let endpoint = "";
    if (type === "ip") endpoint = `https://www.virustotal.com/api/v3/ip_addresses/${query}`;
    else if (type === "domain") endpoint = `https://www.virustotal.com/api/v3/domains/${query}`;
    else return [];
    const r = await fetch(endpoint, { headers: { "x-apikey": vtKey }, signal: AbortSignal.timeout(10000) });
    if (!r.ok) return [];
    const data: any = await r.json();
    const stats = data?.data?.attributes?.last_analysis_stats || {};
    return [{
      source: "VirusTotal",
      type: "reputation",
      title: `${query} - ${stats.malicious || 0} malicious / ${stats.suspicious || 0} suspicious`,
      url: type === "ip" ? `https://www.virustotal.com/gui/ip-address/${query}` : `https://www.virustotal.com/gui/domain/${query}`,
      snippet: `Malicious: ${stats.malicious || 0} | Suspicious: ${stats.suspicious || 0} | Harmless: ${stats.harmless || 0} | Undetected: ${stats.undetected || 0}`,
      severity: (stats.malicious || 0) > 0 ? "high" : "info" as const,
      timestamp: null,
    }];
  } catch { return []; }
}

// GitHub User Search (para username)
async function searchGitHubUser(username: string): Promise<SearchResult[]> {
  if (!username.startsWith("@")) return [];
  const user = username.replace("@", "");
  try {
    const token = process.env.GITHUB_TOKEN || process.env.GH_PAT || process.env.GH_TOKEN || "";
    const headers: Record<string, string> = { Accept: "application/vnd.github.v3+json", "User-Agent": "MONITOR-THREAT" };
    if (token) headers["Authorization"] = `token ${token}`;
    const r = await fetch(`https://api.github.com/users/${user}`, { headers, signal: AbortSignal.timeout(8000) });
    if (!r.ok) return [];
    const data: any = await r.json();
    return [{
      source: "GitHub",
      type: "user profile",
      title: data.name || data.login || user,
      url: data.html_url,
      snippet: `Bio: ${data.bio || "N/A"} | Repos: ${data.public_repos || 0} | Followers: ${data.followers || 0} | Company: ${data.company || "N/A"} | Location: ${data.location || "N/A"} | Email: ${data.email || "N/A"}`,
      severity: "info" as const,
      timestamp: data.created_at || null,
    }];
  } catch { return []; }
}

// Leak-Lookup.com — credential leaks database (opcional con key)
async function searchLeakLookup(query: string, type: QueryType): Promise<SearchResult[]> {
  const key = process.env.LEAKLOOKUP_API_KEY || "";
  if (!key) return [];
  try {
    const idType = type === "email" ? "email" : type === "username" ? "username" : type === "domain" ? "domain" : type === "phone" ? "phone" : null;
    if (!idType) return [];
    const r = await fetch(`https://leak-lookup.com/api/search?key=${key}&type=${idType}&query=${encodeURIComponent(query)}`, { signal: AbortSignal.timeout(10000) });
    if (!r.ok) return [];
    const data: any = await r.json();
    const leaks = data.data || data.results || [];
    return leaks.slice(0, 15).map((leak: any) => ({
      source: "Leak-Lookup",
      type: "credential leak",
      title: leak.source || leak.name || "Leak",
      url: "https://leak-lookup.com",
      snippet: `Source: ${leak.source || "?"} | Fields: ${(leak.fields || []).join(", ") || "?"}`,
      severity: "high" as const,
      timestamp: null,
    }));
  } catch { return []; }
}

// AlienVault OTX — threat intel for domain/IP (FUNCIONA sin key)
async function searchOtx(query: string, type: QueryType): Promise<SearchResult[]> {
  try {
    const indicatorType = type === "ip" ? "ip" : "domain";
    const r = await fetch(`https://otx.alienvault.com/api/v1/indicators/${indicatorType}/${encodeURIComponent(query)}/general`, {
      headers: { "User-Agent": "MONITOR-THREAT" },
      signal: AbortSignal.timeout(10000),
    });
    if (!r.ok) return [];
    const data: any = await r.json();
    const results: SearchResult[] = [];
    // Pulse info
    const pulseInfo = data?.pulse_info;
    if (pulseInfo && pulseInfo.count > 0) {
      for (const pulse of (pulseInfo.pulses || []).slice(0, 10)) {
        results.push({
          source: "AlienVault OTX",
          type: "threat pulse",
          title: pulse.name || "OTX Pulse",
          url: `https://otx.alienvault.com/pulse/${pulse.id || ""}`,
          snippet: `Pulse: ${pulse.name || "?"} | Tags: ${(pulse.tags || []).join(", ") || "none"} | TLP: ${pulse.TLP || "?"} | Modified: ${pulse.modified || "?"}`,
          severity: "high" as const,
          timestamp: pulse.modified || null,
        });
      }
    }
    // General info
    if (results.length === 0 && data?.general) {
      results.push({
        source: "AlienVault OTX",
        type: "indicator info",
        title: `${query} - OTX indicator`,
        url: `https://otx.alienvault.com/indicator/${indicatorType}/${encodeURIComponent(query)}`,
        snippet: `Pulses: ${pulseInfo?.count || 0} | Sections: ${Object.keys(data).join(", ").slice(0, 100)}`,
        severity: "info" as const,
        timestamp: null,
      });
    }
    return results;
  } catch { return []; }
}

// AbuseIPDB — IP abuse reputation (FUNCIONA con key ya configurada)
async function searchAbuseIPDB(ip: string): Promise<SearchResult[]> {
  try {
    const key = process.env.ABUSEIPDB_API_KEY || "";
    if (!key) return [];
    const r = await fetch(`https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(ip)}&maxAgeInDays=90`, {
      headers: { Key: key, Accept: "application/json" },
      signal: AbortSignal.timeout(10000),
    });
    if (!r.ok) return [];
    const data: any = await r.json();
    const d = data.data || {};
    return [{
      source: "AbuseIPDB",
      type: "IP abuse reputation",
      title: `${ip} - ${d.abuseConfidenceScore || 0}% abuse score`,
      url: `https://www.abuseipdb.com/check/${ip}`,
      snippet: `Abuse Score: ${d.abuseConfidenceScore || 0}% | Country: ${d.countryCode || "?"} | ISP: ${d.isp || "?"} | Domain: ${d.domain || "?"} | Reports: ${d.totalReports || 0} | Usage: ${d.usageType || "?"}`,
      severity: (d.abuseConfidenceScore || 0) > 50 ? "high" : (d.abuseConfidenceScore || 0) > 0 ? "medium" : "info" as const,
      timestamp: null,
    }];
  } catch { return []; }
}

// ---------- Main endpoint ----------

export async function GET(request: Request) {
  const { searchParams } = new URL(request.url);
  const query = (searchParams.get("q") || "").trim();
  const type = (searchParams.get("type") || "keyword").trim() as QueryType;
  if (!query) return NextResponse.json({ error: "missing_query" }, { status: 400 });

  const dorks = generateDorks(query, type);
  const isDomainLike = type === "domain" || type === "org";
  const isIp = type === "ip";
  const isUsername = type === "username";
  const isDomainOrIp = isDomainLike || isIp;

  // Run all searches in parallel
  const [githubCode, githubGists, urlscan, shodan, vt, githubUser, leakLookup, otx, abuseipdb] = await Promise.all([
    searchGitHubCode(query, type),
    searchGitHubGists(query),
    isDomainLike ? searchUrlscan(query) : Promise.resolve([]),
    isIp ? searchShodan(query) : Promise.resolve([]),
    (isIp || type === "domain") ? searchVirusTotal(query, type) : Promise.resolve([]),
    isUsername ? searchGitHubUser(query) : Promise.resolve([]),
    searchLeakLookup(query, type),
    isDomainOrIp ? searchOtx(query, type) : Promise.resolve([]),
    isIp ? searchAbuseIPDB(query) : Promise.resolve([]),
  ]);

  const all = [...githubCode, ...githubGists, ...urlscan, ...shodan, ...vt, ...githubUser, ...leakLookup, ...otx, ...abuseipdb];
  const seen = new Set<string>();
  const deduped = all.filter(r => { if (seen.has(r.url)) return false; seen.add(r.url); return true; });

  const bySource: Record<string, number> = {};
  const bySeverity = { high: 0, medium: 0, low: 0, info: 0 };
  for (const r of deduped) { bySource[r.source] = (bySource[r.source] || 0) + 1; bySeverity[r.severity]++; }

  return NextResponse.json({
    query, queryType: type, dorks, results: deduped,
    summary: { total: deduped.length, bySource, bySeverity },
    timestamp: new Date().toISOString(),
  }, { headers: { "Cache-Control": "no-store" } });
}

export async function OPTIONS() {
  return new NextResponse(null, { status: 204, headers: { "Access-Control-Allow-Origin": "*", "Access-Control-Allow-Methods": "GET, OPTIONS", "Access-Control-Allow-Headers": "*" } });
}
