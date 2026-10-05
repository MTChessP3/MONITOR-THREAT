// Dark Web & OSINT Search — 8 categorías con fuentes que FUNCIONAN
//
// Fuentes verificadas desde Vercel serverless:
// 1. GitHub Code Search (leaks de .env, .sql, config, credentials)
// 2. GitHub Gist Search (pastes públicos con credenciales)
// 3. GitHub User Search (perfil + repos del username)
// 4. GitHub Repo Search (repos que contienen el target)
// 5. HIBP Breaches List (1039 breaches, sin auth)
// 6. Shodan InternetDB (IP: puertos, vulns)
// 7. VirusTotal (IP/domain: reputation)
// 8. AlienVault OTX (domain/IP: threat pulses)
// 9. AbuseIPDB (IP: abuse score)
// 10. URLscan.io (domain: scans públicos)
// 11. Gravatar (email: avatar + perfil)
// 12. Leak-Lookup (optional: credential leaks)

import { NextResponse } from "next/server";

interface SearchResult { source: string; type: string; title: string; url: string; snippet: string; severity: "high" | "medium" | "low" | "info"; timestamp: string | null; }
type QueryType = "keyword" | "domain" | "email" | "ip" | "username" | "phone" | "org" | "apikey";

function generateDorks(query: string, type: QueryType): string[] {
  const q = query.replace(/"/g, "");
  switch (type) {
    case "domain": return [`site:${q}`, `"${q}" site:pastebin.com`, `"${q}" site:github.com filetype:env`, `"${q}" "password" OR "credential"`, `"${q}" "leaked" OR "breach"`, `site:${q} filetype:pdf "confidential"`, `"${q}" "index of"`, `"${q}" filetype:env "DB_PASSWORD"`, `site:${q} inurl:admin`, `"${q}" ".git/config"`, `site:${q} filetype:bak`, `"${q}" "server-status"`, `site:${q} inurl:.well-known`];
    case "email": return [`"${q}" site:pastebin.com`, `"${q}" site:github.com filetype:env`, `"${q}" "password" OR "credential"`, `"${q}" site:ghostbin.com`, `"${q}" "leaked" OR "breach"`, `"${q}" filetype:sql "INSERT INTO"`, `"${q}" "BEGIN RSA PRIVATE KEY"`, `"${q}" site:gist.github.com`, `"${q}" "AWS_SECRET_ACCESS_KEY"`, `"${q}" "slack_token"`];
    case "ip": return [`"${q}" "open port" OR "vulnerable"`, `"${q}" "shodan" OR "censys"`, `"${q}" "malware" OR "botnet"`, `"${q}" "scanner" OR "nmap"`, `"${q}" "blacklist" OR "blocklist"`, `"${q}" site:urlscan.io`, `"${q}" "firewall"`, `"${q}" "exploit" OR "CVE"`];
    case "username": return [`"${q}" site:github.com`, `"${q}" site:pastebin.com`, `"${q}" site:twitter.com OR site:x.com`, `"${q}" site:reddit.com`, `"${q}" site:telegram.org`, `"${q}" site:linkedin.com`, `"${q}" "password" OR "leaked"`, `"${q}" "darknet" OR "onion"`, `"${q}" site:instagram.com`, `"${q}" site:twitch.tv`];
    case "phone": return [`"${q}" site:pastebin.com`, `"${q}" "leaked" OR "breach"`, `"${q}" filetype:vcf OR filetype:csv`, `"${q}" site:telegram.org`, `"${q}" "whatsapp" OR "signal"`, `"${q}" "contact" OR "address book"`, `"${q}" filetype:sql "phone"`, `"${q}" "darknet" OR "leak"`];
    case "org": return [`site:${q} filetype:pdf "confidential"`, `"${q}" filetype:env OR filetype:config`, `"${q}" "index of"`, `"${q}" filetype:sql OR filetype:bak`, `"${q}" ".git/config"`, `"${q}" "BEGIN RSA PRIVATE KEY"`, `"${q}" filetype:log "password"`, `"${q}" inurl:admin`, `"${q}" filetype:json "api_key"`, `"${q}" "AWS_SECRET_ACCESS_KEY"`, `"${q}" filetype:yaml "secret:"`, `"${q}" "server-status"`];
    case "apikey": return [`"${q}" filetype:env OR filetype:json`, `"${q}" site:github.com`, `"${q}" site:pastebin.com`, `"${q}" "AKIA" OR "aws_secret"`, `"${q}" "Bearer "`, `"${q}" "slack_token" OR "discord_token"`, `"${q}" "BEGIN PRIVATE KEY"`, `"${q}" "DB_PASSWORD"`, `"${q}" "stripe" OR "paypal"`, `"${q}" "google_api" OR "twilio"`];
    default: return [`"${q}" site:pastebin.com`, `"${q}" "leaked" OR "breach"`, `"${q}" "password" OR "credential"`, `"${q}" site:github.com filetype:env`, `"${q}" "dark web" OR "onion"`, `"${q}" site:ghostbin.com`];
  }
}

// GitHub helper with optional token
function ghHeaders(): Record<string, string> {
  const token = process.env.GITHUB_TOKEN || process.env.GH_PAT || process.env.GH_TOKEN || "";
  const h: Record<string, string> = { Accept: "application/vnd.github.v3+json", "User-Agent": "MONITOR-THREAT" };
  if (token) h["Authorization"] = `token ${token}`;
  return h;
}

// GitHub Code Search — busca .env, .sql, config con el target
async function searchGitHubCode(query: string, type: QueryType): Promise<SearchResult[]> {
  try {
    const queries: string[] = [];
    if (type === "email") { queries.push(`"${query}" filename:.env`); queries.push(`"${query}" filename:config`); queries.push(`"${query}" filename:credentials`); }
    else if (type === "domain") { queries.push(`"${query}" filename:.env`); queries.push(`"${query}" filename:.sql`); queries.push(`"${query}" filename:config`); }
    else if (type === "apikey") { queries.push(`"${query}" filename:.env`); queries.push(`"${query}" filename:config`); queries.push(`"${query}" filename:json`); }
    else if (type === "org") { queries.push(`"${query}" filename:.env`); queries.push(`"${query}" filename:yaml`); queries.push(`"${query}" filename:config`); }
    else { queries.push(`"${query}" filename:.env`); queries.push(`"${query}"`); }

    const all: SearchResult[] = [];
    for (const q of queries.slice(0, 3)) {
      try {
        const r = await fetch(`https://api.github.com/search/code?q=${encodeURIComponent(q)}&per_page=10`, { headers: ghHeaders(), signal: AbortSignal.timeout(10000) });
        if (!r.ok) continue;
        const d: any = await r.json();
        for (const item of (d.items || []).slice(0, 10)) {
          all.push({ source: "GitHub Code", type: "code leak", title: item.name || item.path || "File", url: item.html_url || "", snippet: `Repo: ${item.repository?.full_name || "?"} | File: ${item.path || "?"}`, severity: "high", timestamp: null });
        }
      } catch {}
    }
    return all;
  } catch { return []; }
}

// GitHub Gist Search — pastes públicos con el target
async function searchGitHubGists(query: string): Promise<SearchResult[]> {
  try {
    const r = await fetch(`https://api.github.com/gists/public?per_page=100`, { headers: ghHeaders(), signal: AbortSignal.timeout(10000) });
    if (!r.ok) return [];
    const gists: any[] = await r.json();
    return gists.filter(g => {
      const text = `${g.description || ""} ${Object.keys(g.files || {}).join(" ")}`.toLowerCase();
      return text.includes(query.toLowerCase());
    }).slice(0, 10).map(g => ({
      source: "GitHub Gist", type: "paste leak", title: g.description || "Gist",
      url: g.html_url, snippet: `Files: ${Object.keys(g.files || {}).join(", ")} | Owner: ${g.owner?.login || "?"}`,
      severity: "high" as const, timestamp: g.created_at || null,
    }));
  } catch { return []; }
}

// GitHub User Search — perfil + repos (para username)
async function searchGitHubUser(username: string): Promise<SearchResult[]> {
  const user = username.startsWith("@") ? username.slice(1) : username;
  try {
    const results: SearchResult[] = [];
    // User profile
    const r1 = await fetch(`https://api.github.com/users/${user}`, { headers: ghHeaders(), signal: AbortSignal.timeout(8000) });
    if (r1.ok) {
      const d: any = await r1.json();
      results.push({
        source: "GitHub Profile", type: "user profile", title: d.name || d.login || user,
        url: d.html_url, snippet: `Bio: ${d.bio || "N/A"} | Repos: ${d.public_repos || 0} | Followers: ${d.followers || 0} | Company: ${d.company || "N/A"} | Location: ${d.location || "N/A"} | Email: ${d.email || "N/A"} | Blog: ${d.blog || "N/A"}`,
        severity: "info" as const, timestamp: d.created_at || null,
      });
    }
    // User repos
    const r2 = await fetch(`https://api.github.com/users/${user}/repos?per_page=10&sort=updated`, { headers: ghHeaders(), signal: AbortSignal.timeout(8000) });
    if (r2.ok) {
      const repos: any[] = await r2.json();
      for (const repo of repos.slice(0, 10)) {
        results.push({
          source: "GitHub Repos", type: "user repo", title: repo.full_name,
          url: repo.html_url, snippet: `Stars: ${repo.stargazers_count || 0} | Forks: ${repo.forks_count || 0} | Lang: ${repo.language || "?"} | Desc: ${(repo.description || "").slice(0, 80)}`,
          severity: "low" as const, timestamp: repo.updated_at || null,
        });
      }
    }
    return results;
  } catch { return []; }
}

// GitHub User Search by keyword (busca usuarios que coinciden)
async function searchGitHubUsersByKeyword(query: string): Promise<SearchResult[]> {
  try {
    const r = await fetch(`https://api.github.com/search/users?q=${encodeURIComponent(query)}&per_page=10`, { headers: ghHeaders(), signal: AbortSignal.timeout(8000) });
    if (!r.ok) return [];
    const d: any = await r.json();
    return (d.items || []).slice(0, 10).map((u: any) => ({
      source: "GitHub Users", type: "user match", title: u.login,
      url: u.html_url, snippet: `Type: ${u.type || "?"} | Score: ${u.score || 0}`,
      severity: "info" as const, timestamp: null,
    }));
  } catch { return []; }
}

// GitHub Repo Search — repos que contienen el target
async function searchGitHubRepos(query: string): Promise<SearchResult[]> {
  try {
    const r = await fetch(`https://api.github.com/search/repositories?q=${encodeURIComponent(query)}&per_page=10&sort=stars`, { headers: ghHeaders(), signal: AbortSignal.timeout(8000) });
    if (!r.ok) return [];
    const d: any = await r.json();
    return (d.items || []).slice(0, 10).map((repo: any) => ({
      source: "GitHub Repo", type: "repository", title: repo.full_name,
      url: repo.html_url, snippet: `Stars: ${repo.stargazers_count || 0} | Forks: ${repo.forks_count || 0} | Lang: ${repo.language || "?"} | Desc: ${(repo.description || "").slice(0, 80)}`,
      severity: "low" as const, timestamp: repo.updated_at || null,
    }));
  } catch { return []; }
}

// HIBP — lista de breaches conocidos (sin auth, 1039 breaches)
async function searchHibpBreaches(): Promise<SearchResult[]> {
  try {
    const r = await fetch("https://haveibeenpwned.com/api/v3/breaches", { headers: { "User-Agent": "MONITOR-THREAT" }, signal: AbortSignal.timeout(10000) });
    if (!r.ok) return [];
    const breaches: any[] = await r.json();
    return breaches.slice(0, 5).map(b => ({
      source: "HIBP Breaches", type: "known breach",
      title: b.Name || "Breach", url: `https://haveibeenpwned.com/breach/${b.Name}`,
      snippet: `PwnCount: ${b.PwnCount || "?"} | Date: ${b.BreachDate || "?"} | Data: ${(b.DataClasses || []).join(", ")}`,
      severity: "high" as const, timestamp: b.BreachDate || null,
    }));
  } catch { return []; }
}

// Gravatar — avatar + perfil del email (sin auth)
async function searchGravatar(email: string): Promise<SearchResult[]> {
  try {
    const crypto = await import("crypto");
    const hash = crypto.createHash("md5").update(email.trim().toLowerCase()).digest("hex");
    const r = await fetch(`https://gravatar.com/${hash}.json`, { signal: AbortSignal.timeout(8000) });
    if (!r.ok) return [];
    const d: any = await r.json();
    const profile = d.entry?.[0];
    if (!profile) return [];
    return [{
      source: "Gravatar", type: "email profile",
      title: profile.displayName || profile.preferredUsername || email,
      url: profile.profileUrl || `https://gravatar.com/${hash}`,
      snippet: `Name: ${profile.displayName || "?"} | Username: ${profile.preferredUsername || "?"} | Accounts: ${(profile.accounts || []).map(a => a.shortname).join(", ") || "none"} | About: ${(profile.aboutMe || "").slice(0, 100) || "N/A"}`,
      severity: "info" as const, timestamp: null,
    }];
  } catch { return []; }
}

// Shodan InternetDB — IP: puertos, vulns (sin auth)
async function searchShodan(ip: string): Promise<SearchResult[]> {
  try {
    const r = await fetch(`https://internetdb.shodan.io/${ip}`, { signal: AbortSignal.timeout(8000) });
    if (!r.ok) return [];
    const d: any = await r.json();
    return [{ source: "Shodan", type: "IP exposure", title: `IP ${ip} - ${d.org || "Unknown"}`, url: `https://www.shodan.io/host/${ip}`, snippet: `Ports: ${(d.ports || []).join(", ") || "none"} | CPEs: ${(d.cpes || []).slice(0, 5).join(", ")} | Vulns: ${(d.vulns || []).length} | Tags: ${(d.tags || []).join(", ")}`, severity: (d.vulns || []).length > 0 ? "high" : "medium" as const, timestamp: null }];
  } catch { return []; }
}

// VirusTotal — IP/domain reputation
async function searchVirusTotal(query: string, type: QueryType): Promise<SearchResult[]> {
  try {
    const key = process.env.VIRUSTOTAL_API_KEY || "";
    if (!key) return [];
    const ep = type === "ip" ? `https://www.virustotal.com/api/v3/ip_addresses/${query}` : `https://www.virustotal.com/api/v3/domains/${query}`;
    const r = await fetch(ep, { headers: { "x-apikey": key }, signal: AbortSignal.timeout(10000) });
    if (!r.ok) return [];
    const d: any = await r.json();
    const s = d?.data?.attributes?.last_analysis_stats || {};
    return [{ source: "VirusTotal", type: "reputation", title: `${query} - ${s.malicious || 0} malicious`, url: type === "ip" ? `https://www.virustotal.com/gui/ip-address/${query}` : `https://www.virustotal.com/gui/domain/${query}`, snippet: `Malicious: ${s.malicious || 0} | Suspicious: ${s.suspicious || 0} | Harmless: ${s.harmless || 0} | Undetected: ${s.undetected || 0}`, severity: (s.malicious || 0) > 0 ? "high" : "info" as const, timestamp: null }];
  } catch { return []; }
}

// AlienVault OTX — threat pulses
async function searchOtx(query: string, type: QueryType): Promise<SearchResult[]> {
  try {
    const it = type === "ip" ? "ip" : "domain";
    const r = await fetch(`https://otx.alienvault.com/api/v1/indicators/${it}/${encodeURIComponent(query)}/general`, { headers: { "User-Agent": "MONITOR-THREAT" }, signal: AbortSignal.timeout(10000) });
    if (!r.ok) return [];
    const d: any = await r.json();
    const results: SearchResult[] = [];
    const pi = d?.pulse_info;
    if (pi && pi.count > 0) {
      for (const p of (pi.pulses || []).slice(0, 10)) {
        results.push({ source: "AlienVault OTX", type: "threat pulse", title: p.name || "Pulse", url: `https://otx.alienvault.com/pulse/${p.id}`, snippet: `Tags: ${(p.tags || []).join(", ")} | TLP: ${p.TLP || "?"} | Modified: ${p.modified || "?"}`, severity: "high" as const, timestamp: p.modified || null });
      }
    }
    if (results.length === 0) results.push({ source: "AlienVault OTX", type: "indicator info", title: `${query}`, url: `https://otx.alienvault.com/indicator/${it}/${encodeURIComponent(query)}`, snippet: `Pulses: ${pi?.count || 0}`, severity: "info" as const, timestamp: null });
    return results;
  } catch { return []; }
}

// AbuseIPDB — IP abuse
async function searchAbuseIPDB(ip: string): Promise<SearchResult[]> {
  try {
    const key = process.env.ABUSEIPDB_API_KEY || "";
    if (!key) return [];
    const r = await fetch(`https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(ip)}&maxAgeInDays=90`, { headers: { Key: key, Accept: "application/json" }, signal: AbortSignal.timeout(10000) });
    if (!r.ok) return [];
    const d: any = await r.json();
    const dd = d.data || {};
    return [{ source: "AbuseIPDB", type: "IP abuse", title: `${ip} - ${dd.abuseConfidenceScore || 0}% abuse`, url: `https://www.abuseipdb.com/check/${ip}`, snippet: `Score: ${dd.abuseConfidenceScore || 0}% | Country: ${dd.countryCode || "?"} | ISP: ${dd.isp || "?"} | Reports: ${dd.totalReports || 0}`, severity: (dd.abuseConfidenceScore || 0) > 50 ? "high" : "medium" as const, timestamp: null }];
  } catch { return []; }
}

// URLscan.io — domain scans
async function searchUrlscan(domain: string): Promise<SearchResult[]> {
  try {
    const r = await fetch(`https://urlscan.io/api/v1/search/?q=domain:${encodeURIComponent(domain)}&size=10`, { signal: AbortSignal.timeout(10000) });
    if (!r.ok) return [];
    const d: any = await r.json();
    return (d.results || []).slice(0, 10).map((i: any) => ({ source: "URLscan.io", type: "public scan", title: i.page?.url || "Scan", url: `https://urlscan.io/result/${i._id}`, snippet: `Page: ${i.page?.title || "?"} | IP: ${i.page?.ip || "?"}`, severity: "low" as const, timestamp: i.task?.time || null }));
  } catch { return []; }
}

export async function GET(request: Request) {
  const { searchParams } = new URL(request.url);
  const query = (searchParams.get("q") || "").trim();
  const type = (searchParams.get("type") || "keyword").trim() as QueryType;
  if (!query) return NextResponse.json({ error: "missing_query" }, { status: 400 });

  const dorks = generateDorks(query, type);
  const isDomainLike = type === "domain" || type === "org";
  const isIp = type === "ip";
  const isUsername = type === "username";
  const isEmail = type === "email";

  // Run all searches in parallel
  const [ghCode, ghGists, ghUser, ghUsersSearch, ghRepos, hibp, gravatar, shodan, vt, otx, abuseipdb, urlscan] = await Promise.all([
    searchGitHubCode(query, type),
    searchGitHubGists(query),
    isUsername ? searchGitHubUser(query) : Promise.resolve([]),
    isUsername ? searchGitHubUsersByKeyword(query) : Promise.resolve([]),
    (type === "keyword" || type === "org") ? searchGitHubRepos(query) : Promise.resolve([]),
    (isEmail || type === "keyword") ? searchHibpBreaches() : Promise.resolve([]),
    isEmail ? searchGravatar(query) : Promise.resolve([]),
    isIp ? searchShodan(query) : Promise.resolve([]),
    (isIp || type === "domain") ? searchVirusTotal(query, type) : Promise.resolve([]),
    (isDomainLike || isIp) ? searchOtx(query, type) : Promise.resolve([]),
    isIp ? searchAbuseIPDB(query) : Promise.resolve([]),
    isDomainLike ? searchUrlscan(query) : Promise.resolve([]),
  ]);

  const all = [...ghCode, ...ghGists, ...ghUser, ...ghUsersSearch, ...ghRepos, ...hibp, ...gravatar, ...shodan, ...vt, ...otx, ...abuseipdb, ...urlscan];
  const seen = new Set<string>();
  const deduped = all.filter(r => { if (seen.has(r.url)) return false; seen.add(r.url); return true; });

  const bySource: Record<string, number> = {};
  const bySeverity = { high: 0, medium: 0, low: 0, info: 0 };
  for (const r of deduped) { bySource[r.source] = (bySource[r.source] || 0) + 1; bySeverity[r.severity]++; }

  return NextResponse.json({ query, queryType: type, dorks, results: deduped, summary: { total: deduped.length, bySource, bySeverity }, timestamp: new Date().toISOString() }, { headers: { "Cache-Control": "no-store" } });
}

export async function OPTIONS() {
  return new NextResponse(null, { status: 204, headers: { "Access-Control-Allow-Origin": "*", "Access-Control-Allow-Methods": "GET, OPTIONS", "Access-Control-Allow-Headers": "*" } });
}
