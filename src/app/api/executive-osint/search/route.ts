// Executive OSINT Search — 4 tipos: nombre, email, telefono, alias
// 8 fuentes verificadas + 55 dorks generados

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

type QueryType = "name" | "email" | "phone" | "username";

function ghHeaders(): Record<string, string> {
  const token = process.env.GITHUB_TOKEN || process.env.GH_PAT || process.env.GH_TOKEN || "";
  const h: Record<string, string> = { Accept: "application/vnd.github.v3+json", "User-Agent": "MONITOR-THREAT" };
  if (token) h["Authorization"] = `token ${token}`;
  return h;
}

// ---- DORKS: 55 dorks en 4 categorias ----
function generateDorks(query: string, type: QueryType): string[] {
  const q = query.replace(/"/g, "");
  switch (type) {
    case "name":
      return [
        `"${q}" site:linkedin.com/in`,
        `"${q}" site:twitter.com OR site:x.com`,
        `"${q}" site:facebook.com`,
        `"${q}" site:instagram.com`,
        `"${q}" site:reddit.com`,
        `"${q}" site:youtube.com`,
        `"${q}" site:tiktok.com`,
        `"${q}" filetype:pdf`,
        `"${q}" "curriculum" OR "cv" OR "resume"`,
        `"${q}" "director" OR "gerente" OR "CEO" OR "CTO" OR "CFO"`,
        `"${q}" "empresa" OR "company"`,
        `"${q}" site:bloomberg.com OR site:reuters.com`,
        `"${q}" "entrevista" OR "conference" OR "presentation"`,
        `"${q}" filetype:doc OR filetype:docx`,
        `"${q}" "contact" OR "email" OR "phone" OR "telefono"`,
      ];
    case "email":
      return [
        `"${q}" site:pastebin.com`,
        `"${q}" site:github.com filetype:env OR filetype:txt`,
        `"${q}" "password" OR "credential" OR "token"`,
        `"${q}" filetype:sql "INSERT INTO"`,
        `"${q}" site:ghostbin.com OR site:hastebin.com`,
        `"${q}" "leaked" OR "breach" OR "dump"`,
        `"${q}" site:linkedin.com`,
        `"${q}" site:twitter.com OR site:x.com`,
        `"${q}" "BEGIN RSA PRIVATE KEY"`,
        `"${q}" site:gist.github.com`,
        `"${q}" "AWS_SECRET_ACCESS_KEY" OR "api_key"`,
        `"${q}" filetype:vcf OR filetype:csv`,
        `"${q}" site:docs.google.com OR site:drive.google.com`,
        `"${q}" "slack_token" OR "discord_token"`,
        `"${q}" site:telegram.org OR site:t.me`,
      ];
    case "phone":
      return [
        `"${q}" site:pastebin.com`,
        `"${q}" "leaked" OR "breach" OR "dump"`,
        `"${q}" filetype:vcf OR filetype:csv OR filetype:txt`,
        `"${q}" site:telegram.org OR site:t.me`,
        `"${q}" "whatsapp" OR "signal" OR "viber"`,
        `"${q}" "contact" OR "address book" OR "phonebook"`,
        `"${q}" filetype:sql "phone" OR "mobile" OR "cell"`,
        `"${q}" site:truecaller.com OR site:sync.me`,
        `"${q}" "darknet" OR "leak" OR "sell"`,
        `"${q}" "registro" OR "database" OR "base de datos"`,
      ];
    case "username":
      return [
        `"${q}" site:github.com OR site:gitlab.com`,
        `"${q}" site:twitter.com OR site:x.com`,
        `"${q}" site:instagram.com`,
        `"${q}" site:facebook.com`,
        `"${q}" site:reddit.com OR site:medium.com`,
        `"${q}" site:linkedin.com`,
        `"${q}" site:tiktok.com`,
        `"${q}" site:youtube.com`,
        `"${q}" site:twitch.tv OR site:steamcommunity.com`,
        `"${q}" site:telegram.org OR site:t.me`,
        `"${q}" site:pinterest.com OR site:tumblr.com`,
        `"${q}" "password" OR "credential" OR "leaked"`,
        `"${q}" site:medium.com OR site:dev.to OR site:hashnode.com`,
        `"${q}" "profile" OR "about" OR "bio"`,
        `"${q}" "darknet" OR "onion" OR "marketplace"`,
      ];
  }
}

// ---- Fuentes ----

// GitHub User Search (para name y username)
async function searchGitHubUsers(query: string): Promise<SearchResult[]> {
  try {
    const r = await fetch(`https://api.github.com/search/users?q=${encodeURIComponent(query)}&per_page=20`, { headers: ghHeaders(), signal: AbortSignal.timeout(10000) });
    if (!r.ok) return [];
    const d: any = await r.json();
    return (d.items || []).slice(0, 20).map((u: any) => ({
      source: "GitHub User", type: "user match", title: u.login,
      url: u.html_url, snippet: `Type: ${u.type || "?"} | Avatar: ${u.avatar_url || "?"}`,
      severity: "info" as const, timestamp: null,
    }));
  } catch { return []; }
}

// GitHub User Profile (para @username)
async function searchGitHubProfile(username: string): Promise<SearchResult[]> {
  const user = username.startsWith("@") ? username.slice(1) : username;
  try {
    const results: SearchResult[] = [];
    const r = await fetch(`https://api.github.com/users/${user}`, { headers: ghHeaders(), signal: AbortSignal.timeout(8000) });
    if (r.ok) {
      const d: any = await r.json();
      results.push({
        source: "GitHub Profile", type: "user profile", title: d.name || d.login || user,
        url: d.html_url, snippet: `Bio: ${d.bio || "N/A"} | Company: ${d.company || "N/A"} | Location: ${d.location || "N/A"} | Email: ${d.email || "N/A"} | Blog: ${d.blog || "N/A"} | Repos: ${d.public_repos || 0} | Followers: ${d.followers || 0} | Following: ${d.following || 0} | Created: ${d.created_at || "?"}`,
        severity: "info" as const, timestamp: d.created_at || null,
      });
    }
    // User repos
    const r2 = await fetch(`https://api.github.com/users/${user}/repos?per_page=20&sort=updated`, { headers: ghHeaders(), signal: AbortSignal.timeout(8000) });
    if (r2.ok) {
      const repos: any[] = await r2.json();
      for (const repo of repos.slice(0, 20)) {
        results.push({
          source: "GitHub Repos", type: "user repo", title: repo.full_name,
          url: repo.html_url, snippet: `Stars: ${repo.stargazers_count || 0} | Forks: ${repo.forks_count || 0} | Lang: ${repo.language || "?"} | ${(repo.description || "").slice(0, 80)}`,
          severity: "low" as const, timestamp: repo.updated_at || null,
        });
      }
    }
    return results;
  } catch { return []; }
}

// GitHub Code Search (para email, phone — busca en .env, config, etc.)
async function searchGitHubCode(query: string, type: QueryType): Promise<SearchResult[]> {
  try {
    const queries: string[] = [];
    if (type === "email") { queries.push(`"${query}" filename:.env`); queries.push(`"${query}" filename:config`); queries.push(`"${query}" filename:credentials`); }
    else if (type === "phone") { queries.push(`"${query}" filename:.env`); queries.push(`"${query}" filename:config`); queries.push(`"${query}"`); }
    else if (type === "name") { queries.push(`"${query}" filename:env`); }
    else { queries.push(`"${query}"`); }

    const all: SearchResult[] = [];
    for (const q of queries.slice(0, 3)) {
      try {
        const r = await fetch(`https://api.github.com/search/code?q=${encodeURIComponent(q)}&per_page=20`, { headers: ghHeaders(), signal: AbortSignal.timeout(10000) });
        if (!r.ok) continue;
        const d: any = await r.json();
        for (const item of (d.items || []).slice(0, 20)) {
          all.push({
            source: "GitHub Code", type: "code leak", title: item.name || item.path || "File",
            url: item.html_url, snippet: `Repo: ${item.repository?.full_name || "?"} | File: ${item.path || "?"}`,
            severity: "high" as const, timestamp: null,
          });
        }
      } catch {}
    }
    return all;
  } catch { return []; }
}

// GitHub Gist Search
async function searchGitHubGists(query: string): Promise<SearchResult[]> {
  try {
    const r = await fetch(`https://api.github.com/gists/public?per_page=100`, { headers: ghHeaders(), signal: AbortSignal.timeout(10000) });
    if (!r.ok) return [];
    const gists: any[] = await r.json();
    return gists.filter(g => {
      const text = `${g.description || ""} ${Object.keys(g.files || {}).join(" ")}`.toLowerCase();
      return text.includes(query.toLowerCase());
    }).slice(0, 20).map(g => ({
      source: "GitHub Gist", type: "paste", title: g.description || "Gist",
      url: g.html_url, snippet: `Files: ${Object.keys(g.files || {}).join(", ")} | Owner: ${g.owner?.login || "?"}`,
      severity: "high" as const, timestamp: g.created_at || null,
    }));
  } catch { return []; }
}

// Gravatar (email → profile)
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

// HIBP Breaches (contexto)
async function searchHibpBreaches(): Promise<SearchResult[]> {
  try {
    const r = await fetch("https://haveibeenpwned.com/api/v3/breaches", { headers: { "User-Agent": "MONITOR-THREAT" }, signal: AbortSignal.timeout(10000) });
    if (!r.ok) return [];
    const breaches: any[] = await r.json();
    return breaches.slice(0, 20).map(b => ({
      source: "HIBP Breaches", type: "known breach",
      title: b.Name || "Breach", url: `https://haveibeenpwned.com/breach/${b.Name}`,
      snippet: `PwnCount: ${b.PwnCount || "?"} | Date: ${b.BreachDate || "?"} | Data: ${(b.DataClasses || []).join(", ")}`,
      severity: "high" as const, timestamp: b.BreachDate || null,
    }));
  } catch { return []; }
}

// VirusTotal (si el email tiene dominio)
async function searchVirusTotal(query: string, type: QueryType): Promise<SearchResult[]> {
  try {
    const key = process.env.VIRUSTOTAL_API_KEY || "";
    if (!key || type !== "email") return [];
    const domain = query.split("@")[1];
    if (!domain || !domain.includes(".")) return [];
    const r = await fetch(`https://www.virustotal.com/api/v3/domains/${domain}`, { headers: { "x-apikey": key }, signal: AbortSignal.timeout(10000) });
    if (!r.ok) return [];
    const d: any = await r.json();
    const s = d?.data?.attributes?.last_analysis_stats || {};
    return [{ source: "VirusTotal", type: "domain reputation", title: `${domain} - ${s.malicious || 0} malicious`, url: `https://www.virustotal.com/gui/domain/${domain}`, snippet: `Malicious: ${s.malicious || 0} | Suspicious: ${s.suspicious || 0} | Harmless: ${s.harmless || 0}`, severity: (s.malicious || 0) > 0 ? "high" : "info" as const, timestamp: null }];
  } catch { return []; }
}

// ---- Main ----
export async function GET(request: Request) {
  const { searchParams } = new URL(request.url);
  const query = (searchParams.get("q") || "").trim();
  const type = (searchParams.get("type") || "name").trim() as QueryType;
  if (!query) return NextResponse.json({ error: "missing_query" }, { status: 400 });

  const dorks = generateDorks(query, type);

  const isUsername = type === "username";
  const isEmail = type === "email";
  const isPhone = type === "phone";

  const [ghUsers, ghProfile, ghCode, ghGists, gravatar, hibp, vt] = await Promise.all([
    (type === "name" || isUsername) ? searchGitHubUsers(query) : Promise.resolve([]),
    isUsername ? searchGitHubProfile(query) : Promise.resolve([]),
    (isEmail || isPhone || type === "name") ? searchGitHubCode(query, type) : Promise.resolve([]),
    (isEmail || isPhone || isUsername || type === "name") ? searchGitHubGists(query) : Promise.resolve([]),
    isEmail ? searchGravatar(query) : Promise.resolve([]),
    isEmail ? searchHibpBreaches() : Promise.resolve([]),
    searchVirusTotal(query, type),
  ]);

  const all = [...ghUsers, ...ghProfile, ...ghCode, ...ghGists, ...gravatar, ...hibp, ...vt];
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
