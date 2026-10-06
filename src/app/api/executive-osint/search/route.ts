// Executive OSINT Search — 4 tipos: name, email, phone, username
// Multi-source / multi-engine: GitHub (4 sub-fuentes), Gravatar, HIBP (real),
// VirusTotal, Wikipedia, Bing engine (parser decodifica ck/a?u=a1<base64>),
// Hunter.io, Sherlock (17 sitios verificados server-side)

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

function htmlFetchHeaders(): Record<string, string> {
  return {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
    "Accept-Encoding": "gzip",
    "Cache-Control": "max-age=0",
    "Sec-Fetch-Dest": "document",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-Site": "none",
    "Sec-Fetch-User": "?1",
    "Upgrade-Insecure-Requests": "1",
  };
}

// ---- DORKS ----
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

// ============================================================
//  GitHub (4 sub-fuentes)
// ============================================================
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

// ============================================================
//  Gravatar (email → profile)
// ============================================================
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

// ============================================================
//  HIBP — búsqueda REAL por email (con API key) + fallback genérico
// ============================================================
async function searchHibpBreaches(email?: string): Promise<SearchResult[]> {
  const key = process.env.HIBP_API_KEY || "";
  if (key && email) {
    try {
      const r = await fetch(`https://haveibeenpwned.com/api/v3/breachedaccount/${encodeURIComponent(email)}?truncateResponse=false`, {
        headers: { "hibp-api-key": key, "User-Agent": "MONITOR-THREAT" },
        signal: AbortSignal.timeout(10000),
      });
      if (r.ok) {
        const breaches: any[] = await r.json();
        return breaches.slice(0, 25).map(b => ({
          source: "HIBP Breach", type: "confirmed breach",
          title: `${b.Name} — ${email}`, url: `https://haveibeenpwned.com/breach/${b.Name}`,
          snippet: `PwnCount: ${b.PwnCount || "?"} | Date: ${b.BreachDate || "?"} | Data: ${(b.DataClasses || []).join(", ")}`,
          severity: "high" as const, timestamp: b.BreachDate || null,
        }));
      }
      if (r.status === 404) {
        return [{ source: "HIBP", type: "no breaches", title: `${email} — NOT BREACHED`, url: "https://haveibeenpwned.com", snippet: "Email not found in any known breach.", severity: "info" as const, timestamp: null }];
      }
    } catch {}
  }
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

// ============================================================
//  VirusTotal
// ============================================================
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

// ============================================================
//  Wikipedia — búsqueda biográfica
// ============================================================
async function searchWikipedia(query: string): Promise<SearchResult[]> {
  try {
    const r = await fetch(`https://en.wikipedia.org/w/api.php?action=opensearch&search=${encodeURIComponent(query)}&limit=15&format=json&origin=*`, { signal: AbortSignal.timeout(8000) });
    if (!r.ok) return [];
    const d: any = await r.json();
    const titles: string[] = d[1] || [];
    const urls: string[] = d[3] || [];
    return titles.slice(0, 15).map((t, i) => ({
      source: "Wikipedia", type: "biography match",
      title: t, url: urls[i] || `https://en.wikipedia.org/wiki/${encodeURIComponent(t.replace(/ /g, "_"))}`,
      snippet: `Encyclopedia entry — possible identity match`,
      severity: "info" as const, timestamp: null,
    }));
  } catch { return []; }
}

// ============================================================
//  Hunter.io
// ============================================================
async function searchHunter(email: string): Promise<SearchResult[]> {
  try {
    const key = process.env.HUNTER_API_KEY || "";
    if (!key) return [];
    const r = await fetch(`https://api.hunter.io/v2/email-verifier?email=${encodeURIComponent(email)}&api_key=${key}`, { signal: AbortSignal.timeout(10000) });
    if (!r.ok) return [];
    const d: any = await r.json();
    const data = d?.data || {};
    return [{
      source: "Hunter.io", type: "email verification",
      title: `${email} — ${data.status || "?"}`,
      url: `https://hunter.io/email-verifier/${encodeURIComponent(email)}`,
      snippet: `Status: ${data.status || "?"} | Result: ${data.result || "?"} | Score: ${data.score || "?"} | Domain: ${data.domain || "?"}`,
      severity: data.status === "valid" ? "info" : "low" as const, timestamp: null,
    }];
  } catch { return []; }
}

// ============================================================
//  BING ENGINE — parser decodifica ck/a?u=a1<base64>
// ============================================================
function decodeBingUrl(ckAurl: string): string | null {
  try {
    // Bing URL: https://www.bing.com/ck/a?...&u=a1<base64>&ntb=1
    // The base64 may be URL-encoded (&amp; → &)
    const decoded = ckAurl.replace(/&amp;/g, "&");
    const m = decoded.match(/u=a1([A-Za-z0-9+/=_-]+)/);
    if (!m) return null;
    let b64 = m[1];
    // URL-decode (%3D → =) — but base64 in URLs typically already unescaped
    b64 = decodeURIComponent(b64);
    // Bing uses URL-safe base64 (- and _), convert to standard
    b64 = b64.replace(/-/g, "+").replace(/_/g, "/");
    // Pad
    b64 += "=".repeat((4 - (b64.length % 4)) % 4);
    const decodedUrl = Buffer.from(b64, "base64").toString("utf-8");
    if (!decodedUrl.startsWith("http")) return null;
    return decodedUrl;
  } catch { return null; }
}

function parseBingHtml(html: string): SearchResult[] {
  const results: SearchResult[] = [];
  // Modern Bing: <h2 ...><a href="https://www.bing.com/ck/a?...&u=a1<base64>...">Title</a></h2>
  // Then nearby <p> contains snippet
  // Match each result block: from <h2 to the next </h2>
  const blockRe = /<h2[^>]*>\s*<a[^>]*href="(https:\/\/www\.bing\.com\/ck\/a\?[^"]+)"[^>]*>([\s\S]*?)<\/a>\s*<\/h2>([\s\S]*?)(?=<h2|<div class="b_pag|<\/div>\s*<div class="b_footer|$)/g;
  let m: RegExpExecArray | null;
  let count = 0;
  while ((m = blockRe.exec(html)) && count < 30) {
    const ckAurl = m[1];
    const titleHtml = m[2];
    const tail = m[3];
    const url = decodeBingUrl(ckAurl);
    if (!url) continue;
    // Skip Bing-internal nav links (/images, /videos, /maps, /news, /shop)
    if (url.includes("bing.com/") && !url.includes("://www.bing.com/search?q=") === false) continue;
    if (/bing\.com\/(images|videos|maps|news|shop|search)/.test(url)) continue;
    const title = titleHtml.replace(/<[^>]+>/g, "").trim();
    if (!title) continue;
    // Snippet: first <p> after the h2
    const pMatch = tail.match(/<p[^>]*>([\s\S]*?)<\/p>/);
    const snippet = (pMatch ? pMatch[1] : "").replace(/<[^>]+>/g, "").trim();
    results.push({
      source: "Bing",
      type: "search hit",
      title: title.slice(0, 150),
      url,
      snippet: snippet.slice(0, 250) || "(no snippet)",
      severity: "medium" as const,
      timestamp: null,
    });
    count++;
  }
  return results;
}

async function runDorkOnBing(dork: string): Promise<SearchResult[]> {
  try {
    const r = await fetch(
      `https://www.bing.com/search?q=${encodeURIComponent(dork)}&count=30&setlang=en-US&cc=US&FORM=QBLH&nfpr=1`,
      { headers: htmlFetchHeaders(), signal: AbortSignal.timeout(12000) },
    );
    if (!r.ok) return [];
    const html = await r.text();
    const parsed = parseBingHtml(html);
    return parsed;
  } catch { return []; }
}

async function runSearchEngines(dorks: string[]): Promise<SearchResult[]> {
  // Ejecuta los primeros 5 dorks en Bing (en paralelo con rate-limit)
  const selected = dorks.slice(0, 5);
  const all = await Promise.all(selected.map(d => runDorkOnBing(d)));
  const seen = new Set<string>();
  const out: SearchResult[] = [];
  for (const arr of all) {
    for (const r of arr) {
      if (seen.has(r.url)) continue;
      seen.add(r.url);
      out.push(r);
    }
  }
  return out.slice(0, 60);
}

// ============================================================
//  Sherlock — 17 sitios verificados que responden server-side
// ============================================================
interface SherlockSite {
  name: string;
  url: (u: string) => string;
  // Patrón en el HTML que indica "no encontrado" (false positive filter)
  notFoundPattern?: RegExp;
}

const SHERLOCK_SITES: SherlockSite[] = [
  { name: "GitHub", url: u => `https://github.com/${u}`, notFoundPattern: /Not Found|page doesn't exist/i },
  { name: "GitLab", url: u => `https://gitlab.com/${u}` },
  { name: "Twitter/X", url: u => `https://x.com/${u}` },
  { name: "TikTok", url: u => `https://tiktok.com/@${u}` },
  { name: "YouTube", url: u => `https://youtube.com/@${u}` },
  { name: "Twitch", url: u => `https://twitch.tv/${u}` },
  { name: "Telegram", url: u => `https://t.me/${u}` },
  { name: "Pinterest", url: u => `https://pinterest.com/${u}` },
  { name: "SoundCloud", url: u => `https://soundcloud.com/${u}` },
  { name: "Dev.to", url: u => `https://dev.to/${u}` },
  { name: "Hashnode", url: u => `https://hashnode.com/@${u}` },
  { name: "HackerNews", url: u => `https://news.ycombinator.com/user?id=${u}` },
  { name: "Steam", url: u => `https://steamcommunity.com/id/${u}` },
  { name: "Keybase", url: u => `https://keybase.io/${u}` },
  { name: "Kaggle", url: u => `https://kaggle.com/${u}` },
  { name: "Spotify", url: u => `https://open.spotify.com/user/${u}` },
  { name: "Pastebin", url: u => `https://pastebin.com/u/${u}` },
];

async function checkSherlockUrl(site: SherlockSite, username: string): Promise<SearchResult | null> {
  try {
    const url = site.url(username);
    const r = await fetch(url, {
      method: "GET",
      headers: htmlFetchHeaders(),
      redirect: "follow",
      signal: AbortSignal.timeout(8000),
    });
    if (r.status !== 200) return null;
    const html = await r.text();
    // Si la pagina tiene el patron de "no encontrado", es un falso positivo
    if (site.notFoundPattern && site.notFoundPattern.test(html)) return null;
    // Algunos sitios devuelven 200 con contenido de "login" si el usuario no existe
    // pero es muy dificil de detectar universalmente, asi que lo dejamos como "hit probable"
    return {
      source: site.name,
      type: "username found",
      title: `${username} en ${site.name}`,
      url: r.url,
      snippet: `HTTP 200 — perfil probable de "${username}" en ${site.name}`,
      severity: "medium" as const,
      timestamp: null,
    };
  } catch {
    return null;
  }
}

async function sherlockEnumerate(username: string): Promise<SearchResult[]> {
  const user = username.startsWith("@") ? username.slice(1) : username;
  // Lanzar todos los checks en paralelo (17 es un numero manejable)
  const checks = await Promise.all(SHERLOCK_SITES.map(s => checkSherlockUrl(s, user)));
  return checks.filter((c): c is SearchResult => c !== null);
}

// ============================================================
//  Main
// ============================================================
export async function GET(request: Request) {
  const { searchParams } = new URL(request.url);
  const query = (searchParams.get("q") || "").trim();
  const type = (searchParams.get("type") || "name").trim() as QueryType;
  if (!query) return NextResponse.json({ error: "missing_query" }, { status: 400 });

  const dorks = generateDorks(query, type);

  const isUsername = type === "username";
  const isEmail = type === "email";
  const isPhone = type === "phone";
  const isName = type === "name";

  // Lote 1 — fuentes API directas (rápidas)
  const [ghUsers, ghProfile, ghCode, ghGists, gravatar, hibp, vt, wiki, hunter] = await Promise.all([
    (isName || isUsername) ? searchGitHubUsers(query) : Promise.resolve([]),
    isUsername ? searchGitHubProfile(query) : Promise.resolve([]),
    (isEmail || isPhone || isName) ? searchGitHubCode(query, type) : Promise.resolve([]),
    (isEmail || isPhone || isUsername || isName) ? searchGitHubGists(query) : Promise.resolve([]),
    isEmail ? searchGravatar(query) : Promise.resolve([]),
    isEmail ? searchHibpBreaches(query) : Promise.resolve([]),
    searchVirusTotal(query, type),
    isName ? searchWikipedia(query) : Promise.resolve([]),
    isEmail ? searchHunter(query) : Promise.resolve([]),
  ]);

  // Lote 2 — motor Bing ejecutando 5 dorks
  const engineResults = await runSearchEngines(dorks);

  // Lote 3 — enumeración Sherlock (solo para username)
  const sherlockResults = isUsername ? await sherlockEnumerate(query) : [];

  const all = [
    ...ghUsers, ...ghProfile, ...ghCode, ...ghGists,
    ...gravatar, ...hibp, ...vt,
    ...wiki, ...hunter,
    ...engineResults,
    ...sherlockResults,
  ];
  const seen = new Set<string>();
  const deduped = all.filter(r => { if (seen.has(r.url)) return false; seen.add(r.url); return true; });

  const bySource: Record<string, number> = {};
  const bySeverity = { high: 0, medium: 0, low: 0, info: 0 };
  for (const r of deduped) { bySource[r.source] = (bySource[r.source] || 0) + 1; bySeverity[r.severity]++; }

  return NextResponse.json({
    query, queryType: type, dorks,
    sourcesUsed: Object.keys(bySource),
    enginesUsed: ["Bing"],
    results: deduped,
    summary: {
      total: deduped.length,
      bySource,
      bySeverity,
      engines: { bing: engineResults.length },
      sherlock: sherlockResults.length,
    },
    timestamp: new Date().toISOString(),
  }, { headers: { "Cache-Control": "no-store" } });
}

export async function OPTIONS() {
  return new NextResponse(null, { status: 204, headers: { "Access-Control-Allow-Origin": "*", "Access-Control-Allow-Methods": "GET, OPTIONS", "Access-Control-Allow-Headers": "*" } });
}
