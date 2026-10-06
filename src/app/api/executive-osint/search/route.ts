// Executive OSINT Search — 4 tipos: name, email, phone, username
// Multi-source / multi-engine: GitHub (4 sub-fuentes), Gravatar, HIBP (real),
// VirusTotal, Wikipedia, DuckDuckGo engine, Bing engine, Hunter.io, Sherlock (25+ sitios)

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
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9,es;q=0.8",
  };
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
  // Real breach lookup si hay API key
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
  // Fallback: lista de breaches conocidos (contexto)
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
//  VirusTotal — reputación del dominio del email
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
//  Wikipedia — búsqueda biográfica para nombres
// ============================================================
async function searchWikipedia(query: string): Promise<SearchResult[]> {
  try {
    // OpenSearch devuelve matches con título + snippet + URL
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
//  Hunter.io — email → nombre/cargo/domain (con API key opcional)
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
//  DuckDuckGo engine — ejecuta dorks y parsea HTML
// ============================================================
function parseDDGHtml(html: string, engine: string): SearchResult[] {
  const results: SearchResult[] = [];
  // DDG html.duckduckgo.com usa <a class="result__a" href="..."> + <a class="result__snippet">
  const linkRe = /<a[^>]*class="[^"]*result__a[^"]*"[^>]*href="([^"]+)"[^>]*>([\s\S]*?)<\/a>/g;
  const snippetRe = /<a[^>]*class="[^"]*result__snippet[^"]*"[^>]*>([\s\S]*?)<\/a>/g;
  const links: { url: string; title: string }[] = [];
  let m: RegExpExecArray | null;
  while ((m = linkRe.exec(html)) && links.length < 30) {
    let href = m[1];
    // DDG wraps with //duckduckgo.com/l/?uddg=ENC
    const uddg = href.match(/uddg=([^&]+)/);
    if (uddg) {
      try { href = decodeURIComponent(uddg[1]); } catch {}
    }
    const title = m[2].replace(/<[^>]+>/g, "").trim();
    if (href.startsWith("http")) links.push({ url: href, title });
  }
  const snippets: string[] = [];
  while ((m = snippetRe.exec(html)) && snippets.length < 30) {
    snippets.push(m[1].replace(/<[^>]+>/g, "").trim());
  }
  for (let i = 0; i < links.length; i++) {
    results.push({
      source: engine, type: "search hit",
      title: links[i].title.slice(0, 120),
      url: links[i].url,
      snippet: (snippets[i] || "").slice(0, 200) || "(no snippet)",
      severity: "medium" as const, timestamp: null,
    });
  }
  return results;
}

function parseBingHtml(html: string, engine: string): SearchResult[] {
  const results: SearchResult[] = [];
  // Bing: <li class="b_algo"><h2><a href="...">title</a></h2><p>...snippet...</p>
  const blockRe = /<li class="b_algo"[^>]*>([\s\S]*?)<\/li>/g;
  const linkRe = /<a[^>]*href="(https?:[^"]+)"[^>]*>([\s\S]*?)<\/a>/;
  const snippetRe = /<p[^>]*>([\s\S]*?)<\/p>/;
  let m: RegExpExecArray | null;
  let count = 0;
  while ((m = blockRe.exec(html)) && count < 30) {
    const block = m[1];
    const lm = block.match(linkRe);
    if (!lm) continue;
    const url = lm[1];
    const title = lm[2].replace(/<[^>]+>/g, "").trim();
    const sm = block.match(snippetRe);
    const snippet = (sm ? sm[1] : "").replace(/<[^>]+>/g, "").trim();
    if (url && title) {
      results.push({
        source: engine, type: "search hit",
        title: title.slice(0, 120),
        url,
        snippet: snippet.slice(0, 200) || "(no snippet)",
        severity: "medium" as const, timestamp: null,
      });
      count++;
    }
  }
  return results;
}

async function runDorkOnDDG(dork: string): Promise<SearchResult[]> {
  try {
    const r = await fetch(`https://html.duckduckgo.com/html/?q=${encodeURIComponent(dork)}`, {
      headers: htmlFetchHeaders(),
      signal: AbortSignal.timeout(12000),
    });
    if (!r.ok) return [];
    const html = await r.text();
    return parseDDGHtml(html, "DuckDuckGo");
  } catch { return []; }
}

async function runDorkOnBing(dork: string): Promise<SearchResult[]> {
  try {
    const r = await fetch(`https://www.bing.com/search?q=${encodeURIComponent(dork)}&count=30`, {
      headers: htmlFetchHeaders(),
      signal: AbortSignal.timeout(12000),
    });
    if (!r.ok) return [];
    const html = await r.text();
    return parseBingHtml(html, "Bing");
  } catch { return []; }
}

// Ejecuta los N dorks más relevantes en paralelo contra DDG + Bing
async function runSearchEngines(dorks: string[]): Promise<SearchResult[]> {
  // Limita a los primeros 4 dorks para evitar rate-limit
  const selected = dorks.slice(0, 4);
  const tasks: Promise<SearchResult[]>[] = [];
  for (const d of selected) {
    tasks.push(runDorkOnDDG(d));
    tasks.push(runDorkOnBing(d));
  }
  const all = await Promise.all(tasks);
  // Combina y de-dup por URL dentro de esta llamada
  const seen = new Set<string>();
  const out: SearchResult[] = [];
  for (const arr of all) {
    for (const r of arr) {
      if (seen.has(r.url)) continue;
      seen.add(r.url);
      out.push(r);
    }
  }
  // Limita total a 60 resultados de motor
  return out.slice(0, 60);
}

// ============================================================
//  Sherlock — enumeración de usernames en 25+ sitios
// ============================================================
interface SherlockSite {
  name: string;
  url: (u: string) => string;
  //errorMsg?: RegExp;  // opcional: patrón en el HTML que indica "no existe"
}

const SHERLOCK_SITES: SherlockSite[] = [
  { name: "GitHub", url: u => `https://github.com/${u}` },
  { name: "GitLab", url: u => `https://gitlab.com/${u}` },
  { name: "Bitbucket", url: u => `https://bitbucket.org/${u}` },
  { name: "Twitter/X", url: u => `https://x.com/${u}` },
  { name: "Instagram", url: u => `https://instagram.com/${u}` },
  { name: "Facebook", url: u => `https://facebook.com/${u}` },
  { name: "Reddit", url: u => `https://reddit.com/user/${u}` },
  { name: "TikTok", url: u => `https://tiktok.com/@${u}` },
  { name: "YouTube", url: u => `https://youtube.com/@${u}` },
  { name: "Twitch", url: u => `https://twitch.tv/${u}` },
  { name: "Telegram", url: u => `https://t.me/${u}` },
  { name: "Pinterest", url: u => `https://pinterest.com/${u}` },
  { name: "Tumblr", url: u => `https://${u}.tumblr.com` },
  { name: "Medium", url: u => `https://medium.com/@${u}` },
  { name: "Dev.to", url: u => `https://dev.to/${u}` },
  { name: "Hashnode", url: u => `https://hashnode.com/@${u}` },
  { name: "HackerNews", url: u => `https://news.ycombinator.com/user?id=${u}` },
  { name: "Steam", url: u => `https://steamcommunity.com/id/${u}` },
  { name: "Keybase", url: u => `https://keybase.io/${u}` },
  { name: "Replit", url: u => `https://replit.com/@${u}` },
  { name: "Vimeo", url: u => `https://vimeo.com/${u}` },
  { name: "SoundCloud", url: u => `https://soundcloud.com/${u}` },
  { name: "Spotify", url: u => `https://open.spotify.com/user/${u}` },
  { name: "Patreon", url: u => `https://patreon.com/${u}` },
  { name: "Mastodon (mstdn)", url: u => `https://mstdn.social/@${u}` },
  { name: "Stack Overflow", url: u => `https://stackoverflow.com/users/${u}` },
  { name: "Kaggle", url: u => `https://kaggle.com/${u}` },
];

async function checkUrl(url: string): Promise<{ ok: boolean; status: number; finalUrl: string }> {
  try {
    const r = await fetch(url, {
      method: "GET",
      headers: htmlFetchHeaders(),
      redirect: "follow",
      signal: AbortSignal.timeout(8000),
    });
    // Algunos sitios devuelven 200 con página "no encontrado". Aceptamos como hit de todas formas
    // (la verificación humana en el snippet/show lo confirma).
    return { ok: r.ok && r.status === 200, status: r.status, finalUrl: r.url };
  } catch {
    return { ok: false, status: 0, finalUrl: url };
  }
}

async function sherlockEnumerate(username: string): Promise<SearchResult[]> {
  const user = username.startsWith("@") ? username.slice(1) : username;
  // Limita a 12 sitios en paralelo para no agotar sockets
  const chunks: SherlockSite[][] = [];
  for (let i = 0; i < SHERLOCK_SITES.length; i += 12) {
    chunks.push(SHERLOCK_SITES.slice(i, i + 12));
  }
  const results: SearchResult[] = [];
  for (const chunk of chunks) {
    const checks = await Promise.all(chunk.map(async s => {
      const url = s.url(user);
      const c = await checkUrl(url);
      return { site: s.name, url, ...c };
    }));
    for (const c of checks) {
      if (c.ok) {
        results.push({
          source: c.site, type: "username found",
          title: `${user} en ${c.site}`,
          url: c.finalUrl,
          snippet: `HTTP ${c.status} — perfil probable de "${user}" en ${c.site}`,
          severity: "medium" as const, timestamp: null,
        });
      }
    }
  }
  return results;
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

  // Lote 2 — motores de búsqueda (DuckDuckGo + Bing ejecutando 4 dorks cada uno)
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
    enginesUsed: ["DuckDuckGo", "Bing"],
    results: deduped,
    summary: {
      total: deduped.length,
      bySource,
      bySeverity,
      engines: { duckduckgo: engineResults.filter(r => r.source === "DuckDuckGo").length, bing: engineResults.filter(r => r.source === "Bing").length },
      sherlock: sherlockResults.length,
    },
    timestamp: new Date().toISOString(),
  }, { headers: { "Cache-Control": "no-store" } });
}

export async function OPTIONS() {
  return new NextResponse(null, { status: 204, headers: { "Access-Control-Allow-Origin": "*", "Access-Control-Allow-Methods": "GET, OPTIONS", "Access-Control-Allow-Headers": "*" } });
}
