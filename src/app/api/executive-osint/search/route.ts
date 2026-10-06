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

// ---- Helpers de normalizacion ----

// Convierte un nombre a variantes con/sin acentos (ej: "Juan Pérez" -> ["Juan Pérez", "Juan Perez"])
function accentVariants(name: string): string[] {
  const noAccent = name.normalize("NFD").replace(/[\u0300-\u036f]/g, "");
  const variants = new Set<string>([name]);
  if (noAccent !== name) variants.add(noAccent);
  return Array.from(variants);
}

// Tokeniza un nombre en palabras significativas (ignora preposiciones tipo "de", "del", "la", "los", "y")
function nameTokens(name: string): string[] {
  return name.toLowerCase().split(/\s+/).filter(t => t.length > 1 && !/^(de|del|la|las|los|el|y|van|von|di|da|do|dos|san|sant|santa)$/.test(t));
}

// Para Bing: añade "+" delante de cada palabra obligatoria (fuerza coincidencia exacta)
function bingExact(query: string, type: QueryType): string {
  const clean = query.replace(/"/g, "").trim();
  if (type === "email" || type === "phone" || type === "username") {
    return `+${clean}`;
  }
  // Para nombres: +Palabra1 +Palabra2 (cada token obligatorio)
  const tokens = clean.split(/\s+/).filter(t => t.length > 1);
  return tokens.map(t => `+${t}`).join(" ");
}

// ---- DORKS ----
function generateDorks(query: string, type: QueryType): string[] {
  const q = query.replace(/"/g, "");
  switch (type) {
    case "name": {
      // Variantes con/sin acentos
      const variants = accentVariants(q);
      const dorks: string[] = [];
      for (const v of variants) {
        dorks.push(
          `"${v}" site:linkedin.com/in`,
          `"${v}" site:twitter.com OR site:x.com`,
          `"${v}" site:facebook.com`,
          `"${v}" site:instagram.com`,
          `"${v}" site:reddit.com`,
          `"${v}" site:youtube.com`,
          `"${v}" site:tiktok.com`,
          `"${v}" filetype:pdf`,
          `"${v}" "curriculum" OR "cv" OR "resume"`,
          `"${v}" "director" OR "gerente" OR "CEO" OR "CTO" OR "CFO"`,
          `"${v}" "empresa" OR "company"`,
          `"${v}" site:bloomberg.com OR site:reuters.com`,
          `"${v}" "entrevista" OR "conference" OR "presentation"`,
          `"${v}" filetype:doc OR filetype:docx`,
          `"${v}" "contact" OR "email" OR "phone" OR "telefono"`,
        );
      }
      return dorks;
    }
    case "email":
      return [
        `"${q}" site:pastebin.com`,
        `"${q}" site:github.com`,
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
    case "username": {
      const clean = q.replace(/^@/, "");
      return [
        `"${clean}" site:github.com OR site:gitlab.com`,
        `"${clean}" site:twitter.com OR site:x.com`,
        `"${clean}" site:instagram.com`,
        `"${clean}" site:facebook.com`,
        `"${clean}" site:reddit.com OR site:medium.com`,
        `"${clean}" site:linkedin.com`,
        `"${clean}" site:tiktok.com`,
        `"${clean}" site:youtube.com`,
        `"${clean}" site:twitch.tv OR site:steamcommunity.com`,
        `"${clean}" site:telegram.org OR site:t.me`,
        `"${clean}" site:pinterest.com OR site:tumblr.com`,
        `"${clean}" "password" OR "credential" OR "leaked"`,
        `"${clean}" site:medium.com OR site:dev.to OR site:hashnode.com`,
        `"${clean}" "profile" OR "about" OR "bio"`,
        `"${clean}" "darknet" OR "onion" OR "marketplace"`,
      ];
    }
  }
}

// ============================================================
//  GitHub (4 sub-fuentes)
// ============================================================
async function searchGitHubUsers(query: string, type: QueryType): Promise<SearchResult[]> {
  try {
    let ghQueries: string[] = [];
    if (type === "name") {
      const tokens = nameTokens(query);
      // Probar tanto el nombre literal como la variante sin acentos
      const variants = accentVariants(query);
      for (const v of variants) {
        if (tokens.length >= 2) {
          ghQueries.push(`fullname:"${v}" in:name`);
          ghQueries.push(`"${v}" in:name`);
        } else {
          ghQueries.push(`${v} in:name`);
        }
      }
    } else if (type === "username") {
      const user = query.replace(/^@/, "");
      ghQueries.push(`user:${user}`);
      ghQueries.push(`${user} in:login`);
    } else if (type === "email") {
      ghQueries.push(`${query} in:email`);
      ghQueries.push(`${query}`);
    } else {
      ghQueries.push(query);
    }
    const seen = new Set<string>();
    const allItems: any[] = [];
    await Promise.all(ghQueries.slice(0, 4).map(async q => {
      try {
        const r = await fetch(`https://api.github.com/search/users?q=${encodeURIComponent(q)}&per_page=20`, { headers: ghHeaders(), signal: AbortSignal.timeout(10000) });
        if (!r.ok) return;
        const d: any = await r.json();
        for (const u of (d.items || [])) {
          if (seen.has(u.html_url)) continue;
          seen.add(u.html_url);
          allItems.push(u);
        }
      } catch {}
    }));
    // Filtro post-hoc para nombres: para cada candidato, hacer fetch del perfil real
    // y verificar que el campo "name" contiene TODOS los tokens del query
    let filtered = allItems;
    if (type === "name") {
      const required = nameTokens(query);
      const accentless = required.map(t => t.normalize("NFD").replace(/[\u0300-\u036f]/g, ""));
      // Limitamos a 12 verificaciones para no agotar rate limit
      const checks = await Promise.all(allItems.slice(0, 12).map(async (u: any) => {
        try {
          const pr = await fetch(`https://api.github.com/users/${u.login}`, { headers: ghHeaders(), signal: AbortSignal.timeout(6000) });
          if (!pr.ok) return { u, name: u.login || "" };
          const pd: any = await pr.json();
          return { u, name: `${pd.name || ""} ${pd.login || ""} ${pd.bio || ""}` };
        } catch { return { u, name: u.login || "" }; }
      }));
      filtered = checks.filter(c => {
        const candidate = (c.name || "").toLowerCase();
        const normalized = candidate.normalize("NFD").replace(/[\u0300-\u036f]/g, "");
        return required.every(t => candidate.includes(t)) || accentless.every(t => normalized.includes(t));
      }).map(c => c.u);
    }
    return filtered.slice(0, 20).map((u: any) => ({
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
async function searchWikipedia(query: string, type: QueryType): Promise<SearchResult[]> {
  if (type !== "name") return [];
  try {
    const results: SearchResult[] = [];
    // 1. Wikipedia REST search: devuelve matches con ambos terminos (busqueda AND)
    const r = await fetch(`https://en.wikipedia.org/w/rest.php/v1/search/page?q=${encodeURIComponent(query)}&limit=15`, {
      headers: { "User-Agent": "MONITOR-THREAT" },
      signal: AbortSignal.timeout(8000),
    });
    if (r.ok) {
      const d: any = await r.json();
      const required = nameTokens(query);
      const accentless = required.map(t => t.normalize("NFD").replace(/[\u0300-\u036f]/g, ""));
      for (const p of (d.pages || [])) {
        const title = p.title || "";
        const excerpt = (p.excerpt || "").replace(/<[^>]+>/g, "");
        const combined = `${title} ${excerpt}`.toLowerCase();
        const normalized = combined.normalize("NFD").replace(/[\u0300-\u036f]/g, "");
        // Verificar que TODOS los tokens esten presentes
        if (required.length > 0 && !required.every(t => combined.includes(t)) && !accentless.every(t => normalized.includes(t))) continue;
        results.push({
          source: "Wikipedia",
          type: "biography match",
          title,
          url: `https://en.wikipedia.org/wiki/${encodeURIComponent(title.replace(/ /g, "_"))}`,
          snippet: excerpt.slice(0, 200),
          severity: "info" as const,
          timestamp: null,
        });
      }
    }
    // 2. Spanish Wikipedia
    const rEs = await fetch(`https://es.wikipedia.org/w/rest.php/v1/search/page?q=${encodeURIComponent(query)}&limit=10`, {
      headers: { "User-Agent": "MONITOR-THREAT" },
      signal: AbortSignal.timeout(8000),
    });
    if (rEs.ok) {
      const d: any = await rEs.json();
      const required = nameTokens(query);
      const accentless = required.map(t => t.normalize("NFD").replace(/[\u0300-\u036f]/g, ""));
      for (const p of (d.pages || [])) {
        const title = p.title || "";
        const excerpt = (p.excerpt || "").replace(/<[^>]+>/g, "");
        const combined = `${title} ${excerpt}`.toLowerCase();
        const normalized = combined.normalize("NFD").replace(/[\u0300-\u036f]/g, "");
        if (required.length > 0 && !required.every(t => combined.includes(t)) && !accentless.every(t => normalized.includes(t))) continue;
        results.push({
          source: "Wikipedia (ES)",
          type: "biography match",
          title,
          url: `https://es.wikipedia.org/wiki/${encodeURIComponent(title.replace(/ /g, "_"))}`,
          snippet: excerpt.slice(0, 200),
          severity: "info" as const,
          timestamp: null,
        });
      }
    }
    // Dedup by URL
    const seen = new Set<string>();
    return results.filter(r => { if (seen.has(r.url)) return false; seen.add(r.url); return true; }).slice(0, 20);
  } catch { return []; }
}

// ============================================================
//  DuckDuckGo Instant Answer API — biografias exactas
// ============================================================
async function searchDdgInstantAnswer(query: string, type: QueryType): Promise<SearchResult[]> {
  if (type !== "name") return [];
  try {
    const r = await fetch(`https://api.duckduckgo.com/?q=${encodeURIComponent(query)}&format=json&no_html=1&no_redirect=1&skip_disambig=0`, {
      headers: { "User-Agent": "MONITOR-THREAT" },
      signal: AbortSignal.timeout(8000),
    });
    if (!r.ok) return [];
    const d: any = await r.json();
    const results: SearchResult[] = [];
    // AbstractText (resumen de Wikipedia/Infozubiri)
    if (d.AbstractText) {
      results.push({
        source: "DuckDuckGo IA",
        type: "biography abstract",
        title: d.Heading || query,
        url: d.AbstractURL || `https://duckduckgo.com/?q=${encodeURIComponent(query)}`,
        snippet: d.AbstractText.slice(0, 250),
        severity: "info" as const,
        timestamp: null,
      });
    }
    // RelatedTopics (resultados relacionados)
    const required = nameTokens(query);
    const accentless = required.map(t => t.normalize("NFD").replace(/[\u0300-\u036f]/g, ""));
    for (const t of (d.RelatedTopics || [])) {
      if (typeof t !== "object" || !t.Text) continue;
      const text = (t.Text || "").toLowerCase();
      const normalized = text.normalize("NFD").replace(/[\u0300-\u036f]/g, "");
      // Solo incluir si contiene TODOS los tokens del nombre
      if (required.length > 0 && !required.every(tok => text.includes(tok)) && !accentless.every(tok => normalized.includes(tok))) continue;
      results.push({
        source: "DuckDuckGo IA",
        type: "related topic",
        title: (t.Text || "").slice(0, 100),
        url: t.FirstURL || `https://duckduckgo.com/?q=${encodeURIComponent(query)}`,
        snippet: (t.Text || "").slice(0, 200),
        severity: "low" as const,
        timestamp: null,
      });
    }
    return results.slice(0, 20);
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

function parseBingHtml(html: string, query: string, type: QueryType): SearchResult[] {
  const results: SearchResult[] = [];
  // Tokens obligatorios para post-filtro (solo para nombres)
  const requiredTokens = type === "name" ? nameTokens(query) : [];
  const blockRe = /<h2[^>]*>\s*<a[^>]*href="(https:\/\/www\.bing\.com\/ck\/a\?[^"]+)"[^>]*>([\s\S]*?)<\/a>\s*<\/h2>([\s\S]*?)(?=<h2|<div class="b_pag|<\/div>\s*<div class="b_footer|$)/g;
  let m: RegExpExecArray | null;
  let count = 0;
  while ((m = blockRe.exec(html)) && count < 30) {
    const ckAurl = m[1];
    const titleHtml = m[2];
    const tail = m[3];
    const url = decodeBingUrl(ckAurl);
    if (!url) continue;
    if (/bing\.com\/(images|videos|maps|news|shop|search)/.test(url)) continue;
    const title = titleHtml.replace(/<[^>]+>/g, "").trim();
    if (!title) continue;
    const pMatch = tail.match(/<p[^>]*>([\s\S]*?)<\/p>/);
    const snippet = (pMatch ? pMatch[1] : "").replace(/<[^>]+>/g, "").trim();
    // Post-filtro para nombres: el title o snippet DEBE contener TODOS los tokens
    if (requiredTokens.length > 0) {
      const combined = `${title} ${snippet}`.toLowerCase();
      const allPresent = requiredTokens.every(t => combined.includes(t));
      if (!allPresent) continue;
    }
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

async function runDorkOnBing(dork: string, query: string, type: QueryType): Promise<SearchResult[]> {
  try {
    const r = await fetch(
      `https://www.bing.com/search?q=${encodeURIComponent(dork)}&count=30&setlang=en-US&cc=US&FORM=QBLH&nfpr=1`,
      { headers: htmlFetchHeaders(), signal: AbortSignal.timeout(12000) },
    );
    if (!r.ok) return [];
    const html = await r.text();
    const parsed = parseBingHtml(html, query, type);
    return parsed;
  } catch { return []; }
}

async function runSearchEngines(dorks: string[], query: string, type: QueryType): Promise<SearchResult[]> {
  // Ejecuta los primeros 5 dorks en Bing (en paralelo con rate-limit)
  const selected = dorks.slice(0, 5);
  const all = await Promise.all(selected.map(d => runDorkOnBing(d, query, type)));
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
  const [ghUsers, ghProfile, ghCode, ghGists, gravatar, hibp, vt, wiki, ddgIa, hunter] = await Promise.all([
    (isName || isUsername) ? searchGitHubUsers(query, type) : Promise.resolve([]),
    isUsername ? searchGitHubProfile(query) : Promise.resolve([]),
    (isEmail || isPhone || isName) ? searchGitHubCode(query, type) : Promise.resolve([]),
    (isEmail || isPhone || isUsername || isName) ? searchGitHubGists(query) : Promise.resolve([]),
    isEmail ? searchGravatar(query) : Promise.resolve([]),
    isEmail ? searchHibpBreaches(query) : Promise.resolve([]),
    searchVirusTotal(query, type),
    isName ? searchWikipedia(query, type) : Promise.resolve([]),
    isName ? searchDdgInstantAnswer(query, type) : Promise.resolve([]),
    isEmail ? searchHunter(query) : Promise.resolve([]),
  ]);

  // Lote 2 — motor Bing ejecutando 5 dorks (con post-filtro de coincidencia exacta)
  const engineResults = await runSearchEngines(dorks, query, type);

  // Lote 3 — enumeración Sherlock (solo para username)
  const sherlockResults = isUsername ? await sherlockEnumerate(query) : [];

  const all = [
    ...ghUsers, ...ghProfile, ...ghCode, ...ghGists,
    ...gravatar, ...hibp, ...vt,
    ...wiki, ...ddgIa, ...hunter,
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
      preciseMatch: { wikipedia: wiki.length, ddg: ddgIa.length },
    },
    timestamp: new Date().toISOString(),
  }, { headers: { "Cache-Control": "no-store" } });
}

export async function OPTIONS() {
  return new NextResponse(null, { status: 204, headers: { "Access-Control-Allow-Origin": "*", "Access-Control-Allow-Methods": "GET, OPTIONS", "Access-Control-Allow-Headers": "*" } });
}
