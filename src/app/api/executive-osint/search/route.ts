// Executive OSINT Search — Fast version
//
// ESTRATEGIA:
//   1. Ejecutar SOLO las fuentes API directas (GitHub, Wikipedia, Wikidata,
//      HIBP, Gravatar) en paralelo — rapido (<2s).
//   2. Ejecutar SOLO 3-5 dorks en Bing en paralelo (no 20).
//   3. Devolver resultados en <5s (dentro del limite de Vercel).
//
// Las busquedas manuales en Google/Yandex/Edge se hacen via botones en el
// frontend (cada dork tiene un boton G/Y/E/B/D que abre el navegador).

import { NextResponse } from "next/server";

interface SearchResult {
  category: string;
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
    "Accept-Language": "en-US,en;q=0.9",
  };
}

function nameTokens(name: string): string[] {
  return name.toLowerCase().split(/\s+/).filter(t => t.length > 1 && !/^(de|del|la|las|los|el|y|van|von|di|da|do|dos|san|sant|santa)$/.test(t));
}

// ============================================================
//  CATEGORIAS DE DORKS (20 categorias, pero solo ejecutamos 5)
// ============================================================
interface DorkCategory {
  id: string;
  name: string;
  icon: string;
  dorks: string[];
  severity: "high" | "medium" | "low" | "info";
}

function buildDorkCategories(query: string, type: QueryType): DorkCategory[] {
  const q = query.replace(/"/g, "");
  const Q = `"${q}"`;
  const categories: DorkCategory[] = [
    { id: "social-media", name: "Social Media Profiles", icon: "Users", severity: "info", dorks: [
      `${Q} (site:linkedin.com/in | site:twitter.com | site:x.com | site:facebook.com | site:instagram.com | site:tiktok.com)`,
      `${Q} site:linkedin.com/in`,
      `${Q} site:twitter.com OR site:x.com`,
      `${Q} site:facebook.com`,
      `${Q} site:instagram.com`,
      `${Q} site:tiktok.com`,
    ]},
    { id: "developer-profiles", name: "Developer & Tech Profiles", icon: "Code", severity: "info", dorks: [
      `${Q} (site:github.com | site:gitlab.com | site:stackoverflow.com)`,
      `${Q} site:github.com`,
      `${Q} site:gitlab.com`,
      `${Q} site:stackoverflow.com`,
    ]},
    { id: "general-web", name: "General Web Presence", icon: "Globe", severity: "low", dorks: [
      `${Q} (email | username | contact | contacto | about | perfil)`,
      `${Q} "about me" OR "acerca de" OR "biografia"`,
    ]},
    { id: "emails-usernames", name: "Find Emails & Usernames", icon: "Mail", severity: "medium", dorks: [
      `${Q} (email | username | alias | handle)`,
      `${Q} "@" OR "email:" OR "correo:"`,
    ]},
    { id: "location-contact", name: "Find Location & Contact Info", icon: "MapPin", severity: "medium", dorks: [
      `${Q} (location | address | phone | ubicacion | direccion | telefono)`,
      `${Q} (address | direccion | location | ciudad | city)`,
    ]},
    { id: "pdf-pubs", name: "Professional & Academic Publications (PDF)", icon: "FileText", severity: "low", dorks: [
      `${Q} filetype:pdf (resume | cv | "hoja de vida" | paper | portfolio)`,
      `${Q} filetype:pdf (cv | curriculum | resume)`,
    ]},
    { id: "work-history", name: "Work History & Company Mentions", icon: "Briefcase", severity: "low", dorks: [
      `${Q} (worked at | "trabajo en" | employed by | founder of | CEO of | company)`,
      `${Q} (CEO | CFO | CTO | director | gerente | presidente)`,
    ]},
    { id: "images", name: "Images", icon: "Image", severity: "info", dorks: [
      `${Q} (filetype:jpg OR filetype:png OR filetype:jpeg)`,
      `${Q} site:flickr.com OR site:imgur.com`,
    ]},
    { id: "news-blogs", name: "News, Blogs, & Articles", icon: "Newspaper", severity: "low", dorks: [
      `${Q} (interview | entrevista | article | articulo | mentioned in | blog)`,
      `${Q} site:bloomberg.com OR site:reuters.com OR site:nytimes.com`,
    ]},
    { id: "public-records", name: "Public Records & Legal Documents", icon: "Scale", severity: "medium", dorks: [
      `${Q} (court | lawsuit | demanda | case | caso | docket)`,
      `${Q} (inurl:docket | inurl:court | inurl:demanda)`,
    ]},
    { id: "forums", name: "Forum & Community Discussions", icon: "MessageSquare", severity: "low", dorks: [
      `${Q} (inurl:forum | inurl:foro | inurl:thread | "discussion")`,
      `${Q} site:reddit.com OR site:quora.com`,
    ]},
    { id: "leaks-pastes", name: "Data Leaks & Paste Sites", icon: "AlertTriangle", severity: "high", dorks: [
      `${Q} (site:pastebin.com | site:ghostbin.com | "leak" | "breach" | "filtracion")`,
      `${Q} site:pastebin.com OR site:ghostbin.com`,
    ]},
    { id: "academic", name: "Academic & Research Profiles", icon: "GraduationCap", severity: "info", dorks: [
      `${Q} (site:researchgate.net | site:academia.edu | site:orcid.org)`,
      `${Q} (PhD | researcher | investigador | professor)`,
    ]},
    { id: "company-registries", name: "Company Registries & Business Filings", icon: "Building", severity: "medium", dorks: [
      `${Q} (site:opencorporates.com | "director" | "shareholder" | "registro mercantil")`,
      `${Q} (director | accionista | administrador | socio)`,
    ]},
    { id: "usernames-handles", name: "Usernames & Handles (cross-reference)", icon: "AtSign", severity: "medium", dorks: [
      `${Q} (intext:"@" | "username:" | "alias" | "user profile")`,
      `${Q} (alias | handle | nickname | apodo)`,
    ]},
    { id: "breaches", name: "Breach Databases", icon: "Shield", severity: "high", dorks: [
      `${Q} (site:haveibeenpwned.com | "exposed in" | "found in breach")`,
      `${Q} ("exposed in" | "compromised" | "comprometido")`,
    ]},
    { id: "intel-search", name: "Intelligence Search (IntelX, Shodan)", icon: "Radar", severity: "medium", dorks: [
      `${Q} (site:intelx.io | site:shodan.io | "exposed" | "indexed")`,
      `${Q} (exposed | indexed | expuesto)`,
    ]},
    { id: "darkweb", name: "Dark Web & Onion Mentions", icon: "Skull", severity: "high", dorks: [
      `${Q} ("dark web" | darkweb | onion | tor | .onion)`,
      `${Q} ("deep web" | "profunda web" | "hidden service")`,
    ]},
    { id: "phone-address", name: "Phone & Address Lookups", icon: "Phone", severity: "medium", dorks: [
      `${Q} (site:truecaller.com | phone | telefono | address | direccion)`,
      `${Q} (phone | telefono | celular | movil | address)`,
    ]},
    { id: "deepfake", name: "Deep Fake Search", icon: "Eye", severity: "high", dorks: [
      `${Q} ("deepfake" OR "deep fake") (filetype:mp4 OR site:reddit.com OR site:youtube.com)`,
      `${Q} ("deepfake" | "deep fake" | "fake video")`,
    ]},
  ];
  return categories;
}

// ============================================================
//  GitHub API — user search
// ============================================================
async function searchGitHub(query: string, type: QueryType): Promise<SearchResult[]> {
  const out: SearchResult[] = [];
  try {
    let q = query;
    if (type === "name") {
      const tokens = nameTokens(query);
      if (tokens.length >= 2) q = `"${query}" in:name`;
      else q = `${query} in:name`;
    } else if (type === "username") {
      q = `user:${query.replace(/^@/, "")}`;
    } else if (type === "email") {
      q = `${query} in:email OR ${query}`;
    }
    const r = await fetch(`https://api.github.com/search/users?q=${encodeURIComponent(q)}&per_page=10`, {
      headers: ghHeaders(),
      signal: AbortSignal.timeout(8000),
    });
    if (r.ok) {
      const d: any = await r.json();
      for (const u of (d.items || []).slice(0, 10)) {
        out.push({
          category: "developer-profiles",
          source: "GitHub User",
          type: "user match",
          title: u.login,
          url: u.html_url,
          snippet: `Type: ${u.type || "?"} | Avatar: ${u.avatar_url?.slice(0, 60) || "?"}`,
          severity: "info",
          timestamp: null,
        });
      }
    }
  } catch {}
  return out;
}

// ============================================================
//  Wikipedia REST
// ============================================================
async function searchWikipedia(query: string, type: QueryType): Promise<SearchResult[]> {
  if (type !== "name") return [];
  try {
    const r = await fetch(`https://en.wikipedia.org/w/rest.php/v1/search/page?q=${encodeURIComponent(query)}&limit=10`, {
      headers: { "User-Agent": "MONITOR-THREAT" },
      signal: AbortSignal.timeout(8000),
    });
    if (!r.ok) return [];
    const d: any = await r.json();
    const required = nameTokens(query);
    const accentless = required.map(t => t.normalize("NFD").replace(/[\u0300-\u036f]/g, ""));
    return (d.pages || []).filter((p: any) => {
      const combined = `${p.title || ""} ${p.excerpt || ""}`.toLowerCase();
      const normalized = combined.normalize("NFD").replace(/[\u0300-\u036f]/g, "");
      if (required.length === 0) return true;
      return required.every(t => combined.includes(t)) || accentless.every(t => normalized.includes(t));
    }).slice(0, 10).map((p: any) => ({
      category: "news-blogs",
      source: "Wikipedia",
      type: "biography match",
      title: p.title || query,
      url: `https://en.wikipedia.org/wiki/${encodeURIComponent((p.title || "").replace(/ /g, "_"))}`,
      snippet: (p.excerpt || "").replace(/<[^>]+>/g, "").slice(0, 200),
      severity: "info" as const,
      timestamp: null,
    }));
  } catch { return []; }
}

// ============================================================
//  DuckDuckGo Instant Answer
// ============================================================
async function searchDdgIA(query: string, type: QueryType): Promise<SearchResult[]> {
  if (type !== "name") return [];
  try {
    const r = await fetch(`https://api.duckduckgo.com/?q=${encodeURIComponent(query)}&format=json&no_html=1&no_redirect=1`, {
      signal: AbortSignal.timeout(8000),
    });
    if (!r.ok) return [];
    const d: any = await r.json();
    const out: SearchResult[] = [];
    if (d.AbstractText) {
      out.push({
        category: "news-blogs",
        source: "DuckDuckGo IA",
        type: "biography abstract",
        title: d.Heading || query,
        url: d.AbstractURL || `https://duckduckgo.com/?q=${encodeURIComponent(query)}`,
        snippet: (d.AbstractText || "").slice(0, 250),
        severity: "info",
        timestamp: null,
      });
    }
    const required = nameTokens(query);
    for (const t of (d.RelatedTopics || [])) {
      if (typeof t !== "object" || !t.Text) continue;
      const text = (t.Text || "").toLowerCase();
      if (required.length > 0 && !required.every(tok => text.includes(tok))) continue;
      out.push({
        category: "general-web",
        source: "DuckDuckGo IA",
        type: "related topic",
        title: (t.Text || "").slice(0, 100),
        url: t.FirstURL || `https://duckduckgo.com/?q=${encodeURIComponent(query)}`,
        snippet: (t.Text || "").slice(0, 200),
        severity: "low",
        timestamp: null,
      });
    }
    return out.slice(0, 10);
  } catch { return []; }
}

// ============================================================
//  Gravatar (email)
// ============================================================
async function searchGravatar(email: string): Promise<SearchResult[]> {
  try {
    const crypto = await import("crypto");
    const hash = crypto.createHash("md5").update(email.trim().toLowerCase()).digest("hex");
    const r = await fetch(`https://gravatar.com/${hash}.json`, { signal: AbortSignal.timeout(6000) });
    if (!r.ok) return [];
    const d: any = await r.json();
    const profile = d.entry?.[0];
    if (!profile) return [];
    return [{
      category: "images",
      source: "Gravatar",
      type: "email profile",
      title: profile.displayName || email,
      url: profile.profileUrl || `https://gravatar.com/${hash}`,
      snippet: `Name: ${profile.displayName || "?"} | Username: ${profile.preferredUsername || "?"}`,
      severity: "info",
      timestamp: null,
    }];
  } catch { return []; }
}

// ============================================================
//  HIBP (sin API key — solo lista de breaches conocidos)
// ============================================================
async function searchHibp(): Promise<SearchResult[]> {
  try {
    const r = await fetch("https://haveibeenpwned.com/api/v3/breaches", {
      headers: { "User-Agent": "MONITOR-THREAT" },
      signal: AbortSignal.timeout(8000),
    });
    if (!r.ok) return [];
    const d: any[] = await r.json();
    return d.slice(0, 10).map(b => ({
      category: "breaches",
      source: "HIBP Breaches",
      type: "known breach",
      title: b.Name || "Breach",
      url: `https://haveibeenpwned.com/breach/${b.Name}`,
      snippet: `PwnCount: ${b.PwnCount || "?"} | Date: ${b.BreachDate || "?"} | Data: ${(b.DataClasses || []).join(", ")}`,
      severity: "high" as const,
      timestamp: b.BreachDate || null,
    }));
  } catch { return []; }
}

// ============================================================
//  Wikidata
// ============================================================
async function searchWikidata(query: string, type: QueryType): Promise<SearchResult[]> {
  if (type !== "name") return [];
  try {
    const r = await fetch(`https://www.wikidata.org/w/api.php?action=wbsearchentities&search=${encodeURIComponent(query)}&language=es&language=en&limit=10&format=json&origin=*`, {
      headers: { "User-Agent": "MONITOR-THREAT" },
      signal: AbortSignal.timeout(8000),
    });
    if (!r.ok) return [];
    const d: any = await r.json();
    const required = nameTokens(query);
    return (d.search || []).filter((e: any) => {
      const combined = `${e.label || ""} ${e.description || ""}`.toLowerCase();
      return required.length === 0 || required.every(t => combined.includes(t));
    }).slice(0, 10).map((e: any) => ({
      category: "academic",
      source: "Wikidata",
      type: "entity match",
      title: e.label || query,
      url: `https://www.wikidata.org/wiki/${e.id}`,
      snippet: `${e.description || "(no description)"} [QID: ${e.id}]`,
      severity: "info" as const,
      timestamp: null,
    }));
  } catch { return []; }
}

// ============================================================
//  BING ENGINE — parser
// ============================================================
function decodeBingUrl(ckAurl: string): string | null {
  try {
    const decoded = ckAurl.replace(/&amp;/g, "&");
    const m = decoded.match(/u=a1([A-Za-z0-9+/=_-]+)/);
    if (!m) return null;
    let b64 = m[1];
    b64 = b64.replace(/-/g, "+").replace(/_/g, "/");
    b64 += "=".repeat((4 - (b64.length % 4)) % 4);
    const url = Buffer.from(b64, "base64").toString("utf-8");
    if (!url.startsWith("http")) return null;
    return url;
  } catch { return null; }
}

function parseBingHtml(html: string, query: string, type: QueryType, category: string, severity: "high" | "medium" | "low" | "info"): SearchResult[] {
  const results: SearchResult[] = [];
  const requiredTokens = type === "name" ? nameTokens(query) : [];
  const accentless = requiredTokens.map(t => t.normalize("NFD").replace(/[\u0300-\u036f]/g, ""));
  const blockRe = /<h2[^>]*>\s*<a[^>]*href="(https:\/\/www\.bing\.com\/ck\/a\?[^"]+)"[^>]*>([\s\S]*?)<\/a>\s*<\/h2>([\s\S]*?)(?=<h2|<div class="b_pag|$)/g;
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
    if (requiredTokens.length > 0) {
      const combined = `${title} ${snippet}`.toLowerCase();
      const normalized = combined.normalize("NFD").replace(/[\u0300-\u036f]/g, "");
      if (!requiredTokens.every(t => combined.includes(t)) && !accentless.every(t => normalized.includes(t))) continue;
    }
    results.push({
      category, source: "Bing", type: "search hit",
      title: title.slice(0, 150), url,
      snippet: snippet.slice(0, 250) || "(no snippet)",
      severity, timestamp: null,
    });
    count++;
  }
  return results;
}

async function runDorkOnBing(dork: string, query: string, type: QueryType, category: string, severity: "high" | "medium" | "low" | "info"): Promise<SearchResult[]> {
  try {
    const r = await fetch(
      `https://www.bing.com/search?q=${encodeURIComponent(dork)}&count=20&setlang=en-US&cc=US&FORM=QBLH&nfpr=1`,
      { headers: htmlFetchHeaders(), signal: AbortSignal.timeout(10000) },
    );
    if (!r.ok) return [];
    const html = await r.text();
    return parseBingHtml(html, query, type, category, severity);
  } catch { return []; }
}

// ============================================================
//  MAIN — fast version: 5 dorks en paralelo + APIs en paralelo
// ============================================================
export async function GET(request: Request) {
  try {
    const { searchParams } = new URL(request.url);
    const query = (searchParams.get("q") || "").trim();
    const type = (searchParams.get("type") || "name").trim() as QueryType;
    if (!query) return NextResponse.json({ error: "missing_query" }, { status: 400 });

    const categories = buildDorkCategories(query, type);
    const allDorks = categories.flatMap(c => c.dorks);

    const isUsername = type === "username";
    const isEmail = type === "email";
    const isName = type === "name";

    // LOTE 1 — APIs directas (rápidas, en paralelo)
    const [gh, wiki, ddgIa, gravatar, hibp, wikidata] = await Promise.all([
      (isName || isUsername) ? searchGitHub(query, type) : Promise.resolve([]),
      isName ? searchWikipedia(query, type) : Promise.resolve([]),
      isName ? searchDdgIA(query, type) : Promise.resolve([]),
      isEmail ? searchGravatar(query) : Promise.resolve([]),
      isEmail ? searchHibp() : Promise.resolve([]),
      isName ? searchWikidata(query, type) : Promise.resolve([]),
    ]);

    // LOTE 2 — Bing: ejecutar 5 dorks (las 5 categorias mas relevantes)
    const top5Dorks = categories.slice(0, 5).map(c => ({ dork: c.dorks[0], cat: c.id, sev: c.severity }));
    const bingResults = await Promise.all(top5Dorks.map(t => runDorkOnBing(t.dork, query, type, t.cat, t.sev)));

    // Combinar resultados
    const all: SearchResult[] = [
      ...gh, ...wiki, ...ddgIa, ...gravatar, ...hibp, ...wikidata,
      ...bingResults.flat(),
    ];
    const seen = new Set<string>();
    const deduped = all.filter(r => { if (seen.has(r.url)) return false; seen.add(r.url); return true; });

    // Generar URLs manuales para Google/Yandex/Edge para TODOS los dorks (no solo los 5 ejecutados)
    const manualLinks: Record<string, { google: string; yandex: string; edge: string; bing: string; duckduckgo: string }> = {};
    for (const cat of categories) {
      for (const dork of cat.dorks) {
        manualLinks[dork] = {
          google: `https://www.google.com/search?q=${encodeURIComponent(dork)}`,
          yandex: `https://yandex.com/search/?text=${encodeURIComponent(dork)}`,
          edge: `https://www.bing.com/search?q=${encodeURIComponent(dork)}&form=EDGE&setmkt=en-US`,
          bing: `https://www.bing.com/search?q=${encodeURIComponent(dork)}`,
          duckduckgo: `https://duckduckgo.com/?q=${encodeURIComponent(dork)}`,
        };
      }
    }

    const byCategory: Record<string, number> = {};
    const bySource: Record<string, number> = {};
    const bySeverity = { high: 0, medium: 0, low: 0, info: 0 };
    for (const r of deduped) {
      byCategory[r.category] = (byCategory[r.category] || 0) + 1;
      bySource[r.source] = (bySource[r.source] || 0) + 1;
      bySeverity[r.severity]++;
    }

    return NextResponse.json({
      query, queryType: type,
      categories: categories.map(c => ({ id: c.id, name: c.name, icon: c.icon, severity: c.severity, dorksCount: c.dorks.length })),
      dorks: allDorks,
      dorksByCategory: categories.reduce((acc, c) => { acc[c.id] = c.dorks; return acc; }, {} as Record<string, string[]>),
      dorksExecuted: top5Dorks.length,
      manualLinks,
      sourcesUsed: Object.keys(bySource),
      enginesUsed: ["Bing", "DuckDuckGo", "Google", "Yandex", "Edge"],
      enginesAuto: ["Bing"],
      enginesManual: ["Google", "Yandex", "Edge", "DuckDuckGo"],
      results: deduped,
      summary: {
        total: deduped.length,
        byCategory,
        bySource,
        bySeverity,
        engines: { bing: bingResults.flat().length },
        preciseMatch: { wikipedia: wiki.length, ddg: ddgIa.length, wikidata: wikidata.length },
      },
      timestamp: new Date().toISOString(),
    }, { headers: { "Cache-Control": "no-store" } });
  } catch (err: any) {
    console.error("[executive-osint] ERROR:", err?.message || err);
    return NextResponse.json(
      { error: "internal_error", message: String(err?.message || err), results: [], dorks: [], summary: { total: 0, bySource: {}, byCategory: {}, bySeverity: { high: 0, medium: 0, low: 0, info: 0 } } },
      { status: 500 }
    );
  }
}

export async function OPTIONS() {
  return new NextResponse(null, { status: 204, headers: { "Access-Control-Allow-Origin": "*", "Access-Control-Allow-Methods": "GET, OPTIONS", "Access-Control-Allow-Headers": "*" } });
}
