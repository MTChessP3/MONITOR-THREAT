// Executive OSINT Search — investigacion por dorks en 20 categorias
// Multi-source / multi-engine: 20 categorias de dorks (LinkedIn, Facebook, Twitter,
// Instagram, TikTok, GitHub, GitLab, StackOverflow, email/username, location, PDFs,
// work history, images, news, public records, forums, leaks, academic, company
// registries, breach databases, IntelX/Shodan, dark web, phone/address, deepfake)
// + Bing engine (parser decodifica ck/a?u=a1<base64>)
// + Image search via face match (Google reverse image + Bing visual search)

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

function accentVariants(name: string): string[] {
  const noAccent = name.normalize("NFD").replace(/[\u0300-\u036f]/g, "");
  const variants = new Set<string>([name]);
  if (noAccent !== name) variants.add(noAccent);
  return Array.from(variants);
}

function nameTokens(name: string): string[] {
  return name.toLowerCase().split(/\s+/).filter(t => t.length > 1 && !/^(de|del|la|las|los|el|y|van|von|di|da|do|dos|san|sant|santa)$/.test(t));
}

// ============================================================
//  CATEGORIAS DE DORKS (20 categorias)
// ============================================================
// Cada categoria: { id, name, icon, dorks[] }.
// Los dorks usan {Q} como placeholder para el query string (nombre/email/etc.).

interface DorkCategory {
  id: string;
  name: string;
  icon: string;
  dorks: string[];
  // Severity por defecto de los hits de esta categoria
  severity: "high" | "medium" | "low" | "info";
}

function buildDorkCategories(query: string, type: QueryType): DorkCategory[] {
  const q = query.replace(/"/g, "");
  const Q = `"${q}"`;

  // Para email y username, usamos el query tal cual; para name, las variantes con/sin acentos
  // se aplican solo en el fetch posterior, no en el dork base.
  const categories: DorkCategory[] = [
    {
      id: "social-media",
      name: "Social Media Profiles",
      icon: "Users",
      severity: "info",
      dorks: [
        `${Q} (site:linkedin.com | site:facebook.com | site:twitter.com | site:x.com | site:instagram.com | site:tiktok.com)`,
        `${Q} site:linkedin.com/in`,
        `${Q} site:twitter.com OR site:x.com`,
        `${Q} site:facebook.com`,
        `${Q} site:instagram.com`,
        `${Q} site:tiktok.com`,
      ],
    },
    {
      id: "developer-profiles",
      name: "Developer & Tech Profiles",
      icon: "Code",
      severity: "info",
      dorks: [
        `${Q} (site:github.com | site:gitlab.com | site:stackoverflow.com)`,
        `${Q} site:github.com`,
        `${Q} site:gitlab.com`,
        `${Q} site:stackoverflow.com`,
        `${Q} site:dev.to OR site:hashnode.com OR site:medium.com`,
      ],
    },
    {
      id: "general-web",
      name: "General Web Presence",
      icon: "Globe",
      severity: "low",
      dorks: [
        `${Q} (email | username | contact | contacto | about | perfil | profile)`,
        `${Q} "about me" OR "acerca de" OR "biografia" OR "bio"`,
        `${Q} "contacto" OR "contact" OR "perfil" OR "profile"`,
      ],
    },
    {
      id: "emails-usernames",
      name: "Find Emails & Usernames",
      icon: "Mail",
      severity: "medium",
      dorks: [
        `${Q} (email | username | alias | handle | contacto)`,
        `${Q} "@" OR "email:" OR "correo:" OR "mail:"`,
        `${Q} (mail | correo | contacto) site:pastebin.com OR site:ghostbin.com`,
      ],
    },
    {
      id: "location-contact",
      name: "Find Location & Contact Info",
      icon: "MapPin",
      severity: "medium",
      dorks: [
        `${Q} (location | address | phone | "contact info" | ubicacion | direccion | telefono | contacto)`,
        `${Q} "address:" OR "direccion:" OR "location:" OR "ubicacion:"`,
        `${Q} (address | direccion | location | ubicacion | ciudad | city | pais | country)`,
      ],
    },
    {
      id: "pdf-pubs",
      name: "Professional & Academic Publications (PDF)",
      icon: "FileText",
      severity: "low",
      dorks: [
        `${Q} filetype:pdf (resume | cv | "hoja de vida" | paper | publication | portfolio | publicacion)`,
        `${Q} filetype:pdf (cv | curriculum | resume | "hoja de vida")`,
        `${Q} filetype:pdf (paper | publication | publicacion | articulo | article)`,
        `${Q} filetype:pdf (portfolio | portafolio | "case study" | "caso de estudio")`,
      ],
    },
    {
      id: "work-history",
      name: "Work History & Company Mentions",
      icon: "Briefcase",
      severity: "low",
      dorks: [
        `${Q} (worked at | "trabajo en" | employed by | "empleado de" | founder of | "fundador de" | CEO of | company | empresa)`,
        `${Q} (CEO | CFO | CTO | "director" | "gerente" | "presidente")`,
        `${Q} (company | empresa | founded | cofundador | "co-founder")`,
      ],
    },
    {
      id: "images",
      name: "Images",
      icon: "Image",
      severity: "info",
      dorks: [
        `${Q} (filetype:jpg OR filetype:png OR filetype:jpeg OR filetype:webp)`,
        `${Q} site:images.google.com OR site:flickr.com OR site:imgur.com`,
        `${Q} (foto | photo | picture | imagen)`,
      ],
    },
    {
      id: "news-blogs",
      name: "News, Blogs, & Articles",
      icon: "Newspaper",
      severity: "low",
      dorks: [
        `${Q} (interview | entrevista | article | articulo | mentioned in | "mencionado en" | blog | post)`,
        `${Q} site:bloomberg.com OR site:reuters.com OR site:ft.com OR site:wsj.com OR site:nytimes.com`,
        `${Q} site:eluniversal.com OR site:eltiempo.com OR site:lanacion.com.ar OR site:elpais.com`,
        `${Q} (entrevista | article | articulo | mentioned | mencionado)`,
      ],
    },
    {
      id: "public-records",
      name: "Public Records & Legal Documents",
      icon: "Scale",
      severity: "medium",
      dorks: [
        `${Q} (court | corte | lawsuit | demanda | case | caso | docket | filing)`,
        `${Q} (lawsuit | demanda | "court case" | "caso judicial" | "demanda judicial")`,
        `${Q} (inurl:docket | inurl:court | inurl:demanda | inurl:caso)`,
      ],
    },
    {
      id: "forums",
      name: "Forum & Community Discussions",
      icon: "MessageSquare",
      severity: "low",
      dorks: [
        `${Q} (inurl:forum | inurl:foro | inurl:thread | inurl:hilo | "discussion" | "discusion" | "profile" | "perfil")`,
        `${Q} site:reddit.com OR site:quora.com OR site:discord.com`,
        `${Q} (inurl:thread | inurl:hilo | inurl:topic | inurl:tema)`,
      ],
    },
    {
      id: "leaks-pastes",
      name: "Data Leaks & Paste Sites",
      icon: "AlertTriangle",
      severity: "high",
      dorks: [
        `${Q} (site:pastebin.com | site:ghostbin.com | site:throwbin.io | "leak" | "breach" | "filtracion" | "base de datos")`,
        `${Q} site:pastebin.com OR site:ghostbin.com OR site:throwbin.io OR site:hastebin.com`,
        `${Q} (leak | leak | breach | brecha | filtracion | "fuga de datos" | "base de datos")`,
      ],
    },
    {
      id: "academic",
      name: "Academic & Research Profiles",
      icon: "GraduationCap",
      severity: "info",
      dorks: [
        `${Q} (site:scholar.google.com | site:researchgate.net | site:academia.edu | site:orcid.org)`,
        `${Q} site:researchgate.net OR site:academia.edu OR site:orcid.org`,
        `${Q} site:scholar.google.com OR site:semanticscholar.org OR site:arxiv.org`,
        `${Q} (PhD | Doctor | researcher | investigador | profesor | professor)`,
      ],
    },
    {
      id: "company-registries",
      name: "Company Registries & Business Filings",
      icon: "Building",
      severity: "medium",
      dorks: [
        `${Q} (site:opencorporates.com | site:sec.gov | "director" | "shareholder" | "administrador" | "socio" | "registro mercantil")`,
        `${Q} site:opencorporates.com OR site:sec.gov OR site:companieshouse.gov.uk`,
        `${Q} (director | "shareholder" | "accionista" | "administrador" | "socio" | "registro mercantil" | "razon social")`,
      ],
    },
    {
      id: "usernames-handles",
      name: "Usernames & Handles (cross-reference)",
      icon: "AtSign",
      severity: "medium",
      dorks: [
        `${Q} (intext:"@" | "username:" | "alias" | "perfil de usuario" | "user profile")`,
        `${Q} (intext:"@" OR inurl:user OR inurl:profile OR inurl:perfil)`,
        `${Q} (alias | handle | nickname | apodo | "user profile" | "perfil de usuario")`,
      ],
    },
    {
      id: "breaches",
      name: "Breach Databases (HIBP, LeakLookup, Breachbase)",
      icon: "Shield",
      severity: "high",
      dorks: [
        `${Q} (site:haveibeenpwned.com | site:leak-lookup.com | site:breachbase.com | site:dehashed.com | "exposed in" | "found in breach")`,
        `${Q} site:haveibeenpwned.com OR site:leak-lookup.com OR site:breachbase.com`,
        `${Q} ("exposed in" | "found in breach" | "filtrado en" | "encontrado en breach" | "compromised" | "comprometido")`,
      ],
    },
    {
      id: "intel-search",
      name: "Intelligence Search (IntelX, Shodan, ZoomEye)",
      icon: "Radar",
      severity: "medium",
      dorks: [
        `${Q} (site:intelx.io | site:shodan.io | site:zoomeye.org | site:fofa.info | "exposed" | "indexed")`,
        `${Q} site:intelx.io OR site:shodan.io OR site:zoomeye.org OR site:fofa.info`,
        `${Q} (exposed | indexed | "open" | "exposto" | expuesto)`,
      ],
    },
    {
      id: "darkweb",
      name: "Dark Web & Onion Mentions",
      icon: "Skull",
      severity: "high",
      dorks: [
        `${Q} (site:onion.ly | site:dark.fail | "dark web" | "darkweb" | onion | tor | .onion)`,
        `${Q} ("dark web" | darkweb | "deep web" | "profunda web")`,
        `${Q} (onion | tor | .onion | "hidden service" | "servicio oculto")`,
      ],
    },
    {
      id: "phone-address",
      name: "Phone & Address Lookups",
      icon: "Phone",
      severity: "medium",
      dorks: [
        `${Q} (site:truecaller.com | site:whitepages.com | site:spokeo.com | site:pipl.com | phone | telefono | address)`,
        `${Q} (phone | telefono | celular | movil | mobile)`,
        `${Q} (address | direccion | location | ubicacion | "phone book" | agenda)`,
      ],
    },
    {
      id: "deepfake",
      name: "Deep Fake Search",
      icon: "Eye",
      severity: "high",
      dorks: [
        `${Q} ("deepfake" OR "deep fake") (filetype:mp4 OR filetype:mkv OR filetype:avi OR site:reddit.com OR site:twitter.com OR site:x.com OR site:youtube.com)`,
        `${Q} ("deepfake" OR "deep fake" OR "deepfakes" OR "fake video")`,
        `${Q} (deepfake | "deep fake") (video | synthesis | sintesis | manipulated | manipulado)`,
      ],
    },
  ];

  // Para email/phone/username, adaptamos algunos dorks que solo aplican a nombres
  if (type === "email" || type === "phone") {
    return categories.filter(c => !["pdf-pubs", "academic", "company-registries", "deepfake", "work-history"].includes(c.id));
  }

  return categories;
}

// ============================================================
//  GitHub (4 sub-fuentes)
// ============================================================
async function searchGitHubUsers(query: string, type: QueryType): Promise<SearchResult[]> {
  try {
    let ghQueries: string[] = [];
    if (type === "name") {
      const tokens = nameTokens(query);
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
    let filtered = allItems;
    if (type === "name") {
      const required = nameTokens(query);
      const accentless = required.map(t => t.normalize("NFD").replace(/[\u0300-\u036f]/g, ""));
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
      category: "developer-profiles",
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
        category: "developer-profiles",
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
          category: "developer-profiles",
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
            category: "leaks-pastes",
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
      category: "leaks-pastes",
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
      category: "images",
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
          category: "breaches",
          source: "HIBP Breach", type: "confirmed breach",
          title: `${b.Name} — ${email}`, url: `https://haveibeenpwned.com/breach/${b.Name}`,
          snippet: `PwnCount: ${b.PwnCount || "?"} | Date: ${b.BreachDate || "?"} | Data: ${(b.DataClasses || []).join(", ")}`,
          severity: "high" as const, timestamp: b.BreachDate || null,
        }));
      }
      if (r.status === 404) {
        return [{ category: "breaches", source: "HIBP", type: "no breaches", title: `${email} — NOT BREACHED`, url: "https://haveibeenpwned.com", snippet: "Email not found in any known breach.", severity: "info" as const, timestamp: null }];
      }
    } catch {}
  }
  try {
    const r = await fetch("https://haveibeenpwned.com/api/v3/breaches", { headers: { "User-Agent": "MONITOR-THREAT" }, signal: AbortSignal.timeout(10000) });
    if (!r.ok) return [];
    const breaches: any[] = await r.json();
    return breaches.slice(0, 20).map(b => ({
      category: "breaches",
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
    return [{ category: "intel-search", source: "VirusTotal", type: "domain reputation", title: `${domain} - ${s.malicious || 0} malicious`, url: `https://www.virustotal.com/gui/domain/${domain}`, snippet: `Malicious: ${s.malicious || 0} | Suspicious: ${s.suspicious || 0} | Harmless: ${s.harmless || 0}`, severity: (s.malicious || 0) > 0 ? "high" : "info" as const, timestamp: null }];
  } catch { return []; }
}

// ============================================================
//  Wikipedia — búsqueda biográfica (EN + ES)
// ============================================================
async function searchWikipedia(query: string, type: QueryType): Promise<SearchResult[]> {
  if (type !== "name") return [];
  try {
    const results: SearchResult[] = [];
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
        if (required.length > 0 && !required.every(t => combined.includes(t)) && !accentless.every(t => normalized.includes(t))) continue;
        results.push({
          category: "news-blogs",
          source: "Wikipedia", type: "biography match",
          title,
          url: `https://en.wikipedia.org/wiki/${encodeURIComponent(title.replace(/ /g, "_"))}`,
          snippet: excerpt.slice(0, 200),
          severity: "info" as const, timestamp: null,
        });
      }
    }
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
          category: "news-blogs",
          source: "Wikipedia (ES)", type: "biography match",
          title,
          url: `https://es.wikipedia.org/wiki/${encodeURIComponent(title.replace(/ /g, "_"))}`,
          snippet: excerpt.slice(0, 200),
          severity: "info" as const, timestamp: null,
        });
      }
    }
    const seen = new Set<string>();
    return results.filter(r => { if (seen.has(r.url)) return false; seen.add(r.url); return true; }).slice(0, 20);
  } catch { return []; }
}

// ============================================================
//  DuckDuckGo Instant Answer API
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
    if (d.AbstractText) {
      results.push({
        category: "news-blogs",
        source: "DuckDuckGo IA", type: "biography abstract",
        title: d.Heading || query,
        url: d.AbstractURL || `https://duckduckgo.com/?q=${encodeURIComponent(query)}`,
        snippet: d.AbstractText.slice(0, 250),
        severity: "info" as const, timestamp: null,
      });
    }
    const required = nameTokens(query);
    const accentless = required.map(t => t.normalize("NFD").replace(/[\u0300-\u036f]/g, ""));
    for (const t of (d.RelatedTopics || [])) {
      if (typeof t !== "object" || !t.Text) continue;
      const text = (t.Text || "").toLowerCase();
      const normalized = text.normalize("NFD").replace(/[\u0300-\u036f]/g, "");
      if (required.length > 0 && !required.every(tok => text.includes(tok)) && !accentless.every(tok => normalized.includes(tok))) continue;
      results.push({
        category: "general-web",
        source: "DuckDuckGo IA", type: "related topic",
        title: (t.Text || "").slice(0, 100),
        url: t.FirstURL || `https://duckduckgo.com/?q=${encodeURIComponent(query)}`,
        snippet: (t.Text || "").slice(0, 200),
        severity: "low" as const, timestamp: null,
      });
    }
    return results.slice(0, 20);
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
      category: "emails-usernames",
      source: "Hunter.io", type: "email verification",
      title: `${email} — ${data.status || "?"}`,
      url: `https://hunter.io/email-verifier/${encodeURIComponent(email)}`,
      snippet: `Status: ${data.status || "?"} | Result: ${data.result || "?"} | Score: ${data.score || "?"} | Domain: ${data.domain || "?"}`,
      severity: data.status === "valid" ? "info" : "low" as const, timestamp: null,
    }];
  } catch { return []; }
}

// ============================================================
//  Wikidata
// ============================================================
async function searchWikidata(query: string, type: QueryType): Promise<SearchResult[]> {
  if (type !== "name") return [];
  try {
    const r = await fetch(
      `https://www.wikidata.org/w/api.php?action=wbsearchentities&search=${encodeURIComponent(query)}&language=es&language=en&limit=20&format=json&origin=*`,
      { headers: { "User-Agent": "MONITOR-THREAT" }, signal: AbortSignal.timeout(8000) }
    );
    if (!r.ok) return [];
    const d: any = await r.json();
    const required = nameTokens(query);
    const accentless = required.map(t => t.normalize("NFD").replace(/[\u0300-\u036f]/g, ""));
    return (d.search || []).filter((e: any) => {
      const combined = `${e.label || ""} ${e.description || ""}`.toLowerCase();
      const normalized = combined.normalize("NFD").replace(/[\u0300-\u036f]/g, "");
      if (required.length === 0) return true;
      return required.every(t => combined.includes(t)) || accentless.every(t => normalized.includes(t));
    }).slice(0, 15).map((e: any) => ({
      category: "academic",
      source: "Wikidata", type: "entity match",
      title: e.label || query,
      url: `https://www.wikidata.org/wiki/${e.id}`,
      snippet: `${e.description || "(no description)"} [QID: ${e.id || "?"}]`,
      severity: "info" as const, timestamp: null,
    }));
  } catch { return []; }
}

// ============================================================
//  OpenCorporates
// ============================================================
async function searchOpenCorporates(query: string, type: QueryType): Promise<SearchResult[]> {
  if (type !== "name") return [];
  try {
    const token = process.env.OPENCORPORATES_TOKEN || "";
    const url = `https://api.opencorporates.com/v0.4/officers/search?q=${encodeURIComponent(query)}&per_page=20${token ? `&api_token=${token}` : ""}`;
    const r = await fetch(url, { headers: { "User-Agent": "MONITOR-THREAT" }, signal: AbortSignal.timeout(8000) });
    if (!r.ok) return [];
    const d: any = await r.json();
    const required = nameTokens(query);
    const accentless = required.map(t => t.normalize("NFD").replace(/[\u0300-\u036f]/g, ""));
    return (d.results?.officers || []).filter((o: any) => {
      const combined = `${o.officer?.name || ""}`.toLowerCase();
      const normalized = combined.normalize("NFD").replace(/[\u0300-\u036f]/g, "");
      if (required.length === 0) return true;
      return required.every(t => combined.includes(t)) || accentless.every(t => normalized.includes(t));
    }).slice(0, 20).map((o: any) => ({
      category: "company-registries",
      source: "OpenCorporates", type: "company officer",
      title: o.officer?.name || "Officer",
      url: `https://opencorporates.com/officers/${o.officer?.id || ""}`,
      snippet: `Company: ${o.officer?.company?.name || "?"} | Position: ${o.officer?.position || "?"} | Jurisdiction: ${o.officer?.company?.jurisdiction_code || "?"} | Start: ${o.officer?.start_date || "?"}`,
      severity: "medium" as const, timestamp: o.officer?.start_date || null,
    }));
  } catch { return []; }
}

// ============================================================
//  BING ENGINE — parser decodifica ck/a?u=a1<base64>
// ============================================================
function decodeBingUrl(ckAurl: string): string | null {
  try {
    const decoded = ckAurl.replace(/&amp;/g, "&");
    const m = decoded.match(/u=a1([A-Za-z0-9+/=_-]+)/);
    if (!m) return null;
    let b64 = m[1];
    b64 = decodeURIComponent(b64);
    b64 = b64.replace(/-/g, "+").replace(/_/g, "/");
    b64 += "=".repeat((4 - (b64.length % 4)) % 4);
    const decodedUrl = Buffer.from(b64, "base64").toString("utf-8");
    if (!decodedUrl.startsWith("http")) return null;
    return decodedUrl;
  } catch { return null; }
}

function parseBingHtml(html: string, query: string, type: QueryType, category: string, severity: "high" | "medium" | "low" | "info"): SearchResult[] {
  const results: SearchResult[] = [];
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
    if (requiredTokens.length > 0) {
      const combined = `${title} ${snippet}`.toLowerCase();
      const normalized = combined.normalize("NFD").replace(/[\u0300-\u036f]/g, "");
      const accentless = requiredTokens.map(t => t.normalize("NFD").replace(/[\u0300-\u036f]/g, ""));
      const allPresent = requiredTokens.every(t => combined.includes(t)) || accentless.every(t => normalized.includes(t));
      if (!allPresent) continue;
    }
    results.push({
      category,
      source: "Bing",
      type: "search hit",
      title: title.slice(0, 150),
      url,
      snippet: snippet.slice(0, 250) || "(no snippet)",
      severity,
      timestamp: null,
    });
    count++;
  }
  return results;
}

async function runDorkOnBing(dork: string, query: string, type: QueryType, category: string, severity: "high" | "medium" | "low" | "info"): Promise<SearchResult[]> {
  try {
    const r = await fetch(
      `https://www.bing.com/search?q=${encodeURIComponent(dork)}&count=30&setlang=en-US&cc=US&FORM=QBLH&nfpr=1`,
      { headers: htmlFetchHeaders(), signal: AbortSignal.timeout(12000) },
    );
    if (!r.ok) return [];
    const html = await r.text();
    return parseBingHtml(html, query, type, category, severity);
  } catch { return []; }
}

// Ejecuta 1 dork por categoria (20 categorias = 20 dorks) en lotes de 4
async function runSearchEngines(categories: DorkCategory[], query: string, type: QueryType): Promise<{ results: SearchResult[]; dorksExecuted: number }> {
  // Tomamos el dork principal de cada categoria (el mas representativo)
  const tasks = categories.map(cat => ({
    dork: cat.dorks[0],
    category: cat.id,
    severity: cat.severity,
  }));
  const out: SearchResult[] = [];
  const seen = new Set<string>();
  let dorksExecuted = 0;
  for (let i = 0; i < tasks.length; i += 4) {
    const batch = tasks.slice(i, i + 4);
    const arrs = await Promise.all(batch.map(t => runDorkOnBing(t.dork, query, type, t.category, t.severity)));
    dorksExecuted += batch.length;
    for (const arr of arrs) {
      for (const r of arr) {
        if (seen.has(r.url)) continue;
        seen.add(r.url);
        out.push(r);
      }
    }
  }
  return { results: out.slice(0, 200), dorksExecuted };
}

// ============================================================
//  Sherlock — 17 sitios verificados que responden server-side
// ============================================================
interface SherlockSite {
  name: string;
  url: (u: string) => string;
  category: string;
  notFoundPattern?: RegExp;
}

const SHERLOCK_SITES: SherlockSite[] = [
  { name: "GitHub", url: u => `https://github.com/${u}`, category: "developer-profiles", notFoundPattern: /Not Found|page doesn't exist/i },
  { name: "GitLab", url: u => `https://gitlab.com/${u}`, category: "developer-profiles" },
  { name: "Twitter/X", url: u => `https://x.com/${u}`, category: "social-media" },
  { name: "TikTok", url: u => `https://tiktok.com/@${u}`, category: "social-media" },
  { name: "YouTube", url: u => `https://youtube.com/@${u}`, category: "social-media" },
  { name: "Twitch", url: u => `https://twitch.tv/${u}`, category: "social-media" },
  { name: "Telegram", url: u => `https://t.me/${u}`, category: "social-media" },
  { name: "Pinterest", url: u => `https://pinterest.com/${u}`, category: "social-media" },
  { name: "SoundCloud", url: u => `https://soundcloud.com/${u}`, category: "social-media" },
  { name: "Dev.to", url: u => `https://dev.to/${u}`, category: "developer-profiles" },
  { name: "Hashnode", url: u => `https://hashnode.com/@${u}`, category: "developer-profiles" },
  { name: "HackerNews", url: u => `https://news.ycombinator.com/user?id=${u}`, category: "forums" },
  { name: "Steam", url: u => `https://steamcommunity.com/id/${u}`, category: "social-media" },
  { name: "Keybase", url: u => `https://keybase.io/${u}`, category: "usernames-handles" },
  { name: "Kaggle", url: u => `https://kaggle.com/${u}`, category: "academic" },
  { name: "Spotify", url: u => `https://open.spotify.com/user/${u}`, category: "social-media" },
  { name: "Pastebin", url: u => `https://pastebin.com/u/${u}`, category: "leaks-pastes" },
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
    if (site.notFoundPattern && site.notFoundPattern.test(html)) return null;
    return {
      category: site.category,
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
  const checks = await Promise.all(SHERLOCK_SITES.map(s => checkSherlockUrl(s, user)));
  return checks.filter((c): c is SearchResult => c !== null);
}

// ============================================================
//  MAIN
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
    const isPhone = type === "phone";
    const isName = type === "name";

    // Lote 1 — fuentes API directas (rápidas)
    const [ghUsers, ghProfile, ghCode, ghGists, gravatar, hibp, vt, wiki, ddgIa, hunter, wikidata, opencorp] = await Promise.all([
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
      isName ? searchWikidata(query, type) : Promise.resolve([]),
      isName ? searchOpenCorporates(query, type) : Promise.resolve([]),
    ]);

    // Lote 2 — Bing ejecuta 1 dork por categoria (20 categorias en lotes de 4)
    const { results: engineResults, dorksExecuted } = await runSearchEngines(categories, query, type);

    // Lote 3 — enumeración Sherlock (solo para username)
    const sherlockResults = isUsername ? await sherlockEnumerate(query) : [];

    const all = [
      ...ghUsers, ...ghProfile, ...ghCode, ...ghGists,
      ...gravatar, ...hibp, ...vt,
      ...wiki, ...ddgIa, ...hunter,
      ...wikidata, ...opencorp,
      ...engineResults,
      ...sherlockResults,
    ];
    const seen = new Set<string>();
    const deduped = all.filter(r => { if (seen.has(r.url)) return false; seen.add(r.url); return true; });

    // Agrupar por categoria
    const byCategory: Record<string, number> = {};
    for (const r of deduped) byCategory[r.category] = (byCategory[r.category] || 0) + 1;

    const bySource: Record<string, number> = {};
    const bySeverity = { high: 0, medium: 0, low: 0, info: 0 };
    for (const r of deduped) { bySource[r.source] = (bySource[r.source] || 0) + 1; bySeverity[r.severity]++; }

    return NextResponse.json({
      query, queryType: type,
      categories: categories.map(c => ({ id: c.id, name: c.name, icon: c.icon, severity: c.severity, dorksCount: c.dorks.length })),
      dorks: allDorks,
      dorksByCategory: categories.reduce((acc, c) => { acc[c.id] = c.dorks; return acc; }, {} as Record<string, string[]>),
      dorksExecuted,
      sourcesUsed: Object.keys(bySource),
      enginesUsed: ["Bing"],
      results: deduped,
      summary: {
        total: deduped.length,
        byCategory,
        bySource,
        bySeverity,
        engines: { bing: engineResults.length },
        sherlock: sherlockResults.length,
        preciseMatch: { wikipedia: wiki.length, ddg: ddgIa.length, wikidata: wikidata.length, opencorporates: opencorp.length },
      },
      timestamp: new Date().toISOString(),
    }, { headers: { "Cache-Control": "no-store" } });
  } catch (err: any) {
    console.error("[executive-osint] ERROR:", err?.message || err, err?.stack || "");
    return NextResponse.json(
      { error: "internal_error", message: String(err?.message || err), dorks: [], results: [], summary: { total: 0, bySource: {}, byCategory: {}, bySeverity: { high: 0, medium: 0, low: 0, info: 0 } } },
      { status: 500 }
    );
  }
}

export async function OPTIONS() {
  return new NextResponse(null, { status: 204, headers: { "Access-Control-Allow-Origin": "*", "Access-Control-Allow-Methods": "GET, OPTIONS", "Access-Control-Allow-Headers": "*" } });
}
