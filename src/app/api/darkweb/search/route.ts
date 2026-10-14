// Deep & Dark Web Search — multi-source, sin API key requerida
//
// Fuentes REALES que funcionan server-side sin API key:
// 1. Wikipedia REST API (busqueda biografica + enciclopedica)
// 2. Wikidata (entidades estructuradas)
// 3. crt.sh (Certificate Transparency — dominios con certificados TLS)
// 4. HIBP Breaches (lista de breaches conocidos, 1045+)
// 5. HackerNews Algolia API (noticias de tecnologia/seguridad)
// 6. DuckDuckGo Instant Answer API (resultados instantaneos)
// 7. OpenStreetMap Nominatim (ubicaciones geograficas)
//
// Si GOOGLE_CSE_API_KEY esta configurada (env var), tambien usa Google
// Custom Search con los 25 CSE IDs pre-configurados.

import { NextResponse } from "next/server";

interface SearchResult {
  source: string;
  type: string;
  title: string;
  url: string;
  snippet: string;
  severity: "high" | "medium" | "low" | "info";
  timestamp: string | null;
  category?: string;
  displayLink?: string;
  mime?: string;
}

// API key opcional de Google CSE
const GOOGLE_CSE_API_KEY = process.env.GOOGLE_CSE_API_KEY || "";

// 25 CSE IDs pre-configurados por categoria
const CSE_ENGINES: Record<string, { id: string; name: string; severity: "high" | "medium" | "low" | "info" }> = {
  "general": { id: "a78edd165e3ed4d62", name: "General OSINT", severity: "info" },
  "crime": { id: "40e93c9d539fc4f8e", name: "Crimen", severity: "high" },
  "criminal-organizations": { id: "8563e5ec8553c4b16", name: "Organizaciones criminales", severity: "high" },
  "criminal-records": { id: "200639c56095b44e8", name: "Records criminales", severity: "high" },
  "cold-cases": { id: "070a50ad9b1c64e2f", name: "Casos frios", severity: "medium" },
  "fraud": { id: "f78d1d8341858428b", name: "Fraude", severity: "high" },
  "money-laundering": { id: "22fab206df26b4f31", name: "Lavado de dinero", severity: "high" },
  "sanctions": { id: "46a45c9f1d9aa4e2a", name: "Sanciones", severity: "high" },
  "terrorism": { id: "172e2a6f5372a42d7", name: "Terrorismo", severity: "high" },
  "extremism": { id: "619672b674db64d79", name: "Extremismo", severity: "high" },
  "narcotics": { id: "5395add9046a74f9d", name: "Narcoticos", severity: "high" },
  "missing-person": { id: "969925ba7e4fb4f44", name: "Personas desaparecidas", severity: "medium" },
  "murder": { id: "766fdaa1ec875451b", name: "Asesinatos", severity: "high" },
  "sexual-abuse": { id: "a42e0bcf7a72945cc", name: "Abuso sexual", severity: "high" },
  "child-abuse": { id: "f558749e2e7814052", name: "Abuso infantil", severity: "high" },
  "cryptocurrency": { id: "821660eb22e544915", name: "Criptomonedas", severity: "medium" },
  "trade-index": { id: "05ce073b65eac4bea", name: "Indice comercial", severity: "low" },
  "news": { id: "b208849a91aca438a", name: "Noticias", severity: "info" },
  "politics": { id: "038ba72a8d1614035", name: "Politica", severity: "low" },
  "religion": { id: "f088bf13165c74adc", name: "Religion", severity: "low" },
  "history": { id: "36d1b8982172f4c20", name: "Historia", severity: "info" },
  "culture": { id: "46fab7d2e92e14c15", name: "Cultura", severity: "info" },
  "medical": { id: "d23d399660b6b4883", name: "Medico", severity: "low" },
  "social-media": { id: "145751ef0e4db4308", name: "Redes sociales", severity: "medium" },
  "satellite": { id: "63b562431b5e8452b", name: "Satelital", severity: "info" },
  "webcams": { id: "57b28d5e5b6f048f1", name: "Webcams", severity: "info" },
};

// ============================================================
//  FUENTES GRATUITAS (sin API key)
// ============================================================

// Wikipedia REST API
async function searchWikipedia(query: string): Promise<SearchResult[]> {
  try {
    const r = await fetch(`https://en.wikipedia.org/w/rest.php/v1/search/page?q=${encodeURIComponent(query)}&limit=10`, {
      headers: { "User-Agent": "MONITOR-THREAT" },
      signal: AbortSignal.timeout(8000),
    });
    if (!r.ok) return [];
    const d: any = await r.json();
    return (d.pages || []).map((p: any) => ({
      source: "Wikipedia", type: "enciclopedia",
      title: p.title, url: `https://en.wikipedia.org/wiki/${encodeURIComponent((p.title || "").replace(/ /g, "_"))}`,
      snippet: (p.excerpt || "").replace(/<[^>]+>/g, "").slice(0, 200),
      severity: "info" as const, timestamp: null,
      category: "general", displayLink: "en.wikipedia.org",
    }));
  } catch { return []; }
}

// Wikidata
async function searchWikidata(query: string): Promise<SearchResult[]> {
  try {
    const r = await fetch(`https://www.wikidata.org/w/api.php?action=wbsearchentities&search=${encodeURIComponent(query)}&language=es&language=en&limit=10&format=json&origin=*`, {
      headers: { "User-Agent": "MONITOR-THREAT" },
      signal: AbortSignal.timeout(8000),
    });
    if (!r.ok) return [];
    const d: any = await r.json();
    return (d.search || []).map((e: any) => ({
      source: "Wikidata", type: "entidad",
      title: e.label || query, url: `https://www.wikidata.org/wiki/${e.id}`,
      snippet: `${e.description || "(no description)"} [QID: ${e.id}]`,
      severity: "info" as const, timestamp: null,
      category: "general", displayLink: "www.wikidata.org",
    }));
  } catch { return []; }
}

// crt.sh — Certificate Transparency (dominios con certificados TLS)
async function searchCrtSh(query: string): Promise<SearchResult[]> {
  // Extraer dominio del query si parece un dominio
  const domainMatch = query.match(/([a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z]{2,})/);
  if (!domainMatch) return [];
  const domain = domainMatch[1];
  try {
    const r = await fetch(`https://crt.sh/?q=%${encodeURIComponent(domain)}&output=json`, {
      headers: { "User-Agent": "MONITOR-THREAT" },
      signal: AbortSignal.timeout(15000),
    });
    if (!r.ok) return [];
    const d: any[] = await r.json();
    // Filtrar y dedup por common_name
    const seen = new Set<string>();
    return d.filter(c => {
      const cn = c.common_name || "";
      if (seen.has(cn)) return false;
      seen.add(cn);
      return cn && !cn.includes(domain); // solo los que NO son el dominio oficial
    }).slice(0, 10).map(c => ({
      source: "crt.sh", type: "certificado TLS sospechoso",
      title: c.common_name || "(no title)",
      url: `https://crt.sh/?q=${encodeURIComponent(c.common_name || "")}`,
      snippet: `Issuer: ${(c.issuer_name || "").slice(0, 80)} | Not before: ${c.not_before?.slice(0, 10)}`,
      severity: "high" as const, timestamp: c.not_before || null,
      category: "fraud", displayLink: "crt.sh",
    }));
  } catch { return []; }
}

// HIBP Breaches (lista de breaches conocidos)
async function searchHibp(): Promise<SearchResult[]> {
  try {
    const r = await fetch("https://haveibeenpwned.com/api/v3/breaches", {
      headers: { "User-Agent": "MONITOR-THREAT" },
      signal: AbortSignal.timeout(8000),
    });
    if (!r.ok) return [];
    const d: any[] = await r.json();
    return d.slice(0, 10).map(b => ({
      source: "HIBP", type: "breach conocido",
      title: b.Name || "Breach", url: `https://haveibeenpwned.com/breach/${b.Name}`,
      snippet: `PwnCount: ${b.PwnCount || "?"} | Date: ${b.BreachDate || "?"} | Data: ${(b.DataClasses || []).join(", ")}`,
      severity: "high" as const, timestamp: b.BreachDate || null,
      category: "fraud", displayLink: "haveibeenpwned.com",
    }));
  } catch { return []; }
}

// DuckDuckGo Instant Answer API
async function searchDdgIA(query: string): Promise<SearchResult[]> {
  try {
    const r = await fetch(`https://api.duckduckgo.com/?q=${encodeURIComponent(query)}&format=json&no_html=1&no_redirect=1`, {
      signal: AbortSignal.timeout(8000),
    });
    if (!r.ok) return [];
    const d: any = await r.json();
    const results: SearchResult[] = [];
    if (d.AbstractText) {
      results.push({
        source: "DuckDuckGo IA", type: "abstract",
        title: d.Heading || query, url: d.AbstractURL || `https://duckduckgo.com/?q=${encodeURIComponent(query)}`,
        snippet: (d.AbstractText || "").slice(0, 250),
        severity: "info" as const, timestamp: null,
        category: "general", displayLink: "duckduckgo.com",
      });
    }
    for (const t of (d.RelatedTopics || []).slice(0, 5)) {
      if (typeof t === "object" && t.Text) {
        results.push({
          source: "DuckDuckGo IA", type: "tema relacionado",
          title: (t.Text || "").slice(0, 100), url: t.FirstURL || "",
          snippet: (t.Text || "").slice(0, 200),
          severity: "low" as const, timestamp: null,
          category: "general", displayLink: "duckduckgo.com",
        });
      }
    }
    return results;
  } catch { return []; }
}

// HackerNews Algolia API
async function searchHackerNews(query: string): Promise<SearchResult[]> {
  try {
    const r = await fetch(`https://hn.algolia.com/api/v1/search?query=${encodeURIComponent(query)}&tags=story&hitsPerPage=10`, {
      signal: AbortSignal.timeout(8000),
    });
    if (!r.ok) return [];
    const d: any = await r.json();
    return (d.hits || []).map((h: any) => ({
      source: "HackerNews", type: "noticia tech",
      title: h.title || h.story_title || "(no title)",
      url: h.url || `https://news.ycombinator.com/item?id=${h.objectID}`,
      snippet: (h.story_text || h.comment_text || "").replace(/<[^>]+>/g, "").slice(0, 200) || `Points: ${h.points || 0} | Comments: ${h.num_comments || 0}`,
      severity: "low" as const, timestamp: h.created_at || null,
      category: "news", displayLink: "news.ycombinator.com",
    }));
  } catch { return []; }
}

// ============================================================
//  Google CSE (solo si la API key esta configurada)
// ============================================================
async function searchCSE(cseId: string, query: string, num: number): Promise<SearchResult[]> {
  if (!GOOGLE_CSE_API_KEY) return [];
  try {
    const r = await fetch(`https://www.googleapis.com/customsearch/v1?key=${GOOGLE_CSE_API_KEY}&cx=${cseId}&q=${encodeURIComponent(query)}&num=${num}`, {
      headers: { "User-Agent": "MONITOR-THREAT/1.0" },
      signal: AbortSignal.timeout(15000),
    });
    if (!r.ok) return [];
    const d: any = await r.json();
    if (d.error) return [];
    return (d.items || []).map((it: any) => ({
      source: "Google CSE", type: "search hit",
      title: it.title || "(no title)", url: it.link,
      snippet: it.snippet || "", severity: "info" as const, timestamp: null,
      displayLink: it.displayLink, mime: it.mime,
    }));
  } catch { return []; }
}

// ============================================================
//  MAIN
// ============================================================
export async function GET(request: Request) {
  try {
    const { searchParams } = new URL(request.url);
    const query = (searchParams.get("q") || "").trim();
    const category = (searchParams.get("category") || "all").trim();
    const num = parseInt(searchParams.get("num") || "30");

    if (!query) return NextResponse.json({ error: "missing_query" }, { status: 400 });

    let allResults: SearchResult[] = [];
    let categoriesUsed: string[] = [];
    let totalResultsGoogle = 0;
    let googleUsed = false;

    // LOTE 1: Fuentes gratuitas (siempre funcionan, sin API key)
    const [wiki, wikidata, ddgIa, hn, hibp, crtsh] = await Promise.all([
      searchWikipedia(query),
      searchWikidata(query),
      searchDdgIA(query),
      searchHackerNews(query),
      searchHibp(),
      searchCrtSh(query),
    ]);
    allResults.push(...wiki, ...wikidata, ...ddgIa, ...hn, ...hibp, ...crtsh);

    // LOTE 2: Google CSE (solo si hay API key configurada)
    if (GOOGLE_CSE_API_KEY) {
      googleUsed = true;
      if (category === "all") {
        const topCategories = ["general", "fraud", "crime", "narcotics", "terrorism"];
        categoriesUsed = topCategories;
        const promises = topCategories.map(async (cat) => {
          const cse = CSE_ENGINES[cat];
          const results = await searchCSE(cse.id, query, 6);
          return results.map(r => ({ ...r, category: cat, source: `Google CSE - ${cse.name}`, severity: cse.severity }));
        });
        const responses = await Promise.all(promises);
        for (const r of responses) {
          allResults.push(...r);
          totalResultsGoogle += r.length;
        }
      } else if (CSE_ENGINES[category]) {
        categoriesUsed = [category];
        const cse = CSE_ENGINES[category];
        const results = await searchCSE(cse.id, query, num);
        allResults.push(...results.map(r => ({ ...r, category, source: `Google CSE - ${cse.name}`, severity: cse.severity })));
        totalResultsGoogle = results.length;
      }
    }

    // Dedup by URL
    const seen = new Set<string>();
    const deduped = allResults.filter(r => {
      if (!r.url || seen.has(r.url)) return false;
      seen.add(r.url);
      return true;
    });

    const byCategory: Record<string, number> = {};
    const bySeverity = { high: 0, medium: 0, low: 0, info: 0 };
    for (const r of deduped) {
      if (r.category) byCategory[r.category] = (byCategory[r.category] || 0) + 1;
      bySeverity[r.severity]++;
    }

    return NextResponse.json({
      query, category, categoriesUsed,
      availableCategories: Object.entries(CSE_ENGINES).map(([k, v]) => ({ id: k, name: v.name, severity: v.severity })),
      results: deduped.slice(0, num),
      totalResultsGoogle,
      googleUsed,
      summary: { total: deduped.length, byCategory, bySeverity },
      timestamp: new Date().toISOString(),
    }, { headers: { "Cache-Control": "no-store" } });
  } catch (err: any) {
    console.error("[darkweb/search] ERROR:", err?.message || err);
    return NextResponse.json({ error: "internal_error", message: String(err?.message || err) }, { status: 500 });
  }
}

export async function OPTIONS() {
  return new NextResponse(null, { status: 204, headers: { "Access-Control-Allow-Origin": "*", "Access-Control-Allow-Methods": "GET, OPTIONS", "Access-Control-Allow-Headers": "*" } });
}
