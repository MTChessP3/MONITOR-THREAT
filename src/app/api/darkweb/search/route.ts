// Deep & Dark Web Search via Google Programmable Search Engines (CSE)
//
// Usa Google Programmable Search Engines pre-configurados para
// investigaciones OSINT. Cada categoria tiene un CSE ID especifico que
// Google ha indexado con sites relevantes.
//
// Soporta todos los parametros de busqueda avanzada (igual que el
// panel completo de osintsear.ch):
//   - query (texto principal)
//   - exactMatch (frase exacta, con comillas)
//   - includeWords (palabras a incluir, con +)
//   - excludeWords (palabras a excluir, con -)
//   - domain (limitar a dominio, con site:)
//   - fileTypes (PDF, DOC, DOCX, XLS, XLSX, PPT, PPTX, TXT, CSV, KML, KMZ)
//   - sortBy (relevance / date)
//   - timeRange (all / hour / day / week / month / year / custom)
//   - customStartDate, customEndDate (YYYY-MM-DD)
//   - language (lr=lang_es, lang_en, etc.)
//   - country (cr=countryCO, etc.)
//   - interfaceLanguage (hl=es, en, etc.)
//   - translateFrom, translateTo (Google Translate API)

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
  formattedUrl?: string;
  mime?: string;
  image?: { url: string; height: number; width: number };
}

// API key de Google CSE — configurable via env var GOOGLE_CSE_API_KEY
// Si no esta configurada, el endpoint devuelve un mensaje claro.
// Para obtener una key gratuita:
//   1. Ir a https://console.cloud.google.com/
//   2. Crear un proyecto (o usar uno existente)
//   3. Habilitar "Custom Search API" en APIs & Services > Library
//   4. Ir a APIs & Services > Credentials > Create Credentials > API Key
//   5. Copiar la key y configurarla como GOOGLE_CSE_API_KEY en Vercel
const GOOGLE_CSE_API_KEY = process.env.GOOGLE_CSE_API_KEY || "";

// 25 CSE IDs pre-configurados por categoria
const CSE_ENGINES: Record<string, { id: string; name: string; description: string; severity: "high" | "medium" | "low" | "info" }> = {
  "general": { id: "a78edd165e3ed4d62", name: "General OSINT", description: "Motor OSINT general", severity: "info" },
  "crime": { id: "40e93c9d539fc4f8e", name: "Crimen", description: "Sites de crimen, policias, criminales", severity: "high" },
  "criminal-organizations": { id: "8563e5ec8553c4b16", name: "Organizaciones criminales", description: "Carteles, mafias, pandillas", severity: "high" },
  "criminal-records": { id: "200639c56095b44e8", name: "Records criminales", description: "Antecedentes penales publicos", severity: "high" },
  "cold-cases": { id: "070a50ad9b1c64e2f", name: "Casos frios", description: "Casos sin resolver historicos", severity: "medium" },
  "fraud": { id: "f78d1d8341858428b", name: "Fraude", description: "Phishing, scams, estafas", severity: "high" },
  "money-laundering": { id: "22fab206df26b4f31", name: "Lavado de dinero", description: "AML, KYC, lavado de activos", severity: "high" },
  "sanctions": { id: "46a45c9f1d9aa4e2a", name: "Sanciones", description: "OFAC, UN, EU sanctions lists", severity: "high" },
  "terrorism": { id: "172e2a6f5372a42d7", name: "Terrorismo", description: "Groups terroristas, radicalizacion", severity: "high" },
  "extremism": { id: "619672b674db64d79", name: "Extremismo", description: "Extremismo politico/religioso", severity: "high" },
  "narcotics": { id: "5395add9046a74f9d", name: "Narcoticos", description: "Trafico de drogas, mercados dark", severity: "high" },
  "missing-person": { id: "969925ba7e4fb4f44", name: "Personas desaparecidas", description: "Casos de desaparicion", severity: "medium" },
  "murder": { id: "766fdaa1ec875451b", name: "Asesinatos", description: "Homicidios, casos resueltos/sin resolver", severity: "high" },
  "sexual-abuse": { id: "a42e0bcf7a72945cc", name: "Abuso sexual", description: "Investigaciones de abuso", severity: "high" },
  "child-abuse": { id: "f558749e2e7814052", name: "Abuso infantil", description: "Proteccion infantil, CSAM reports", severity: "high" },
  "cryptocurrency": { id: "821660eb22e544915", name: "Criptomonedas", description: "Wallets, exchanges, scams crypto", severity: "medium" },
  "trade-index": { id: "05ce073b65eac4bea", name: "Indice comercial", description: "Companies, trade data, registries", severity: "low" },
  "news": { id: "b208849a91aca438a", name: "Noticias", description: "Noticias generales y archivos", severity: "info" },
  "politics": { id: "038ba72a8d1614035", name: "Politica", description: "Politica, gobiernos, elecciones", severity: "low" },
  "religion": { id: "f088bf13165c74adc", name: "Religion", description: "Religion, sectas, extremism religioso", severity: "low" },
  "history": { id: "36d1b8982172f4c20", name: "Historia", description: "Archivo historico, documentos antiguos", severity: "info" },
  "culture": { id: "46fab7d2e92e14c15", name: "Cultura", description: "Arte, musica, literatura", severity: "info" },
  "medical": { id: "d23d399660b6b4883", name: "Medico", description: "Datos medicos, farmacias, salud", severity: "low" },
  "social-media": { id: "145751ef0e4db4308", name: "Redes sociales", description: "Perfiles publicos en redes", severity: "medium" },
  "satellite": { id: "63b562431b5e8452b", name: "Satelital", description: "Imagenes satelitales, geoint", severity: "info" },
  "webcams": { id: "57b28d5e5b6f048f1", name: "Webcams", description: "Camaras publicas, webcams", severity: "info" },
};

interface CSESearchResponse {
  items?: Array<{
    title: string;
    link: string;
    snippet: string;
    displayLink: string;
    formattedUrl?: string;
    htmlSnippet?: string;
    mime?: string;
    pagemap?: any;
  }>;
  searchInformation?: {
    totalResults: string;
    searchTime: number;
  };
  error?: { code: number; message: string; status: string };
  queries?: { request?: any[]; nextPage?: any[] };
}

// Traduce el query via Google Translate API (misma key que CSE)
async function translateQuery(text: string, source: string, target: string): Promise<string> {
  if (!source || !target || source === target) return text;
  try {
    const r = await fetch(`https://translation.googleapis.com/language/translate/v2?key=${GOOGLE_CSE_API_KEY}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ q: text, source, target, format: "text" }),
      signal: AbortSignal.timeout(8000),
    });
    if (!r.ok) return text;
    const d: any = await r.json();
    return d?.data?.translations?.[0]?.translatedText || text;
  } catch { return text; }
}

// Construye el query combinando todos los componentes (igual que osintsear.ch)
function buildQuery(params: {
  query: string;
  exactMatch?: string;
  includeWords?: string;
  excludeWords?: string;
  fileTypes?: string;
  domain?: string;
}): string {
  let q = params.query.trim();
  if (params.exactMatch?.trim()) {
    q += ` "${params.exactMatch.trim()}"`;
  }
  if (params.includeWords?.trim()) {
    const includeTerms = params.includeWords
      .split(/[\s,;]+/)
      .filter(t => t.trim())
      .map(t => `+${t.trim()}`)
      .join(" ");
    q += ` ${includeTerms}`;
  }
  if (params.excludeWords?.trim()) {
    const excludeTerms = params.excludeWords
      .split(/[\s,;]+/)
      .filter(t => t.trim())
      .map(t => `-${t.trim()}`)
      .join(" ");
    q += ` ${excludeTerms}`;
  }
  if (params.fileTypes?.trim()) {
    const ftypes = params.fileTypes.split(",").map(t => t.trim()).filter(Boolean);
    if (ftypes.length > 0) {
      const fileTypeQuery = ftypes.map(t => `filetype:${t}`).join(" OR ");
      q += ` ${fileTypeQuery}`;
    }
  }
  if (params.domain?.trim()) {
    const domains = params.domain
      .split(/[\s,;]+/)
      .filter(d => d.trim())
      .map(d => d.trim().toLowerCase());
    if (domains.length > 0) {
      const domainQuery = domains.map(d => `site:${d}`).join(" OR ");
      q = `(${q}) (${domainQuery})`;
    }
  }
  return q;
}

// Construye el dateRestrict parameter de Google
function buildDateRestrict(timeRange: string, startDate?: string, endDate?: string): string {
  switch (timeRange) {
    case "hour": return "d1";
    case "day": return "d1";
    case "week": return "d7";
    case "month": return "d30";
    case "year": return "d365";
    case "custom":
      if (startDate && endDate) {
        const s = new Date(startDate);
        const e = new Date(endDate);
        const sStr = `${s.getFullYear()}${(s.getMonth() + 1).toString().padStart(2, "0")}${s.getDate().toString().padStart(2, "0")}`;
        const eStr = `${e.getFullYear()}${(e.getMonth() + 1).toString().padStart(2, "0")}${e.getDate().toString().padStart(2, "0")}`;
        return `date:r:${sStr}:${eStr}`;
      }
      return "";
    default: return "";
  }
}

// Google CSE API max is 10 per request. Para obtener N resultados, hacemos
// ceil(N/10) requests en paralelo con start=1, 11, 21, etc.
async function searchCSE(
  cseId: string,
  query: string,
  start: number,
  num: number,
  opts: {
    language?: string;
    country?: string;
    interfaceLanguage?: string;
    dateRestrict?: string;
    sortBy?: string;
  } = {},
): Promise<{ results: SearchResult[]; totalResults: number; error: string | null; nextPageStart?: number }> {
  try {
    const requests: number[] = [];
    let current = start;
    while (requests.length * 10 < num && requests.length < 4) {
      requests.push(current);
      current += 10;
    }
    const promises = requests.map(async (s) => {
      let url = `https://www.googleapis.com/customsearch/v1?key=${GOOGLE_CSE_API_KEY}&cx=${cseId}&q=${encodeURIComponent(query)}&start=${s}&num=10`;
      if (opts.language) url += `&lr=${opts.language}`;
      if (opts.country) url += `&cr=country${opts.country.toUpperCase()}`;
      if (opts.interfaceLanguage) url += `&hl=${opts.interfaceLanguage}`;
      if (opts.dateRestrict) url += `&dateRestrict=${opts.dateRestrict}`;
      if (opts.sortBy === "date") url += `&sort=date`;
      const r = await fetch(url, {
        headers: { "User-Agent": "MONITOR-THREAT/1.0" },
        signal: AbortSignal.timeout(15000),
      });
      if (!r.ok) {
        const errText = await r.text();
        return { items: [], total: 0, error: `HTTP ${r.status}: ${errText.slice(0, 200)}`, nextStart: undefined as number | undefined };
      }
      const d: CSESearchResponse = await r.json();
      if (d.error) {
        return { items: [], total: 0, error: d.error.message, nextStart: undefined as number | undefined };
      }
      const items = (d.items || []).map(it => ({
        source: "Google CSE" as const,
        type: "search hit" as const,
        title: it.title || "(no title)",
        url: it.link,
        snippet: it.snippet || "",
        severity: "info" as const,
        timestamp: null,
        displayLink: it.displayLink,
        formattedUrl: it.formattedUrl,
        mime: it.mime,
      }));
      return { items, total: parseInt(d.searchInformation?.totalResults || "0"), error: null, nextStart: d.queries?.nextPage?.[0]?.startIndex as number | undefined };
    });
    const responses = await Promise.all(promises);
    const allItems: SearchResult[] = [];
    let totalResults = 0;
    let firstError: string | null = null;
    let nextStart: number | undefined;
    for (const r of responses) {
      if (r.error && !firstError) firstError = r.error;
      allItems.push(...r.items);
      if (r.total > totalResults) totalResults = r.total;
      if (r.nextStart) nextStart = r.nextStart;
    }
    // Truncate to requested num
    return {
      results: allItems.slice(0, num),
      totalResults,
      error: firstError,
      nextPageStart: nextStart,
    };
  } catch (e: any) {
    return { results: [], totalResults: 0, error: String(e?.message || e) };
  }
}

// GET /api/darkweb/search con todos los parametros
export async function GET(request: Request) {
  try {
    const { searchParams } = new URL(request.url);
    const query = (searchParams.get("q") || "").trim();
    const category = (searchParams.get("category") || "all").trim();
    const start = parseInt(searchParams.get("start") || "1");
    const num = parseInt(searchParams.get("num") || "30");

    // Parametros avanzados
    const exactMatch = searchParams.get("exactMatch") || "";
    const includeWords = searchParams.get("includeWords") || "";
    const excludeWords = searchParams.get("excludeWords") || "";
    const domain = searchParams.get("domain") || "";
    const fileTypes = searchParams.get("fileTypes") || "";
    const sortBy = searchParams.get("sortBy") || "relevance";
    const timeRange = searchParams.get("timeRange") || "all";
    const customStartDate = searchParams.get("customStartDate") || "";
    const customEndDate = searchParams.get("customEndDate") || "";
    const language = searchParams.get("language") || "";
    const country = searchParams.get("country") || "";
    const interfaceLanguage = searchParams.get("interfaceLanguage") || "";
    const translateFrom = searchParams.get("translateFrom") || "";
    const translateTo = searchParams.get("translateTo") || "";

    // Permitir busqueda sin query principal si hay filtros avanzados
    const hasAnyFilter = exactMatch.trim() || includeWords.trim() || excludeWords.trim() ||
      domain.trim() || fileTypes.trim();
    if (!query && !hasAnyFilter) return NextResponse.json({ error: "missing_query" }, { status: 400 });

    // Verificar que la API key este configurada
    if (!GOOGLE_CSE_API_KEY) {
      return NextResponse.json({
        error: "api_key_not_configured",
        message: "GOOGLE_CSE_API_KEY no esta configurada. Para usar este modulo necesitas una API key gratuita de Google Custom Search.",
        instructions: [
          "1. Ve a https://console.cloud.google.com/",
          "2. Crea un proyecto o usa uno existente",
          "3. Habilita 'Custom Search API' en APIs & Services > Library",
          "4. Ve a APIs & Services > Credentials > Create Credentials > API Key",
          "5. Copia la key y configurala como variable de entorno GOOGLE_CSE_API_KEY en Vercel (Settings > Environment Variables)",
          "6. Es gratis: 100 consultas por dia",
        ],
        results: [],
        summary: { total: 0, byCategory: {}, bySeverity: { high: 0, medium: 0, low: 0, info: 0 } },
      }, { status: 503 });
    }

    // Traducir query si se solicito
    let finalQuery = query;
    if (translateFrom && translateTo && translateFrom !== translateTo) {
      finalQuery = await translateQuery(query, translateFrom, translateTo);
    }

    // Construir query con todos los componentes
    const fullQuery = buildQuery({
      query: finalQuery,
      exactMatch,
      includeWords,
      excludeWords,
      fileTypes,
      domain,
    });

    // Construir dateRestrict
    const dateRestrict = buildDateRestrict(timeRange, customStartDate, customEndDate);

    const opts = { language, country, interfaceLanguage, dateRestrict, sortBy };

    let allResults: SearchResult[] = [];
    let errors: string[] = [];
    let totalResults = 0;
    let categoriesUsed: string[] = [];
    let nextPageStart: number | undefined;

    if (category === "all") {
      // Ejecutar 5 categorias mas relevantes en paralelo
      // 5 categorias × 6 resultados = 30 resultados por pagina
      const topCategories = ["general", "fraud", "crime", "narcotics", "terrorism"];
      categoriesUsed = topCategories;
      const promises = topCategories.map(async (cat) => {
        const cse = CSE_ENGINES[cat];
        if (!cse) return { cat, results: [], error: "categoria_no_existe", total: 0, nextPageStart: undefined as number | undefined };
        const r = await searchCSE(cse.id, fullQuery, 1, 6, opts);
        return { cat, results: r.results, error: r.error, total: r.totalResults, nextPageStart: r.nextPageStart };
      });
      const responses = await Promise.all(promises);
      for (const resp of responses) {
        if (resp.error) errors.push(`${resp.cat}: ${resp.error}`);
        const cseInfo = CSE_ENGINES[resp.cat];
        for (const r of resp.results) {
          allResults.push({
            ...r,
            category: resp.cat,
            source: `Google CSE - ${cseInfo?.name || resp.cat}`,
            severity: cseInfo?.severity || "info",
          });
        }
        totalResults += resp.total;
        if (resp.nextPageStart) nextPageStart = resp.nextPageStart;
      }
    } else if (CSE_ENGINES[category]) {
      categoriesUsed = [category];
      const cse = CSE_ENGINES[category];
      const r = await searchCSE(cse.id, fullQuery, start, num, opts);
      if (r.error) errors.push(r.error);
      totalResults = r.totalResults;
      nextPageStart = r.nextPageStart;
      allResults = r.results.map(it => ({
        ...it,
        category,
        source: `Google CSE - ${cse.name}`,
        severity: cse.severity,
      }));
    } else {
      return NextResponse.json({
        error: "invalid_category",
        message: `Categoria '${category}' no existe. Categorias disponibles: ${Object.keys(CSE_ENGINES).join(", ")}`,
        availableCategories: Object.keys(CSE_ENGINES).map(k => ({ id: k, name: CSE_ENGINES[k].name })),
      }, { status: 400 });
    }

    // Dedup by URL
    const seen = new Set<string>();
    const deduped = allResults.filter(r => {
      if (seen.has(r.url)) return false;
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
      query,
      fullQuery, // query final construido (con exact match, include, exclude, filetypes, domain)
      translatedQuery: finalQuery !== query ? finalQuery : undefined,
      category,
      categoriesUsed,
      availableCategories: Object.entries(CSE_ENGINES).map(([k, v]) => ({
        id: k, name: v.name, description: v.description, severity: v.severity,
      })),
      filters: {
        exactMatch, includeWords, excludeWords, domain, fileTypes,
        sortBy, timeRange, customStartDate, customEndDate,
        language, country, interfaceLanguage, translateFrom, translateTo,
      },
      results: deduped,
      totalResultsGoogle: totalResults,
      nextPageStart,
      summary: { total: deduped.length, byCategory, bySeverity },
      errors: errors.length > 0 ? errors : undefined,
      timestamp: new Date().toISOString(),
    }, { headers: { "Cache-Control": "no-store" } });
  } catch (err: any) {
    console.error("[darkweb/search] ERROR:", err?.message || err);
    return NextResponse.json(
      { error: "internal_error", message: String(err?.message || err) },
      { status: 500 }
    );
  }
}

export async function OPTIONS() {
  return new NextResponse(null, {
    status: 204,
    headers: { "Access-Control-Allow-Origin": "*", "Access-Control-Allow-Methods": "GET, OPTIONS", "Access-Control-Allow-Headers": "*" },
  });
}
