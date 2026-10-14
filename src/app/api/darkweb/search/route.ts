// Deep & Dark Web Search via Google Programmable Search Engines (CSE)
//
// Usa Google Programmable Search Engines pre-configurados para
// investigaciones OSINT. Cada categoria tiene un CSE ID especifico que
// Google ha indexado con sites relevantes.
//
// Fuentes:
// - Google Custom Search JSON API (free 100 queries/day per API key)
// - 25 CSE IDs pre-configurados para OSINT
// - API key: AIzaSyC2u5gvv4VvHY1GaiaJRz1VYAXdCGovdwc
//
// Categorias disponibles:
// - default (general OSINT)
// - crime, criminal-organizations, criminal-records, cold-cases
// - fraud, money-laundering, sanctions
// - terrorism, extremism
// - narcotics
// - missing-person, murder, sexual-abuse, child-abuse
// - cryptocurrency, trade-index
// - news, politics, religion, history, culture
// - medical
// - social-media
// - satellite, webcams

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
}

// API key publica de Google CSE (100 queries/dia)
const GOOGLE_CSE_API_KEY = "AIzaSyC2u5gvv4VvHY1GaiaJRz1VYAXdCGovdwc";

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
    pagemap?: any;
  }>;
  searchInformation?: {
    totalResults: string;
    searchTime: number;
  };
  error?: { code: number; message: string; status: string };
  queries?: { request?: any[]; nextPage?: any[] };
}

// Llama a Google Custom Search JSON API
async function searchCSE(
  cseId: string,
  query: string,
  start: number = 1,
  num: number = 10,
): Promise<{ results: SearchResult[]; totalResults: number; error: string | null }> {
  try {
    const url = `https://www.googleapis.com/customsearch/v1?key=${GOOGLE_CSE_API_KEY}&cx=${cseId}&q=${encodeURIComponent(query)}&start=${start}&num=${num}`;
    const r = await fetch(url, {
      headers: { "User-Agent": "MONITOR-THREAT/1.0" },
      signal: AbortSignal.timeout(15000),
    });
    if (!r.ok) {
      const errText = await r.text();
      return { results: [], totalResults: 0, error: `HTTP ${r.status}: ${errText.slice(0, 200)}` };
    }
    const d: CSESearchResponse = await r.json();
    if (d.error) {
      return { results: [], totalResults: 0, error: d.error.message };
    }
    const items = d.items || [];
    return {
      results: items.map(it => ({
        source: "Google CSE",
        type: "search hit",
        title: it.title || "(no title)",
        url: it.link,
        snippet: it.snippet || "",
        severity: "info" as const,
        timestamp: null,
        displayLink: it.displayLink,
      })),
      totalResults: parseInt(d.searchInformation?.totalResults || "0"),
      error: null,
    };
  } catch (e: any) {
    return { results: [], totalResults: 0, error: String(e?.message || e) };
  }
}

// GET /api/darkweb/search?q=<query>&category=<cat>&start=<num>
// - category: 'all' para todas las categorias, o un ID de categoria
// - start: pagination offset (default 1)
// - Si category='all', ejecuta en paralelo las 5 categorias mas relevantes
//   para investigacion OSINT (general, fraud, crime, narcotics, terrorism)
//   y combina resultados.
export async function GET(request: Request) {
  try {
    const { searchParams } = new URL(request.url);
    const query = (searchParams.get("q") || "").trim();
    const category = (searchParams.get("category") || "all").trim();
    const start = parseInt(searchParams.get("start") || "1");
    const num = parseInt(searchParams.get("num") || "10");

    if (!query) return NextResponse.json({ error: "missing_query" }, { status: 400 });

    let allResults: SearchResult[] = [];
    let errors: string[] = [];
    let totalResults = 0;
    let categoriesUsed: string[] = [];

    if (category === "all") {
      // Ejecutar 5 categorias mas relevantes en paralelo (limite de rate de CSE)
      const topCategories = ["general", "fraud", "crime", "narcotics", "terrorism"];
      categoriesUsed = topCategories;
      const promises = topCategories.map(async (cat) => {
        const cse = CSE_ENGINES[cat];
        if (!cse) return { cat, results: [], error: "categoria_no_existe" };
        const r = await searchCSE(cse.id, query, 1, 5);  // 5 resultados por categoria
        return { cat, results: r.results, error: r.error, total: r.totalResults };
      });
      const responses = await Promise.all(promises);
      for (const resp of responses) {
        if (resp.error) errors.push(`${resp.cat}: ${resp.error}`);
        // Etiquetar cada resultado con su categoria
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
      }
    } else if (CSE_ENGINES[category]) {
      // Solo una categoria
      categoriesUsed = [category];
      const cse = CSE_ENGINES[category];
      const r = await searchCSE(cse.id, query, start, num);
      if (r.error) errors.push(r.error);
      totalResults = r.totalResults;
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

    // Summary
    const byCategory: Record<string, number> = {};
    const bySeverity = { high: 0, medium: 0, low: 0, info: 0 };
    for (const r of deduped) {
      if (r.category) byCategory[r.category] = (byCategory[r.category] || 0) + 1;
      bySeverity[r.severity]++;
    }

    return NextResponse.json({
      query,
      category,
      categoriesUsed,
      availableCategories: Object.entries(CSE_ENGINES).map(([k, v]) => ({
        id: k, name: v.name, description: v.description, severity: v.severity,
      })),
      results: deduped,
      totalResultsGoogle: totalResults,
      summary: {
        total: deduped.length,
        byCategory,
        bySeverity,
      },
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
