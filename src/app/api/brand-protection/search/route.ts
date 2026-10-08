// Brand Protection — Phishing detection for 9 pre-configured brands
//
// Brands: Bancolombia, Nequi, Wenia, Banco Agricola, Banco Agro Mercantil,
// Cibest, SUFI, WOMPI, Zaswin.
//
// Estrategia:
//   1. Genera dorks anti-phishing por cada marca (login, account, secure,
//      verificar, suspender, etc. + typosquatting variations).
//   2. Ejecuta SOLO 5 dorks por marca en Bing (en lotes de 4) — rapido <8s.
//   3. DuckDuckGo en paralelo (3 dorks por marca).
//   4. Devuelve resultados categorizados por marca + tipo (phishing/typosquatting/leak).
//   5. Genera URLs manuales para Google/Yandex/Edge para todos los dorks.

import { NextResponse } from "next/server";

interface BrandResult {
  brand: string;
  category: string;          // phishing | typosquatting | leak | impersonation | app
  source: string;             // Bing | DuckDuckGo | Manual
  type: string;
  title: string;
  url: string;
  snippet: string;
  severity: "high" | "medium" | "low" | "info";
  timestamp: string | null;
}

// 9 marcas pre-configuradas con metadatos
interface Brand {
  id: string;
  name: string;
  officialDomain: string;     // dominio oficial para excluir de resultados
  aliases: string[];          // nombres alternativos
  typos: string[];            // typosquatting variations comunes
  category: string;            // Bancos, Fintech, Cooperativas, etc.
}

const BRANDS: Brand[] = [
  {
    id: "bancolombia",
    name: "Bancolombia",
    officialDomain: "bancolombia.com",
    aliases: ["Bancolombia"],
    typos: ["banc0lombia", "bancolomb1a", "ban-colombia", "bancolombiia", "bancolombia-app"],
    category: "Bancos",
  },
  {
    id: "nequi",
    name: "Nequi",
    officialDomain: "nequi.com.co",
    aliases: ["Nequi"],
    typos: ["n3qui", "neki", "nequii", "nequi-app", "nequi-bancolombia"],
    category: "Fintech",
  },
  {
    id: "wenia",
    name: "Wenia",
    officialDomain: "wenia.com",
    aliases: ["Wenia"],
    typos: ["w3nia", "wenia-app", "wenia-bancolombia"],
    category: "Fintech",
  },
  {
    id: "banco-agricola",
    name: "Banco Agricola",
    officialDomain: "bancoagricola.com",
    aliases: ["Banco Agricola", "bancoagricola"],
    typos: ["banco-agricola", "bancoagricola-el-salvador"],
    category: "Bancos",
  },
  {
    id: "banco-agro-mercantil",
    name: "Banco Agro Mercantil",
    officialDomain: "agromercantil.com.bo",
    aliases: ["Banco Agro Mercantil", "BAM Bolivia"],
    typos: ["banco-agro-mercantil", "agro-mercantil"],
    category: "Bancos",
  },
  {
    id: "cibest",
    name: "Cibest",
    officialDomain: "cibest.com",
    aliases: ["Cibest"],
    typos: ["c1best", "cib3st", "cibest-app"],
    category: "Servicios Financieros",
  },
  {
    id: "sufi",
    name: "SUFI",
    officialDomain: "sufi.com.co",
    aliases: ["SUFI", "Sufi Bancolombia"],
    typos: ["suf1", "sufi-bancolombia", "sufi-app"],
    category: "Servicios Financieros",
  },
  {
    id: "wompi",
    name: "WOMPI",
    officialDomain: "wompi.co",
    aliases: ["WOMPI", "Wompi"],
    typos: ["w0mpi", "wompi-app", "wompi-payments"],
    category: "Pagos",
  },
  {
    id: "zaswin",
    name: "Zaswin",
    officialDomain: "zaswin.com",
    aliases: ["Zaswin"],
    typos: ["zasw1n", "zas-win", "zaswin-app"],
    category: "Servicios Financieros",
  },
];

// Generar dorks anti-phishing para una marca
// IMPORTANTE: buscamos dominios que contengan la marca en el hostname
// (no solo mencionen la marca en el snippet). El filtro isResultRelevant
// valida que el hostname contenga la marca o un typo conocido.
function generateBrandDorks(brand: Brand): { phishing: string[]; typosquatting: string[]; leak: string[]; impersonation: string[] } {
  const name = brand.name;
  const officialDomain = brand.officialDomain;

  // Dorks de phishing: combinaciones de marca + palabras de phishing
  // en el title/snippet. El filtro isResultRelevant eliminara los que
  // no contengan la marca en el hostname.
  const phishing = [
    `${name} ("iniciar sesion" OR "acceder" OR "mi cuenta" OR login) -site:${officialDomain}`,
    `${name} ("verificar" OR "suspendida" OR "bloqueada" OR "reactivar") -site:${officialDomain}`,
    `${name} ("actualizar datos" OR "confirmar identidad" OR "verificacion de cuenta") -site:${officialDomain}`,
    `${name} ("cambiar clave" OR "restablecer contrasena" OR "recuperar cuenta") -site:${officialDomain}`,
    `${name} ("transferencia segura" OR "pago verificado" OR "tarjeta bloqueada") -site:${officialDomain}`,
    `${name} (estafa OR scam OR phishing OR fraude OR "phishing") -site:${officialDomain}`,
  ];

  // Typosquatting: buscar los typos conocidos como strings (no site:)
  // porque site:dominio-falso no funciona en Bing
  const typosquatting = [
    ...brand.typos.map(t => `"${t}" (login OR cuenta OR banco OR acceso)`),
    `"${name}" typosquatting OR cybersquatting OR "domain squatting"`,
    `"${name}" ("clone" OR "fake site" OR "sitio falso") -site:${officialDomain}`,
  ];

  // Leaks: credenciales filtradas
  const leak = [
    `${name} (site:pastebin.com OR site:ghostbin.com OR site:throwbin.io)`,
    `${name} ("credenciales filtradas" OR "leak" OR "filtracion" OR "breach")`,
    `${name} ("AWS_SECRET" OR "api_key" OR "private_key" OR "BEGIN RSA")`,
  ];

  // Impersonation: redes sociales
  const impersonation = [
    `${name} site:facebook.com (fake OR impersonation OR clone OR estafa)`,
    `${name} site:twitter.com OR site:x.com (fake OR scam OR estafa)`,
    `${name} site:instagram.com (fake OR clone OR estafa)`,
  ];

  return { phishing, typosquatting, leak, impersonation };
}

// ============================================================
//  FILTRO DE FALSOS POSITIVOS — solo URLs que contienen la marca
// ============================================================
// Dominios conocidos que NUNCA son phishing de la marca (excluirlos)
const KNOWN_SAFE_DOMAINS = [
  // Enciclopedias y referencias
  "wikipedia.org", "wikidata.org", "wikimedia.org",
  // Redes sociales y multimedia
  "youtube.com", "youtu.be", "facebook.com", "fb.com",
  "twitter.com", "x.com", "instagram.com", "linkedin.com", "tiktok.com",
  "github.com", "gitlab.com", "bitbucket.org", "reddit.com",
  "pinterest.com", "pinterest.co", "pinterest.es", "tumblr.com",
  "flickr.com", "imgur.com", "vimeo.com", "twitch.tv", "snapchat.com",
  "whatsapp.com", "telegram.org",
  // E-commerce
  "amazon.com", "amazon.es", "amazon.co", "ebay.com", "mercadolibre.com",
  "aliexpress.com", "alibaba.com", "etsy.com",
  // Buscadores y Microsoft
  "google.com", "google.es", "google.co", "google.com.co",
  "bing.com", "duckduckgo.com", "yahoo.com", "msn.com",
  "microsoft.com", "live.com", "office.com", "outlook.com",
  "apple.com", "icloud.com",
  // Viajes
  "booking.com", "airbnb.com", "tripadvisor.com", "expedia.com",
  "hoteles.com", "trivago.es", "despegar.com",
  // Autos
  "toyota.com", "toyota.es", "honda.com", "ford.com", "volkswagen.com",
  "coches.net", "motor.es", "carwow.es", "ofertas-toyota.com",
  // Retail
  "lowes.com", "homedepot.com", "walmart.com", "target.com", "costco.com",
  // Streaming
  "netflix.com", "hulu.com", "disney.com", "disneyplus.com",
  "spotify.com", "soundcloud.com", "pandora.com",
  // Maps y ubicaciones
  "maps.google", "google.com/maps", "maps.google.es",
  "comunidad.madrid", "madrid.es", "esmadrid.com", "visitmadrid.es",
  "geoportal.madrid.es", "munimadrid.es",
  // Otros irrelevantes
  "instrument.com.cn", "bbs.instrument.com.cn",
  "artofit.org", "tse3.mm.bing.net", "r.bing.com",
  "th.bing.com", "bing.net",
  "play.google.com", "apps.apple.com",
  "news.google.com",
];

// Palabras clave que indican phishing (en title o snippet)
const PHISHING_KEYWORDS = /login|iniciar sesi[oó]n|acceder|mi cuenta|verificar|suspender|bloquear|reactivar|actualizar datos|confirmar identidad|cambiar clave|restablecer contrase[nñ]a|recuperar cuenta|transferencia|clave|contrase[nñ]a|password|cuenta|acceso|tarjeta/i;

function isResultRelevant(brand: Brand, resultUrl: string, title: string, snippet: string): boolean {
  const lowerUrl = resultUrl.toLowerCase();
  const lowerTitle = (title || "").toLowerCase();
  const lowerSnippet = (snippet || "").toLowerCase();
  const name = brand.name.toLowerCase();
  const nameNoSpace = name.replace(/\s+/g, "");
  const allBrandVariants = [name, nameNoSpace, ...brand.typos];

  // 1. Excluir dominios seguros conocidos (no phishing)
  for (const safe of KNOWN_SAFE_DOMAINS) {
    if (lowerUrl.includes(safe)) return false;
  }

  // 2. Excluir el dominio oficial de la marca (todas sus variantes)
  if (lowerUrl.includes(brand.officialDomain)) return false;

  // 3. Verificar relevancia: el hostname DEBE contener la marca o un typo
  try {
    const url = new URL(resultUrl);
    const host = url.hostname.toLowerCase();
    const hostHasBrand = allBrandVariants.some(v => v.length >= 3 && host.includes(v));

    if (hostHasBrand) {
      // El hostname contiene la marca → potencial phishing/typosquatting
      return true;
    }

    // Si el hostname no contiene la marca, solo relevante si:
    // - El title contiene la marca
    // - El title/snippet contiene palabras de phishing
    const titleHasBrand = allBrandVariants.some(v => v.length >= 3 && lowerTitle.includes(v));
    const hasPhishingKw = PHISHING_KEYWORDS.test(lowerTitle + " " + lowerSnippet);
    if (titleHasBrand && hasPhishingKw) return true;

    return false;
  } catch { return false; }
}

function htmlFetchHeaders(): Record<string, string> {
  return {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9,es;q=0.8",
  };
}

// ============================================================
//  BING ENGINE
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

function parseBingHtml(html: string): { url: string; title: string; snippet: string }[] {
  const results: { url: string; title: string; snippet: string }[] = [];
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
    results.push({ url, title: title.slice(0, 150), snippet: snippet.slice(0, 250) || "(no snippet)" });
    count++;
  }
  return results;
}

async function runDorkOnBing(dork: string): Promise<{ url: string; title: string; snippet: string }[]> {
  try {
    const r = await fetch(
      `https://www.bing.com/search?q=${encodeURIComponent(dork)}&count=20&setlang=es-ES&cc=ES&FORM=QBLH&nfpr=1`,
      { headers: htmlFetchHeaders(), signal: AbortSignal.timeout(10000) },
    );
    if (!r.ok) return [];
    const html = await r.text();
    return parseBingHtml(html);
  } catch { return []; }
}

// ============================================================
//  DUCKDUCKGO ENGINE
// ============================================================
function parseDdgHtml(html: string): { url: string; title: string; snippet: string }[] {
  const results: { url: string; title: string; snippet: string }[] = [];
  const blockRe = /<a[^>]*class="result__a"[^>]*href="([^"]+)"[^>]*>([\s\S]*?)<\/a>[\s\S]*?<a[^>]*class="result__snippet"[^>]*>([\s\S]*?)<\/a>/g;
  let m: RegExpExecArray | null;
  let count = 0;
  while ((m = blockRe.exec(html)) && count < 30) {
    let href = m[1];
    const titleHtml = m[2];
    const snippetHtml = m[3];
    const uddgMatch = href.match(/uddg=([^&]+)/);
    if (uddgMatch) {
      try { href = decodeURIComponent(uddgMatch[1]); } catch {}
    }
    if (!href.startsWith("http")) continue;
    const title = titleHtml.replace(/<[^>]+>/g, "").trim();
    if (!title) continue;
    const snippet = snippetHtml.replace(/<[^>]+>/g, "").trim();
    results.push({ url: href, title: title.slice(0, 150), snippet: snippet.slice(0, 250) || "(no snippet)" });
    count++;
  }
  return results;
}

async function runDorkOnDDG(dork: string): Promise<{ url: string; title: string; snippet: string }[]> {
  try {
    const r = await fetch(
      `https://html.duckduckgo.com/html/?q=${encodeURIComponent(dork)}`,
      { headers: htmlFetchHeaders(), signal: AbortSignal.timeout(10000) },
    );
    if (!r.ok) return [];
    const html = await r.text();
    return parseDdgHtml(html);
  } catch { return []; }
}

// ============================================================
//  Genera URLs manuales para Google/Yandex/Edge/Bing/DDG
// ============================================================
function buildManualLinks(dork: string): { google: string; yandex: string; edge: string; bing: string; duckduckgo: string } {
  return {
    google: `https://www.google.com/search?q=${encodeURIComponent(dork)}`,
    yandex: `https://yandex.com/search/?text=${encodeURIComponent(dork)}`,
    edge: `https://www.bing.com/search?q=${encodeURIComponent(dork)}&form=EDGE&setmkt=en-US`,
    bing: `https://www.bing.com/search?q=${encodeURIComponent(dork)}`,
    duckduckgo: `https://duckduckgo.com/?q=${encodeURIComponent(dork)}`,
  };
}

// ============================================================
//  MAIN — busca phishing para las 9 marcas
// ============================================================
export async function GET(request: Request) {
  try {
    const { searchParams } = new URL(request.url);
    // Marca a buscar: 'all' para todas, o el id de una marca especifica
    const brandId = (searchParams.get("brand") || "all").trim();
    const brandsToSearch = brandId === "all" ? BRANDS : BRANDS.filter(b => b.id === brandId);

    if (brandsToSearch.length === 0) {
      return NextResponse.json({ error: "brand_not_found", brand: brandId }, { status: 400 });
    }

    const allResults: BrandResult[] = [];
    const dorksByBrand: Record<string, { phishing: string[]; typosquatting: string[]; leak: string[]; impersonation: string[] }> = {};
    const manualLinks: Record<string, { google: string; yandex: string; edge: string; bing: string; duckduckgo: string }> = {};

    // Para cada marca, generar dorks y ejecutar los principales
    // Hacemos brands en lotes de 3 en paralelo para no saturar
    for (let bi = 0; bi < brandsToSearch.length; bi += 3) {
      const brandBatch = brandsToSearch.slice(bi, bi + 3);

      await Promise.all(brandBatch.map(async (brand) => {
        const dorks = generateBrandDorks(brand);
        dorksByBrand[brand.id] = dorks;

        // Generar manualLinks para TODOS los dorks de esta marca
        for (const cat of ["phishing", "typosquatting", "leak", "impersonation"] as const) {
          for (const d of dorks[cat]) {
            manualLinks[d] = buildManualLinks(d);
          }
        }

        // Ejecutar en Bing + DDG en paralelo: 5 dorks de phishing + 2 typosquatting + 1 leak
        // = 8 dorks en Bing, 3 en DDG (los 3 primeros de phishing)
        const dorksToExecute: { dork: string; category: string; severity: "high" | "medium" | "low" | "info" }[] = [
          ...dorks.phishing.slice(0, 5).map(d => ({ dork: d, category: "phishing", severity: "high" as const })),
          ...dorks.typosquatting.slice(0, 2).map(d => ({ dork: d, category: "typosquatting", severity: "high" as const })),
          ...dorks.leak.slice(0, 1).map(d => ({ dork: d, category: "leak", severity: "high" as const })),
        ];

        // Ejecutar en lotes de 4 en Bing (en paralelo con DDG para los 3 primeros)
        const bingTasks = dorksToExecute.map(t => runDorkOnBing(t.dork));
        const ddgTasks = dorksToExecute.slice(0, 3).map(t => runDorkOnDDG(t.dork));

        const [bingResults, ddgResults] = await Promise.all([
          Promise.all(bingTasks),
          Promise.all(ddgTasks),
        ]);

        // Combinar resultados
        const seen = new Set<string>();
        const addResults = (
          results: { url: string; title: string; snippet: string }[],
          dorkMeta: { category: string; severity: "high" | "medium" | "low" | "info" },
          source: "Bing" | "DuckDuckGo",
        ) => {
          for (const r of results) {
            if (seen.has(r.url)) continue;
            // Aplicar filtro de relevancia (excluye dominios seguros conocidos
            // y resultados donde la marca no esta en el dominio ni en title+login kw)
            if (!isResultRelevant(brand, r.url, r.title, r.snippet)) continue;
            seen.add(r.url);
            allResults.push({
              brand: brand.name,
              category: dorkMeta.category,
              source,
              type: `${dorkMeta.category} detection`,
              title: r.title,
              url: r.url,
              snippet: r.snippet,
              severity: dorkMeta.severity,
              timestamp: null,
            });
          }
        };

        // Bing: 8 dorks × resultados
        bingResults.forEach((res, i) => addResults(res, dorksToExecute[i], "Bing"));
        // DDG: 3 dorks × resultados
        ddgResults.forEach((res, i) => addResults(res, dorksToExecute[i], "DuckDuckGo"));
      }));
    }

    // Resumen por marca y categoria
    const byBrand: Record<string, number> = {};
    const byCategory: Record<string, number> = {};
    const bySeverity = { high: 0, medium: 0, low: 0, info: 0 };
    for (const r of allResults) {
      byBrand[r.brand] = (byBrand[r.brand] || 0) + 1;
      byCategory[r.category] = (byCategory[r.category] || 0) + 1;
      bySeverity[r.severity]++;
    }

    return NextResponse.json({
      brands: BRANDS.map(b => ({ id: b.id, name: b.name, category: b.category, officialDomain: b.officialDomain })),
      searchedBrands: brandsToSearch.map(b => b.id),
      dorksByBrand,
      manualLinks,
      results: allResults,
      summary: {
        total: allResults.length,
        byBrand,
        byCategory,
        bySeverity,
      },
      enginesUsed: ["Bing", "DuckDuckGo", "Google", "Yandex", "Edge"],
      enginesAuto: ["Bing", "DuckDuckGo"],
      enginesManual: ["Google", "Yandex", "Edge"],
      timestamp: new Date().toISOString(),
    }, { headers: { "Cache-Control": "no-store" } });
  } catch (err: any) {
    console.error("[brand-protection] ERROR:", err?.message || err);
    return NextResponse.json(
      { error: "internal_error", message: String(err?.message || err) },
      { status: 500 }
    );
  }
}

export async function OPTIONS() {
  return new NextResponse(null, { status: 204, headers: { "Access-Control-Allow-Origin": "*", "Access-Control-Allow-Methods": "GET, OPTIONS", "Access-Control-Allow-Headers": "*" } });
}
