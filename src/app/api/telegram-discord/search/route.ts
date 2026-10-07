// Telegram Monitor Search — SOLO Telegram (sin Instagram, sin TGStat)
// Busca menciones de keywords en canales publicos de Telegram via scraping.
//
// Estrategia: para cada keyword, prueba multiples variaciones de nombres de canal:
// - nombre exacto (bancolombia)
// - nombre + sufijos comunes (bancolombia_oficial, bancolombiaphishing, etc.)
// - nombre sin espacios + variaciones
//
// Tambien genera dorks para uso manual en Google.

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

export const DEFAULT_KEYWORDS = [
  "Bancolombia", "Nequi", "Wenia", "Banco Agricola", "Banco Agro Mercantil",
  "Cibest", "SUFI", "WOMPI", "Zaswin",
];

// Generate channel name variations to try on Telegram
function getChannelVariations(keyword: string): string[] {
  const base = keyword.toLowerCase().replace(/\s+/g, "");
  return [
    base,
    base + "_oficial",
    base + "_official",
    base + "phishing",
    base + "_phishing",
    base + "scam",
    base + "clone",
    base + "clon",
    base + "fake",
    base + "alerta",
    base + "alert",
    base + "info",
    base + "bot",
    base + "canal",
    base + "grupo",
    base + "noticias",
    base + "app",
    base + "colombia",
    base + "peru",
    base + "soporte",
    base + "help",
  ];
}

// Scrape a single Telegram channel
async function scrapeTelegramChannel(channelName: string, keyword: string): Promise<SearchResult[]> {
  try {
    const r = await fetch(`https://t.me/s/${channelName}`, {
      headers: { "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36" },
      signal: AbortSignal.timeout(8000),
    });
    if (!r.ok) return [];
    const html = await r.text();
    if (!html.includes("tgme_widget_message")) return []; // channel doesn't exist

    const results: SearchResult[] = [];

    // Channel title
    const titleMatch = html.match(/<meta property="og:title" content="([^"]*)"/);
    const channelTitle = titleMatch ? titleMatch[1] : `@${channelName}`;

    // Channel description
    const descMatch = html.match(/<meta property="og:description" content="([^"]*)"/);
    const channelDesc = descMatch ? descMatch[1] : "";

    // Extract messages
    const messageMatches = [...html.matchAll(/tgme_widget_message_text[^>]*>(.*?)<\/div>/gs)];
    const messages = messageMatches.slice(0, 20).map(m => m[1].replace(/<[^>]*>/g, "").trim()).filter(t => t && t !== "Channel created");

    if (messages.length === 0) {
      // Channel exists but has no messages — still report it
      results.push({
        source: "Telegram",
        type: "channel found",
        title: channelTitle,
        url: `https://t.me/${channelName}`,
        snippet: `Canal existe pero sin mensajes publicos. ${channelDesc.slice(0, 100)}`,
        severity: "info" as const,
        timestamp: null,
      });
      return results;
    }

    // Add channel info as first result
    results.push({
      source: "Telegram",
      type: "channel",
      title: channelTitle,
      url: `https://t.me/${channelName}`,
      snippet: `Canal: @${channelName} | Mensajes: ${messages.length} | ${channelDesc.slice(0, 100)}`,
      severity: "medium" as const,
      timestamp: null,
    });

    // Check each message for phishing/scam keywords
    for (const msg of messages) {
      const lowerMsg = msg.toLowerCase();
      const isPhishing = /phishing|scam|clone|fake|fraud|estafa|clon|falso|robo|credential|password|login|verificar|clonar|cuenta|tarjeta|credito|debito|otp|sms|codigo|link|registro|datos/.test(lowerMsg);
      const mentionsBrand = lowerMsg.includes(keyword.toLowerCase());

      if (isPhishing || mentionsBrand) {
        results.push({
          source: "Telegram",
          type: isPhishing ? "phishing message" : "brand mention",
          title: channelTitle,
          url: `https://t.me/s/${channelName}`,
          snippet: msg.slice(0, 300),
          severity: isPhishing ? "high" : "medium" as const,
          timestamp: null,
        });
      }
    }

    return results;
  } catch { return []; }
}

// Telegram Bot API (optional)
async function searchTelegramBot(query: string): Promise<SearchResult[]> {
  try {
    const token = process.env.TELEGRAM_BOT_TOKEN || "";
    if (!token) return [];
    const r = await fetch(`https://api.telegram.org/bot${token}/getUpdates?limit=100`, { signal: AbortSignal.timeout(10000) });
    if (!r.ok) return [];
    const d: any = await r.json();
    if (!d.ok) return [];
    const results: SearchResult[] = [];
    for (const update of (d.result || [])) {
      const msg = update.channel_post || update.message;
      if (!msg) continue;
      const text = (msg.text || msg.caption || "").toLowerCase();
      if (text.includes(query.toLowerCase())) {
        const chatTitle = msg.chat?.title || msg.chat?.username || "?";
        const link = msg.chat?.username && msg.message_id
          ? `https://t.me/${msg.chat.username}/${msg.message_id}` : "#";
        results.push({
          source: "Telegram (Bot)", type: "real-time message",
          title: chatTitle, url: link,
          snippet: (msg.text || msg.caption || "").slice(0, 300),
          severity: "high" as const,
          timestamp: new Date((msg.date || 0) * 1000).toISOString(),
        });
      }
    }
    return results.slice(0, 20);
  } catch { return []; }
}

function generateDorks(query: string): string[] {
  return [
    `site:t.me "${query}"`,
    `site:t.me "${query}" phishing OR scam OR clone`,
    `site:t.me/s/ "${query}"`,
    `"${query}" "telegram" "canal" OR "grupo"`,
    `"${query}" "telegram" phishing OR estafa OR clon`,
    `"${query}" telegram channel scam`,
    `"${query}" site:t.me OR site:telegram.me`,
    `"${query}" "telegram" "bot" OR "link"`,
  ];
}

export async function GET(request: Request) {
  const { searchParams } = new URL(request.url);
  const query = (searchParams.get("q") || "").trim();
  if (!query) return NextResponse.json({ error: "missing_query" }, { status: 400 });

  const dorks = generateDorks(query);
  const variations = getChannelVariations(query);

  // Scrape multiple channel variations in parallel (max 8 at a time)
  const batchSize = 8;
  const allResults: SearchResult[] = [];
  for (let i = 0; i < variations.length; i += batchSize) {
    const batch = variations.slice(i, i + batchSize);
    const batchResults = await Promise.all(batch.map(v => scrapeTelegramChannel(v, query)));
    for (const r of batchResults) allResults.push(...r);
  }

  // Telegram Bot (optional)
  const tgBot = await searchTelegramBot(query);
  allResults.push(...tgBot);

  // Deduplicate by URL + snippet
  const seen = new Set<string>();
  const deduped = allResults.filter(r => {
    const key = `${r.url}:${r.snippet.slice(0, 50)}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });

  const bySource: Record<string, number> = {};
  const bySeverity = { high: 0, medium: 0, low: 0, info: 0 };
  for (const r of deduped) { bySource[r.source] = (bySource[r.source] || 0) + 1; bySeverity[r.severity]++; }

  return NextResponse.json({
    query, dorks, results: deduped,
    channelsTried: variations.length,
    channelsFound: deduped.filter(r => r.type === "channel" || r.type === "channel found").length,
    summary: { total: deduped.length, bySource, bySeverity },
    hasTelegramBot: !!(process.env.TELEGRAM_BOT_TOKEN || ""),
    timestamp: new Date().toISOString(),
  }, { headers: { "Cache-Control": "no-store" } });
}

export async function OPTIONS() {
  return new NextResponse(null, { status: 204, headers: { "Access-Control-Allow-Origin": "*", "Access-Control-Allow-Methods": "GET, OPTIONS", "Access-Control-Allow-Headers": "*" } });
}
