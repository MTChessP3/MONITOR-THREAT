// Telegram & Instagram Monitor Search
// Busca menciones de keywords SOLO en Telegram e Instagram:
// 1. Telegram scraping (t.me/s/<keyword>) — mensajes de canales publicos
// 2. TGStat (tgstat.com) — busca canales de Telegram indexados
// 3. Instagram scraping (instagram.com/<keyword>) — perfil publico
// 4. Instagram hashtag scraping (instagram.com/explore/tags/<keyword>)
// 5. Optional: Telegram Bot API (TELEGRAM_BOT_TOKEN)
// 6. Dorks para Telegram e Instagram (uso manual en Google)

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

// ---- TELEGRAM: scraping de canales publicos ----
async function searchTelegramChannel(keyword: string): Promise<SearchResult[]> {
  try {
    const channelName = keyword.toLowerCase().replace(/\s+/g, "");
    const r = await fetch(`https://t.me/s/${channelName}`, {
      headers: { "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36" },
      signal: AbortSignal.timeout(10000),
    });
    if (!r.ok) return [];
    const html = await r.text();
    const results: SearchResult[] = [];

    const titleMatch = html.match(/<meta property="og:title" content="([^"]*)"/);
    const channelTitle = titleMatch ? titleMatch[1] : `@${channelName}`;

    // Extract messages
    const messageMatches = [...html.matchAll(/tgme_widget_message_text[^>]*>(.*?)<\/div>/gs)];
    for (const m of messageMatches.slice(0, 20)) {
      const text = m[1].replace(/<[^>]*>/g, "").trim().slice(0, 300);
      if (!text || text === "Channel created") continue;
      const lowerText = text.toLowerCase();
      const isPhishing = /phishing|scam|clone|fake|fraud|estafa|phishing|clon|falso|robo|credential|password|login|verificar|clonar/.test(lowerText);
      results.push({
        source: "Telegram",
        type: isPhishing ? "phishing message" : "channel message",
        title: channelTitle,
        url: `https://t.me/s/${channelName}`,
        snippet: text,
        severity: isPhishing ? "high" : "medium" as const,
        timestamp: null,
      });
    }
    return results;
  } catch { return []; }
}

// ---- TELEGRAM: TGStat search (busca canales indexados) ----
async function searchTGStat(keyword: string): Promise<SearchResult[]> {
  try {
    const r = await fetch(`https://tgstat.com/en/search?q=${encodeURIComponent(keyword)}`, {
      headers: { "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36" },
      signal: AbortSignal.timeout(10000),
    });
    if (!r.ok) return [];
    const html = await r.text();
    const results: SearchResult[] = [];
    const channelMatches = [...html.matchAll(/<a[^>]*href="https:\/\/t\.me\/([^"\/]+)"[^>]*>(?:<img[^>]*>)?([^<]*)<\/a>/g)];
    for (const m of channelMatches.slice(0, 20)) {
      const username = m[1];
      const name = (m[2] || "").replace(/<[^>]*>/g, "").trim() || `@${username}`;
      results.push({
        source: "TGStat (Telegram)",
        type: "telegram channel",
        title: name,
        url: `https://t.me/${username}`,
        snippet: `Canal de Telegram: @${username}`,
        severity: "medium" as const,
        timestamp: null,
      });
    }
    return results;
  } catch { return []; }
}

// ---- TELEGRAM: Bot API (opcional) ----
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
          ? `https://t.me/${msg.chat.username}/${msg.message_id}`
          : "#";
        results.push({
          source: "Telegram (Bot)",
          type: "real-time message",
          title: chatTitle,
          url: link,
          snippet: (msg.text || msg.caption || "").slice(0, 300),
          severity: "high" as const,
          timestamp: new Date((msg.date || 0) * 1000).toISOString(),
        });
      }
    }
    return results.slice(0, 20);
  } catch { return []; }
}

// ---- INSTAGRAM: scraping de perfil publico ----
async function searchInstagramProfile(keyword: string): Promise<SearchResult[]> {
  try {
    const username = keyword.toLowerCase().replace(/\s+/g, "").replace(/^@/, "");
    const r = await fetch(`https://www.instagram.com/${username}/`, {
      headers: { "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36" },
      signal: AbortSignal.timeout(10000),
    });
    if (!r.ok) return [];
    const html = await r.text();
    const results: SearchResult[] = [];

    // Extract profile info from meta tags
    const titleMatch = html.match(/<meta property="og:title" content="([^"]*)"/);
    const descMatch = html.match(/<meta property="og:description" content="([^"]*)"/);
    const imageMatch = html.match(/<meta property="og:image" content="([^"]*)"/);

    if (titleMatch || descMatch) {
      const title = titleMatch ? titleMatch[1] : `@${username}`;
      const desc = descMatch ? descMatch[1] : "";
      // Extract follower count from description
      const followersMatch = desc.match(/([\d,.]+[KMk]?)\s*Followers/);
      const followers = followersMatch ? followersMatch[1] : "?";

      results.push({
        source: "Instagram",
        type: "profile",
        title: title,
        url: `https://www.instagram.com/${username}/`,
        snippet: `Followers: ${followers} | ${desc.slice(0, 200)}`,
        severity: "info" as const,
        timestamp: null,
      });

      // Check if profile mentions phishing/scam keywords
      const lowerDesc = desc.toLowerCase();
      if (/phishing|scam|clone|fake|fraud|estafa|clon|falso|robo/.test(lowerDesc)) {
        results.push({
          source: "Instagram",
          type: "suspicious profile",
          title: `⚠ ${title} — posible phishing`,
          url: `https://www.instagram.com/${username}/`,
          snippet: `La bio del perfil contiene keywords sospechosas: ${desc.slice(0, 200)}`,
          severity: "high" as const,
          timestamp: null,
        });
      }
    }
    return results;
  } catch { return []; }
}

// ---- INSTAGRAM: hashtag scraping ----
async function searchInstagramHashtag(keyword: string): Promise<SearchResult[]> {
  try {
    const tag = keyword.toLowerCase().replace(/\s+/g, "").replace(/^#/, "");
    const r = await fetch(`https://www.instagram.com/explore/tags/${tag}/`, {
      headers: { "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36" },
      signal: AbortSignal.timeout(10000),
    });
    if (!r.ok) return [];
    const html = await r.text();

    // Extract hashtag count
    const countMatch = html.match(/"edge_hashtag_to_media":\{"count":(\d+)/);
    const count = countMatch ? countMatch[1] : "?";

    return [{
      source: "Instagram Hashtag",
      type: "hashtag",
      title: `#${tag}`,
      url: `https://www.instagram.com/explore/tags/${tag}/`,
      snippet: `Posts: ${count} | Hashtag: #${tag}`,
      severity: "medium" as const,
      timestamp: null,
    }];
  } catch { return []; }
}

// ---- Dorks (para uso manual en Google) ----
function generateDorks(query: string): string[] {
  return [
    `site:t.me "${query}"`,
    `site:t.me "${query}" phishing OR scam OR clone`,
    `site:t.me/s/ "${query}"`,
    `site:instagram.com "${query}"`,
    `site:instagram.com "${query}" phishing OR scam OR clone OR fake`,
    `"${query}" "telegram" "canal" OR "grupo" phishing`,
    `"${query}" "instagram" "cuenta" OR "perfil" fake OR clone`,
    `"${query}" site:t.me OR site:instagram.com`,
  ];
}

// ---- Main endpoint ----
export async function GET(request: Request) {
  const { searchParams } = new URL(request.url);
  const query = (searchParams.get("q") || "").trim();
  if (!query) return NextResponse.json({ error: "missing_query" }, { status: 400 });

  const dorks = generateDorks(query);
  const channelName = query.toLowerCase().replace(/\s+/g, "");

  // SOLO Telegram e Instagram — sin GitHub, URLscan, OTX, VT (esos ya estan en Deep & Dark Web)
  const [tgChannel, tgStat, tgBot, igProfile, igHashtag] = await Promise.all([
    searchTelegramChannel(channelName),
    searchTGStat(query),
    searchTelegramBot(query),
    searchInstagramProfile(query),
    searchInstagramHashtag(query),
  ]);

  const all = [...tgChannel, ...tgStat, ...tgBot, ...igProfile, ...igHashtag];
  const seen = new Set<string>();
  const deduped = all.filter(r => { if (seen.has(r.url)) return false; seen.add(r.url); return true; });

  const bySource: Record<string, number> = {};
  const bySeverity = { high: 0, medium: 0, low: 0, info: 0 };
  for (const r of deduped) { bySource[r.source] = (bySource[r.source] || 0) + 1; bySeverity[r.severity]++; }

  return NextResponse.json({
    query, dorks, results: deduped,
    summary: { total: deduped.length, bySource, bySeverity },
    hasTelegramBot: !!(process.env.TELEGRAM_BOT_TOKEN || ""),
    timestamp: new Date().toISOString(),
  }, { headers: { "Cache-Control": "no-store" } });
}

export async function OPTIONS() {
  return new NextResponse(null, { status: 204, headers: { "Access-Control-Allow-Origin": "*", "Access-Control-Allow-Methods": "GET, OPTIONS", "Access-Control-Allow-Headers": "*" } });
}
