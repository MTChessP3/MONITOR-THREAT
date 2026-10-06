// Telegram & Discord Monitor Search
// Busca menciones de keywords (marcas financieras) en:
// 1. Telegram scraping (t.me/s/<keyword>) — lee mensajes de canales publicos
// 2. TGStat scraping (tgstat.com/en/search) — busca canales indexados
// 3. GitHub Code + Repo Search (phishing tools, leaked configs)
// 4. AlienVault OTX (IOCs relacionados)
// 5. URLscan.io (scans de paginas de phishing)
// 6. VirusTotal (domain reputation)
// 7. Optional: Telegram Bot API (TELEGRAM_BOT_TOKEN)
// 8. Optional: Discord Bot API (DISCORD_BOT_TOKEN)

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

function ghHeaders(): Record<string, string> {
  const token = process.env.GITHUB_TOKEN || process.env.GH_PAT || process.env.GH_TOKEN || "";
  const h: Record<string, string> = { Accept: "application/vnd.github.v3+json", "User-Agent": "MONITOR-THREAT" };
  if (token) h["Authorization"] = `token ${token}`;
  return h;
}

// ---- TELEGRAM: scraping de canales publicos ----
async function searchTelegramChannel(keyword: string): Promise<SearchResult[]> {
  try {
    // t.me/s/<channel> muestra los mensajes publicos del canal
    const channelName = keyword.toLowerCase().replace(/\s+/g, "");
    const r = await fetch(`https://t.me/s/${channelName}`, {
      headers: { "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36" },
      signal: AbortSignal.timeout(10000),
    });
    if (!r.ok) return [];
    const html = await r.text();
    const results: SearchResult[] = [];

    // Extract channel name/title
    const titleMatch = html.match(/<meta property="og:title" content="([^"]*)"/);
    const channelTitle = titleMatch ? titleMatch[1] : `@${channelName}`;

    // Extract messages
    const messageMatches = [...html.matchAll(/tgme_widget_message_text[^>]*>(.*?)<\/div>/gs)];
    for (const m of messageMatches.slice(0, 20)) {
      const text = m[1].replace(/<[^>]*>/g, "").trim().slice(0, 300);
      if (!text || text === "Channel created") continue;
      // Check if message mentions phishing/scam/clone keywords
      const lowerText = text.toLowerCase();
      const isPhishing = /phishing|scam|clone|fake|fraud|estafa|phishing|clon|falso|robo|credential|password|login|verificar/.test(lowerText);
      results.push({
        source: "Telegram (scraping)",
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

    // Extract channel links from TGStat results
    const channelMatches = [...html.matchAll(/<a[^>]*href="https:\/\/t\.me\/([^"\/]+)"[^>]*>(?:<img[^>]*>)?([^<]*)<\/a>/g)];
    for (const m of channelMatches.slice(0, 20)) {
      const username = m[1];
      const name = (m[2] || "").replace(/<[^>]*>/g, "").trim() || `@${username}`;
      results.push({
        source: "TGStat (Telegram)",
        type: "telegram channel",
        title: name,
        url: `https://t.me/${username}`,
        snippet: `Canal de Telegram encontrado en TGStat: @${username}`,
        severity: "medium" as const,
        timestamp: null,
      });
    }
    return results;
  } catch { return []; }
}

// ---- TELEGRAM: Bot API (opcional, necesita token) ----
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

// ---- DISCORD: Bot API (opcional, necesita token) ----
async function searchDiscordBot(query: string): Promise<SearchResult[]> {
  try {
    const token = process.env.DISCORD_BOT_TOKEN || "";
    if (!token) return [];
    // Get bot's guilds
    const guildsRes = await fetch("https://discord.com/api/v10/users/@me/guilds", {
      headers: { Authorization: `Bot ${token}` },
      signal: AbortSignal.timeout(10000),
    });
    if (!guildsRes.ok) return [];
    const guilds: any[] = await guildsRes.json();
    const results: SearchResult[] = [];
    for (const guild of guilds.slice(0, 5)) {
      try {
        // Search messages in each guild
        const searchRes = await fetch(`https://discord.com/api/v10/guilds/${guild.id}/messages/search?content=${encodeURIComponent(query)}&limit=20`, {
          headers: { Authorization: `Bot ${token}` },
          signal: AbortSignal.timeout(8000),
        });
        if (!searchRes.ok) continue;
        const searchData: any = await searchRes.json();
        for (const msg of (searchData.messages || []).flat().slice(0, 20)) {
          results.push({
            source: "Discord (Bot)",
            type: "server message",
            title: `${guild.name} → #${msg.channel_id}`,
            url: `https://discord.com/channels/${guild.id}/${msg.channel_id}/${msg.id}`,
            snippet: (msg.content || "").slice(0, 300),
            severity: "high" as const,
            timestamp: msg.timestamp || null,
          });
        }
      } catch {}
    }
    return results.slice(0, 20);
  } catch { return []; }
}

// ---- GitHub Code Search ----
async function searchGitHubCode(query: string): Promise<SearchResult[]> {
  try {
    const r = await fetch(`https://api.github.com/search/code?q=${encodeURIComponent(`"${query}"`)}&per_page=20`, { headers: ghHeaders(), signal: AbortSignal.timeout(10000) });
    if (!r.ok) return [];
    const d: any = await r.json();
    return (d.items || []).slice(0, 20).map((item: any) => ({
      source: "GitHub Code", type: "code mention", title: item.name || "File", url: item.html_url,
      snippet: `Repo: ${item.repository?.full_name || "?"} | File: ${item.path || "?"}`,
      severity: "medium" as const, timestamp: null,
    }));
  } catch { return []; }
}

// ---- GitHub Repo Search ----
async function searchGitHubRepos(query: string): Promise<SearchResult[]> {
  try {
    const r = await fetch(`https://api.github.com/search/repositories?q=${encodeURIComponent(`${query} phishing OR scam OR clone OR fake`)}&per_page=20&sort=updated`, { headers: ghHeaders(), signal: AbortSignal.timeout(10000) });
    if (!r.ok) return [];
    const d: any = await r.json();
    return (d.items || []).slice(0, 20).map((repo: any) => ({
      source: "GitHub Repo", type: "phishing tool", title: repo.full_name, url: repo.html_url,
      snippet: `Stars: ${repo.stargazers_count || 0} | Forks: ${repo.forks_count || 0} | Lang: ${repo.language || "?"} | ${(repo.description || "").slice(0, 80)}`,
      severity: "high" as const, timestamp: repo.updated_at || null,
    }));
  } catch { return []; }
}

// ---- AlienVault OTX ----
async function searchOtx(query: string): Promise<SearchResult[]> {
  try {
    const r = await fetch(`https://otx.alienvault.com/api/v1/search/pulses?q=${encodeURIComponent(query)}&limit=20`, { headers: { "User-Agent": "MONITOR-THREAT" }, signal: AbortSignal.timeout(10000) });
    if (!r.ok) return [];
    const d: any = await r.json();
    return (d?.results || []).slice(0, 20).map((p: any) => ({
      source: "AlienVault OTX", type: "threat pulse", title: p.name || "Pulse", url: `https://otx.alienvault.com/pulse/${p.id}`,
      snippet: `Tags: ${(p.tags || []).join(", ") || "none"} | IOCs: ${p.indicator_count || 0} | Modified: ${p.modified || "?"}`,
      severity: "high" as const, timestamp: p.modified || null,
    }));
  } catch { return []; }
}

// ---- URLscan.io ----
async function searchUrlscan(query: string): Promise<SearchResult[]> {
  try {
    const r = await fetch(`https://urlscan.io/api/v1/search/?q=page.title:"${encodeURIComponent(query)}"&size=20`, { signal: AbortSignal.timeout(10000) });
    if (!r.ok) return [];
    const d: any = await r.json();
    return (d.results || []).slice(0, 20).map((item: any) => ({
      source: "URLscan.io", type: "phishing page", title: item.page?.title || "Scan", url: `https://urlscan.io/result/${item._id}`,
      snippet: `URL: ${item.page?.url || "?"} | IP: ${item.page?.ip || "?"} | Domain: ${item.page?.domain || "?"}`,
      severity: "high" as const, timestamp: item.task?.time || null,
    }));
  } catch { return []; }
}

// ---- VirusTotal ----
async function searchVirusTotal(query: string): Promise<SearchResult[]> {
  try {
    const key = process.env.VIRUSTOTAL_API_KEY || "";
    if (!key) return [];
    const domain = query.toLowerCase().replace(/\s+/g, "");
    if (!domain.includes(".")) return [];
    const r = await fetch(`https://www.virustotal.com/api/v3/domains/${domain}`, { headers: { "x-apikey": key }, signal: AbortSignal.timeout(10000) });
    if (!r.ok) return [];
    const d: any = await r.json();
    const s = d?.data?.attributes?.last_analysis_stats || {};
    return [{ source: "VirusTotal", type: "domain reputation", title: `${domain} - ${s.malicious || 0} malicious`, url: `https://www.virustotal.com/gui/domain/${domain}`, snippet: `Malicious: ${s.malicious || 0} | Suspicious: ${s.suspicious || 0} | Harmless: ${s.harmless || 0}`, severity: (s.malicious || 0) > 0 ? "high" : "info" as const, timestamp: null }];
  } catch { return []; }
}

// ---- Dorks ----
function generateDorks(query: string): string[] {
  return [
    `site:t.me "${query}"`,
    `site:t.me "${query}" phishing OR scam OR clone`,
    `site:t.me/s/ "${query}"`,
    `site:discord.com "${query}"`,
    `site:discord.com "${query}" phishing OR scam`,
    `"${query}" "telegram" "canal" OR "grupo"`,
    `"${query}" "discord" "server" OR "invite"`,
    `"${query}" phishing telegram OR discord`,
  ];
}

// ---- Main endpoint ----
export async function GET(request: Request) {
  const { searchParams } = new URL(request.url);
  const query = (searchParams.get("q") || "").trim();
  if (!query) return NextResponse.json({ error: "missing_query" }, { status: 400 });

  const dorks = generateDorks(query);
  const channelName = query.toLowerCase().replace(/\s+/g, "");

  const [tgChannel, tgStat, tgBot, dcBot, ghCode, ghRepos, otx, urlscan, vt] = await Promise.all([
    searchTelegramChannel(channelName),
    searchTGStat(query),
    searchTelegramBot(query),
    searchDiscordBot(query),
    searchGitHubCode(query),
    searchGitHubRepos(query),
    searchOtx(query),
    searchUrlscan(query),
    searchVirusTotal(query),
  ]);

  const all = [...tgChannel, ...tgStat, ...tgBot, ...dcBot, ...ghCode, ...ghRepos, ...otx, ...urlscan, ...vt];
  const seen = new Set<string>();
  const deduped = all.filter(r => { if (seen.has(r.url)) return false; seen.add(r.url); return true; });

  const bySource: Record<string, number> = {};
  const bySeverity = { high: 0, medium: 0, low: 0, info: 0 };
  for (const r of deduped) { bySource[r.source] = (bySource[r.source] || 0) + 1; bySeverity[r.severity]++; }

  return NextResponse.json({
    query, dorks, results: deduped,
    summary: { total: deduped.length, bySource, bySeverity },
    hasTelegramBot: !!(process.env.TELEGRAM_BOT_TOKEN || ""),
    hasDiscordBot: !!(process.env.DISCORD_BOT_TOKEN || ""),
    timestamp: new Date().toISOString(),
  }, { headers: { "Cache-Control": "no-store" } });
}

export async function OPTIONS() {
  return new NextResponse(null, { status: 204, headers: { "Access-Control-Allow-Origin": "*", "Access-Control-Allow-Methods": "GET, OPTIONS", "Access-Control-Allow-Headers": "*" } });
}
