// Telegram & Discord Monitor Search
// Busca menciones de keywords (marcas financieras) en:
// 1. GitHub Code Search (bots/tools que mencionan las marcas)
// 2. GitHub Repo Search (repos sobre phishing de esas marcas)
// 3. AlienVault OTX (IOCs relacionados)
// 4. URLscan.io (scans de paginas de phishing que imitan las marcas)
// 5. VirusTotal (reputation del dominio de la marca)
// 6. Google Dorks site:t.me + site:discord.com (generados para uso manual)
// 7. Optional: Telegram Bot API (si hay TELEGRAM_BOT_TOKEN configurado)

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

// Palabras clave pre-cargadas (marcas financieras LATAM)
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

// GitHub Code Search — busca codigo que menciona la marca
async function searchGitHubCode(query: string): Promise<SearchResult[]> {
  try {
    const r = await fetch(`https://api.github.com/search/code?q=${encodeURIComponent(`"${query}"`)}&per_page=20`, { headers: ghHeaders(), signal: AbortSignal.timeout(10000) });
    if (!r.ok) return [];
    const d: any = await r.json();
    return (d.items || []).slice(0, 20).map((item: any) => ({
      source: "GitHub Code", type: "code mention", title: item.name || item.path || "File",
      url: item.html_url, snippet: `Repo: ${item.repository?.full_name || "?"} | File: ${item.path || "?"}`,
      severity: "medium" as const, timestamp: null,
    }));
  } catch { return []; }
}

// GitHub Repo Search — repos sobre phishing/scam de la marca
async function searchGitHubRepos(query: string): Promise<SearchResult[]> {
  try {
    const r = await fetch(`https://api.github.com/search/repositories?q=${encodeURIComponent(`${query} phishing OR scam OR clone OR fake`)}&per_page=20&sort=updated`, { headers: ghHeaders(), signal: AbortSignal.timeout(10000) });
    if (!r.ok) return [];
    const d: any = await r.json();
    return (d.items || []).slice(0, 20).map((repo: any) => ({
      source: "GitHub Repo", type: "phishing tool/repo", title: repo.full_name,
      url: repo.html_url, snippet: `Stars: ${repo.stargazers_count || 0} | Forks: ${repo.forks_count || 0} | Lang: ${repo.language || "?"} | Desc: ${(repo.description || "").slice(0, 100)}`,
      severity: "high" as const, timestamp: repo.updated_at || null,
    }));
  } catch { return []; }
}

// AlienVault OTX — IOCs relacionados con la marca
async function searchOtx(query: string): Promise<SearchResult[]> {
  try {
    // Search OTX for pulses mentioning the brand
    const r = await fetch(`https://otx.alienvault.com/api/v1/search/pulses?q=${encodeURIComponent(query)}&limit=20`, {
      headers: { "User-Agent": "MONITOR-THREAT" }, signal: AbortSignal.timeout(10000),
    });
    if (!r.ok) return [];
    const d: any = await r.json();
    const pulses = d?.results || [];
    return pulses.slice(0, 20).map((p: any) => ({
      source: "AlienVault OTX", type: "threat pulse",
      title: p.name || "Pulse",
      url: `https://otx.alienvault.com/pulse/${p.id}`,
      snippet: `Tags: ${(p.tags || []).join(", ") || "none"} | TLP: ${p.TLP || "?"} | Modified: ${p.modified || "?"} | IOCs: ${p.indicator_count || 0}`,
      severity: "high" as const, timestamp: p.modified || null,
    }));
  } catch { return []; }
}

// URLscan.io — scans de paginas que imitan la marca
async function searchUrlscan(query: string): Promise<SearchResult[]> {
  try {
    const r = await fetch(`https://urlscan.io/api/v1/search/?q=page.title:"${encodeURIComponent(query)}"&size=20`, { signal: AbortSignal.timeout(10000) });
    if (!r.ok) return [];
    const d: any = await r.json();
    return (d.results || []).slice(0, 20).map((item: any) => ({
      source: "URLscan.io", type: "phishing page scan",
      title: item.page?.title || item.page?.url || "Scan",
      url: `https://urlscan.io/result/${item._id}`,
      snippet: `URL: ${item.page?.url || "?"} | IP: ${item.page?.ip || "?"} | Domain: ${item.page?.domain || "?"} | Server: ${item.page?.server || "?"}`,
      severity: "high" as const, timestamp: item.task?.time || null,
    }));
  } catch { return []; }
}

// VirusTotal — reputation del dominio de la marca
async function searchVirusTotal(query: string): Promise<SearchResult[]> {
  try {
    const key = process.env.VIRUSTOTAL_API_KEY || "";
    if (!key) return [];
    // Try to look up as domain (strip spaces, lowercase)
    const domain = query.toLowerCase().replace(/\s+/g, "").replace(/^www\./, "");
    if (!domain.includes(".")) return []; // not a domain
    const r = await fetch(`https://www.virustotal.com/api/v3/domains/${domain}`, { headers: { "x-apikey": key }, signal: AbortSignal.timeout(10000) });
    if (!r.ok) return [];
    const d: any = await r.json();
    const s = d?.data?.attributes?.last_analysis_stats || {};
    return [{
      source: "VirusTotal", type: "domain reputation",
      title: `${domain} - ${s.malicious || 0} malicious`,
      url: `https://www.virustotal.com/gui/domain/${domain}`,
      snippet: `Malicious: ${s.malicious || 0} | Suspicious: ${s.suspicious || 0} | Harmless: ${s.harmless || 0} | Undetected: ${s.undetected || 0}`,
      severity: (s.malicious || 0) > 0 ? "high" : "info" as const,
      timestamp: null,
    }];
  } catch { return []; }
}

// Telegram Bot API — busca en canales donde el bot es miembro (opcional)
async function searchTelegramBot(query: string): Promise<SearchResult[]> {
  try {
    const token = process.env.TELEGRAM_BOT_TOKEN || "";
    if (!token) return [];
    // Get bot updates (messages from channels)
    const r = await fetch(`https://api.telegram.org/bot${token}/getUpdates?limit=100`, { signal: AbortSignal.timeout(10000) });
    if (!r.ok) return [];
    const d: any = await r.json();
    if (!d.ok) return [];
    const updates = d.result || [];
    const results: SearchResult[] = [];
    for (const update of updates) {
      const msg = update.channel_post || update.message;
      if (!msg) continue;
      const text = (msg.text || msg.caption || "").toLowerCase();
      if (text.includes(query.toLowerCase())) {
        const chatTitle = msg.chat?.title || msg.chat?.username || "Unknown channel";
        const chatId = msg.chat?.id;
        const msgId = msg.message_id;
        const link = chatId && msgId
          ? `https://t.me/${msg.chat?.username || 'c/' + String(chatId).slice(4)}/${msgId}`
          : "#";
        results.push({
          source: "Telegram (Bot)",
          type: "channel message",
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

// Generate dorks for manual use
function generateDorks(query: string): string[] {
  return [
    `site:t.me "${query}"`,
    `site:t.me "${query}" phishing OR scam OR clone`,
    `site:t.me/s/ "${query}"`,
    `site:discord.com "${query}"`,
    `site:discord.com "${query}" phishing OR scam`,
    `site:discord.com/channels/ "${query}"`,
    `"${query}" site:t.me OR site:telegram.me`,
    `"${query}" "telegram" "canal" OR "grupo"`,
    `"${query}" "discord" "server" OR "invite"`,
    `"${query}" phishing telegram OR discord`,
  ];
}

export async function GET(request: Request) {
  const { searchParams } = new URL(request.url);
  const query = (searchParams.get("q") || "").trim();
  if (!query) return NextResponse.json({ error: "missing_query" }, { status: 400 });

  const dorks = generateDorks(query);

  const [ghCode, ghRepos, otx, urlscan, vt, tgBot] = await Promise.all([
    searchGitHubCode(query),
    searchGitHubRepos(query),
    searchOtx(query),
    searchUrlscan(query),
    searchVirusTotal(query),
    searchTelegramBot(query),
  ]);

  const all = [...ghCode, ...ghRepos, ...otx, ...urlscan, ...vt, ...tgBot];
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
