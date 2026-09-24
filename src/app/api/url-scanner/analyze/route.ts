// URL Scanner — full URL analysis
//
// Analyzes a specific URL (not the domain, not the IP — the actual URL
// with path, query, fragment). This is fundamentally different from
// Domain Intel and IP Intel: it looks at what's served at that exact
// path, the redirect chain, the forms, the scripts, and whether the
// URL is in phishing/malware databases.
//
// Pipeline:
//   1. URL parse & risk indicators (local)
//   2. HTTP fetch & redirect chain (local fetch)
//   3. Content extraction (forms, scripts, iframes, emails, crypto, trackers)
//   4. VirusTotal URL report (existing API key)
//   5. OpenPhish check (free feed, no key)
//   6. Composite risk score (0-100)

import { NextResponse } from "next/server";
import crypto from "node:crypto";

const TIMEOUT_MS = 8000;
const PHISHISH_KEYWORDS = [
  "login", "signin", "sign-in", "log-in", "account", "verify", "secure",
  "confirm", "update", "password", "credential", "banking", "wallet",
  "metamask", "paypal", "amazon", "apple", "microsoft", "google",
  "facebook", "instagram", "netflix", "spotify", "reset", "unlock",
  "suspended", "limited", "restricted", "activate", "validate",
  "gift", "free", "prize", "winner", "bonus", "claim", "reward",
];

interface RiskIndicator {
  indicator: string;
  weight: number;
  detail: string;
}

interface UrlParse {
  scheme: string;
  host: string;
  port: string;
  path: string;
  query: string;
  fragment: string;
  pathname: string;
  fullUrl: string;
  hostname: string;
  domain: string;
  tld: string;
  subdomainDepth: number;
  urlLength: number;
  pathLength: number;
  queryParamCount: number;
  hasIpAsHost: boolean;
  hasPort: boolean;
  hasCredentials: boolean;
  hasTrackingParams: boolean;
  hasPunycode: boolean;
  hasHomoglyph: boolean;
  suspiciousKeywords: string[];
  isShortened: boolean;
}

interface RedirectHop {
  url: string;
  status: number;
  headers: Record<string, string>;
}

interface ContentExtraction {
  title: string;
  description: string;
  forms: Array<{ action: string; method: string; inputCount: number; hasPasswordField: boolean; externalAction: boolean }>;
  externalLinks: string[];
  scripts: string[];
  iframes: Array<{ src: string; hidden: boolean }>;
  trackingPixels: number;
  emails: string[];
  cryptoAddresses: string[];
  googleAnalyticsIds: string[];
  metaPixelIds: string[];
  htmlComments: string[];
  hasFavicon: boolean;
  hasViewport: boolean;
  bodyHashMd5: string;
  bodyHashSha256: string;
  bodySize: number;
}

interface VtUrlResult {
  available: boolean;
  url: string;
  lastAnalysisStats: { malicious: number; suspicious: number; harmless: number; undetected: number; timeout: number };
  totalEngines: number;
  flaggedEnginesCount: number;
  flaggedEngines: Array<{ engine: string; category: string; result: string }>;
  reputation: number;
  totalVotes: { harmless: number; malicious: number };
  categories: Array<{ source: string; category: string }>;
  classification: "BENIGN" | "SUSPICIOUS" | "MALICIOUS";
  error?: string;
}

interface UrlScanResult {
  url: string;
  timestamp: string;
  parse: UrlParse;
  riskIndicators: RiskIndicator[];
  riskScore: number;
  riskClassification: "SAFE" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  verdict: string;
  fetch: {
    available: boolean;
    finalUrl: string;
    redirectChain: RedirectHop[];
    redirectCount: number;
    finalStatus: number;
    responseTimeMs: number;
    contentType: string;
    server: string;
    headers: Record<string, string>;
    bodySize: number;
  };
  content: ContentExtraction;
  virusTotal: VtUrlResult;
  openPhish: {
    checked: boolean;
    isPhishing: boolean;
    matchCount: number;
    matches: string[];
  };
  urlscanIo: UrlScanResult_urlscan | null;
  error?: string;
}

interface UrlScanResult_urlscan {
  available: boolean;
  totalScans: number;
  screenshot?: string;
  server?: string;
  ip?: string;
  asn?: string;
  asnName?: string;
  title?: string;
  domainAgeDays?: number;
  umbrellaRank?: number;
  tlsIssuer?: string;
  redirected?: string;
  verdictUrl?: string;
  scanTime?: string;
  malicious?: boolean;
  error?: string;
}

// ---------- URL Parsing & Risk Indicators ----------

function parseUrl(rawUrl: string): UrlParse {
  // Prepend https:// if no scheme
  let url = rawUrl.trim();
  if (!url.match(/^https?:\/\//i)) {
    url = "https://" + url;
  }
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    // If URL constructor fails, return a minimal parse
    return {
      scheme: "", host: "", port: "", path: "", query: "", fragment: "",
      pathname: "", fullUrl: url, hostname: "", domain: "", tld: "",
      subdomainDepth: 0, urlLength: url.length, pathLength: 0,
      queryParamCount: 0, hasIpAsHost: false, hasPort: false,
      hasCredentials: false, hasTrackingParams: false, hasPunycode: false,
      hasHomoglyph: false, suspiciousKeywords: [], isShortened: false,
    };
  }

  const hostname = parsed.hostname;
  const parts = hostname.split(".");
  const tld = parts.length > 1 ? parts[parts.length - 1] : "";
  const domain = parts.length > 1 ? parts[parts.length - 2] + "." + tld : hostname;
  const subdomainDepth = parts.length > 2 ? parts.length - 2 : 0;

  // Check for IP as host
  const ipRegex = /^(\d{1,3}\.){3}\d{1,3}$/;
  const hasIpAsHost = ipRegex.test(hostname);

  // Check for punycode
  const hasPunycode = hostname.includes("xn--");

  // Check for homoglyphs (non-ASCII in hostname that isn't punycode)
  const hasHomoglyph = /[^\x00-\x7F]/.test(hostname) && !hasPunycode;

  // Check for credentials in URL
  const hasCredentials = parsed.username !== "" || parsed.password !== "";

  // Check for tracking params
  const trackingParams = ["utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content", "gclid", "fbclid", "msclkid", "mc_eid", "mc_cid"];
  const searchParams = parsed.searchParams;
  let hasTrackingParams = false;
  for (const tp of trackingParams) {
    if (searchParams.get(tp)) { hasTrackingParams = true; break; }
  }

  // Check for suspicious keywords in path
  const pathLower = (parsed.pathname + parsed.search).toLowerCase();
  const suspiciousKeywords = PHISHISH_KEYWORDS.filter(kw => pathLower.includes(kw));

  // Check for URL shorteners
  const shorteners = ["bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly", "rebrand.ly", "cutt.ly", "shorturl.at", "tiny.cc"];
  const isShortened = shorteners.some(s => hostname === s || hostname.endsWith("." + s));

  return {
    scheme: parsed.protocol.replace(":", ""),
    host: parsed.host,
    port: parsed.port || (parsed.protocol === "https:" ? "443" : "80"),
    path: parsed.pathname,
    query: parsed.search,
    fragment: parsed.hash,
    pathname: parsed.pathname,
    fullUrl: parsed.href,
    hostname,
    domain,
    tld,
    subdomainDepth,
    urlLength: parsed.href.length,
    pathLength: parsed.pathname.length,
    queryParamCount: [...searchParams.keys()].length,
    hasIpAsHost,
    hasPort: parsed.port !== "",
    hasCredentials,
    hasTrackingParams,
    hasPunycode,
    hasHomoglyph,
    suspiciousKeywords,
    isShortened,
  };
}

function computeRiskIndicators(parse: UrlParse): RiskIndicator[] {
  const indicators: RiskIndicator[] = [];

  if (parse.hasIpAsHost) {
    indicators.push({ indicator: "IP-as-host", weight: 25, detail: "URL uses an IP address instead of a domain — common in phishing/malware" });
  }
  if (parse.scheme !== "https") {
    indicators.push({ indicator: "No HTTPS", weight: 15, detail: "URL uses HTTP instead of HTTPS — traffic is unencrypted" });
  }
  if (parse.hasCredentials) {
    indicators.push({ indicator: "Embedded credentials", weight: 20, detail: "URL contains username:password@ — credential stuffing attempt" });
  }
  if (parse.hasPunycode) {
    indicators.push({ indicator: "Punycode/IDN", weight: 20, detail: "Domain uses international characters — possible homograph attack" });
  }
  if (parse.hasHomoglyph) {
    indicators.push({ indicator: "Homoglyph", weight: 25, detail: "Non-ASCII characters in hostname — lookalike domain" });
  }
  if (parse.subdomainDepth > 3) {
    indicators.push({ indicator: "Deep subdomain", weight: 10, detail: `${parse.subdomainDepth} levels of subdomains — suspicious structure` });
  }
  if (parse.urlLength > 100) {
    indicators.push({ indicator: "Very long URL", weight: 10, detail: `URL is ${parse.urlLength} chars — possible obfuscation` });
  }
  if (parse.suspiciousKeywords.length > 0) {
    indicators.push({ indicator: "Suspicious keywords", weight: parse.suspiciousKeywords.length * 5, detail: `Found: ${parse.suspiciousKeywords.join(", ")}` });
  }
  if (parse.isShortened) {
    indicators.push({ indicator: "URL shortener", weight: 5, detail: "Uses a URL shortening service — destination is hidden" });
  }
  if (parse.hasTrackingParams) {
    indicators.push({ indicator: "Tracking params", weight: 2, detail: "Contains UTM/tracking parameters" });
  }

  return indicators;
}

// ---------- HTTP Fetch & Redirect Chain ----------

async function fetchWithRedirects(url: string): Promise<UrlScanResult["fetch"] & { body: string }> {
  const chain: RedirectHop[] = [];
  let current = url;
  let body = "";
  const start = Date.now();

  for (let i = 0; i < 10; i++) {
    try {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), TIMEOUT_MS);
      const res = await fetch(current, {
        signal: controller.signal,
        redirect: "manual",
        headers: { "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36" },
      });
      clearTimeout(timeout);

      const headers: Record<string, string> = {};
      res.headers.forEach((v, k) => { headers[k] = v; });

      chain.push({ url: current, status: res.status, headers });

      if (res.status >= 300 && res.status < 400) {
        const location = res.headers.get("location");
        if (!location) break;
        current = new URL(location, current).toString();
        continue;
      }

      // Final response
      const contentType = res.headers.get("content-type") || "";
      if (contentType.includes("text") || contentType.includes("html") || contentType.includes("xml") || contentType.includes("json")) {
        body = await res.text();
      }
      const elapsed = Date.now() - start;
      return {
        available: true,
        finalUrl: current,
        redirectChain: chain,
        redirectCount: chain.length - 1,
        finalStatus: res.status,
        responseTimeMs: elapsed,
        contentType,
        server: res.headers.get("server") || "",
        headers,
        bodySize: body.length,
        body,
      };
    } catch (err: any) {
      return {
        available: false,
        finalUrl: current,
        redirectChain: chain,
        redirectCount: chain.length - 1,
        finalStatus: 0,
        responseTimeMs: Date.now() - start,
        contentType: "",
        server: "",
        headers: {},
        bodySize: 0,
        body: "",
      };
    }
  }

  return {
    available: true,
    finalUrl: current,
    redirectChain: chain,
    redirectCount: chain.length - 1,
    finalStatus: 0,
    responseTimeMs: Date.now() - start,
    contentType: "",
    server: "",
    headers: {},
    bodySize: 0,
    body,
  };
}

// ---------- Content Extraction ----------

function extractContent(html: string, baseUrl: string): ContentExtraction {
  const lowerHtml = html.toLowerCase();

  // Title
  const titleMatch = html.match(/<title[^>]*>([^<]*)<\/title>/i);
  const title = titleMatch ? titleMatch[1].trim() : "";

  // Meta description
  const descMatch = html.match(/<meta\s+(?:name|property)=["']description["']\s+content=["']([^"']*)["']/i);
  const description = descMatch ? descMatch[1] : "";

  // Forms
  const forms: ContentExtraction["forms"] = [];
  const formMatches = html.matchAll(/<form[^>]*>/gi);
  for (const m of formMatches) {
    const formTag = m[0];
    const actionMatch = formTag.match(/action=["'`]([^"'`]+)["'`]/i);
    const methodMatch = formTag.match(/method=["'`]([^"'`]+)["'`]/i);
    const action = actionMatch ? actionMatch[1] : "";
    const method = methodMatch ? methodMatch[1].toUpperCase() : "GET";
    // Count inputs after this form
    const formEnd = html.indexOf("</form>", m.index);
    const formContent = formEnd > 0 ? html.slice(m.index, formEnd) : html.slice(m.index, m.index + 5000);
    const inputMatches = formContent.match(/<input[^>]*>/gi) || [];
    const hasPasswordField = /type=["']password["']/i.test(formContent);
    let externalAction = false;
    if (action) {
      try {
        const actionUrl = new URL(action, baseUrl);
        const baseUrlParsed = new URL(baseUrl);
        externalAction = actionUrl.hostname !== baseUrlParsed.hostname;
      } catch { /* ignore */ }
    }
    forms.push({ action, method, inputCount: inputMatches.length, hasPasswordField, externalAction });
  }

  // External links
  const externalLinks: string[] = [];
  const linkMatches = html.matchAll(/<a[^>]+href=["'`]([^"'`]+)["'`]/gi);
  for (const m of linkMatches) {
    const raw = m[1];
    if (!raw || raw.startsWith("#") || raw.startsWith("javascript:")) continue;
    try {
      const abs = new URL(raw, baseUrl);
      const baseUrlParsed = new URL(baseUrl);
      if (abs.hostname !== baseUrlParsed.hostname && !externalLinks.includes(abs.hostname)) {
        externalLinks.push(abs.hostname);
      }
    } catch { /* ignore */ }
  }

  // Scripts
  const scripts: string[] = [];
  const scriptMatches = html.matchAll(/<script[^>]+src=["'`]([^"'`]+)["'`]/gi);
  for (const m of scriptMatches) {
    if (!scripts.includes(m[1])) scripts.push(m[1]);
  }

  // Iframes
  const iframes: ContentExtraction["iframes"] = [];
  const iframeMatches = html.matchAll(/<iframe[^>]*>/gi);
  for (const m of iframeMatches) {
    const srcMatch = m[0].match(/src=["'`]([^"'`]+)["'`]/i);
    const styleMatch = m[0].match(/style=["'`]([^"'`]+)["'`]/i);
    const isHidden = styleMatch ? /display:\s*none|visibility:\s*hidden|width:\s*0|height:\s*0/i.test(styleMatch[1]) : false;
    iframes.push({ src: srcMatch ? srcMatch[1] : "", hidden: isHidden });
  }

  // Tracking pixels (1x1 images)
  const trackingPixels = (html.match(/<img[^>]+(width|height)=["']1["'][^>]*/gi) || []).length;

  // Emails
  const emails: string[] = [];
  const emailMatches = html.matchAll(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g);
  for (const m of emailMatches) {
    if (!emails.includes(m[0])) emails.push(m[0]);
  }

  // Crypto addresses
  const cryptoAddresses: string[] = [];
  const btcMatches = html.matchAll(/\b(?:[13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-z0-9]{39,59})\b/g);
  for (const m of btcMatches) {
    if (!cryptoAddresses.includes(m[0])) cryptoAddresses.push(m[0]);
  }
  const ethMatches = html.matchAll(/\b0x[a-fA-F0-9]{40}\b/g);
  for (const m of ethMatches) {
    if (!cryptoAddresses.includes(m[0])) cryptoAddresses.push(m[0]);
  }

  // GA IDs
  const googleAnalyticsIds: string[] = [];
  const gaMatches = html.matchAll(/UA-\d+-\d+/g);
  for (const m of gaMatches) {
    if (!googleAnalyticsIds.includes(m[0])) googleAnalyticsIds.push(m[0]);
  }
  const ga4Matches = html.matchAll(/G-[A-Z0-9]{8,}/g);
  for (const m of ga4Matches) {
    if (!googleAnalyticsIds.includes(m[0])) googleAnalyticsIds.push(m[0]);
  }

  // Meta Pixel
  const metaPixelIds: string[] = [];
  const fbqMatches = html.matchAll(/fbq\(['"]init['"],\s*['"](\d{5,})['"]/g);
  for (const m of fbqMatches) {
    if (!metaPixelIds.includes(m[1])) metaPixelIds.push(m[1]);
  }

  // HTML comments
  const htmlComments: string[] = [];
  const commentMatches = html.matchAll(/<!--([\s\S]*?)-->/g);
  for (const m of commentMatches) {
    const c = m[1].trim();
    if (c && c.length < 300 && !htmlComments.includes(c)) {
      htmlComments.push(c);
    }
  }

  // Favicon & viewport
  const hasFavicon = /<link[^>]*rel=["'`]icon["'`]/i.test(html) || /<link[^>]*rel=["'`]shortcut icon["'`]/i.test(html);
  const hasViewport = /<meta[^>]*name=["']viewport["']/i.test(html);

  // Body hashes
  const bodyHashMd5 = crypto.createHash("md5").update(html).digest("hex");
  const bodyHashSha256 = crypto.createHash("sha256").update(html).digest("hex");

  return {
    title,
    description,
    forms,
    externalLinks: externalLinks.slice(0, 20),
    scripts: scripts.slice(0, 20),
    iframes,
    trackingPixels,
    emails: emails.slice(0, 20),
    cryptoAddresses,
    googleAnalyticsIds,
    metaPixelIds,
    htmlComments: htmlComments.slice(0, 10),
    hasFavicon,
    hasViewport,
    bodyHashMd5,
    bodyHashSha256,
    bodySize: html.length,
  };
}

// ---------- VirusTotal URL Report ----------

async function getVtUrlReport(url: string): Promise<VtUrlResult> {
  const apiKey = process.env.VIRUSTOTAL_API_KEY;
  if (!apiKey) {
    return {
      available: false, url, lastAnalysisStats: { malicious: 0, suspicious: 0, harmless: 0, undetected: 0, timeout: 0 },
      totalEngines: 0, flaggedEnginesCount: 0, flaggedEngines: [], reputation: 0,
      totalVotes: { harmless: 0, malicious: 0 }, categories: [], classification: "BENIGN",
      error: "virustotal_not_configured",
    };
  }
  try {
    // VT v3 uses base64(url) URL-safe as the ID
    const urlId = Buffer.from(url).toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 8000);
    const res = await fetch(`https://www.virustotal.com/api/v3/urls/${urlId}`, {
      signal: controller.signal,
      headers: { "x-apikey": apiKey, Accept: "application/json", "User-Agent": "MONITOR-THREAT/2.0" },
    });
    clearTimeout(timeout);
    if (res.status === 404) {
      // URL not yet scanned — try to submit it
      try {
        const submitRes = await fetch("https://www.virustotal.com/api/v3/urls", {
          method: "POST",
          headers: { "x-apikey": apiKey, "Content-Type": "application/x-www-form-urlencoded", "User-Agent": "MONITOR-THREAT/2.0" },
          body: `url=${encodeURIComponent(url)}`,
        });
        if (!submitRes.ok) {
          return { available: false, url, lastAnalysisStats: { malicious: 0, suspicious: 0, harmless: 0, undetected: 0, timeout: 0 },
            totalEngines: 0, flaggedEnginesCount: 0, flaggedEngines: [], reputation: 0,
            totalVotes: { harmless: 0, malicious: 0 }, categories: [], classification: "BENIGN",
            error: "url_not_scanned_yet" };
        }
        // Wait a moment and retry
        await new Promise(r => setTimeout(r, 2000));
        const retryRes = await fetch(`https://www.virustotal.com/api/v3/urls/${urlId}`, {
          headers: { "x-apikey": apiKey, Accept: "application/json", "User-Agent": "MONITOR-THREAT/2.0" },
        });
        if (!retryRes.ok) {
          return { available: false, url, lastAnalysisStats: { malicious: 0, suspicious: 0, harmless: 0, undetected: 0, timeout: 0 },
            totalEngines: 0, flaggedEnginesCount: 0, flaggedEngines: [], reputation: 0,
            totalVotes: { harmless: 0, malicious: 0 }, categories: [], classification: "BENIGN",
            error: "url_scan_in_progress" };
        }
        const data = await retryRes.json();
        return parseVtData(data, url);
      } catch {
        return { available: false, url, lastAnalysisStats: { malicious: 0, suspicious: 0, harmless: 0, undetected: 0, timeout: 0 },
          totalEngines: 0, flaggedEnginesCount: 0, flaggedEngines: [], reputation: 0,
          totalVotes: { harmless: 0, malicious: 0 }, categories: [], classification: "BENIGN",
          error: "url_submission_failed" };
      }
    }
    if (!res.ok) {
      return { available: false, url, lastAnalysisStats: { malicious: 0, suspicious: 0, harmless: 0, undetected: 0, timeout: 0 },
        totalEngines: 0, flaggedEnginesCount: 0, flaggedEngines: [], reputation: 0,
        totalVotes: { harmless: 0, malicious: 0 }, categories: [], classification: "BENIGN",
        error: `vt_error_${res.status}` };
    }
    const data = await res.json();
    return parseVtData(data, url);
  } catch (err: any) {
    return { available: false, url, lastAnalysisStats: { malicious: 0, suspicious: 0, harmless: 0, undetected: 0, timeout: 0 },
      totalEngines: 0, flaggedEnginesCount: 0, flaggedEngines: [], reputation: 0,
      totalVotes: { harmless: 0, malicious: 0 }, categories: [], classification: "BENIGN",
      error: "vt_unreachable" };
  }
}

function parseVtData(data: any, url: string): VtUrlResult {
  const a = data?.data?.attributes;
  if (!a) {
    return { available: false, url, lastAnalysisStats: { malicious: 0, suspicious: 0, harmless: 0, undetected: 0, timeout: 0 },
      totalEngines: 0, flaggedEnginesCount: 0, flaggedEngines: [], reputation: 0,
      totalVotes: { harmless: 0, malicious: 0 }, categories: [], classification: "BENIGN",
      error: "no_data" };
  }
  const stats = a.last_analysis_stats || { malicious: 0, suspicious: 0, harmless: 0, undetected: 0, timeout: 0 };
  const total = stats.malicious + stats.suspicious + stats.harmless + stats.undetected + (stats.timeout || 0);
  const flagged = stats.malicious + stats.suspicious;
  const flaggedEngines: VtUrlResult["flaggedEngines"] = [];
  const results = a.last_analysis_results || {};
  for (const [engine, r] of Object.entries(results)) {
    const cat = (r as any)?.category as string;
    if (cat === "malicious" || cat === "suspicious") {
      flaggedEngines.push({ engine, category: cat, result: (r as any)?.result || cat });
    }
  }
  const categories: VtUrlResult["categories"] = [];
  if (a.categories) {
    for (const [src, cat] of Object.entries(a.categories)) {
      categories.push({ source: src, category: String(cat) });
    }
  }
  const classification = flagged >= 5 ? "MALICIOUS" : flagged >= 1 ? "SUSPICIOUS" : "BENIGN";
  return {
    available: true,
    url: a.url || url,
    lastAnalysisStats: stats,
    totalEngines: total,
    flaggedEnginesCount: flagged,
    flaggedEngines,
    reputation: a.reputation ?? 0,
    totalVotes: a.total_votes || { harmless: 0, malicious: 0 },
    categories,
    classification: classification as any,
  };
}

// ---------- OpenPhish Check ----------

let openphishCache: { urls: Set<string>; loadedAt: number } | null = null;
const OPENPHISH_TTL = 6 * 60 * 60 * 1000; // 6 hours

async function loadOpenphish(): Promise<Set<string>> {
  if (openphishCache && Date.now() - openphishCache.loadedAt < OPENPHISH_TTL) {
    return openphishCache.urls;
  }
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 10000);
    const res = await fetch("https://openphish.com/feed.txt", {
      signal: controller.signal,
      headers: { "User-Agent": "Mozilla/5.0" },
      redirect: "follow",
    });
    clearTimeout(timeout);
    if (!res.ok) return openphishCache?.urls || new Set();
    const text = await res.text();
    const urls = new Set<string>();
    for (const line of text.split("\n")) {
      const u = line.trim();
      if (u && u.startsWith("http")) {
        // Store both the full URL and the hostname for matching
        urls.add(u);
        try { urls.add(new URL(u).hostname); } catch { /* ignore */ }
      }
    }
    openphishCache = { urls, loadedAt: Date.now() };
    return urls;
  } catch {
    return openphishCache?.urls || new Set();
  }
}

async function checkOpenPhish(url: string): Promise<UrlScanResult["openPhish"]> {
  const feed = await loadOpenphish();
  const matches: string[] = [];
  // Check full URL
  if (feed.has(url)) {
    matches.push(url);
  }
  // Check hostname
  try {
    const hostname = new URL(url).hostname;
    if (feed.has(hostname)) {
      matches.push(`hostname: ${hostname}`);
    }
    // Check if any feed URL has the same hostname + path prefix
    const path = new URL(url).pathname;
    for (const feedUrl of feed) {
      if (feedUrl.startsWith("http")) {
        try {
          const feedParsed = new URL(feedUrl);
          if (feedParsed.hostname === hostname && feedParsed.pathname === path) {
            if (!matches.includes(feedUrl)) matches.push(feedUrl);
          }
        } catch { /* ignore */ }
      }
    }
  } catch { /* ignore */ }
  return { checked: true, isPhishing: matches.length > 0, matchCount: matches.length, matches };
}

// ---------- Composite Risk Score ----------

function computeRiskScore(
  indicators: RiskIndicator[],
  vt: VtUrlResult,
  openPhish: UrlScanResult["openPhish"],
  content: ContentExtraction,
  fetchResult: UrlScanResult["fetch"]
): { score: number; classification: "SAFE" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"; verdict: string } {
  let score = 0;
  // From URL indicators
  for (const ind of indicators) {
    score += ind.weight;
  }
  // From VirusTotal
  if (vt.available) {
    if (vt.classification === "MALICIOUS") score += 40;
    else if (vt.classification === "SUSPICIOUS") score += 20;
    if (vt.reputation < -10) score += 10;
  }
  // From OpenPhish
  if (openPhish.isPhishing) score += 50;
  // From content
  for (const form of content.forms) {
    if (form.hasPasswordField && form.externalAction) score += 30;
    else if (form.hasPasswordField) score += 10;
    if (form.externalAction) score += 15;
  }
  for (const iframe of content.iframes) {
    if (iframe.hidden) score += 15;
  }
  if (content.cryptoAddresses.length > 0) score += 10;
  if (!content.hasFavicon) score += 5;
  if (!content.hasViewport) score += 5;
  if (!content.title) score += 5;
  // From fetch
  if (fetchResult.available && fetchResult.finalStatus >= 400) score += 10;
  if (fetchResult.redirectCount > 3) score += 10;

  score = Math.min(100, score);

  let classification: "SAFE" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  if (score >= 75) classification = "CRITICAL";
  else if (score >= 50) classification = "HIGH";
  else if (score >= 25) classification = "MEDIUM";
  else if (score >= 10) classification = "LOW";
  else classification = "SAFE";

  // Verdict narrative
  let verdict = "";
  if (openPhish.isPhishing) {
    verdict = `PHISHING: This URL matches ${openPhish.matchCount} known phishing URL(s) in the OpenPhish feed. `;
  }
  if (vt.available && vt.classification === "MALICIOUS") {
    verdict += `VirusTotal: ${vt.flaggedEnginesCount}/${vt.totalEngines} engines flag this URL as malicious. `;
  }
  if (content.forms.some(f => f.hasPasswordField && f.externalAction)) {
    verdict += `PHISHING INDICATOR: Form with password field submits to an external domain. `;
  }
  if (content.cryptoAddresses.length > 0) {
    verdict += `CRYPTO SCAM: Cryptocurrency address found in page content. `;
  }
  if (indicators.some(i => i.indicator === "IP-as-host")) {
    verdict += `URL uses IP address instead of domain — common in malware distribution. `;
  }
  if (indicators.some(i => i.indicator === "Homoglyph" || i.indicator === "Punycode/IDN")) {
    verdict += `Lookalike domain detected — possible homograph attack. `;
  }
  if (!verdict) {
    verdict = `No significant risk indicators detected. The URL appears to be safe based on structural analysis, content inspection, and reputation checks.`;
  }

  return { score, classification, verdict };
}

// ---------- urlscan.io Check ----------

interface UrlScanResult {
  available: boolean;
  totalScans: number;
  screenshot?: string;
  server?: string;
  ip?: string;
  asn?: string;
  asnName?: string;
  title?: string;
  domainAgeDays?: number;
  umbrellaRank?: number;
  tlsIssuer?: string;
  redirected?: string;
  verdictUrl?: string;
  scanTime?: string;
  malicious?: boolean;
  error?: string;
}

async function checkUrlscanIo(url: string): Promise<UrlScanResult> {
  try {
    // Extract domain from URL for the search query
    const parsed = new URL(url);
    const domain = parsed.hostname;
    const searchUrl = `https://urlscan.io/api/v1/search/?q=domain:${encodeURIComponent(domain)}&size=1`;
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 8000);
    const res = await fetch(searchUrl, {
      signal: controller.signal,
      headers: { "User-Agent": "Mozilla/5.0", Accept: "application/json" },
    });
    clearTimeout(timeout);
    if (!res.ok) {
      return { available: false, totalScans: 0, error: `urlscan_error_${res.status}` };
    }
    const data = await res.json();
    const results = data.results || [];
    const total = data.total || 0;
    if (results.length === 0) {
      return { available: true, totalScans: total, error: "no_public_scans" };
    }
    const r = results[0];
    const page = r.page || {};
    const task = r.task || {};
    const verdicts = r.verdicts || {};
    const overall = verdicts.overall || {};
    return {
      available: true,
      totalScans: total,
      screenshot: r.screenshot || undefined,
      server: page.server || undefined,
      ip: page.ip || undefined,
      asn: page.asn ? String(page.asn) : undefined,
      asnName: page.asnname || undefined,
      title: page.title || undefined,
      domainAgeDays: page.domainAgeDays || undefined,
      umbrellaRank: page.umbrellaRank || undefined,
      tlsIssuer: page.tlsIssuer || undefined,
      redirected: page.redirected || undefined,
      verdictUrl: `https://urlscan.io/result/${r._id}/`,
      scanTime: task.time || undefined,
      malicious: overall.malicious || false,
    };
  } catch (err: any) {
    return { available: false, totalScans: 0, error: "urlscan_unreachable" };
  }
}

// ---------- Main endpoint ----------

export async function GET(request: Request) {
  const { searchParams } = new URL(request.url);
  const rawUrl = (searchParams.get("url") || "").trim();

  if (!rawUrl) {
    return NextResponse.json({ error: "missing_params", hint: "Provide a 'url' query parameter." }, { status: 400 });
  }

  try {
    // 1. Parse URL & compute risk indicators
    const parse = parseUrl(rawUrl);
    const riskIndicators = computeRiskIndicators(parse);

    // 2. Fetch the URL (redirect chain + body)
    const fetchResult = await fetchWithRedirects(parse.fullUrl);

    // 3. Extract content from body
    const content = fetchResult.body ? extractContent(fetchResult.body, fetchResult.finalUrl) : {
      title: "", description: "", forms: [], externalLinks: [], scripts: [],
      iframes: [], trackingPixels: 0, emails: [], cryptoAddresses: [],
      googleAnalyticsIds: [], metaPixelIds: [], htmlComments: [],
      hasFavicon: false, hasViewport: false, bodyHashMd5: "", bodyHashSha256: "",
      bodySize: 0,
    };

    // Remove body from fetch result (don't send to client)
    const { body, ...fetchWithoutBody } = fetchResult;

    // 4. VirusTotal URL report + OpenPhish + urlscan.io (all in parallel)
    const [vtResult, openPhishResult, urlscanResult] = await Promise.all([
      getVtUrlReport(parse.fullUrl),
      checkOpenPhish(parse.fullUrl),
      checkUrlscanIo(parse.fullUrl),
    ]);

    // 5. Compute risk score
    const { score, classification, verdict } = computeRiskScore(
      riskIndicators, vtResult, openPhishResult, content, fetchWithoutBody as any
    );

    const result: UrlScanResult = {
      url: parse.fullUrl,
      timestamp: new Date().toISOString(),
      parse,
      riskIndicators,
      riskScore: score,
      riskClassification: classification,
      verdict,
      fetch: fetchWithoutBody as any,
      content,
      virusTotal: vtResult,
      openPhish: openPhishResult,
      urlscanIo: urlscanResult,
    };

    return NextResponse.json(result);
  } catch (err: any) {
    return NextResponse.json(
      { error: "scan_failed", hint: err.message, url: rawUrl },
      { status: 502 }
    );
  }
}
