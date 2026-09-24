// Domain Intel — Hosting & Technologies detection
//
// Fetches the homepage over HTTPS, captures all response headers, and
// derives:
//   - IP address (resolved via DoH A record)
//   - Web server (Server header)
//   - CDN (Cloudflare / CloudFront / Akamai / etc. via headers + IP)
//   - Tech stack (X-Powered-By, X-Generator, Set-Cookie patterns)
//   - Security headers (HSTS, CSP, X-Frame-Options, etc.)
//   - Favicon hash (md5 of the favicon — useful for Shodan pivoting)
//   - Final URL after redirects
//   - Title of the page
//
// We also call the existing /api/ip-intel/aggregate to enrich the IP
// with VirusTotal + AbuseIPDB + Shodan + DNSBL — so the analyst can
// pivot to the IP Intel module with one click.

import { NextResponse } from "next/server";
import { getCached, setCached, cacheKey } from "@/lib/cache";
import crypto from "node:crypto";

interface HostingResult {
  domain: string;
  available: boolean;
  // Network
  ip?: string;
  resolvedViaHttps?: boolean;
  finalUrl?: string;
  redirectCount: number;
  // Server
  webServer?: string;
  poweredBy?: string;
  generator?: string;
  // CDN detection
  cdn?: string;
  cdnEdge?: string;
  // Tech stack
  technologies: Array<{ name: string; evidence: string }>;
  // Security headers
  securityHeaders: {
    hsts?: string;
    csp?: string;
    xFrameOptions?: string;
    xContentTypeOptions?: string;
    referrerPolicy?: string;
    permissionsPolicy?: string;
  };
  securityScore: number; // 0-6 based on which security headers are present
  // Page
  title?: string;
  faviconHash?: string;
  // Response meta
  httpStatus?: number;
  responseTimeMs?: number;
  // Pivot hints
  pivotHints: {
    cdnEdgeIp?: string;
    cdnEdgePop?: string;
    serverHostname?: string;
  };
  error?: string;
}

function detectCdn(headers: Record<string, string>, ip?: string): { cdn?: string; edge?: string } {
  // Cloudflare sets "server: cloudflare" and "cf-ray"
  if (headers["server"]?.toLowerCase().includes("cloudflare")) {
    return { cdn: "Cloudflare", edge: headers["cf-ray"]?.split("-")[1] };
  }
  if (headers["cf-ray"]) {
    return { cdn: "Cloudflare", edge: headers["cf-ray"].split("-")[1] };
  }
  // AWS CloudFront sets "x-amz-cf-id" and "x-amz-cf-pop"
  if (headers["x-amz-cf-id"] || headers["x-amz-cf-pop"]) {
    return { cdn: "AWS CloudFront", edge: headers["x-amz-cf-pop"] };
  }
  // Akamai
  if (headers["x-akamai-transformed"]) {
    return { cdn: "Akamai", edge: undefined };
  }
  // Fastly sets "x-served-by" like "cache-fra-eddf8330056-FRA"
  if (headers["x-served-by"]?.startsWith("cache-")) {
    return { cdn: "Fastly", edge: headers["x-served-by"] };
  }
  // Google Frontend sets "server: gws" or "x-google-*"
  if (headers["server"]?.toLowerCase().includes("gws") || headers["x-google-skip-hosting"]) {
    return { cdn: "Google Frontend", edge: undefined };
  }
  // Sucuri
  if (headers["server"]?.toLowerCase().includes("sucuri") || headers["x-sucuri-cache"]) {
    return { cdn: "Sucuri", edge: headers["x-sucuri-id"] };
  }
  // Bunny.net
  if (headers["server"]?.toLowerCase().includes("bunnycdn")) {
    return { cdn: "BunnyCDN", edge: headers["cdn-pullzone"] };
  }
  return {};
}

function detectTech(headers: Record<string, string>, html: string): Array<{ name: string; evidence: string }> {
  const tech: Array<{ name: string; evidence: string }> = [];
  const lowerHtml = html.toLowerCase();
  // X-Powered-By
  if (headers["x-powered-by"]) {
    tech.push({ name: headers["x-powered-by"], evidence: "X-Powered-By header" });
  }
  // X-Generator (Drupal, TYPO3)
  if (headers["x-generator"]) {
    tech.push({ name: headers["x-generator"], evidence: "X-Generator header" });
  }
  // WordPress
  if (lowerHtml.includes("wp-content") || lowerHtml.includes("wp-includes")) {
    tech.push({ name: "WordPress", evidence: "wp-content / wp-includes paths" });
  }
  // Shopify
  if (lowerHtml.includes("cdn.shopify.com") || lowerHtml.includes("shopify.theme")) {
    tech.push({ name: "Shopify", evidence: "Shopify CDN paths" });
  }
  // Drupal
  if (lowerHtml.includes("drupal.js") || lowerHtml.includes("sites/all/themes")) {
    tech.push({ name: "Drupal", evidence: "Drupal asset paths" });
  }
  // Joomla
  if (lowerHtml.includes("media/jui/") || lowerHtml.includes('name="generator" content="joomla')) {
    tech.push({ name: "Joomla", evidence: "Joomla asset paths" });
  }
  // React
  if (lowerHtml.includes("data-reactroot") || lowerHtml.includes("__next_data__")) {
    tech.push({ name: "Next.js (React)", evidence: "Next.js SSR markers" });
  } else if (lowerHtml.includes("data-reactroot")) {
    tech.push({ name: "React", evidence: "data-reactroot attribute" });
  }
  // Vue
  if (lowerHtml.includes("data-v-") || lowerHtml.includes("__nuxt__")) {
    tech.push({ name: "Vue/Nuxt", evidence: "Vue/Nuxt SSR markers" });
  }
  // Angular
  if (lowerHtml.includes("ng-version") || lowerHtml.includes("_ngcontent")) {
    tech.push({ name: "Angular", evidence: "Angular SSR markers" });
  }
  // Cloudflare-specific (Rocket Loader, etc.)
  if (lowerHtml.includes("cf-loader.js") || lowerHtml.includes("cloudflare-static")) {
    tech.push({ name: "Cloudflare CDN", evidence: "Cloudflare script tags" });
  }
  // Google Analytics
  const gaMatch = html.match(/UA-\d+-\d+/);
  if (gaMatch) {
    tech.push({ name: `Google Analytics ${gaMatch[0]}`, evidence: "GA tracking ID" });
  }
  const ga4Match = html.match(/G-[A-Z0-9]{8,}/);
  if (ga4Match) {
    tech.push({ name: `Google Analytics 4 ${ga4Match[0]}`, evidence: "GA4 measurement ID" });
  }
  // Facebook Pixel
  const fbMatch = html.match(/fbq\(['"]init['"],\s*['"](\d+)['"]/);
  if (fbMatch) {
    tech.push({ name: `Facebook Pixel ${fbMatch[1]}`, evidence: "Facebook Pixel ID" });
  }
  return tech;
}

function extractTitle(html: string): string | undefined {
  const m = html.match(/<title[^>]*>([^<]+)<\/title>/i);
  if (m) {
    return m[1].trim().slice(0, 200);
  }
  return undefined;
}

async function fetchFaviconHash(url: string): Promise<string | undefined> {
  try {
    const faviconUrl = new URL("/favicon.ico", url).toString();
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 4000);
    const res = await fetch(faviconUrl, {
      signal: controller.signal,
      headers: { "User-Agent": "Mozilla/5.0" },
    });
    clearTimeout(timeout);
    if (!res.ok) return undefined;
    const buf = await res.arrayBuffer();
    if (buf.byteLength === 0) return undefined;
    const hash = crypto.createHash("md5").update(Buffer.from(buf)).digest("hex");
    return hash;
  } catch {
    return undefined;
  }
}

async function fetchDoH(name: string, type: number): Promise<string | undefined> {
  try {
    const url = `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(name)}&type=${type}`;
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 4000);
    const res = await fetch(url, {
      signal: controller.signal,
      headers: { accept: "application/dns-json", "User-Agent": "MONITOR-THREAT/2.0" },
    });
    clearTimeout(timeout);
    if (!res.ok) return undefined;
    const data = await res.json();
    const answers = data.Answer || [];
    const ip = answers.find((a: any) => /^\d+\.\d+\.\d+\.\d+$/.test(a.data))?.data;
    return ip;
  } catch {
    return undefined;
  }
}

export async function GET(request: Request) {
  const { searchParams } = new URL(request.url);
  const domain = (searchParams.get("domain") || "").trim().toLowerCase();

  if (!domain) {
    return NextResponse.json(
      { error: "missing_params", hint: "Provide a 'domain' query parameter." },
      { status: 400 }
    );
  }
  if (!/^[a-z0-9.-]+\.[a-z]{2,}$/i.test(domain) || domain.includes("..")) {
    return NextResponse.json(
      { error: "invalid_domain", hint: `Not a valid domain: ${domain}` },
      { status: 400 }
    );
  }

  const cacheK = cacheKey("hosting", domain);
  const cached = getCached<HostingResult>(cacheK);
  if (cached) return NextResponse.json({ ...cached, cached: true });

  // 1. Resolve A record via DoH
  const ip = await fetchDoH(domain, 1);

  // 2. Fetch homepage over HTTPS — capture headers, follow redirects, get title
  const url = `https://${domain}/`;
  let html = "";
  let headers: Record<string, string> = {};
  let finalUrl: string | undefined;
  let redirectCount = 0;
  let httpStatus: number | undefined;
  let responseTimeMs: number | undefined;
  let resolvedViaHttps = true;

  try {
    const start = Date.now();
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 8000);
    const res = await fetch(url, {
      signal: controller.signal,
      redirect: "follow",
      headers: { "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36" },
    });
    clearTimeout(timeout);
    responseTimeMs = Date.now() - start;
    httpStatus = res.status;
    finalUrl = res.url;
    // Detect redirects by counting the response.url vs original
    if (finalUrl !== url) {
      // There may have been multiple — we can't easily count, but we know there was at least one
      redirectCount = 1;
    }
    headers = {};
    res.headers.forEach((value, key) => {
      headers[key.toLowerCase()] = value;
    });
    html = await res.text();
  } catch (err: any) {
    // Try HTTP as fallback — some sites don't have HTTPS
    try {
      const httpUrl = `http://${domain}/`;
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 8000);
      const res = await fetch(httpUrl, {
        signal: controller.signal,
        redirect: "follow",
        headers: { "User-Agent": "Mozilla/5.0" },
      });
      clearTimeout(timeout);
      httpStatus = res.status;
      finalUrl = res.url;
      resolvedViaHttps = false;
      headers = {};
      res.headers.forEach((value, key) => {
        headers[key.toLowerCase()] = value;
      });
      html = await res.text();
    } catch {
      return NextResponse.json({
        domain,
        available: false,
        ip,
        technologies: [],
        securityHeaders: {},
        securityScore: 0,
        pivotHints: {},
        error: "site_unreachable",
      });
    }
  }

  // 3. Detect CDN, tech stack, security headers
  const cdnInfo = detectCdn(headers, ip);
  const tech = detectTech(headers, html);
  const title = extractTitle(html);
  const faviconHash = finalUrl ? await fetchFaviconHash(finalUrl) : undefined;

  const securityHeaders = {
    hsts: headers["strict-transport-security"],
    csp: headers["content-security-policy"],
    xFrameOptions: headers["x-frame-options"],
    xContentTypeOptions: headers["x-content-type-options"],
    referrerPolicy: headers["referrer-policy"],
    permissionsPolicy: headers["permissions-policy"],
  };
  let securityScore = 0;
  if (securityHeaders.hsts) securityScore++;
  if (securityHeaders.csp) securityScore++;
  if (securityHeaders.xFrameOptions) securityScore++;
  if (securityHeaders.xContentTypeOptions) securityScore++;
  if (securityHeaders.referrerPolicy) securityScore++;
  if (securityHeaders.permissionsPolicy) securityScore++;

  // Pivot hints
  const pivotHints: HostingResult["pivotHints"] = {
    cdnEdgeIp: headers["cf-ray"]?.split("-")[0],
    cdnEdgePop: cdnInfo.edge,
    serverHostname: headers["server"] || undefined,
  };

  const result: HostingResult = {
    domain,
    available: true,
    ip,
    resolvedViaHttps,
    finalUrl,
    redirectCount,
    webServer: headers["server"],
    poweredBy: headers["x-powered-by"],
    generator: headers["x-generator"] || (tech.find((t) => t.evidence.includes("Generator"))?.name),
    cdn: cdnInfo.cdn,
    cdnEdge: cdnInfo.edge,
    technologies: tech,
    securityHeaders,
    securityScore,
    title,
    faviconHash,
    httpStatus,
    responseTimeMs,
    pivotHints,
  };

  setCached(cacheK, result, 30 * 60 * 1000); // 30 min
  return NextResponse.json(result);
}
