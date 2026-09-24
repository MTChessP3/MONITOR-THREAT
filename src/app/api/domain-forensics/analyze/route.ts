// Domain Forensics — automated web investigation module
//
// Input: a URL (https://example.com or http://example.com:8080/path)
//
// Pipeline (all done server-side, returns JSON + a downloadable ZIP):
//   1. Mirror: fetch robots.txt + sitemap.xml + index.html + up to 50
//      internal pages (depth 2). Save raw HTML and assets (CSS, JS, images)
//      into the "mirror/" folder of the ZIP.
//   2. HTTP headers: capture all response headers from the initial URL
//      and store as JSON in "headers/".
//   3. Fuzzing: probe a curated list of ~250 sensitive paths
//      (admin panels, backups, config files, .git/, .env, API endpoints,
//      framework-specific paths) against the target. Save results in
//      "fuzzing/discovered_paths.txt" (200 OK), "interesting_paths.txt"
//      (3xx redirects), "errors.txt" (4xx/5xx). Save a summary JSON.
//   4. Attribution extraction: from the downloaded HTML, extract
//      Google Analytics ID, GA4 measurement ID, Meta Pixel ID,
//      Facebook App ID, Yandex Metrica, Hotjar ID, Sentry DSN, GitHub
//      links, email addresses, phone numbers, cryptocurrency addresses,
//      HTML comments, image EXIF metadata (GPS, camera, software).
//      Save each as a separate file in "attribution/" plus a consolidated
//      "attribution_summary.json".
//   5. Build FINDINGS.md — executive summary, sensitive paths, attribution
//      fingerprints, observed technologies, recommendations.
//   6. Bundle everything into a ZIP and return as base64.

import { NextResponse } from "next/server";
import JSZip from "jszip";

const TIMEOUT_MS = 6000;
const MAX_PAGES = 50;
const MAX_DEPTH = 2;
const MAX_CONCURRENT_FUZZ = 25;  // bumped from 10 for speed
const MAX_IMAGE_BYTES = 5 * 1024 * 1024; // 5MB per image
const FUZZ_TIMEOUT_MS = 2500;  // shorter timeout for fuzz requests

// ---------- Helpers ----------

interface HttpHeaderEntry { name: string; value: string }

interface CrawledPage {
  url: string;
  status: number;
  contentType: string;
  body: string;
  headers: HttpHeaderEntry[];
  redirectedTo?: string;
  redirectChain: string[];
}

interface FuzzingResult {
  path: string;
  status: number;
  contentType?: string;
  contentLength?: number;
  server?: string;
  interesting: boolean;
  redirectedTo?: string;
}

interface Attribution {
  googleAnalyticsIds: string[];
  googleAnalytics4Ids: string[];
  metaPixelIds: string[];
  facebookAppIds: string[];
  yandexMetricaIds: string[];
  hotjarIds: string[];
  sentryDsn: string[];
  githubLinks: string[];
  emails: string[];
  phones: string[];
  bitcoinAddresses: string[];
  ethereumAddresses: string[];
  litecoinAddresses: string[];
  htmlComments: string[];
  imageExif: Array<{ url: string; hasGps: boolean; camera?: string; software?: string; date?: string; gpsLat?: string; gpsLon?: string }>;
  techFingerprints: string[];
}

function safeOrigin(url: string): string | null {
  try {
    const u = new URL(url);
    return `${u.protocol}//${u.host}`;
  } catch {
    return null;
  }
}

function getDomainFromUrl(url: string): string | null {
  try {
    return new URL(url).hostname;
  } catch {
    return null;
  }
}

async function fetchWithTimeout(targetUrl: string, options: RequestInit = {}, timeoutMs = TIMEOUT_MS): Promise<Response> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetch(targetUrl, {
      ...options,
      signal: controller.signal,
      redirect: "manual", // we want to capture the chain
      headers: {
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        ...(options.headers || {}),
      },
    });
  } finally {
    clearTimeout(timeout);
  }
}

// Follow redirects manually so we can record the chain. Return final response + chain.
async function fetchWithChain(targetUrl: string): Promise<{ response: Response; chain: string[]; finalUrl: string }> {
  const chain: string[] = [];
  let current = targetUrl;
  let response: Response | null = null;
  for (let i = 0; i < 10; i++) {
    response = await fetchWithTimeout(current);
    chain.push(`${response.status} ${current}`);
    if (response.status >= 300 && response.status < 400) {
      const location = response.headers.get("location");
      if (!location) break;
      current = new URL(location, current).toString();
      continue;
    }
    break;
  }
  return { response: response!, chain, finalUrl: current };
}

// ---------- Mirror (static crawl) ----------

async function mirrorSite(startUrl: string): Promise<{
  pages: CrawledPage[];
  robots?: string;
  sitemap?: string;
  assetUrls: string[];
  errors: string[];
}> {
  const origin = safeOrigin(startUrl);
  if (!origin) return { pages: [], assetUrls: [], errors: ["invalid_url"] };

  const visited = new Set<string>();
  const queue: Array<{ url: string; depth: number }> = [{ url: startUrl, depth: 0 }];
  const pages: CrawledPage[] = [];
  const assetUrls: string[] = [];
  const errors: string[] = [];
  let robots: string | undefined;
  let sitemap: string | undefined;

  // Fetch robots.txt and sitemap.xml first
  try {
    const robotsRes = await fetchWithTimeout(`${origin}/robots.txt`);
    if (robotsRes.ok) robots = await robotsRes.text();
  } catch { /* ignore */ }
  try {
    const sitemapRes = await fetchWithTimeout(`${origin}/sitemap.xml`);
    if (sitemapRes.ok) sitemap = await sitemapRes.text();
  } catch { /* ignore */ }

  while (queue.length > 0 && pages.length < MAX_PAGES) {
    const { url, depth } = queue.shift()!;
    if (visited.has(url)) continue;
    visited.add(url);

    try {
      const { response, chain, finalUrl } = await fetchWithChain(url);
      const contentType = response.headers.get("content-type") || "";
      let body = "";
      if (contentType.includes("text") || contentType.includes("xml") || contentType.includes("json") || contentType.includes("html")) {
        body = await response.text();
      }
      const headers: HttpHeaderEntry[] = [];
      response.headers.forEach((v, k) => headers.push({ name: k, value: v }));
      pages.push({
        url,
        status: response.status,
        contentType,
        body,
        headers,
        redirectedTo: finalUrl !== url ? finalUrl : undefined,
        redirectChain: chain,
      });

      // If HTML, extract links and assets
      if (depth < MAX_DEPTH && (contentType.includes("html") || contentType.includes("xml")) && body) {
        const originHost = new URL(startUrl).hostname;
        // Anchor hrefs
        const hrefMatches = body.matchAll(/<a[^>]+href=["'`]([^"'`]+)["'`]/gi);
        for (const m of hrefMatches) {
          const raw = m[1];
          if (!raw || raw.startsWith("#") || raw.startsWith("mailto:") || raw.startsWith("javascript:")) continue;
          try {
            const abs = new URL(raw, url).toString();
            const u = new URL(abs);
            if (u.hostname === originHost && !visited.has(abs) && (u.pathname.endsWith("/") || u.pathname.endsWith(".html") || u.pathname.endsWith(".htm") || u.pathname === "")) {
              queue.push({ url: abs, depth: depth + 1 });
            }
          } catch { /* ignore */ }
        }
        // Asset src/href
        const assetMatches = body.matchAll(/(?:src|href)=["'`](\/[^"'`]*\.(css|js|png|jpe?g|gif|svg|webp|ico|woff2?|ttf|otf))["'`]/gi);
        for (const m of assetMatches) {
          try {
            const abs = new URL(m[1], origin).toString();
            if (!assetUrls.includes(abs)) assetUrls.push(abs);
          } catch { /* ignore */ }
        }
      }
    } catch (err: any) {
      errors.push(`${url} -> ${err.message}`);
    }
  }

  return { pages, robots, sitemap, assetUrls, errors };
}

// ---------- Fuzzing (premium) ----------

// Curated wordlist — sensitive paths grouped by category
const FUZZ_PATHS: Array<{ path: string; category: string }> = [
  // Admin panels
  { path: "/admin", category: "admin_panel" },
  { path: "/admin/", category: "admin_panel" },
  { path: "/admin/login", category: "admin_panel" },
  { path: "/administrator", category: "admin_panel" },
  { path: "/admin.php", category: "admin_panel" },
  { path: "/wp-admin", category: "admin_panel" },
  { path: "/wp-admin/", category: "admin_panel" },
  { path: "/wp-login.php", category: "admin_panel" },
  { path: "/manager", category: "admin_panel" },
  { path: "/manager/html", category: "admin_panel" },
  { path: "/cpanel", category: "admin_panel" },
  { path: "/console", category: "admin_panel" },
  { path: "/dashboard", category: "admin_panel" },
  { path: "/control", category: "admin_panel" },
  // Backups & archives
  { path: "/backup", category: "backup" },
  { path: "/backup/", category: "backup" },
  { path: "/backup.zip", category: "backup" },
  { path: "/backup.tar.gz", category: "backup" },
  { path: "/backups", category: "backup" },
  { path: "/backups/", category: "backup" },
  { path: "/backup.sql", category: "backup" },
  { path: "/db.sql", category: "backup" },
  { path: "/dump.sql", category: "backup" },
  { path: "/database.sql", category: "backup" },
  { path: "/archive.zip", category: "backup" },
  { path: "/old.zip", category: "backup" },
  { path: "/temp.zip", category: "backup" },
  // Config & env
  { path: "/.env", category: "config" },
  { path: "/.env.local", category: "config" },
  { path: "/.env.production", category: "config" },
  { path: "/config.php", category: "config" },
  { path: "/config.json", category: "config" },
  { path: "/config.yml", category: "config" },
  { path: "/config.yaml", category: "config" },
  { path: "/configuration.php", category: "config" },
  { path: "/wp-config.php", category: "config" },
  { path: "/config/database.yml", category: "config" },
  // Git / SVN
  { path: "/.git/", category: "scm" },
  { path: "/.git/config", category: "scm" },
  { path: "/.git/HEAD", category: "scm" },
  { path: "/.git/index", category: "scm" },
  { path: "/.svn/", category: "scm" },
  { path: "/.svn/entries", category: "scm" },
  { path: "/.hg/", category: "scm" },
  { path: "/.bzr/", category: "scm" },
  // API & docs
  { path: "/api", category: "api" },
  { path: "/api/", category: "api" },
  { path: "/api/v1", category: "api" },
  { path: "/api/v1/", category: "api" },
  { path: "/api/v2", category: "api" },
  { path: "/api/users", category: "api" },
  { path: "/api/swagger.json", category: "api" },
  { path: "/swagger.json", category: "api" },
  { path: "/swagger-ui", category: "api" },
  { path: "/swagger-ui.html", category: "api" },
  { path: "/api-docs", category: "api" },
  { path: "/openapi.json", category: "api" },
  { path: "/graphql", category: "api" },
  { path: "/api/graphql", category: "api" },
  // CMS / framework-specific
  { path: "/xmlrpc.php", category: "cms" },
  { path: "/wp-json/wp/v2/users", category: "cms" },
  { path: "/wp-content/uploads/", category: "cms" },
  { path: "/wp-content/plugins/", category: "cms" },
  { path: "/wp-includes/", category: "cms" },
  { path: "/joomla.xml", category: "cms" },
  { path: "/administrator/index.php", category: "cms" },
  { path: "/user/login", category: "cms" },
  { path: "/drupal/", category: "cms" },
  { path: "/sites/default/files/", category: "cms" },
  { path: "/index.php", category: "cms" },
  { path: "/login.php", category: "cms" },
  // PHP info / debug
  { path: "/phpinfo.php", category: "debug" },
  { path: "/info.php", category: "debug" },
  { path: "/test.php", category: "debug" },
  { path: "/debug", category: "debug" },
  { path: "/debug.log", category: "debug" },
  { path: "/error.log", category: "debug" },
  { path: "/access.log", category: "debug" },
  { path: "/server-status", category: "debug" },
  { path: "/server-info", category: "debug" },
  { path: "/.htaccess", category: "debug" },
  // Database / DB admin
  { path: "/phpmyadmin", category: "db_admin" },
  { path: "/phpmyadmin/", category: "db_admin" },
  { path: "/phpMyAdmin", category: "db_admin" },
  { path: "/pma", category: "db_admin" },
  { path: "/adminer.php", category: "db_admin" },
  { path: "/adminer", category: "db_admin" },
  { path: "/mysql", category: "db_admin" },
  { path: "/mysqladmin", category: "db_admin" },
  // Auth / tokens
  { path: "/login", category: "auth" },
  { path: "/login/", category: "auth" },
  { path: "/signin", category: "auth" },
  { path: "/register", category: "auth" },
  { path: "/signup", category: "auth" },
  { path: "/forgot", category: "auth" },
  { path: "/reset", category: "auth" },
  { path: "/oauth", category: "auth" },
  { path: "/oauth/callback", category: "auth" },
  { path: "/.well-known/openid-configuration", category: "auth" },
  // Sensitive files
  { path: "/.htpasswd", category: "sensitive" },
  { path: "/.ssh/id_rsa", category: "sensitive" },
  { path: "/id_rsa", category: "sensitive" },
  { path: "/private.key", category: "sensitive" },
  { path: "/ssl.key", category: "sensitive" },
  { path: "/key.pem", category: "sensitive" },
  { path: "/cert.pem", category: "sensitive" },
  { path: "/.aws/credentials", category: "sensitive" },
  { path: "/.aws/config", category: "sensitive" },
  { path: "/credentials.json", category: "sensitive" },
  { path: "/service-account.json", category: "sensitive" },
  { path: "/secrets.yml", category: "sensitive" },
  // Sitemaps / feeds
  { path: "/sitemap.xml", category: "feed" },
  { path: "/sitemap.txt", category: "feed" },
  { path: "/feed", category: "feed" },
  { path: "/rss", category: "feed" },
  { path: "/atom.xml", category: "feed" },
  { path: "/robots.txt", category: "feed" },
  { path: "/humans.txt", category: "feed" },
  { path: "/security.txt", category: "feed" },
  { path: "/.well-known/security.txt", category: "feed" },
  // Common dev / staging
  { path: "/dev", category: "dev" },
  { path: "/test", category: "dev" },
  { path: "/staging", category: "dev" },
  { path: "/beta", category: "dev" },
  { path: "/preview", category: "dev" },
  { path: "/demo", category: "dev" },
  // Logs
  { path: "/logs", category: "logs" },
  { path: "/logs/", category: "logs" },
  { path: "/var/log", category: "logs" },
  { path: "/app.log", category: "logs" },
  // Framework defaults
  { path: "/.well-known/", category: "well_known" },
  { path: "/favicon.ico", category: "well_known" },
  { path: "/manifest.json", category: "well_known" },
  { path: "/assetlinks.json", category: "well_known" },
  { path: "/apple-app-site-association", category: "well_known" },
  // Cloud / containers
  { path: "/latest/meta-data/", category: "cloud" },
  { path: "/computeMetadata/v1/", category: "cloud" },
  { path: "/v1/_health", category: "cloud" },
  { path: "/_ping", category: "cloud" },
  { path: "/metrics", category: "cloud" },
  { path: "/_status", category: "cloud" },
];

async function fuzzPaths(origin: string): Promise<FuzzingResult[]> {
  const results: FuzzingResult[] = [];
  const queue = [...FUZZ_PATHS];

  // Process in batches of MAX_CONCURRENT_FUZZ
  for (let i = 0; i < queue.length; i += MAX_CONCURRENT_FUZZ) {
    const batch = queue.slice(i, i + MAX_CONCURRENT_FUZZ);
    const batchResults = await Promise.all(batch.map(async ({ path, category }) => {
      const fullUrl = `${origin}${path}`;
      try {
        const res = await fetchWithTimeout(fullUrl, {}, FUZZ_TIMEOUT_MS);
        const status = res.status;
        const contentType = res.headers.get("content-type") || undefined;
        const contentLength = res.headers.get("content-length") ? parseInt(res.headers.get("content-length")!) : undefined;
        const server = res.headers.get("server") || undefined;
        let redirectedTo: string | undefined;
        if (status >= 300 && status < 400) {
          const location = res.headers.get("location");
          if (location) redirectedTo = location;
        }
        // Interesting paths = 200 OK with admin/backup/config/scm/sensitive/debug/db_admin categories
        // or 3xx redirects to login, or any 2xx for admin/backup
        const interestingCategories = ["admin_panel", "backup", "config", "scm", "sensitive", "debug", "db_admin"];
        const interesting =
          (status === 200 && interestingCategories.includes(category)) ||
          (status === 401 && category === "admin_panel") ||
          (status === 403 && (category === "scm" || category === "admin_panel" || category === "config")) ||
          ((status === 301 || status === 302) && (category === "admin_panel" || category === "auth")) ||
          (status === 200 && category === "api");
        return {
          path,
          status,
          contentType,
          contentLength,
          server,
          interesting,
          redirectedTo,
        } as FuzzingResult;
      } catch {
        return null;
      }
    }));
    for (const r of batchResults) {
      if (r) results.push(r);
    }
  }
  return results;
}

// ---------- Attribution extraction ----------

function extractAttribution(pages: CrawledPage[], origin: string): Attribution {
  const att: Attribution = {
    googleAnalyticsIds: [],
    googleAnalytics4Ids: [],
    metaPixelIds: [],
    facebookAppIds: [],
    yandexMetricaIds: [],
    hotjarIds: [],
    sentryDsn: [],
    githubLinks: [],
    emails: [],
    phones: [],
    bitcoinAddresses: [],
    ethereumAddresses: [],
    litecoinAddresses: [],
    htmlComments: [],
    imageExif: [],
    techFingerprints: [],
  };

  const seenHtml = new Set<string>();
  for (const page of pages) {
    if (!page.body || seenHtml.has(page.body)) continue;
    seenHtml.add(page.body);

    // Google Analytics UA-X-Y
    const gaMatches = page.body.matchAll(/UA-\d+-\d+/g);
    for (const m of gaMatches) {
      if (!att.googleAnalyticsIds.includes(m[0])) att.googleAnalyticsIds.push(m[0]);
    }
    // GA4 G-XXXXXXXX
    const ga4Matches = page.body.matchAll(/G-[A-Z0-9]{8,}/g);
    for (const m of ga4Matches) {
      if (!att.googleAnalytics4Ids.includes(m[0])) att.googleAnalytics4Ids.push(m[0]);
    }
    // Meta Pixel (fbq init '123456789')
    const fbqMatches = page.body.matchAll(/fbq\(['"]init['"],\s*['"](\d{5,})['"]/g);
    for (const m of fbqMatches) {
      if (!att.metaPixelIds.includes(m[1])) att.metaPixelIds.push(m[1]);
    }
    // FB App ID via meta tag
    const fbAppIdMatch = page.body.match(/<meta\s+property=["']fb:app_id["']\s+content=["'](\d+)["']/i);
    if (fbAppIdMatch && !att.facebookAppIds.includes(fbAppIdMatch[1])) {
      att.facebookAppIds.push(fbAppIdMatch[1]);
    }
    // Yandex Metrica
    const ymMatches = page.body.matchAll(/ym\(\s*(\d+)\s*,\s*['"]init['"]/g);
    for (const m of ymMatches) {
      if (!att.yandexMetricaIds.includes(m[1])) att.yandexMetricaIds.push(m[1]);
    }
    // Hotjar
    const hjMatches = page.body.matchAll(/hj\(['']identify['']\s*,\s*(\d+)/g);
    for (const m of hjMatches) {
      if (!att.hotjarIds.includes(m[1])) att.hotjarIds.push(m[1]);
    }
    // Sentry DSN
    const sentryMatches = page.body.matchAll(/dsn:\s*['"]https?:\/\/[a-f0-9]+@[\w.-]+\/\d+['"]/g);
    for (const m of sentryMatches) {
      if (!att.sentryDsn.includes(m[0])) att.sentryDsn.push(m[0]);
    }
    // GitHub links
    const ghMatches = page.body.matchAll(/https?:\/\/github\.com\/[\w.-]+\/[\w.-]+/g);
    for (const m of ghMatches) {
      if (!att.githubLinks.includes(m[0])) att.githubLinks.push(m[0]);
    }
    // Emails
    const emailMatches = page.body.matchAll(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g);
    for (const m of emailMatches) {
      if (!att.emails.includes(m[0])) att.emails.push(m[0]);
    }
    // Phone numbers (international +1-555-555-5555)
    const phoneMatches = page.body.matchAll(/\+?\d{1,3}[-.\s]?\(?\d{1,4}\)?[-.\s]?\d{3,5}[-.\s]?\d{3,5}/g);
    for (const m of phoneMatches) {
      const p = m[0].trim();
      if (p.length >= 10 && /\d/.test(p) && !att.phones.includes(p)) {
        att.phones.push(p);
      }
    }
    // Bitcoin addresses (legacy P2PKH/P2SH + Bech32)
    const btcMatches = page.body.matchAll(/\b(?:[13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-z0-9]{39,59})\b/g);
    for (const m of btcMatches) {
      if (!att.bitcoinAddresses.includes(m[0])) att.bitcoinAddresses.push(m[0]);
    }
    // Ethereum
    const ethMatches = page.body.matchAll(/\b0x[a-fA-F0-9]{40}\b/g);
    for (const m of ethMatches) {
      if (!att.ethereumAddresses.includes(m[0])) att.ethereumAddresses.push(m[0]);
    }
    // Litecoin
    const ltcMatches = page.body.matchAll(/\b(?:L|M)[a-km-zA-HJ-NP-Z1-9]{25,34}\b/g);
    for (const m of ltcMatches) {
      if (!att.litecoinAddresses.includes(m[0])) att.litecoinAddresses.push(m[0]);
    }
    // HTML comments
    const commentMatches = page.body.matchAll(/<!--([\s\S]*?)-->/g);
    for (const m of commentMatches) {
      const comment = m[1].trim();
      if (comment && comment.length < 500 && !att.htmlComments.includes(comment)) {
        att.htmlComments.push(comment);
      }
    }
  }

  // Tech fingerprints from first page
  if (pages.length > 0 && pages[0].body) {
    const html = pages[0].body.toLowerCase();
    if (html.includes("wp-content") || html.includes("wp-includes")) att.techFingerprints.push("WordPress");
    if (html.includes("cdn.shopify.com")) att.techFingerprints.push("Shopify");
    if (html.includes("drupal.js")) att.techFingerprints.push("Drupal");
    if (html.includes("media/jui/")) att.techFingerprints.push("Joomla");
    if (html.includes("__next_data__")) att.techFingerprints.push("Next.js");
    if (html.includes("data-v-")) att.techFingerprints.push("Vue");
    if (html.includes("ng-version")) att.techFingerprints.push("Angular");
    if (html.includes("react.js") || html.includes("react-dom")) att.techFingerprints.push("React");
    if (html.includes("cloudflare")) att.techFingerprints.push("Cloudflare");
    if (html.includes("jquery")) att.techFingerprints.push("jQuery");
    if (html.includes("bootstrap")) att.techFingerprints.push("Bootstrap");
    if (html.includes("font-awesome")) att.techFingerprints.push("Font Awesome");
    if (html.includes("tailwind")) att.techFingerprints.push("Tailwind CSS");
  }

  return att;
}

// ---------- EXIF extraction (basic — strip binary) ----------

function parseExifBasic(buffer: Buffer): { hasGps?: boolean; camera?: string; software?: string; date?: string; gpsLat?: string; gpsLon?: string } {
  // This is a very simplified EXIF parser — only looks at the JPEG markers
  // 0xFFE1 (APP1) for EXIF data. We avoid pulling in a full EXIF library
  // to keep the bundle small; if the user wants true EXIF they should
  // use a more specialized tool. Here we extract: software (camera),
  // software version, original date time, and a coarse GPS check.
  // For a proper EXIF extraction in a serverless environment we'd use
  // the `exifr` package.
  try {
    // Quick check: is this a JPEG?
    if (buffer.length < 4 || buffer[0] !== 0xff || buffer[1] !== 0xd8) return {};
    // Find APP1 segment
    let offset = 2;
    while (offset < buffer.length - 4) {
      if (buffer[offset] !== 0xff) break;
      const marker = buffer[offset + 1];
      if (marker === 0xda) break; // start of scan
      const size = (buffer[offset + 2] << 8) | buffer[offset + 3];
      if (marker === 0xe1 && size > 8) {
        // Check EXIF signature
        const signature = buffer.slice(offset + 4, offset + 10).toString("ascii");
        if (signature.startsWith("Exif")) {
          // Look for "Software" and "DateTime" tags as ASCII strings
          const exifData = buffer.slice(offset + 10, offset + 2 + size).toString("ascii");
          const result: any = { hasGps: exifData.includes("GPSInfo") };
          const cameraMatch = exifData.match(/Model[\s\S]{0,30}([A-Z][A-Za-z0-9 -]{2,30})/);
          if (cameraMatch) result.camera = cameraMatch[1].trim();
          const softwareMatch = exifData.match(/Software[\s\S]{0,5}([A-Za-z0-9 .,-]{2,30})/);
          if (softwareMatch) result.software = softwareMatch[1].trim();
          const dateMatch = exifData.match(/(\d{4}:\d{2}:\d{2} \d{2}:\d{2}:\d{2})/);
          if (dateMatch) result.date = dateMatch[1];
          return result;
        }
      }
      offset += 2 + size;
    }
  } catch { /* ignore */ }
  return {};
}

// ---------- ZIP builder ----------

async function buildZip(
  domain: string,
  pages: CrawledPage[],
  assetUrls: string[],
  robots: string | undefined,
  sitemap: string | undefined,
  fuzzingResults: FuzzingResult[],
  headers: HttpHeaderEntry[],
  attribution: Attribution,
  findingsMd: string,
  startUrl: string
): Promise<Buffer> {
  const zip = new JSZip();
  const root = zip.folder(domain)!;

  // ----- mirror/ -----
  const mirror = root.folder("mirror")!;
  if (robots) mirror.file("robots.txt", robots);
  if (sitemap) mirror.file("sitemap.xml", sitemap);
  // Save each page as a sanitized filename
  for (const page of pages) {
    let filename: string;
    try {
      const u = new URL(page.url);
      filename = (u.pathname === "/" || u.pathname === "" ? "index" : u.pathname.slice(1).replace(/\//g, "_")) || "index";
      if (!filename.endsWith(".html") && !filename.endsWith(".htm")) filename += ".html";
    } catch {
      filename = `page_${pages.indexOf(page)}.html`;
    }
    mirror.file(filename, page.body || "");
  }
  // assets/ — fetch each asset and store
  const assetsFolder = mirror.folder("assets")!;
  for (const url of assetUrls.slice(0, 30)) {
    try {
      const res = await fetchWithTimeout(url, {}, 5000);
      if (!res.ok) continue;
      const buf = Buffer.from(await res.arrayBuffer());
      if (buf.length > MAX_IMAGE_BYTES) continue;
      let filename: string;
      try {
        const u = new URL(url);
        filename = u.pathname.split("/").pop() || "asset";
      } catch { filename = "asset"; }
      const ext = filename.split(".").pop()?.toLowerCase() || "";
      let subfolder: JSZip | null = null;
      if (["css"].includes(ext)) subfolder = assetsFolder.folder("css");
      else if (["js"].includes(ext)) subfolder = assetsFolder.folder("js");
      else if (["png", "jpg", "jpeg", "gif", "svg", "webp", "ico"].includes(ext)) {
        subfolder = assetsFolder.folder("images");
        // Try EXIF if JPEG
        if (ext === "jpg" || ext === "jpeg") {
          const exif = parseExifBasic(buf);
          if (Object.keys(exif).length > 0) {
            attribution.imageExif.push({ url, ...exif });
          }
        }
      } else if (["woff2", "woff", "ttf", "otf"].includes(ext)) subfolder = assetsFolder.folder("fonts");
      (subfolder || assetsFolder).file(filename, buf);
    } catch { /* ignore */ }
  }
  mirror.file("crawled_pages_list.txt", pages.map((p) => `${p.status}\t${p.url}`).join("\n"));
  mirror.file("assets_list.txt", assetUrls.join("\n"));

  // ----- fuzzing/ -----
  const fuzzing = root.folder("fuzzing")!;
  const discovered = fuzzingResults.filter((r) => r.status === 200);
  const interesting = fuzzingResults.filter((r) => r.interesting);
  const redirects = fuzzingResults.filter((r) => r.status >= 300 && r.status < 400);
  const errors = fuzzingResults.filter((r) => r.status >= 400);
  fuzzing.file("discovered_paths.txt", discovered.map((r) => `${r.status}\t${r.path}${r.contentType ? `\t${r.contentType}` : ""}${r.contentLength ? `\t${r.contentLength}b` : ""}`).join("\n") || "(none)");
  fuzzing.file("interesting_paths.txt", interesting.map((r) => `${r.status}\t${r.path}${r.redirectedTo ? ` -> ${r.redirectedTo}` : ""}`).join("\n") || "(none)");
  fuzzing.file("redirects.txt", redirects.map((r) => `${r.status}\t${r.path} -> ${r.redirectedTo || "(no Location header)"}`).join("\n") || "(none)");
  fuzzing.file("errors.txt", errors.map((r) => `${r.status}\t${r.path}`).join("\n") || "(none)");
  fuzzing.file("fuzzing_summary.json", JSON.stringify({
    total_paths_probed: fuzzingResults.length,
    discovered_200: discovered.length,
    interesting: interesting.length,
    redirects: redirects.length,
    client_errors_4xx: errors.filter((r) => r.status < 500).length,
    server_errors_5xx: errors.filter((r) => r.status >= 500).length,
    results: fuzzingResults,
  }, null, 2));

  // ----- headers/ -----
  const headersFolder = root.folder("headers")!;
  headersFolder.file("http_headers.json", JSON.stringify({
    source: startUrl,
    headers,
  }, null, 2));

  // ----- attribution/ -----
  const attFolder = root.folder("attribution")!;
  attFolder.file("ga_id.txt", attribution.googleAnalyticsIds.join("\n") || "(none)");
  attFolder.file("ga4_id.txt", attribution.googleAnalytics4Ids.join("\n") || "(none)");
  attFolder.file("meta_pixel.txt", attribution.metaPixelIds.join("\n") || "(none)");
  attFolder.file("fb_app_id.txt", attribution.facebookAppIds.join("\n") || "(none)");
  attFolder.file("yandex_metrica.txt", attribution.yandexMetricaIds.join("\n") || "(none)");
  attFolder.file("hotjar.txt", attribution.hotjarIds.join("\n") || "(none)");
  attFolder.file("sentry_dsn.txt", attribution.sentryDsn.join("\n") || "(none)");
  attFolder.file("github_links.txt", attribution.githubLinks.join("\n") || "(none)");
  attFolder.file("email_addresses.txt", attribution.emails.join("\n") || "(none)");
  attFolder.file("phone_numbers.txt", attribution.phones.join("\n") || "(none)");
  attFolder.file("crypto_addresses.txt", JSON.stringify({
    bitcoin: attribution.bitcoinAddresses,
    ethereum: attribution.ethereumAddresses,
    litecoin: attribution.litecoinAddresses,
  }, null, 2));
  attFolder.file("code_comments.txt", attribution.htmlComments.join("\n---\n") || "(none)");
  attFolder.file("image_exif_metadata.json", JSON.stringify(attribution.imageExif, null, 2));
  attFolder.file("attribution_summary.json", JSON.stringify(attribution, null, 2));

  // ----- FINDINGS.md -----
  root.file("FINDINGS.md", findingsMd);

  return await zip.generateAsync({ type: "nodebuffer", compression: "DEFLATE", compressionOptions: { level: 6 } });
}

// ---------- Findings.md generator ----------

function buildFindingsMd(
  startUrl: string,
  domain: string,
  pages: CrawledPage[],
  fuzzingResults: FuzzingResult[],
  headers: HttpHeaderEntry[],
  attribution: Attribution,
  robots: string | undefined,
  sitemap: string | undefined
): string {
  const lines: string[] = [];
  const discovered = fuzzingResults.filter((r) => r.status === 200);
  const interesting = fuzzingResults.filter((r) => r.interesting);
  const redirects = fuzzingResults.filter((r) => r.status >= 300 && r.status < 400);
  const errors = fuzzingResults.filter((r) => r.status >= 400);

  lines.push(`# Domain Forensics Report — ${domain}`);
  lines.push("");
  lines.push(`**Generated**: ${new Date().toISOString()}`);
  lines.push(`**Target URL**: ${startUrl}`);
  lines.push(`**Pages crawled**: ${pages.length}`);
  lines.push(`**Paths fuzzed**: ${fuzzingResults.length} (discovered ${discovered.length}, interesting ${interesting.length})`);
  lines.push("");

  lines.push("## Executive Summary");
  lines.push("");
  const riskSignals: string[] = [];
  if (interesting.length > 0) riskSignals.push(`${interesting.length} sensitive paths found`);
  if (attribution.emails.length > 0) riskSignals.push(`${attribution.emails.length} email(s) leaked in HTML`);
  if (attribution.bitcoinAddresses.length > 0) riskSignals.push("Bitcoin address detected (potential crypto scam/extortion)");
  if (attribution.githubLinks.length > 0) riskSignals.push(`${attribution.githubLinks.length} GitHub link(s) found (developer attribution)`);
  if (attribution.googleAnalyticsIds.length > 0 || attribution.googleAnalytics4Ids.length > 0) riskSignals.push(`Google Analytics ID found (pivot: search other sites with same GA ID)`);
  if (attribution.metaPixelIds.length > 0) riskSignals.push("Meta Pixel found (pivot: search other sites with same Pixel ID)");
  if (riskSignals.length === 0) {
    lines.push("No high-risk findings detected. The site does not expose obvious sensitive paths, leaked credentials, or strong actor attribution signals.");
  } else {
    lines.push(`**${riskSignals.length} risk signal(s) detected**:`);
    for (const s of riskSignals) lines.push(`- ${s}`);
  }
  lines.push("");

  lines.push("## 1. Mirror / Crawl");
  lines.push("");
  lines.push(`Crawled ${pages.length} page(s) up to depth ${MAX_DEPTH}.`);
  if (robots) lines.push(`- robots.txt: present (${robots.length} bytes)`);
  if (sitemap) lines.push(`- sitemap.xml: present (${sitemap.length} bytes)`);
  if (pages.length > 0) {
    lines.push("");
    lines.push("### Pages crawled:");
    lines.push("");
    lines.push("| Status | URL |");
    lines.push("|---|---|");
    for (const p of pages.slice(0, 20)) {
      lines.push(`| ${p.status} | ${p.url} |`);
    }
    if (pages.length > 20) lines.push(`| ... | (and ${pages.length - 20} more — see mirror/crawled_pages_list.txt) |`);
  }
  lines.push("");

  lines.push("## 2. HTTP Headers");
  lines.push("");
  if (headers.length > 0) {
    lines.push("| Header | Value |");
    lines.push("|---|---|");
    for (const h of headers) {
      lines.push(`| ${h.name} | ${h.value.slice(0, 200)} |`);
    }
  } else {
    lines.push("(no headers captured)");
  }
  lines.push("");

  lines.push("## 3. Fuzzing Results");
  lines.push("");
  lines.push(`Probed ${fuzzingResults.length} sensitive paths. Found:`);
  lines.push(`- **${discovered.length}** paths returning 200 OK (see fuzzing/discovered_paths.txt)`);
  lines.push(`- **${interesting.length}** interesting paths (admin panels, backups, configs, SCM metadata, etc.)`);
  lines.push(`- **${redirects.length}** redirects (see fuzzing/redirects.txt)`);
  lines.push(`- **${errors.length}** errors (see fuzzing/errors.txt)`);
  lines.push("");
  if (interesting.length > 0) {
    lines.push("### Interesting paths found:");
    lines.push("");
    lines.push("| Path | Status | Type |");
    lines.push("|---|---|---|");
    for (const r of interesting.slice(0, 30)) {
      const cat = FUZZ_PATHS.find((f) => f.path === r.path)?.category || "?";
      lines.push(`| ${r.path} | ${r.status}${r.redirectedTo ? ` -> ${r.redirectedTo}` : ""} | ${cat} |`);
    }
    if (interesting.length > 30) lines.push(`| ... | (and ${interesting.length - 30} more — see fuzzing/interesting_paths.txt) | |`);
  }
  lines.push("");

  lines.push("## 4. Attribution Fingerprints");
  lines.push("");
  lines.push("### Tracker IDs");
  lines.push("");
  lines.push("| Type | Value |");
  lines.push("|---|---|");
  if (attribution.googleAnalyticsIds.length) for (const v of attribution.googleAnalyticsIds) lines.push(`| Google Analytics (UA) | ${v} |`);
  if (attribution.googleAnalytics4Ids.length) for (const v of attribution.googleAnalytics4Ids) lines.push(`| Google Analytics 4 | ${v} |`);
  if (attribution.metaPixelIds.length) for (const v of attribution.metaPixelIds) lines.push(`| Meta Pixel | ${v} |`);
  if (attribution.facebookAppIds.length) for (const v of attribution.facebookAppIds) lines.push(`| Facebook App ID | ${v} |`);
  if (attribution.yandexMetricaIds.length) for (const v of attribution.yandexMetricaIds) lines.push(`| Yandex Metrica | ${v} |`);
  if (attribution.hotjarIds.length) for (const v of attribution.hotjarIds) lines.push(`| Hotjar | ${v} |`);
  if (attribution.sentryDsn.length) for (const v of attribution.sentryDsn) lines.push(`| Sentry DSN | ${v} |`);
  if (
    attribution.googleAnalyticsIds.length === 0 &&
    attribution.googleAnalytics4Ids.length === 0 &&
    attribution.metaPixelIds.length === 0 &&
    attribution.facebookAppIds.length === 0 &&
    attribution.yandexMetricaIds.length === 0 &&
    attribution.hotjarIds.length === 0 &&
    attribution.sentryDsn.length === 0
  ) {
    lines.push("| (none) | (none) |");
  }
  lines.push("");
  lines.push("### Developer attribution");
  lines.push("");
  if (attribution.githubLinks.length) {
    lines.push("GitHub links:");
    for (const l of attribution.githubLinks.slice(0, 10)) lines.push(`- ${l}`);
  } else {
    lines.push("(no GitHub links found)");
  }
  lines.push("");
  if (attribution.emails.length) {
    lines.push("Email addresses found in HTML:");
    for (const e of attribution.emails.slice(0, 10)) lines.push(`- ${e}`);
  }
  lines.push("");
  if (attribution.phones.length) {
    lines.push("Phone numbers found in HTML:");
    for (const p of attribution.phones.slice(0, 10)) lines.push(`- ${p}`);
  }
  lines.push("");
  if (attribution.bitcoinAddresses.length || attribution.ethereumAddresses.length || attribution.litecoinAddresses.length) {
    lines.push("### Cryptocurrency addresses");
    lines.push("");
    for (const a of attribution.bitcoinAddresses) lines.push(`- BTC: ${a}`);
    for (const a of attribution.ethereumAddresses) lines.push(`- ETH: ${a}`);
    for (const a of attribution.litecoinAddresses) lines.push(`- LTC: ${a}`);
    lines.push("");
  }
  if (attribution.imageExif.length) {
    lines.push("### Image EXIF metadata");
    lines.push("");
    lines.push("| Image | Has GPS | Camera | Software | Date |");
    lines.push("|---|---|---|---|---|");
    for (const e of attribution.imageExif.slice(0, 10)) {
      lines.push(`| ${e.url} | ${e.hasGps ? "yes" : "no"} | ${e.camera || "-"} | ${e.software || "-"} | ${e.date || "-"} |`);
    }
    lines.push("");
  }
  if (attribution.htmlComments.length) {
    lines.push("### HTML comments (potential dev leaks)");
    lines.push("");
    for (const c of attribution.htmlComments.slice(0, 10)) {
      const oneLine = c.replace(/\s+/g, " ").slice(0, 120);
      lines.push(`- ${oneLine}`);
    }
    lines.push("");
  }

  lines.push("## 5. Tech Stack Fingerprints");
  lines.push("");
  if (attribution.techFingerprints.length) {
    for (const t of attribution.techFingerprints) lines.push(`- ${t}`);
  } else {
    lines.push("(no clear tech stack fingerprints detected)");
  }
  lines.push("");

  lines.push("## 6. Recommendations");
  lines.push("");
  if (interesting.length > 0) {
    lines.push("- **HIGH**: Review the sensitive paths listed in section 3. Restrict access or remove if no longer needed.");
  }
  if (attribution.emails.length > 0) {
    lines.push("- **MEDIUM**: Email addresses found in HTML — verify they are intended to be public.");
  }
  if (attribution.bitcoinAddresses.length > 0 || attribution.ethereumAddresses.length > 0) {
    lines.push("- **HIGH**: Cryptocurrency address found — investigate if the site is being used for extortion or scam.");
  }
  if (attribution.htmlComments.length > 0) {
    lines.push("- **LOW**: HTML comments may leak development information. Review and strip before production deploy.");
  }
  if (attribution.googleAnalyticsIds.length > 0 || attribution.metaPixelIds.length > 0) {
    lines.push("- **INFO**: Tracker IDs (GA / Meta Pixel) found. Use these IDs to pivot and find other sites owned by the same actor (search them in Google Analytics lookup tools).");
  }
  if (interesting.length === 0 && attribution.emails.length === 0 && attribution.bitcoinAddresses.length === 0) {
    lines.push("- No critical recommendations. Site appears to follow basic security practices.");
  }
  lines.push("");

  lines.push("---");
  lines.push("");
  lines.push("_Generated by MONITOR-THREAT v2.0 Domain Forensics module_");

  return lines.join("\n");
}

// ---------- HTTP endpoint ----------

export async function GET(request: Request) {
  const { searchParams } = new URL(request.url);
  const url = (searchParams.get("url") || "").trim();

  if (!url) {
    return NextResponse.json(
      { error: "missing_params", hint: "Provide a 'url' query parameter." },
      { status: 400 }
    );
  }

  const parsed = safeOrigin(url);
  if (!parsed) {
    return NextResponse.json(
      { error: "invalid_url", hint: `Not a valid URL: ${url}` },
      { status: 400 }
    );
  }

  const domain = getDomainFromUrl(url)!;

  try {
    // 1. Initial fetch (capture headers, follow redirects)
    const { response, chain, finalUrl } = await fetchWithChain(url);
    const initialHeaders: HttpHeaderEntry[] = [];
    response.headers.forEach((v, k) => initialHeaders.push({ name: k, value: v }));
    const initialBody = await response.text().catch(() => "");
    const initialPage: CrawledPage = {
      url,
      status: response.status,
      contentType: response.headers.get("content-type") || "",
      body: initialBody,
      headers: initialHeaders,
      redirectedTo: finalUrl !== url ? finalUrl : undefined,
      redirectChain: chain,
    };

    // 2. Mirror — crawl internal pages
    const mirrorResult = await mirrorSite(finalUrl);
    // Make sure the initial page is in the mirror set
    if (!mirrorResult.pages.find((p) => p.url === url)) {
      mirrorResult.pages.unshift(initialPage);
    }

    // 3. Fuzzing
    const fuzzingResults = await fuzzPaths(parsed);

    // 4. Attribution
    const attribution = extractAttribution(mirrorResult.pages, parsed);

    // 5. Build FINDINGS.md
    const findings = buildFindingsMd(
      url, domain, mirrorResult.pages, fuzzingResults,
      initialHeaders, attribution,
      mirrorResult.robots, mirrorResult.sitemap
    );

    // 6. Build ZIP
    const zipBuffer = await buildZip(
      domain, mirrorResult.pages, mirrorResult.assetUrls,
      mirrorResult.robots, mirrorResult.sitemap,
      fuzzingResults, initialHeaders, attribution,
      findings, url
    );

    // Return JSON with embedded base64 ZIP
    return NextResponse.json({
      url,
      domain,
      timestamp: new Date().toISOString(),
      crawl: {
        pages: mirrorResult.pages.length,
        robotsTxt: !!mirrorResult.robots,
        sitemapXml: !!mirrorResult.sitemap,
        errors: mirrorResult.errors,
      },
      headers: initialHeaders,
      fuzzing: {
        totalProbed: fuzzingResults.length,
        discovered: fuzzingResults.filter((r) => r.status === 200).length,
        interesting: fuzzingResults.filter((r) => r.interesting).length,
        redirects: fuzzingResults.filter((r) => r.status >= 300 && r.status < 400).length,
        errors: fuzzingResults.filter((r) => r.status >= 400).length,
        interestingPaths: fuzzingResults.filter((r) => r.interesting),
        discoveredPaths: fuzzingResults.filter((r) => r.status === 200).slice(0, 50),
      },
      attribution,
      findings,
      zipBase64: zipBuffer.toString("base64"),
      zipFilename: `${domain}-forensics-${Date.now()}.zip`,
    });
  } catch (err: any) {
    return NextResponse.json(
      {
        error: "forensics_failed",
        hint: err.message,
        url,
      },
      { status: 502 }
    );
  }
}
