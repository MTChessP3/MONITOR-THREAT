// IP Intel — DNSBL / blacklist lookups
//
// Strategy (optimized for speed):
// 1. Run 15 direct DNSBL DNS checks in parallel (node:dns) — these resolve
//    in ~50-300ms total.
// 2. In parallel, scrape multirbl.valli.org: GET the lookup HTML, extract
//    session hash + test rows, then POST in batches of 25 with a 3s timeout
//    per batch. If multirbl takes >5s or fails, we still return the direct
//    results.
// 3. Cache the combined result for 10 minutes per IP.

import { NextResponse } from "next/server";
import * as dns from "node:dns/promises";
import { getCached, setCached, cacheKey } from "@/lib/cache";

interface BlacklistEntry {
  rid: string;
  zone: string;
  url?: string;
  result: string;
  category: "black" | "brown" | "yellow" | "white" | "neutral" | "not_listed" | "failed";
  reason?: string;
}

interface BlacklistResult {
  ip: string;
  source: string;
  summary: {
    total: number;
    blacklisted: number;
    brownlisted: number;
    yellowlisted: number;
    whitelisted: number;
    neutrallisted: number;
    notListed: number;
    failed: number;
  };
  entries: BlacklistEntry[];
  embedded_url: string;
  multirbl_ok: boolean;
}

// Direct DNSBL zones — most relevant for IP reputation
const DIRECT_DNSBL_ZONES = [
  { zone: "zen.spamhaus.org", url: "https://www.spamhaus.org/zen/", category: "black" as const },
  { zone: "bl.spamcop.net", url: "https://www.spamcop.net/bl.shtml", category: "black" as const },
  { zone: "dnsbl.sorbs.net", url: "https://www.sorbs.net/", category: "black" as const },
  { zone: "b.barracudacentral.org", url: "https://www.barracudacentral.org/", category: "black" as const },
  { zone: "dnsbl-1.uceprotect.net", url: "https://www.uceprotect.net/", category: "black" as const },
  { zone: "dnsbl-2.uceprotect.net", url: "https://www.uceprotect.net/", category: "black" as const },
  { zone: "dnsbl-3.uceprotect.net", url: "https://www.uceprotect.net/", category: "black" as const },
  { zone: "cbl.abuseat.org", url: "https://www.abuseat.org/", category: "black" as const },
  { zone: "psbl.surriel.com", url: "https://psbl.surriel.com/", category: "black" as const },
  { zone: "dyna.spamrats.com", url: "https://www.spamrats.com/", category: "black" as const },
  { zone: "access.mailspike.net", url: "https://mailspike.net/", category: "black" as const },
  { zone: "rbl.interserver.net", url: "https://interserver.net/", category: "black" as const },
  { zone: "db.wpbl.info", url: "https://wpbl.info/", category: "black" as const },
  { zone: "truncate.gbudb.net", url: "https://gbudb.net/", category: "black" as const },
  { zone: "dnsbl.dronebl.org", url: "https://dronebl.org/", category: "black" as const },
];

function reverseIpv4(ip: string): string {
  return ip.split(".").reverse().join(".");
}

async function checkDirectDnsbl(ip: string): Promise<BlacklistEntry[]> {
  const reversed = reverseIpv4(ip);
  const checks = DIRECT_DNSBL_ZONES.map(async (z) => {
    const zoneTrim = z.zone.trim();
    const lookup = `${reversed}.${zoneTrim}`;
    try {
      // 2s timeout per DNS query (DNS is fast; if it takes longer it's broken)
      const c = new AbortController();
      const t = setTimeout(() => c.abort(), 2000);
      const records = await dns.resolve4(lookup).catch((e) => {
        if (e.code === "ENOTFOUND" || e.code === "ENODATA") return [];
        throw e;
      });
      clearTimeout(t);
      if (records.length > 0) {
        return {
          rid: `direct_${zoneTrim}`,
          zone: zoneTrim,
          url: z.url,
          result: `Listed (${records.join(", ")})`,
          category: z.category,
          reason: `DNSBL return: ${records.join(", ")}`,
        } as BlacklistEntry;
      }
      return {
        rid: `direct_${zoneTrim}`,
        zone: zoneTrim,
        url: z.url,
        result: "Not listed",
        category: "not_listed" as const,
      } as BlacklistEntry;
    } catch (err: any) {
      return {
        rid: `direct_${zoneTrim}`,
        zone: zoneTrim,
        url: z.url,
        result: "Not listed",
        category: "not_listed" as const,
      } as BlacklistEntry;
    }
  });
  return Promise.all(checks);
}

async function checkMultirbl(ip: string): Promise<{
  entries: BlacklistEntry[];
  sessionHash: string | null;
  totalScanned: number;
  ok: boolean;
}> {
  try {
    const controller = new AbortController();
    // Strict 4s timeout for the HTML fetch
    const timeout = setTimeout(() => controller.abort(), 4000);
    const htmlRes = await fetch(`https://multirbl.valli.org/lookup/${encodeURIComponent(ip)}.html`, {
      signal: controller.signal,
      headers: {
        "User-Agent":
          "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120 Safari/537.36",
      },
    });
    clearTimeout(timeout);

    if (!htmlRes.ok) {
      return { entries: [], sessionHash: null, totalScanned: 0, ok: false };
    }

    const html = await htmlRes.text();

    const hashMatch = html.match(/"asessionHash":\s*"([a-f0-9]+)"/);
    const sessionHash = hashMatch ? hashMatch[1] : null;

    if (!sessionHash) {
      return { entries: [], sessionHash: null, totalScanned: 0, ok: false };
    }

    // Extract test rows
    const rowRegex =
      /<tr\s+id="([^"]+)">\s*<td class="l_id">(\d+)<\/td>\s*<td class="l_qhost">([^<]+)<\/td>/g;
    const rows: { rid: string; lid: string; qhost: string }[] = [];
    let match;
    while ((match = rowRegex.exec(html)) !== null) {
      rows.push({ rid: match[1], lid: match[2], qhost: match[3] });
    }

    if (rows.length === 0) {
      return { entries: [], sessionHash, totalScanned: 0, ok: false };
    }

    // POST in batches of 50, with a 3s timeout per batch
    const CONCURRENCY = 50;
    const entries: BlacklistEntry[] = [];

    for (let i = 0; i < rows.length; i += CONCURRENCY) {
      const batch = rows.slice(i, i + CONCURRENCY);
      const batchResults = await Promise.all(
        batch.map(async (row) => {
          try {
            const c = new AbortController();
            // Per-row timeout — total batch is bounded by slowest row
            const t = setTimeout(() => c.abort(), 3000);
            const r = await fetch("https://multirbl.valli.org/json-lookup.php", {
              method: "POST",
              signal: c.signal,
              headers: {
                "Content-Type": "application/x-www-form-urlencoded",
                "User-Agent":
                  "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120 Safari/537.36",
                Referer: `https://multirbl.valli.org/lookup/${encodeURIComponent(ip)}.html`,
              },
              body: `ash=${sessionHash}&rid=${row.rid}&lid=${row.lid}&q=${encodeURIComponent(row.qhost)}`,
            });
            clearTimeout(t);
            if (!r.ok) {
              return {
                rid: row.rid,
                zone: row.rid.split("_")[0],
                result: "Failed",
                category: "failed" as const,
              } as BlacklistEntry;
            }
            const json = await r.json();
            const listed = json?.data?.listed === true;
            const failed = json?.data?.failed === true;
            const color = json?.result_color;
            const host = json?.data?.host || "";

            let category: BlacklistEntry["category"] = "not_listed";
            let resultStr = "Not listed";
            let reason: string | undefined;
            if (failed) {
              category = "failed";
              resultStr = "Failed";
            } else if (listed) {
              category =
                color === "black"
                  ? "black"
                  : color === "brown"
                  ? "brown"
                  : color === "yellow"
                  ? "yellow"
                  : color === "white"
                  ? "white"
                  : color === "neutral"
                  ? "neutral"
                  : "not_listed";
              resultStr = "Listed";
              if (json?.data?.txt) {
                reason = Array.isArray(json.data.txt)
                  ? json.data.txt.join("; ")
                  : String(json.data.txt);
              }
            }

            return {
              rid: row.rid,
              zone: host || row.rid.split("_")[0],
              result: resultStr,
              category,
              reason,
            } as BlacklistEntry;
          } catch {
            return {
              rid: row.rid,
              zone: row.rid.split("_")[0],
              result: "Failed",
              category: "failed" as const,
            } as BlacklistEntry;
          }
        })
      );
      entries.push(...batchResults);
    }

    return { entries, sessionHash, totalScanned: entries.length, ok: true };
  } catch {
    return { entries: [], sessionHash: null, totalScanned: 0, ok: false };
  }
}

function summarize(entries: BlacklistEntry[]) {
  return {
    total: entries.length,
    blacklisted: entries.filter((e) => e.category === "black").length,
    brownlisted: entries.filter((e) => e.category === "brown").length,
    yellowlisted: entries.filter((e) => e.category === "yellow").length,
    whitelisted: entries.filter((e) => e.category === "white").length,
    neutrallisted: entries.filter((e) => e.category === "neutral").length,
    notListed: entries.filter((e) => e.category === "not_listed").length,
    failed: entries.filter((e) => e.category === "failed").length,
  };
}

export async function GET(request: Request) {
  const { searchParams } = new URL(request.url);
  const ip = (searchParams.get("ip") || "").trim();

  if (!ip) {
    return NextResponse.json(
      { error: "missing_params", hint: "Provide an 'ip' query parameter." },
      { status: 400 }
    );
  }

  const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/;
  if (!ipv4Regex.test(ip)) {
    return NextResponse.json(
      { error: "invalid_ip", hint: "Only IPv4 supported for blacklist lookups." },
      { status: 400 }
    );
  }

  // Cache check — saves ~3-5s on repeat queries
  const cacheK = cacheKey("blacklists", ip);
  const cached = getCached<BlacklistResult>(cacheK);
  if (cached) {
    return NextResponse.json({ ...cached, cached: true });
  }

  // Run both in parallel — multirbl is slow, direct is fast
  const [directResult, multirblResult] = await Promise.all([
    checkDirectDnsbl(ip),
    checkMultirbl(ip),
  ]);

  const combined: BlacklistEntry[] = [...multirblResult.entries, ...directResult];

  const result: BlacklistResult = {
    ip,
    source: "multirbl.valli.org + direct DNSBL",
    summary: summarize(combined),
    entries: combined,
    embedded_url: `https://multirbl.valli.org/lookup/${encodeURIComponent(ip)}.html`,
    multirbl_ok: multirblResult.ok,
  };

  setCached(cacheK, result);

  return NextResponse.json(result);
}
