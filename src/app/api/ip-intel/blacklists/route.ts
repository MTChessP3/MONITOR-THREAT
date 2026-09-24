// IP Intel — DNSBL / blacklist lookups via multirbl.valli.org
// Strategy:
// 1. GET https://multirbl.valli.org/lookup/{ip}.html  → extract asessionHash + list of test rows
// 2. POST https://multirbl.valli.org/json-lookup.php in parallel for each row
// 3. Aggregate results: blacklisted / brownlisted / yellowlisted / whitelisted / not listed / failed
// 4. Also do direct DNSBL checks via Node's dns module as a fast parallel source

import { NextResponse } from "next/server";
import * as dns from "node:dns/promises";

interface BlacklistEntry {
  rid: string;
  zone: string;
  url?: string;
  result: string; // Listed / Not listed / Failed
  category: "black" | "brown" | "yellow" | "white" | "neutral" | "not_listed" | "failed";
  reason?: string;
}

interface BlacklistResult {
  ip: string;
  source: string; // "multirbl.valli.org" or "direct-dnsbl"
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
}

// Quick direct DNSBL zones — most relevant for IP reputation
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
  { zone: "singular.ttk.pte.hu", url: "https://tk.pte.hu/", category: "black" as const },
  { zone: " truncate.gbudb.net", url: "https://gbudb.net/", category: "black" as const },
];

// Reverse an IPv4 address for DNSBL lookup
function reverseIpv4(ip: string): string {
  return ip.split(".").reverse().join(".");
}

async function checkDirectDnsbl(ip: string): Promise<BlacklistEntry[]> {
  const reversed = reverseIpv4(ip);
  const results: BlacklistEntry[] = [];

  const checks = DIRECT_DNSBL_ZONES.map(async (z) => {
    try {
      const lookup = `${reversed}.${z.zone.trim()}`;
      const records = await dns.resolve4(lookup).catch(() => []);
      if (records.length > 0) {
        return {
          rid: `direct_${z.zone.trim()}`,
          zone: z.zone.trim(),
          url: z.url,
          result: `Listed (${records.join(", ")})`,
          category: z.category,
          reason: records.includes("127.0.0.2") ? "Spam source" : `DNSBL return: ${records.join(", ")}`,
        } as BlacklistEntry;
      }
      return {
        rid: `direct_${z.zone.trim()}`,
        zone: z.zone.trim(),
        url: z.url,
        result: "Not listed",
        category: "not_listed" as const,
      } as BlacklistEntry;
    } catch (err: any) {
      if (err.code === "ENOTFOUND" || err.code === "ENODATA") {
        return {
          rid: `direct_${z.zone.trim()}`,
          zone: z.zone.trim(),
          url: z.url,
          result: "Not listed",
          category: "not_listed" as const,
        } as BlacklistEntry;
      }
      return {
        rid: `direct_${z.zone.trim()}`,
        zone: z.zone.trim(),
        url: z.url,
        result: "Failed",
        category: "failed" as const,
        reason: err.message,
      } as BlacklistEntry;
    }
  });

  return Promise.all(checks);
}

async function checkMultirbl(ip: string): Promise<{
  entries: BlacklistEntry[];
  sessionHash: string | null;
  error?: string;
}> {
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 10000);

    const htmlRes = await fetch(`https://multirbl.valli.org/lookup/${encodeURIComponent(ip)}.html`, {
      signal: controller.signal,
      headers: {
        "User-Agent":
          "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120 Safari/537.36",
      },
    });
    clearTimeout(timeout);

    if (!htmlRes.ok) {
      return { entries: [], sessionHash: null, error: `multirbl returned ${htmlRes.status}` };
    }

    const html = await htmlRes.text();

    // Extract asessionHash
    const hashMatch = html.match(/"asessionHash":\s*"([a-f0-9]+)"/);
    const sessionHash = hashMatch ? hashMatch[1] : null;

    if (!sessionHash) {
      return { entries: [], sessionHash: null, error: "no session hash" };
    }

    // Extract test rows: <tr id="DNSBLBlacklistTest_0"><td class="l_id">199</td><td class="l_qhost">8.8.8.8</td>...
    const rowRegex =
      /<tr\s+id="([^"]+)">\s*<td class="l_id">(\d+)<\/td>\s*<td class="l_qhost">([^<]+)<\/td>/g;
    const rows: { rid: string; lid: string; qhost: string }[] = [];
    let match;
    while ((match = rowRegex.exec(html)) !== null) {
      rows.push({ rid: match[1], lid: match[2], qhost: match[3] });
    }

    if (rows.length === 0) {
      return { entries: [], sessionHash, error: "no test rows" };
    }

    // POST to /json-lookup.php for each row, in parallel batches
    const CONCURRENCY = 25;
    const entries: BlacklistEntry[] = [];

    for (let i = 0; i < rows.length; i += CONCURRENCY) {
      const batch = rows.slice(i, i + CONCURRENCY);
      const batchResults = await Promise.all(
        batch.map(async (row) => {
          try {
            const c = new AbortController();
            const t = setTimeout(() => c.abort(), 8000);
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
          } catch (err) {
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

    return { entries, sessionHash };
  } catch (err: any) {
    return { entries: [], sessionHash: null, error: err.message };
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

  // Run both checks in parallel
  const [directResult, multirblResult] = await Promise.all([
    checkDirectDnsbl(ip),
    checkMultirbl(ip),
  ]);

  // Combine — prefer multirbl entries (more authoritative, 200+ zones), add direct DNSBL
  const combined: BlacklistEntry[] = [...multirblResult.entries, ...directResult];

  // Build the result with proper source attribution
  const result: BlacklistResult = {
    ip,
    source: "multirbl.valli.org + direct DNSBL",
    summary: summarize(combined),
    entries: combined,
    embedded_url: `https://multirbl.valli.org/lookup/${encodeURIComponent(ip)}.html`,
  };

  return NextResponse.json(result);
}
