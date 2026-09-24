// IP Intel — VirusTotal v3 reputation
// Requires VIRUSTOTAL_API_KEY env var. Free tier: 4 requests/minute, 500/day.
// Returns the full last_analysis_stats + per-engine results + community votes + reputation score.

import { NextResponse } from "next/server";

interface VtResult {
  ip: string;
  provider: "virustotal";
  // Headline numbers
  reputation: number; // community reputation (can be negative)
  lastAnalysisStats: {
    malicious: number;
    suspicious: number;
    undetected: number;
    harmless: number;
    timeout: number;
  };
  totalVotes: {
    harmless: number;
    malicious: number;
  };
  // Normalized 0..100 score (higher = more malicious)
  score: number;
  classification: "BENIGN" | "SUSPICIOUS" | "MALICIOUS";
  // Geo/network metadata VT has
  asn?: number;
  country?: string;
  network?: string;
  // Per-engine results, only those that flag (malicious/suspicious)
  flaggedEngines: Array<{
    engine: string;
    category: "malicious" | "suspicious";
    result: string;
  }>;
  totalEngines: number;
  lastAnalysisDate?: string; // ISO
  // Optional fields
  jarm?: string;
  tags?: string[];
}

function classify(score: number): "BENIGN" | "SUSPICIOUS" | "MALICIOUS" {
  // 0-4 = BENIGN (a few noisy engines, common for shared infrastructure)
  // 5-19 = SUSPICIOUS (worth investigating)
  // 20+ = MALICIOUS (multiple AV engines agree)
  if (score >= 20) return "MALICIOUS";
  if (score >= 5) return "SUSPICIOUS";
  return "BENIGN";
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
  const ipv6Regex = /^([0-9a-fA-F:]+)$/;
  if (!ipv4Regex.test(ip) && !ipv6Regex.test(ip)) {
    return NextResponse.json(
      { error: "invalid_ip", hint: `Not a valid IP: ${ip}` },
      { status: 400 }
    );
  }

  const apiKey = process.env.VIRUSTOTAL_API_KEY;
  if (!apiKey) {
    return NextResponse.json(
      {
        error: "virustotal_not_configured",
        hint: "Set VIRUSTOTAL_API_KEY env var to enable VirusTotal reputation lookups.",
      },
      { status: 503 }
    );
  }

  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 12000);
    const res = await fetch(
      `https://www.virustotal.com/api/v3/ip_addresses/${encodeURIComponent(ip)}`,
      {
        signal: controller.signal,
        headers: {
          "x-apikey": apiKey,
          Accept: "application/json",
          "User-Agent": "MONITOR-THREAT/2.0",
        },
      }
    );
    clearTimeout(timeout);

    if (res.status === 404) {
      return NextResponse.json({
        ip,
        provider: "virustotal",
        error: "not_found",
        hint: "VirusTotal has no report for this IP yet.",
      });
    }
    if (res.status === 429) {
      return NextResponse.json(
        {
          ip,
          provider: "virustotal",
          error: "rate_limited",
          hint: "VirusTotal rate limit hit (free tier: 4 req/min, 500/day).",
        },
        { status: 429 }
      );
    }
    if (!res.ok) {
      return NextResponse.json(
        {
          ip,
          provider: "virustotal",
          error: "upstream_error",
          status: res.status,
        },
        { status: 502 }
      );
    }

    const data = await res.json();
    const a = data?.data?.attributes;
    if (!a) {
      return NextResponse.json(
        { ip, provider: "virustotal", error: "no_attributes" },
        { status: 502 }
      );
    }

    const stats = a.last_analysis_stats || {
      malicious: 0,
      suspicious: 0,
      undetected: 0,
      harmless: 0,
      timeout: 0,
    };
    const totalEngines =
      (stats.malicious || 0) +
      (stats.suspicious || 0) +
      (stats.undetected || 0) +
      (stats.harmless || 0) +
      (stats.timeout || 0);

    // Normalized score 0..100 based on flagged engines ratio.
    // - 1-4 flagged engines = light noise (5-15 score, BENIGN)
    // - 5-9 flagged engines = real signal (15-40 score, SUSPICIOUS)
    // - 10+ flagged engines = MALICIOUS territory (40-100 score)
    const flaggedCount = (stats.malicious || 0) + (stats.suspicious || 0);
    let score: number;
    if (flaggedCount === 0) {
      score = 0;
    } else if (flaggedCount <= 4) {
      score = 5 + (flaggedCount * 3); // 8, 11, 14, 17
    } else if (flaggedCount <= 9) {
      score = 20 + ((flaggedCount - 4) * 4); // 24, 28, 32, 36, 40
    } else {
      score = Math.min(100, 45 + ((flaggedCount - 9) * 5));
    }

    // Per-engine flagged entries
    const flaggedEngines: VtResult["flaggedEngines"] = [];
    const results = a.last_analysis_results || {};
    for (const [engine, r] of Object.entries(results)) {
      const cat = (r as any)?.category as string | undefined;
      if (cat === "malicious" || cat === "suspicious") {
        flaggedEngines.push({
          engine,
          category: cat,
          result: (r as any)?.result || cat,
        });
      }
    }

    const result: VtResult = {
      ip: data.data.id,
      provider: "virustotal",
      reputation: a.reputation ?? 0,
      lastAnalysisStats: stats,
      totalVotes: a.total_votes || { harmless: 0, malicious: 0 },
      score,
      classification: classify(score),
      asn: a.asn,
      country: a.country,
      network: a.network,
      flaggedEngines,
      totalEngines,
      lastAnalysisDate: a.last_analysis_date
        ? new Date(a.last_analysis_date * 1000).toISOString()
        : undefined,
      jarm: a.jarm,
      tags: a.tags,
    };

    return NextResponse.json(result);
  } catch (err: any) {
    return NextResponse.json(
      {
        ip,
        provider: "virustotal",
        error: "virustotal_unreachable",
        hint: err.message,
      },
      { status: 502 }
    );
  }
}
