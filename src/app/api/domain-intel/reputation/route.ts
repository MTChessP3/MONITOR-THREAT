// Domain Intel — Reputation via VirusTotal v3 domain report
//
// Uses the same VIRUSTOTAL_API_KEY env var already configured. Returns
// the last_analysis_stats, community votes, reputation, categories,
// and the engine verdicts (which engines flagged the domain as
// malicious and what they call it).

import { NextResponse } from "next/server";
import { getCached, setCached, cacheKey } from "@/lib/cache";

interface VtDomainResult {
  domain: string;
  available: boolean;
  // Last analysis stats
  lastAnalysisStats: {
    malicious: number;
    suspicious: number;
    harmless: number;
    undetected: number;
    timeout: number;
  };
  totalEngines: number;
  flaggedEnginesCount: number;
  flaggedEngines: Array<{
    engine: string;
    category: "malicious" | "suspicious";
    result: string;
  }>;
  // Categories assigned by VT partners
  categories: Array<{ source: string; category: string }>;
  // Community
  reputation: number;
  totalVotes: { harmless: number; malicious: number };
  // Last analysis
  lastAnalysisDate?: string;
  // Verdict
  classification: "BENIGN" | "SUSPICIOUS" | "MALICIOUS";
  error?: string;
}

function classify(flaggedCount: number, total: number): "BENIGN" | "SUSPICIOUS" | "MALICIOUS" {
  if (total === 0) return "BENIGN";
  if (flaggedCount >= 5) return "MALICIOUS";
  if (flaggedCount >= 1) return "SUSPICIOUS";
  return "BENIGN";
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

  const cacheK = cacheKey("vt_domain", domain);
  const cached = getCached<VtDomainResult>(cacheK);
  if (cached) return NextResponse.json({ ...cached, cached: true });

  const apiKey = process.env.VIRUSTOTAL_API_KEY;
  if (!apiKey) {
    return NextResponse.json({
      domain,
      available: false,
      lastAnalysisStats: { malicious: 0, suspicious: 0, harmless: 0, undetected: 0, timeout: 0 },
      totalEngines: 0,
      flaggedEnginesCount: 0,
      flaggedEngines: [],
      categories: [],
      reputation: 0,
      totalVotes: { harmless: 0, malicious: 0 },
      classification: "BENIGN",
      error: "virustotal_not_configured",
    });
  }

  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 8000);
    const res = await fetch(
      `https://www.virustotal.com/api/v3/domains/${encodeURIComponent(domain)}`,
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
        domain,
        available: false,
        lastAnalysisStats: { malicious: 0, suspicious: 0, harmless: 0, undetected: 0, timeout: 0 },
        totalEngines: 0,
        flaggedEnginesCount: 0,
        flaggedEngines: [],
        categories: [],
        reputation: 0,
        totalVotes: { harmless: 0, malicious: 0 },
        classification: "BENIGN",
        error: "domain_not_scanned",
      });
    }
    if (!res.ok) {
      return NextResponse.json({
        domain,
        available: false,
        lastAnalysisStats: { malicious: 0, suspicious: 0, harmless: 0, undetected: 0, timeout: 0 },
        totalEngines: 0,
        flaggedEnginesCount: 0,
        flaggedEngines: [],
        categories: [],
        reputation: 0,
        totalVotes: { harmless: 0, malicious: 0 },
        classification: "BENIGN",
        error: `vt_error_${res.status}`,
      });
    }

    const data = await res.json();
    const a = data?.data?.attributes;
    if (!a) {
      return NextResponse.json({
        domain,
        available: false,
        lastAnalysisStats: { malicious: 0, suspicious: 0, harmless: 0, undetected: 0, timeout: 0 },
        totalEngines: 0,
        flaggedEnginesCount: 0,
        flaggedEngines: [],
        categories: [],
        reputation: 0,
        totalVotes: { harmless: 0, malicious: 0 },
        classification: "BENIGN",
        error: "no_attributes",
      });
    }

    const stats = a.last_analysis_stats || {
      malicious: 0,
      suspicious: 0,
      harmless: 0,
      undetected: 0,
      timeout: 0,
    };
    const totalEngines =
      stats.malicious + stats.suspicious + stats.harmless + stats.undetected + (stats.timeout || 0);

    // Flagged engines
    const flaggedEngines: VtDomainResult["flaggedEngines"] = [];
    const results = a.last_analysis_results || {};
    for (const [engine, r] of Object.entries(results)) {
      const cat = (r as any)?.category as string;
      if (cat === "malicious" || cat === "suspicious") {
        flaggedEngines.push({
          engine,
          category: cat as any,
          result: (r as any)?.result || cat,
        });
      }
    }

    // Categories (a dictionary of {source: category})
    const categories: VtDomainResult["categories"] = [];
    if (a.categories && typeof a.categories === "object") {
      for (const [src, cat] of Object.entries(a.categories)) {
        categories.push({ source: src, category: String(cat) });
      }
    }

    const flaggedCount = stats.malicious + stats.suspicious;
    const result: VtDomainResult = {
      domain: data.data.id || domain,
      available: true,
      lastAnalysisStats: stats,
      totalEngines,
      flaggedEnginesCount: flaggedCount,
      flaggedEngines,
      categories,
      reputation: a.reputation ?? 0,
      totalVotes: a.total_votes || { harmless: 0, malicious: 0 },
      lastAnalysisDate: a.last_analysis_date
        ? new Date(a.last_analysis_date * 1000).toISOString()
        : undefined,
      classification: classify(flaggedCount, totalEngines),
    };

    setCached(cacheK, result, 60 * 60 * 1000); // 1 hour TTL
    return NextResponse.json(result);
  } catch (err: any) {
    return NextResponse.json(
      {
        domain,
        available: false,
        lastAnalysisStats: { malicious: 0, suspicious: 0, harmless: 0, undetected: 0, timeout: 0 },
        totalEngines: 0,
        flaggedEnginesCount: 0,
        flaggedEngines: [],
        categories: [],
        reputation: 0,
        totalVotes: { harmless: 0, malicious: 0 },
        classification: "BENIGN",
        error: "vt_unreachable",
        hint: err.message,
      },
      { status: 502 }
    );
  }
}
