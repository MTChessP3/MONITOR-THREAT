// IP Intel — reputation & threat intel aggregation
//
// Primary signal: VirusTotal v3 (last_analysis_stats + community votes + reputation)
// Secondary signals:
//  - AbuseIPDB v2 (abuse confidence, total reports, last report, recent reports)
//  - multirbl.valli.org / DNSBL blacklists
//  - Shodan InternetDB tags (tor, scanner, malware, vulnerable)
//
// Final score = weighted combination of all signals, capped at 100.

import { NextResponse } from "next/server";

interface AbuseRecentReport {
  reporter: string;
  reportedAt: string;
  categories: number[];
  comment?: string;
}

interface AbuseIpdbBlock {
  available: boolean;
  abuseConfidenceScore: number;
  totalReports: number;
  numDistinctUsers: number;
  lastReportedAt?: string;
  countryCode?: string;
  usageType?: string;
  isp?: string;
  domain?: string;
  isWhitelisted?: boolean;
  classification: "BENIGN" | "SUSPICIOUS" | "MALICIOUS";
  recentReports: AbuseRecentReport[];
  error?: string;
}

interface ReputationResult {
  ip: string;
  score: number; // 0..100 — higher = more suspicious
  classification: "BENIGN" | "SUSPICIOUS" | "MALICIOUS";
  // VirusTotal is the headline source
  virusTotal: {
    score: number;
    classification: "BENIGN" | "SUSPICIOUS" | "MALICIOUS";
    reputation: number;
    lastAnalysisStats: {
      malicious: number;
      suspicious: number;
      undetected: number;
      harmless: number;
      timeout: number;
    };
    totalVotes: { harmless: number; malicious: number };
    totalEngines: number;
    flaggedEnginesCount: number;
    lastAnalysisDate?: string;
    available: boolean;
    error?: string;
  };
  // AbuseIPDB block — full data, shown alongside VT in the report
  abuseipdb: AbuseIpdbBlock;
  // Secondary signals
  signals: Array<{
    source: string;
    weight: number;
    detail: string;
  }>;
  tags: string[];
  threatIntel: Array<{
    source: string;
    verdict: string;
    details?: string;
  }>;
}

function classify(score: number): "BENIGN" | "SUSPICIOUS" | "MALICIOUS" {
  if (score >= 60) return "MALICIOUS";
  if (score >= 25) return "SUSPICIOUS";
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

  const base = new URL(request.url).origin;
  const ipEnc = encodeURIComponent(ip);

  // Parallel: VirusTotal (primary) + blacklists + shodan + abuseipdb (now via
  // the dedicated endpoint so we get full data, not just the inline minimum).
  const [vtRes, blacklistRes, shodanRes, abuseipdbRes] = await Promise.all([
    fetch(`${base}/api/ip-intel/virustotal?ip=${ipEnc}`).then((r) =>
      r.ok ? r.json() : Promise.resolve({ error: "virustotal_failed" })
    ),
    fetch(`${base}/api/ip-intel/blacklists?ip=${ipEnc}`).then((r) =>
      r.ok ? r.json() : Promise.resolve(null)
    ),
    fetch(`${base}/api/ip-intel/ports?ip=${ipEnc}`).then((r) =>
      r.ok ? r.json() : Promise.resolve(null)
    ),
    fetch(`${base}/api/ip-intel/abuseipdb?ip=${ipEnc}`).then((r) =>
      r.ok ? r.json() : Promise.resolve(null)
    ),
  ]);

  // --- VirusTotal block ---
  const vtBlock: ReputationResult["virusTotal"] = (() => {
    if (!vtRes || vtRes.error) {
      return {
        score: 0,
        classification: "BENIGN",
        reputation: 0,
        lastAnalysisStats: { malicious: 0, suspicious: 0, undetected: 0, harmless: 0, timeout: 0 },
        totalVotes: { harmless: 0, malicious: 0 },
        totalEngines: 0,
        flaggedEnginesCount: 0,
        available: false,
        error: vtRes?.error || "no_data",
      };
    }
    return {
      score: vtRes.score ?? 0,
      classification: vtRes.classification ?? "BENIGN",
      reputation: vtRes.reputation ?? 0,
      lastAnalysisStats: vtRes.lastAnalysisStats,
      totalVotes: vtRes.totalVotes,
      totalEngines: vtRes.totalEngines ?? 0,
      flaggedEnginesCount: (vtRes.flaggedEngines ?? []).length,
      lastAnalysisDate: vtRes.lastAnalysisDate,
      available: true,
    };
  })();

  // --- Secondary signals ---
  const signals: ReputationResult["signals"] = [];
  const tags: string[] = [];
  const threatIntel: ReputationResult["threatIntel"] = [];

  // VirusTotal as a signal
  if (vtBlock.available) {
    const vt = vtRes as any;
    const flagged = vt.flaggedEngines || [];
    if (vtBlock.score > 0) {
      signals.push({
        source: "VirusTotal",
        weight: Math.min(vtBlock.score, 60),
        detail: `${vtBlock.flaggedEnginesCount}/${vtBlock.totalEngines} engines flag this IP — score ${vtBlock.score}/100 (${vtBlock.classification})`,
      });
      if (vtBlock.classification === "MALICIOUS") tags.push("vt-malicious");
      else if (vtBlock.classification === "SUSPICIOUS") tags.push("vt-suspicious");
    }
    // Top flagged engines as extra detail
    if (flagged.length > 0) {
      const top = flagged.slice(0, 3).map((f: any) => `${f.engine} (${f.result})`).join(", ");
      signals.push({
        source: "VirusTotal",
        weight: Math.min(flagged.length * 3, 15),
        detail: `Top flagging engines: ${top}${flagged.length > 3 ? `, +${flagged.length - 3} more` : ""}`,
      });
    }
    threatIntel.push({
      source: "VirusTotal",
      verdict: vtBlock.classification.toLowerCase(),
      details: `${vtBlock.flaggedEnginesCount}/${vtBlock.totalEngines} engines · ${vtBlock.totalVotes.harmless}/${vtBlock.totalVotes.malicious} community votes · reputation ${vtBlock.reputation}`,
    });
  } else {
    threatIntel.push({
      source: "VirusTotal",
      verdict: "unavailable",
      details: vtBlock.error || "no data",
    });
  }

  // Multirbl signal
  if (blacklistRes && typeof blacklistRes === "object" && "summary" in blacklistRes) {
    const s = blacklistRes.summary as any;
    const black = (s.blacklisted || 0) + (s.brownlisted || 0);
    const yellow = s.yellowlisted || 0;
    if (black > 0) {
      signals.push({
        source: "multirbl.valli.org",
        weight: Math.min(black * 12, 40),
        detail: `Listed on ${black} DNSBL blacklist(s): ${s.blacklisted} black, ${s.brownlisted} brown`,
      });
      tags.push("dnsbl-listed");
    }
    if (yellow > 0) {
      signals.push({
        source: "multirbl.valli.org",
        weight: Math.min(yellow * 5, 20),
        detail: `Listed on ${yellow} informational/yellow list(s)`,
      });
      tags.push("dnsbl-watch");
    }
    threatIntel.push({
      source: "multirbl.valli.org",
      verdict: black > 0 ? "blacklisted" : "clean",
      details: `${s.total} DNSBL zones checked`,
    });
  }

  // Shodan signal
  if (shodanRes && typeof shodanRes === "object" && "tags" in shodanRes) {
    const shodanTags = (shodanRes.tags || []) as string[];
    const vulns = (shodanRes.vulns || []) as string[];
    if (shodanTags.includes("tor")) {
      tags.push("tor-exit");
      signals.push({
        source: "Shodan InternetDB",
        weight: 8,
        detail: "Identified as Tor exit relay",
      });
    }
    if (shodanTags.includes("scanner")) {
      tags.push("scanner");
      signals.push({
        source: "Shodan InternetDB",
        weight: 12,
        detail: "Tags include 'scanner' — host has been seen scanning",
      });
    }
    if (shodanTags.includes("malware")) {
      tags.push("malware");
      signals.push({
        source: "Shodan InternetDB",
        weight: 20,
        detail: "Tagged as malware-related by Shodan",
      });
    }
    if (vulns.length > 0) {
      tags.push("vulnerable");
      signals.push({
        source: "Shodan InternetDB",
        weight: Math.min(vulns.length * 5, 15),
        detail: `${vulns.length} known CVE(s): ${vulns.slice(0, 5).join(", ")}`,
      });
    }
    threatIntel.push({
      source: "Shodan InternetDB",
      verdict: shodanTags.length > 0 ? "tagged" : "benign",
      details: `${shodanTags.length} tags, ${(shodanRes.ports || []).length} open ports`,
    });
  }

  // --- AbuseIPDB block (full data) ---
  const abuseipdbBlock: AbuseIpdbBlock = (() => {
    if (!abuseipdbRes || !abuseipdbRes.available) {
      return {
        available: false,
        abuseConfidenceScore: 0,
        totalReports: 0,
        numDistinctUsers: 0,
        recentReports: [],
        classification: "BENIGN" as const,
        error: abuseipdbRes?.error || "not_configured",
      };
    }
    return {
      available: true,
      abuseConfidenceScore: abuseipdbRes.abuseConfidenceScore ?? 0,
      totalReports: abuseipdbRes.totalReports ?? 0,
      numDistinctUsers: abuseipdbRes.numDistinctUsers ?? 0,
      lastReportedAt: abuseipdbRes.lastReportedAt,
      countryCode: abuseipdbRes.countryCode,
      usageType: abuseipdbRes.usageType,
      isp: abuseipdbRes.isp,
      domain: abuseipdbRes.domain,
      isWhitelisted: abuseipdbRes.isWhitelisted,
      classification: abuseipdbRes.classification ?? "BENIGN",
      recentReports: abuseipdbRes.recentReports ?? [],
    };
  })();

  // AbuseIPDB signal
  if (abuseipdbBlock.available) {
    if (abuseipdbBlock.abuseConfidenceScore > 0) {
      signals.push({
        source: "AbuseIPDB",
        weight: Math.min(Math.floor(abuseipdbBlock.abuseConfidenceScore * 0.5), 40),
        detail: `Abuse confidence: ${abuseipdbBlock.abuseConfidenceScore}% · ${abuseipdbBlock.totalReports} report(s) by ${abuseipdbBlock.numDistinctUsers} user(s) in last 90 days`,
      });
      tags.push("abuse-reported");
    }
    if (abuseipdbBlock.isWhitelisted) {
      tags.push("abuse-whitelisted");
    }
    threatIntel.push({
      source: "AbuseIPDB",
      verdict: abuseipdbBlock.classification.toLowerCase(),
      details: `${abuseipdbBlock.totalReports} reports by ${abuseipdbBlock.numDistinctUsers} users · ${abuseipdbBlock.abuseConfidenceScore}% confidence · last report: ${abuseipdbBlock.lastReportedAt ? abuseipdbBlock.lastReportedAt.slice(0, 10) : "—"}`,
    });
  } else {
    threatIntel.push({
      source: "AbuseIPDB",
      verdict: "unavailable",
      details: abuseipdbBlock.error || "no data",
    });
  }

  // Final score — VT score (0-60 weighted) + signals
  // VT carries the bulk; signals add incremental weight capped to 100
  const vtWeight = vtBlock.available ? vtBlock.score : 0;
  const secondaryWeight = signals
    .filter((s) => s.source !== "VirusTotal")
    .reduce((sum, s) => sum + s.weight, 0);
  const score = Math.min(100, Math.round(vtWeight + secondaryWeight * 0.5));

  const result: ReputationResult = {
    ip,
    score,
    classification: classify(score),
    virusTotal: vtBlock,
    abuseipdb: abuseipdbBlock,
    signals,
    tags: [...new Set(tags)],
    threatIntel,
  };

  return NextResponse.json(result);
}
