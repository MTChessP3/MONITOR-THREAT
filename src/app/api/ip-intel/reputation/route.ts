// IP Intel — reputation & threat intel aggregation
//
// Primary signal: VirusTotal v3 (last_analysis_stats + community votes + reputation)
// Secondary signals:
//  - multirbl.valli.org / DNSBL blacklists
//  - Shodan InternetDB tags (tor, scanner, malware, vulnerable)
//  - AbuseIPDB (optional — needs ABUSEIPDB_API_KEY)
//
// Final score = weighted combination of all signals, capped at 100.

import { NextResponse } from "next/server";

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
  abuseipdb?: {
    score: number;
    totalReports: number;
    abuseConfidenceScore: number;
  } | null;
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

  // Parallel: VirusTotal (primary) + blacklists + shodan + abuseipdb
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
    (async () => {
      const apiKey = process.env.ABUSEIPDB_API_KEY;
      if (!apiKey) return null;
      try {
        const c = new AbortController();
        const t = setTimeout(() => c.abort(), 8000);
        const r = await fetch(
          `https://api.abuseipdb.com/api/v2/check?ipAddress=${ipEnc}&maxAgeInDays=90`,
          {
            signal: c.signal,
            headers: {
              Key: apiKey,
              Accept: "application/json",
              "User-Agent": "MONITOR-THREAT/2.0",
            },
          }
        );
        clearTimeout(t);
        if (!r.ok) return null;
        const d = (await r.json())?.data;
        if (!d) return null;
        return {
          score: d.abuseConfidenceScore || 0,
          totalReports: d.totalReports || 0,
          lastReportedAt: d.lastReportedAt,
          abuseConfidenceScore: d.abuseConfidenceScore || 0,
        };
      } catch {
        return null;
      }
    })(),
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

  // AbuseIPDB signal
  if (abuseipdbRes) {
    const ab = abuseipdbRes as NonNullable<ReputationResult["abuseipdb"]>;
    if (ab.abuseConfidenceScore > 0) {
      signals.push({
        source: "AbuseIPDB",
        weight: Math.min(Math.floor(ab.abuseConfidenceScore * 0.5), 40),
        detail: `Abuse confidence: ${ab.abuseConfidenceScore}% · ${ab.totalReports} report(s) in last 90 days`,
      });
      tags.push("abuse-reported");
    }
    threatIntel.push({
      source: "AbuseIPDB",
      verdict:
        ab.abuseConfidenceScore >= 75
          ? "malicious"
          : ab.abuseConfidenceScore >= 25
          ? "suspicious"
          : "clean",
      details: `${ab.totalReports} reports, ${ab.abuseConfidenceScore}% confidence`,
    });
  } else {
    threatIntel.push({
      source: "AbuseIPDB",
      verdict: "not_configured",
      details: "Set ABUSEIPDB_API_KEY env var to enable",
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
    signals,
    tags: [...new Set(tags)],
    threatIntel,
    abuseipdb: abuseipdbRes || null,
  };

  return NextResponse.json(result);
}
