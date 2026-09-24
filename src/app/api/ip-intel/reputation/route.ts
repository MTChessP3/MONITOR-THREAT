// IP Intel — reputation & threat intel aggregation
// Combines:
//  - multirbl.valli.org blacklist summary (derived from blacklists endpoint)
//  - Shodan InternetDB tags (used as a "reputation" signal)
//  - AbuseIPDB (optional — needs ABUSEIPDB_API_KEY env var, free tier: 1000 checks/day)
//
// If ABUSEIPDB_API_KEY is not set, the AbuseIPDB block is skipped and we still return
// a useful reputation score derived from the other signals.

import { NextResponse } from "next/server";

interface ReputationResult {
  ip: string;
  score: number; // 0..100 — higher = more suspicious
  classification: "BENIGN" | "SUSPICIOUS" | "MALICIOUS";
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
    lastReportedAt?: string;
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

  // Parallel: blacklist summary + shodan internetdb
  const [blacklistRes, shodanRes, abuseipdbRes] = await Promise.all([
    fetch(`${base}/api/ip-intel/blacklists?ip=${encodeURIComponent(ip)}`).then((r) =>
      r.ok ? r.json() : Promise.resolve(null)
    ),
    fetch(`${base}/api/ip-intel/ports?ip=${encodeURIComponent(ip)}`).then((r) =>
      r.ok ? r.json() : Promise.resolve(null)
    ),
    (async () => {
      const apiKey = process.env.ABUSEIPDB_API_KEY;
      if (!apiKey) return null;
      try {
        const c = new AbortController();
        const t = setTimeout(() => c.abort(), 8000);
        const r = await fetch(
          `https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(
            ip
          )}&maxAgeInDays=90`,
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

  const signals: ReputationResult["signals"] = [];
  const tags: string[] = [];
  const threatIntel: ReputationResult["threatIntel"] = [];

  // --- Multirbl signal ---
  if (blacklistRes && typeof blacklistRes === "object" && "summary" in blacklistRes) {
    const s = blacklistRes.summary as any;
    const black = (s.blacklisted || 0) + (s.brownlisted || 0);
    const yellow = s.yellowlisted || 0;
    if (black > 0) {
      signals.push({
        source: "multirbl.valli.org",
        weight: Math.min(black * 15, 60),
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

  // --- Shodan signal ---
  if (shodanRes && typeof shodanRes === "object" && "tags" in shodanRes) {
    const shodanTags = (shodanRes.tags || []) as string[];
    const vulns = (shodanRes.vulns || []) as string[];
    if (shodanTags.includes("tor")) {
      tags.push("tor-exit");
      signals.push({
        source: "Shodan InternetDB",
        weight: 10,
        detail: "Identified as Tor exit relay",
      });
    }
    if (shodanTags.includes("scanner")) {
      tags.push("scanner");
      signals.push({
        source: "Shodan InternetDB",
        weight: 15,
        detail: "Tags include 'scanner' — host has been seen scanning",
      });
    }
    if (shodanTags.includes("malware")) {
      tags.push("malware");
      signals.push({
        source: "Shodan InternetDB",
        weight: 25,
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

  // --- AbuseIPDB signal ---
  if (abuseipdbRes) {
    const ab = abuseipdbRes as NonNullable<ReputationResult["abuseipdb"]>;
    if (ab.abuseConfidenceScore > 0) {
      signals.push({
        source: "AbuseIPDB",
        weight: Math.min(Math.floor(ab.abuseConfidenceScore * 0.5), 50),
        detail: `Abuse confidence: ${ab.abuseConfidenceScore}% · ${ab.totalReports} report(s) in last 90 days`,
      });
      tags.push("abuse-reported");
    }
    threatIntel.push({
      source: "AbuseIPDB",
      verdict: ab.abuseConfidenceScore >= 75 ? "malicious" : ab.abuseConfidenceScore >= 25 ? "suspicious" : "clean",
      details: `${ab.totalReports} reports, ${ab.abuseConfidenceScore}% confidence`,
    });
  } else {
    threatIntel.push({
      source: "AbuseIPDB",
      verdict: "not_configured",
      details: "Set ABUSEIPDB_API_KEY env var to enable",
    });
  }

  // Final score — capped at 100
  const score = Math.min(100, signals.reduce((sum, s) => sum + s.weight, 0));

  const result: ReputationResult = {
    ip,
    score,
    classification: classify(score),
    signals,
    tags: [...new Set(tags)],
    threatIntel,
    abuseipdb: abuseipdbRes || null,
  };

  return NextResponse.json(result);
}
