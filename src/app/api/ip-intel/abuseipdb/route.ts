// IP Intel — AbuseIPDB v2 check
// Requires ABUSEIPDB_API_KEY env var. Free tier: 1000 checks/day, 1 req/sec.
// Returns abuse confidence score, total reports, last report, country, ISP,
// usage type, domain and the most recent report details.

import { NextResponse } from "next/server";
import { getCached, setCached, cacheKey } from "@/lib/cache";

interface AbuseReport {
  reporter: string;
  reportedAt: string;
  categories: number[];
  comment?: string;
}

interface AbuseIpdbResult {
  ip: string;
  provider: "abuseipdb";
  available: boolean;
  // Headline numbers
  abuseConfidenceScore: number; // 0..100
  totalReports: number;
  numDistinctUsers: number;
  lastReportedAt?: string;
  // Country / network metadata
  countryCode?: string;
  countryName?: string;
  usageType?: string;
  isp?: string;
  domain?: string;
  hostnames?: string[];
  isWhitelisted?: boolean;
  // Recent reports (up to 10)
  recentReports: AbuseReport[];
  // Verdict derived from score
  classification: "BENIGN" | "SUSPICIOUS" | "MALICIOUS";
  error?: string;
}

const CATEGORY_MAP: Record<number, string> = {
  1: "DNS Compromise",
  2: "DNS Poisoning",
  3: "Domain Fraud",
  4: "Fake Https Cert",
  5: "Fake Mail Server",
  6: "Fraud Orders",
  7: "Hacking",
  8: "Illegal Pharmacy",
  9: "Malware Distribution",
  10: "Malware Website",
  11: "Open Proxy",
  12: "Phishing",
  13: "Ponzi Scheme",
  14: "Port Scan",
  15: "Ransomware Site",
  16: "Referrer Spam",
  17: "Sandbox IP",
  18: "Spam Bot",
  19: "Spam Email",
  20: "Spam Social",
  21: "Spyware / Malware",
  22: "VOIP Fraud",
  23: "Web App Attack",
  24: "Web App DDoS",
  25: "Web App SQLi",
  26: "Web App XSS",
  27: "Web Scrape",
};

function classify(score: number): "BENIGN" | "SUSPICIOUS" | "MALICIOUS" {
  if (score >= 75) return "MALICIOUS";
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

  const apiKey = process.env.ABUSEIPDB_API_KEY;
  if (!apiKey) {
    return NextResponse.json({
      ip,
      provider: "abuseipdb",
      available: false,
      abuseConfidenceScore: 0,
      totalReports: 0,
      numDistinctUsers: 0,
      recentReports: [],
      classification: "BENIGN",
      error: "not_configured",
    });
  }

  // Cache check — 10 min TTL
  const cacheK = cacheKey("abuseipdb", ip);
  const cached = getCached<AbuseIpdbResult>(cacheK);
  if (cached) return NextResponse.json({ ...cached, cached: true });

  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 6000);
    const res = await fetch(
      `https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(
        ip
      )}&maxAgeInDays=90&verbose`,
      {
        signal: controller.signal,
        headers: {
          Key: apiKey,
          Accept: "application/json",
          "User-Agent": "MONITOR-THREAT/2.0",
        },
      }
    );
    clearTimeout(timeout);

    if (!res.ok) {
      if (res.status === 429) {
        return NextResponse.json({
          ip,
          provider: "abuseipdb",
          available: false,
          abuseConfidenceScore: 0,
          totalReports: 0,
          numDistinctUsers: 0,
          recentReports: [],
          classification: "BENIGN",
          error: "rate_limited",
        });
      }
      return NextResponse.json(
        {
          ip,
          provider: "abuseipdb",
          available: false,
          abuseConfidenceScore: 0,
          totalReports: 0,
          numDistinctUsers: 0,
          recentReports: [],
          classification: "BENIGN",
          error: `upstream_error_${res.status}`,
        },
        { status: 502 }
      );
    }

    const data = await res.json();
    const d = data?.data;
    if (!d) {
      return NextResponse.json({
        ip,
        provider: "abuseipdb",
        available: false,
        abuseConfidenceScore: 0,
        totalReports: 0,
        numDistinctUsers: 0,
        recentReports: [],
        classification: "BENIGN",
        error: "no_data",
      });
    }

    // Build recent reports from the reports array (when verbose=1 is passed)
    const reports: AbuseReport[] = (d.reports || []).slice(0, 10).map((r: any) => ({
      reporter: r.reporterCountryCode || r.reporterId || "?",
      reportedAt: r.reportedAt,
      categories: r.categories || [],
      comment: r.comment,
    }));

    const score = d.abuseConfidenceScore ?? 0;
    const result: AbuseIpdbResult = {
      ip: d.ipAddress || ip,
      provider: "abuseipdb",
      available: true,
      abuseConfidenceScore: score,
      totalReports: d.totalReports ?? 0,
      numDistinctUsers: d.numDistinctUsers ?? 0,
      lastReportedAt: d.lastReportedAt,
      countryCode: d.countryCode,
      countryName: d.countryName,
      usageType: d.usageType,
      isp: d.isp,
      domain: d.domain,
      hostnames: d.hostnames,
      isWhitelisted: d.isWhitelisted,
      recentReports: reports,
      classification: classify(score),
    };

    setCached(cacheK, result);
    return NextResponse.json(result);
  } catch (err: any) {
    return NextResponse.json(
      {
        ip,
        provider: "abuseipdb",
        available: false,
        abuseConfidenceScore: 0,
        totalReports: 0,
        numDistinctUsers: 0,
        recentReports: [],
        classification: "BENIGN",
        error: "abuseipdb_unreachable",
        hint: err.message,
      },
      { status: 502 }
    );
  }
}

export { CATEGORY_MAP };
