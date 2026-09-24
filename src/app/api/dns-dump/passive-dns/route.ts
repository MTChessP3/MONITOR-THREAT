// DNS Dump — Passive DNS history via VirusTotal
//
// Uses the VIRUSTOTAL_API_KEY env var (already configured) to get
// all historical DNS resolutions for the domain.

import { NextResponse } from "next/server";
import { getCached, setCached, cacheKey } from "@/lib/cache";

interface PassiveDnsEntry {
  date: string;
  ip: string;
  type: string;
}

interface PassiveDnsResult {
  domain: string;
  available: boolean;
  totalResolutions: number;
  resolutions: PassiveDnsEntry[];
  uniqueIps: string[];
  firstSeen?: string;
  lastSeen?: string;
  error?: string;
}

export async function GET(request: Request) {
  const { searchParams } = new URL(request.url);
  const domain = (searchParams.get("domain") || "").trim().toLowerCase();

  if (!domain) {
    return NextResponse.json({ error: "missing_params" }, { status: 400 });
  }
  if (!/^[a-z0-9.-]+\.[a-z]{2,}$/i.test(domain) || domain.includes("..")) {
    return NextResponse.json({ error: "invalid_domain" }, { status: 400 });
  }

  const cacheK = cacheKey("dnsdump_pdns", domain);
  const cached = getCached<PassiveDnsResult>(cacheK);
  if (cached) return NextResponse.json({ ...cached, cached: true });

  const apiKey = process.env.VIRUSTOTAL_API_KEY;
  if (!apiKey) {
    return NextResponse.json({
      domain,
      available: false,
      totalResolutions: 0,
      resolutions: [],
      uniqueIps: [],
      error: "virustotal_not_configured",
    });
  }

  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 8000);
    const res = await fetch(
      `https://www.virustotal.com/api/v3/domains/${encodeURIComponent(domain)}/resolutions?limit=40`,
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

    if (!res.ok) {
      return NextResponse.json({
        domain,
        available: false,
        totalResolutions: 0,
        resolutions: [],
        uniqueIps: [],
        error: `vt_error_${res.status}`,
      });
    }

    const data = await res.json();
    const rawResolutions = data?.data || [];
    const resolutions: PassiveDnsEntry[] = rawResolutions.map((r: any) => ({
      date: r.attributes?.date || r.attributes?.last_resolved || "",
      ip: r.attributes?.host_name || r.id || r.attributes?.ip_address || "",
      type: "A",
    }));

    const uniqueIps = Array.from(new Set(resolutions.map((r) => r.ip)));
    const sortedDates = resolutions
      .map((r) => r.date)
      .filter(Boolean)
      .sort();

    const result: PassiveDnsResult = {
      domain,
      available: true,
      totalResolutions: resolutions.length,
      resolutions: resolutions.slice(0, 40),
      uniqueIps,
      firstSeen: sortedDates[0],
      lastSeen: sortedDates[sortedDates.length - 1],
    };

    setCached(cacheK, result, 60 * 60 * 1000);
    return NextResponse.json(result);
  } catch (err: any) {
    return NextResponse.json({
      domain,
      available: false,
      totalResolutions: 0,
      resolutions: [],
      uniqueIps: [],
      error: "vt_unreachable",
      hint: err.message,
    });
  }
}
