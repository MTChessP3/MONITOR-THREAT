// Domain Intel — Subdomain enumeration via Certificate Transparency logs
//
// Primary source: crt.sh (Sectigo CT log search — full history, free, no key)
// Fallback: Hackertarget (50 req/day free for unauth users, less complete
// but reliable when crt.sh is down)
//
// Returns unique subdomains, separated into "active" (still resolve via
// DoH A/AAAA lookup) and "historical" (no longer resolve — could be
// decommissioned or subdomain takeover candidate).

import { NextResponse } from "next/server";
import { getCached, setCached, cacheKey } from "@/lib/cache";

interface SubdomainEntry {
  name: string;
  source: "crt.sh" | "hackertarget";
  resolves: boolean;
  ips?: string[];
}

interface SubdomainResult {
  domain: string;
  available: boolean;
  total: number;
  active: number;
  historical: number;
  subdomains: SubdomainEntry[];
  crtShOk: boolean;
  hackertargetOk: boolean;
  error?: string;
}

async function fetchCrtSh(domain: string): Promise<{ names: Set<string>; ok: boolean }> {
  try {
    // Wildcard query: %.domain.com returns all certs that include any *.domain.com
    const url = `https://crt.sh/?q=${encodeURIComponent(`%.${domain}`)}&output=json`;
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 20000);
    const res = await fetch(url, {
      signal: controller.signal,
      headers: {
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        Accept: "application/json",
      },
    });
    clearTimeout(timeout);
    if (!res.ok) return { names: new Set(), ok: false };
    const data = await res.json();
    const names = new Set<string>();
    for (const entry of data) {
      const nameValue = entry.name_value || "";
      for (const name of nameValue.split("\n")) {
        const cleaned = name.trim().toLowerCase().replace(/^\*\./, "");
        if (cleaned && cleaned.endsWith(`.${domain}`)) {
          names.add(cleaned);
        } else if (cleaned === domain) {
          names.add(cleaned);
        }
      }
    }
    return { names, ok: true };
  } catch {
    return { names: new Set(), ok: false };
  }
}

async function fetchHackertarget(domain: string): Promise<{ names: Set<string>; ok: boolean }> {
  try {
    const url = `https://api.hackertarget.com/hostsearch/?q=${encodeURIComponent(domain)}`;
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 8000);
    const res = await fetch(url, {
      signal: controller.signal,
      headers: { "User-Agent": "MONITOR-THREAT/2.0" },
    });
    clearTimeout(timeout);
    if (!res.ok) return { names: new Set(), ok: false };
    const text = await res.text();
    const names = new Set<string>();
    for (const line of text.split("\n")) {
      const commaIdx = line.indexOf(",");
      if (commaIdx === -1) continue;
      const name = line.slice(0, commaIdx).trim().toLowerCase();
      if (name && (name === domain || name.endsWith(`.${domain}`))) {
        names.add(name);
      }
    }
    return { names, ok: true };
  } catch {
    return { names: new Set(), ok: false };
  }
}

// DoH batched A record lookup — used to mark which subdomains still resolve
async function resolveSubdomain(name: string): Promise<{ resolves: boolean; ips: string[] }> {
  try {
    const url = `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(name)}&type=1`;
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 3000);
    const res = await fetch(url, {
      signal: controller.signal,
      headers: { accept: "application/dns-json", "User-Agent": "MONITOR-THREAT/2.0" },
    });
    clearTimeout(timeout);
    if (!res.ok) return { resolves: false, ips: [] };
    const data = await res.json();
    const answers = data.Answer || [];
    const ips = answers.map((a: any) => a.data).filter((d: string) => /^\d+\.\d+\.\d+\.\d+$/.test(d));
    return { resolves: ips.length > 0, ips };
  } catch {
    return { resolves: false, ips: [] };
  }
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

  const cacheK = cacheKey("subdomains", domain);
  const cached = getCached<SubdomainResult>(cacheK);
  if (cached) return NextResponse.json({ ...cached, cached: true });

  // Run both sources in parallel
  const [crtSh, hackertarget] = await Promise.all([fetchCrtSh(domain), fetchHackertarget(domain)]);

  const allNames = new Set<string>([...crtSh.names, ...hackertarget.names]);

  if (allNames.size === 0) {
    return NextResponse.json({
      domain,
      available: true,
      total: 0,
      active: 0,
      historical: 0,
      subdomains: [],
      crtShOk: crtSh.ok,
      hackertargetOk: hackertarget.ok,
      error: crtSh.ok || hackertarget.ok ? "no_subdomains_found" : "all_sources_failed",
    });
  }

  // Limit to top 100 subdomains to keep DNS resolution tractable
  const namesToResolve = Array.from(allNames).slice(0, 100);

  // Resolve each subdomain in parallel batches of 20
  const BATCH = 20;
  const entries: SubdomainEntry[] = [];
  for (let i = 0; i < namesToResolve.length; i += BATCH) {
    const batch = namesToResolve.slice(i, i + BATCH);
    const results = await Promise.all(batch.map(async (name) => {
      const source = crtSh.names.has(name) ? "crt.sh" : "hackertarget";
      const { resolves, ips } = await resolveSubdomain(name);
      return { name, source, resolves, ips } as SubdomainEntry;
    }));
    entries.push(...results);
  }

  const active = entries.filter((e) => e.resolves).length;
  const historical = entries.length - active;

  const result: SubdomainResult = {
    domain,
    available: true,
    total: entries.length,
    active,
    historical,
    subdomains: entries.sort((a, b) => a.name.localeCompare(b.name)),
    crtShOk: crtSh.ok,
    hackertargetOk: hackertarget.ok,
  };

  setCached(cacheK, result, 30 * 60 * 1000); // 30 min TTL
  return NextResponse.json(result);
}
