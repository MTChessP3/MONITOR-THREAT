// Domain Intel — aggregate endpoint
//
// Calls whois + dns + subdomains + certs + reputation + hosting + email +
// blacklists in parallel and returns a single JSON envelope.

import { NextResponse } from "next/server";
import { getCached, setCached, cacheKey } from "@/lib/cache";

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

  const cacheK = cacheKey("domain_aggregate", domain);
  const cached = getCached<any>(cacheK);
  if (cached) return NextResponse.json({ ...cached, cached: true });

  const base = new URL(request.url).origin;
  const enc = encodeURIComponent(domain);

  const [whois, dns, subdomains, certs, reputation, hosting, email, blacklists] = await Promise.all([
    fetch(`${base}/api/domain-intel/whois?domain=${enc}`).then((r) =>
      r.ok ? r.json() : Promise.resolve({ error: "whois_failed" })
    ),
    fetch(`${base}/api/domain-intel/dns?domain=${enc}`).then((r) =>
      r.ok ? r.json() : Promise.resolve({ error: "dns_failed" })
    ),
    fetch(`${base}/api/domain-intel/subdomains?domain=${enc}`).then((r) =>
      r.ok ? r.json() : Promise.resolve({ error: "subdomains_failed" })
    ),
    fetch(`${base}/api/domain-intel/certs?domain=${enc}`).then((r) =>
      r.ok ? r.json() : Promise.resolve({ error: "certs_failed" })
    ),
    fetch(`${base}/api/domain-intel/reputation?domain=${enc}`).then((r) =>
      r.ok ? r.json() : Promise.resolve({ error: "reputation_failed" })
    ),
    fetch(`${base}/api/domain-intel/hosting?domain=${enc}`).then((r) =>
      r.ok ? r.json() : Promise.resolve({ error: "hosting_failed" })
    ),
    fetch(`${base}/api/domain-intel/email?domain=${enc}`).then((r) =>
      r.ok ? r.json() : Promise.resolve({ error: "email_failed" })
    ),
    fetch(`${base}/api/domain-intel/blacklists?domain=${enc}`).then((r) =>
      r.ok ? r.json() : Promise.resolve({ error: "blacklists_failed" })
    ),
  ]);

  const result = {
    domain,
    whois,
    dns,
    subdomains,
    certs,
    reputation,
    hosting,
    email,
    blacklists,
    timestamp: new Date().toISOString(),
  };

  setCached(cacheK, result, 30 * 60 * 1000); // 30 min TTL
  return NextResponse.json(result);
}
