// DNS Dump — aggregate endpoint
//
// Calls records + dnssec + email-infra + subdomains + axfr +
// passive-dns + cross-resolver in parallel and returns one JSON.

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

  const cacheK = cacheKey("dnsdump_aggregate", domain);
  const cached = getCached<any>(cacheK);
  if (cached) return NextResponse.json({ ...cached, cached: true });

  const base = new URL(request.url).origin;
  const enc = encodeURIComponent(domain);

  const [records, dnssec, emailInfra, subdomains, axfr, passiveDns, crossResolver] = await Promise.all([
    fetch(`${base}/api/dns-dump/records?domain=${enc}`).then((r) =>
      r.ok ? r.json() : Promise.resolve({ error: "records_failed" })
    ),
    fetch(`${base}/api/dns-dump/dnssec?domain=${enc}`).then((r) =>
      r.ok ? r.json() : Promise.resolve({ error: "dnssec_failed" })
    ),
    fetch(`${base}/api/dns-dump/email-infra?domain=${enc}`).then((r) =>
      r.ok ? r.json() : Promise.resolve({ error: "email_failed" })
    ),
    fetch(`${base}/api/dns-dump/subdomains?domain=${enc}`).then((r) =>
      r.ok ? r.json() : Promise.resolve({ error: "subdomains_failed" })
    ),
    fetch(`${base}/api/dns-dump/axfr?domain=${enc}`).then((r) =>
      r.ok ? r.json() : Promise.resolve({ error: "axfr_failed" })
    ),
    fetch(`${base}/api/dns-dump/passive-dns?domain=${enc}`).then((r) =>
      r.ok ? r.json() : Promise.resolve({ error: "pdns_failed" })
    ),
    fetch(`${base}/api/dns-dump/cross-resolver?domain=${enc}`).then((r) =>
      r.ok ? r.json() : Promise.resolve({ error: "crossresolver_failed" })
    ),
  ]);

  const result = {
    domain,
    records,
    dnssec,
    emailInfra,
    subdomains,
    axfr,
    passiveDns,
    crossResolver,
    timestamp: new Date().toISOString(),
  };

  setCached(cacheK, result, 30 * 60 * 1000);
  return NextResponse.json(result);
}
