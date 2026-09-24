// Domain Intel — Email infrastructure deep analysis
//
// This is a thin wrapper that calls /api/domain-intel/dns and re-formats
// the email-specific fields into a single focused panel. Same logic as
// the DNS endpoint but with more interpretation:
//   - What MX provider does this domain use?
//   - SPF strength (no SPF / ~all soft fail / -all hard fail / include ...)
//   - DKIM present (try common selectors)
//   - DMARC policy (none / quarantine / reject)
//   - MTA-STS present?
//   - BIMI present?
//   - Overall email security score (0-4)
//
// Directly duplicates what's in the DNS endpoint's email section, but as
// a separate endpoint the panel can be lazily loaded if the user wants
// to deep-dive email infra without re-fetching the DNS block.

import { NextResponse } from "next/server";

export async function GET(request: Request) {
  const { searchParams } = new URL(request.url);
  const domain = (searchParams.get("domain") || "").trim().toLowerCase();

  if (!domain) {
    return NextResponse.json(
      { error: "missing_params", hint: "Provide a 'domain' query parameter." },
      { status: 400 }
    );
  }

  const base = new URL(request.url).origin;
  const dnsRes = await fetch(`${base}/api/domain-intel/dns?domain=${encodeURIComponent(domain)}`);
  if (!dnsRes.ok) {
    return NextResponse.json({ error: "dns_failed" }, { status: 502 });
  }
  const dns = await dnsRes.json();

  // Compute additional scoring signals
  const email = dns.email || {};
  const spf = email.spf;
  const dmarc = email.dmarc;
  const dkim = email.dkim;
  const mtaSts = email.mtaSts;

  // SPF strength classification
  let spfStrength: "none" | "weak" | "medium" | "strong" = "none";
  if (spf) {
    if (spf.record.includes("-all")) spfStrength = "strong";
    else if (spf.record.includes("~all")) spfStrength = "medium";
    else if (spf.record.includes("?all") || spf.record.includes("+all")) spfStrength = "weak";
    else spfStrength = "medium"; // includes without -all
  }

  // DMARC strength
  let dmarcStrength: "none" | "monitor" | "weak" | "strong" = "none";
  if (dmarc) {
    if (dmarc.policy === "reject") dmarcStrength = "strong";
    else if (dmarc.policy === "quarantine") dmarcStrength = "weak";
    else if (dmarc.policy === "none") dmarcStrength = "monitor";
  }

  // Recommendation
  let recommendation = "";
  if (!spf) recommendation += "Add an SPF record (v=spf1 ...) to authorize your email senders. ";
  if (!dkim) recommendation += "Configure DKIM signing on your mail server. ";
  if (!dmarc || dmarc.policy === "missing")
    recommendation += "Add a DMARC record on _dmarc.yourdomain.com — at minimum p=none for monitoring. ";
  else if (dmarc.policy === "none") recommendation += "Upgrade DMARC policy to p=quarantine or p=reject once you're confident no legit email is failing alignment. ";
  if (!mtaSts) recommendation += "Add an MTA-STS policy on _mta-sts.yourdomain.com to enforce STARTTLS for inbound mail. ";
  if (!recommendation) recommendation = "Email infrastructure looks well-configured.";

  return NextResponse.json({
    domain,
    available: true,
    spf: {
      present: !!spf,
      record: spf?.record,
      strength: spfStrength,
      mechanisms: spf?.mechanism || [],
    },
    dkim: {
      present: !!dkim,
      selector: dkim?.selector,
      record: dkim?.record,
      keyType: dkim?.keyType,
    },
    dmarc: {
      present: !!dmarc && dmarc.policy !== "missing",
      record: dmarc?.record,
      policy: dmarc?.policy,
      strength: dmarcStrength,
      pct: dmarc?.pct,
    },
    mtaSts: {
      present: !!mtaSts,
      record: mtaSts?.record,
      id: mtaSts?.id,
    },
    bimi: email.bimi || null,
    mx: {
      count: email.mxCount,
      providers: email.mxProviders,
    },
    emailSecurityScore: dns.emailSecurityScore,
    recommendation,
  });
}
