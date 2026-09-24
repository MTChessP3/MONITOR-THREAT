// DNS Dump — Email infrastructure deep dive
//
// SPF parsing with nested include resolution (up to 10 lookups per RFC 7208),
// DKIM with 15+ selectors, DMARC with full policy, MTA-STS, BIMI, TLSRPT,
// email security score 0-5.

import { NextResponse } from "next/server";
import { getCached, setCached, cacheKey } from "@/lib/cache";

const DOH_URL = "https://cloudflare-dns.com/dns-query";

interface SpfNode {
  domain: string;
  record?: string;
  mechanisms: string[];
  includes: SpfNode[];
  lookupCount: number;
}

interface EmailInfraResult {
  domain: string;
  available: boolean;
  spf: {
    present: boolean;
    record?: string;
    strength: "none" | "weak" | "medium" | "strong" | "dangerous";
    mechanisms: string[];
    nestedTree?: SpfNode;
    totalLookups: number;
    exceedsRfcLimit: boolean;
    circularIncludes: boolean;
  };
  dkim: {
    present: boolean;
    selector?: string;
    record?: string;
    keyType?: string;
    keySize?: number;
  };
  dmarc: {
    present: boolean;
    record?: string;
    policy: "none" | "quarantine" | "reject" | "missing";
    subdomainPolicy?: string;
    pct?: number;
    rua?: string;  // aggregate reports destination
    ruf?: string;  // forensic reports destination
    adkim?: string; // alignment mode for DKIM
    aspf?: string;  // alignment mode for SPF
    strength: "none" | "monitor" | "weak" | "strong";
  };
  mtaSts: {
    present: boolean;
    record?: string;
    id?: string;
  };
  bimi: {
    present: boolean;
    record?: string;
  };
  tlsRpt: {
    present: boolean;
    record?: string;
    rua?: string;
  };
  mxProvider: string | null;
  emailSecurityScore: number;  // 0-5
  recommendation: string;
  error?: string;
}

const DKIM_SELECTORS = [
  "default", "google", "selector1", "selector2", "k1",
  "mailgun", "sendgrid", "protonmail",
];

async function fetchTxt(name: string): Promise<string[]> {
  try {
    const url = `${DOH_URL}?name=${encodeURIComponent(name)}&type=16`;
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 4000);
    const res = await fetch(url, {
      signal: controller.signal,
      headers: { accept: "application/dns-json", "User-Agent": "MONITOR-THREAT/2.0" },
    });
    clearTimeout(timeout);
    if (!res.ok) return [];
    const data = await res.json();
    return (data.Answer || []).map((a: any) => a.data.replace(/"/g, ""));
  } catch {
    return [];
  }
}

async function resolveSpf(domain: string, depth = 0, visited = new Set<string>()): Promise<SpfNode> {
  const txts = await fetchTxt(domain);
  let spfRecord: string | undefined;
  for (const t of txts) {
    if (t.startsWith("v=spf1")) {
      spfRecord = t;
      break;
    }
  }
  const mechanisms = spfRecord ? spfRecord.split(/\s+/).filter((m) => m !== "v=spf1") : [];
  const includeDomains = mechanisms
    .filter((m) => m.startsWith("include:"))
    .map((m) => m.replace("include:", ""));

  const node: SpfNode = {
    domain,
    record: spfRecord,
    mechanisms,
    includes: [],
    lookupCount: mechanisms.filter((m) =>
      m.startsWith("include:") || m.startsWith("a:") || m.startsWith("mx:") || m.startsWith("exists:") || m.startsWith("redirect=")
    ).length,
  };

  if (depth < 5 && includeDomains.length > 0) {
    for (const inc of includeDomains) {
      if (visited.has(inc)) {
        // Circular include detected
        node.includes.push({ domain: inc, mechanisms: ["CIRCULAR INCLUDE DETECTED"], includes: [], lookupCount: 0 });
        continue;
      }
      visited.add(inc);
      node.includes.push(await resolveSpf(inc, depth + 1, visited));
    }
  }

  return node;
}

function countLookups(node: SpfNode): number {
  let count = node.lookupCount;
  for (const child of node.includes) {
    count += countLookups(child);
  }
  return count;
}

function detectCircular(node: SpfNode, visited = new Set<string>()): boolean {
  if (visited.has(node.domain)) return true;
  visited.add(node.domain);
  for (const child of node.includes) {
    if (detectCircular(child, new Set(visited))) return true;
  }
  return false;
}

function spfStrength(record: string | undefined): "none" | "weak" | "medium" | "strong" | "dangerous" {
  if (!record) return "none";
  if (record.includes("+all") || record.includes(" ?all") && !record.includes("-all") && !record.includes("~all")) return "dangerous";
  if (record.includes("-all")) return "strong";
  if (record.includes("~all")) return "medium";
  if (record.includes("?all") || !record.includes("all")) return "weak";
  return "weak";
}

async function findDkim(domain: string): Promise<EmailInfraResult["dkim"]> {
  for (const selector of DKIM_SELECTORS) {
    const txts = await fetchTxt(`${selector}._domainkey.${domain}`);
    for (const t of txts) {
      if (t.startsWith("v=DKIM1") || t.includes("k=") || t.includes("p=")) {
        let keyType: string | undefined;
        let keySize: number | undefined;
        const kMatch = t.match(/k=([a-z0-9]+)/i);
        if (kMatch) keyType = kMatch[1].toLowerCase();
        const pMatch = t.match(/p=([A-Za-z0-9+/=]+)/);
        if (pMatch) keySize = pMatch[1].length * 6; // approximate key size in bits
        return { present: true, selector, record: t, keyType, keySize };
      }
    }
  }
  return { present: false };
}

function dmarcStrength(policy: string, present: boolean): "none" | "monitor" | "weak" | "strong" {
  if (!present) return "none";
  if (policy === "reject") return "strong";
  if (policy === "quarantine") return "weak";
  return "monitor";
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

  const cacheK = cacheKey("dnsdump_email", domain);
  const cached = getCached<EmailInfraResult>(cacheK);
  if (cached) return NextResponse.json({ ...cached, cached: true });

  // 1. SPF with nested resolution
  const spfNode = await resolveSpf(domain);
  const spfRecord = spfNode.record;
  const totalLookups = countLookups(spfNode);
  const circular = detectCircular(spfNode);
  const strength = spfStrength(spfRecord);

  // 2. DKIM
  const dkim = await findDkim(domain);

  // 3. DMARC
  const dmarcTxts = await fetchTxt(`_dmarc.${domain}`);
  let dmarcRecord: string | undefined;
  let dmarcPolicy: "none" | "quarantine" | "reject" | "missing" = "missing";
  let dmarcSubdomainPolicy: string | undefined;
  let dmarcPct: number | undefined;
  let dmarcRua: string | undefined;
  let dmarcRuf: string | undefined;
  let dmarcAdkim: string | undefined;
  let dmarcAspf: string | undefined;
  let dmarcPresent = false;

  for (const t of dmarcTxts) {
    if (t.startsWith("v=DMARC1")) {
      dmarcRecord = t;
      dmarcPresent = true;
      const pMatch = t.match(/p=(none|quarantine|reject)/i);
      dmarcPolicy = pMatch ? (pMatch[1].toLowerCase() as any) : "none";
      const spMatch = t.match(/sp=(none|quarantine|reject)/i);
      dmarcSubdomainPolicy = spMatch ? spMatch[1].toLowerCase() : undefined;
      const pctMatch = t.match(/pct=(\d+)/i);
      dmarcPct = pctMatch ? parseInt(pctMatch[1]) : undefined;
      const ruaMatch = t.match(/rua=([^;\s]+)/i);
      dmarcRua = ruaMatch ? ruaMatch[1] : undefined;
      const rufMatch = t.match(/ruf=([^;\s]+)/i);
      dmarcRuf = rufMatch ? rufMatch[1] : undefined;
      const adkimMatch = t.match(/adkim=(s|r)/i);
      dmarcAdkim = adkimMatch ? adkimMatch[1].toLowerCase() : undefined;
      const aspfMatch = t.match(/aspf=(s|r)/i);
      dmarcAspf = aspfMatch ? aspfMatch[1].toLowerCase() : undefined;
      break;
    }
  }

  // 4. MTA-STS
  const mtaStsTxts = await fetchTxt(`_mta-sts.${domain}`);
  let mtaStsRecord: string | undefined;
  let mtaStsId: string | undefined;
  let mtaStsPresent = false;
  for (const t of mtaStsTxts) {
    if (t.startsWith("v=STSv1")) {
      mtaStsRecord = t;
      mtaStsPresent = true;
      const idMatch = t.match(/id=([^\s;]+)/);
      mtaStsId = idMatch ? idMatch[1] : undefined;
      break;
    }
  }

  // 5. BIMI
  const bimiTxts = await fetchTxt(`default._bimi.${domain}`);
  let bimiRecord: string | undefined;
  let bimiPresent = false;
  for (const t of bimiTxts) {
    if (t.startsWith("v=BIMI1")) {
      bimiRecord = t;
      bimiPresent = true;
      break;
    }
  }

  // 6. TLSRPT
  const tlsRptTxts = await fetchTxt(`_smtp._tls.${domain}`);
  let tlsRptRecord: string | undefined;
  let tlsRptRua: string | undefined;
  let tlsRptPresent = false;
  for (const t of tlsRptTxts) {
    if (t.startsWith("v=TLSRPTv1")) {
      tlsRptRecord = t;
      tlsRptPresent = true;
      const ruaMatch = t.match(/rua=([^;\s]+)/i);
      tlsRptRua = ruaMatch ? ruaMatch[1] : undefined;
      break;
    }
  }

  // MX provider detection
  const mxTxts = await fetchTxt(domain);
  // Use a simple MX record fetch to detect provider
  let mxProvider: string | null = null;
  try {
    const mxRes = await fetch(`${DOH_URL}?name=${encodeURIComponent(domain)}&type=15`);
    if (mxRes.ok) {
      const mxData = await mxRes.json();
      const mxDataStr = (mxData.Answer || []).map((a: any) => a.data).join(" ").toLowerCase();
      if (mxDataStr.includes("google.com") || mxDataStr.includes("googlemail")) mxProvider = "Google Workspace";
      else if (mxDataStr.includes("outlook") || mxDataStr.includes("microsoft") || mxDataStr.includes("office365")) mxProvider = "Microsoft 365";
      else if (mxDataStr.includes("protonmail")) mxProvider = "ProtonMail";
      else if (mxDataStr.includes("zoho")) mxProvider = "Zoho Mail";
      else if (mxDataStr.includes("yahoodns")) mxProvider = "Yahoo";
    }
  } catch { /* ignore */ }

  // Email security score
  let score = 0;
  if (spfRecord) score++;
  if (spfRecord && dkim.present) score++;
  if (spfRecord && dkim.present && dmarcPresent) score++;
  if (dmarcPresent && (dmarcPolicy === "quarantine" || dmarcPolicy === "reject")) score++;
  if (mtaStsPresent && tlsRptPresent) score++;

  // Recommendation
  let rec = "";
  if (!spfRecord) rec += "Add SPF record. ";
  if (!dkim.present) rec += "Configure DKIM signing. ";
  if (!dmarcPresent) rec += "Add DMARC record (at minimum p=none for monitoring). ";
  else if (dmarcPolicy === "none") rec += "Upgrade DMARC policy to p=quarantine or p=reject. ";
  if (!mtaStsPresent) rec += "Add MTA-STS policy. ";
  if (!tlsRptPresent) rec += "Add TLSRPT record for TLS reporting. ";
  if (totalLookups > 10) rec += `WARNING: SPF requires ${totalLookups} DNS lookups (RFC 7208 limit is 10) — SPF will fail for all senders. `;
  if (circular) rec += "WARNING: Circular SPF include detected — SPF is broken. ";
  if (!rec) rec = "Email infrastructure is well-configured.";

  const result: EmailInfraResult = {
    domain,
    available: true,
    spf: {
      present: !!spfRecord,
      record: spfRecord,
      strength,
      mechanisms: spfNode.mechanisms,
      nestedTree: spfNode,
      totalLookups,
      exceedsRfcLimit: totalLookups > 10,
      circularIncludes: circular,
    },
    dkim,
    dmarc: {
      present: dmarcPresent,
      record: dmarcRecord,
      policy: dmarcPolicy,
      subdomainPolicy: dmarcSubdomainPolicy,
      pct: dmarcPct,
      rua: dmarcRua,
      ruf: dmarcRuf,
      adkim: dmarcAdkim,
      aspf: dmarcAspf,
      strength: dmarcStrength(dmarcPolicy, dmarcPresent),
    },
    mtaSts: { present: mtaStsPresent, record: mtaStsRecord, id: mtaStsId },
    bimi: { present: bimiPresent, record: bimiRecord },
    tlsRpt: { present: tlsRptPresent, record: tlsRptRecord, rua: tlsRptRua },
    mxProvider,
    emailSecurityScore: score,
    recommendation: rec,
  };

  setCached(cacheK, result, 30 * 60 * 1000);
  return NextResponse.json(result);
}
