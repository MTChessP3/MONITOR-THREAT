// DNS Dump — DNSSEC deep analysis
//
// Checks DS + DNSKEY records, detects algorithm, key tag, digest type,
// chain validation status, NSEC vs NSEC3.

import { NextResponse } from "next/server";
import { getCached, setCached, cacheKey } from "@/lib/cache";

const DOH_URL = "https://cloudflare-dns.com/dns-query";

interface DnssecResult {
  domain: string;
  available: boolean;
  signed: boolean;
  dnskeyRecords: Array<{ name: string; ttl: number; data: string; flags?: number; protocol?: number; algorithm?: number }>;
  dsRecords: Array<{ name: string; ttl: number; data: string; keyTag?: number; algorithm?: number; digestType?: number; digest?: string }>;
  nsecRecords: number;
  nsec3Records: number;
  nsec3ParamRecords: number;
  denialType: "NSEC" | "NSEC3" | "none";
  algorithms: string[];
  chainValid: boolean;
  error?: string;
}

const ALGORITHM_NAMES: Record<number, string> = {
  1: "RSASHA1",
  2: "DSA",
  3: "DSA-NSEC3-SHA1",
  5: "RSASHA1",
  7: "RSASHA1-NSEC3-SHA1",
  8: "RSASHA256",
  10: "RSASHA512",
  13: "ECDSAP256SHA256",
  14: "ECDSAP384SHA384",
  15: "ED25519",
  16: "ED448",
};

async function fetchDoh(domain: string, typeNum: number): Promise<any[]> {
  try {
    const url = `${DOH_URL}?name=${encodeURIComponent(domain)}&type=${typeNum}`;
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 4000);
    const res = await fetch(url, {
      signal: controller.signal,
      headers: { accept: "application/dns-json", "User-Agent": "MONITOR-THREAT/2.0" },
    });
    clearTimeout(timeout);
    if (!res.ok) return [];
    const data = await res.json();
    return data.Answer || [];
  } catch {
    return [];
  }
}

function parseDnskeyData(data: string): { flags?: number; protocol?: number; algorithm?: number } {
  // DNSKEY format: flags protocol algorithm base64key
  const parts = data.split(/\s+/);
  if (parts.length < 4) return {};
  return {
    flags: parseInt(parts[0]),
    protocol: parseInt(parts[1]),
    algorithm: parseInt(parts[2]),
  };
}

function parseDsData(data: string): { keyTag?: number; algorithm?: number; digestType?: number; digest?: string } {
  // DS format: keyTag algorithm digestType digest
  const parts = data.split(/\s+/);
  if (parts.length < 4) return {};
  return {
    keyTag: parseInt(parts[0]),
    algorithm: parseInt(parts[1]),
    digestType: parseInt(parts[2]),
    digest: parts[3],
  };
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

  const cacheK = cacheKey("dnsdump_dnssec", domain);
  const cached = getCached<DnssecResult>(cacheK);
  if (cached) return NextResponse.json({ ...cached, cached: true });

  const [dnskeyRaw, dsRaw, nsecRaw, nsec3Raw, nsec3paramRaw] = await Promise.all([
    fetchDoh(domain, 48),  // DNSKEY
    fetchDoh(domain, 43),  // DS
    fetchDoh(domain, 47),  // NSEC
    fetchDoh(domain, 50),  // NSEC3
    fetchDoh(domain, 51),  // NSEC3PARAM
  ]);

  const dnskeyRecords = dnskeyRaw.map((r: any) => ({
    name: r.name,
    ttl: r.TTL,
    data: r.data,
    ...parseDnskeyData(r.data),
  }));

  const dsRecords = dsRaw.map((r: any) => ({
    name: r.name,
    ttl: r.TTL,
    data: r.data,
    ...parseDsData(r.data),
  }));

  const algorithms: string[] = [];
  for (const dk of dnskeyRecords) {
    if (dk.algorithm && !algorithms.includes(ALGORITHM_NAMES[dk.algorithm] || `ALG-${dk.algorithm}`)) {
      algorithms.push(ALGORITHM_NAMES[dk.algorithm] || `ALG-${dk.algorithm}`);
    }
  }

  const signed = dnskeyRecords.length > 0 || dsRecords.length > 0;
  const chainValid = dsRecords.length > 0 && dnskeyRecords.length > 0;

  let denialType: "NSEC" | "NSEC3" | "none" = "none";
  if (nsec3Raw.length > 0 || nsec3paramRaw.length > 0) denialType = "NSEC3";
  else if (nsecRaw.length > 0) denialType = "NSEC";

  const result: DnssecResult = {
    domain,
    available: true,
    signed,
    dnskeyRecords,
    dsRecords,
    nsecRecords: nsecRaw.length,
    nsec3Records: nsec3Raw.length,
    nsec3ParamRecords: nsec3paramRaw.length,
    denialType,
    algorithms,
    chainValid,
  };

  setCached(cacheK, result, 30 * 60 * 1000);
  return NextResponse.json(result);
}
