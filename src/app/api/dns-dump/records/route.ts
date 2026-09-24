// DNS Dump — all DNS record types via Cloudflare DoH
//
// Fetches A, AAAA, MX, NS, TXT, CNAME, SOA, SRV, CAA, DNSKEY, DS, TLSA,
// SSHFP, NAPTR, URI, OPENPGPKEYS, SMIMEA, PTR, NSEC, NSEC3, NSEC3PARAM
// in parallel. Also captures TTLs and EDNS info.

import { NextResponse } from "next/server";
import { getCached, setCached, cacheKey } from "@/lib/cache";

const DOH_URL = "https://cloudflare-dns.com/dns-query";

const ALL_TYPES: Record<string, number> = {
  A: 1, NS: 2, CNAME: 5, SOA: 6, MX: 15, TXT: 16, AAAA: 28,
  SRV: 33, NAPTR: 35, NSEC: 47, DNSKEY: 48, DS: 43, NSEC3: 50,
  NSEC3PARAM: 51, TLSA: 52, SMIMEA: 53, SSHFP: 44, OPENPGPKEYS: 61,
  CAA: 257, URI: 256, PTR: 12,
};

interface DnsRecord {
  type: string;
  name: string;
  ttl: number;
  data: string;
}

interface RecordsResult {
  domain: string;
  available: boolean;
  records: Record<string, DnsRecord[]>;
  recordCounts: Record<string, number>;
  totalRecords: number;
  soa?: {
    mname?: string;
    rname?: string;
    serial?: number;
    refresh?: number;
    retry?: number;
    expire?: number;
    minimum?: number;
  };
  error?: string;
}

async function fetchDoh(domain: string, type: string): Promise<DnsRecord[]> {
  const typeNum = ALL_TYPES[type];
  if (!typeNum) return [];
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
    return (data.Answer || []).map((a: any) => ({
      type,
      name: a.name,
      ttl: a.TTL,
      data: a.data,
    }));
  } catch {
    return [];
  }
}

function parseSoa(data: string): RecordsResult["soa"] {
  // SOA format: mname rname serial refresh retry expire minimum
  const parts = data.split(/\s+/);
  if (parts.length < 7) return undefined;
  return {
    mname: parts[0],
    rname: parts[1],
    serial: parseInt(parts[2]) || undefined,
    refresh: parseInt(parts[3]) || undefined,
    retry: parseInt(parts[4]) || undefined,
    expire: parseInt(parts[5]) || undefined,
    minimum: parseInt(parts[6]) || undefined,
  };
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

  const cacheK = cacheKey("dnsdump_records", domain);
  const cached = getCached<RecordsResult>(cacheK);
  if (cached) return NextResponse.json({ ...cached, cached: true });

  const types = Object.keys(ALL_TYPES);
  const results = await Promise.all(types.map((t) => fetchDoh(domain, t)));

  const records: Record<string, DnsRecord[]> = {};
  const recordCounts: Record<string, number> = {};
  let totalRecords = 0;

  types.forEach((type, i) => {
    records[type] = results[i];
    recordCounts[type] = results[i].length;
    totalRecords += results[i].length;
  });

  // Parse SOA if present
  let soa: RecordsResult["soa"] = undefined;
  if (records.SOA && records.SOA.length > 0) {
    soa = parseSoa(records.SOA[0].data);
  }

  const result: RecordsResult = {
    domain,
    available: true,
    records,
    recordCounts,
    totalRecords,
    soa,
  };

  setCached(cacheK, result, 30 * 60 * 1000);
  return NextResponse.json(result);
}
