// Domain Intel — WHOIS / RDAP lookup
//
// RDAP is the modern replacement for WHOIS — JSON, official, rate-limited
// by IANA. We use rdap.org as bootstrap (it 302-redirects to the
// authoritative server per TLD — e.g. rdap.verisign.com for .com).

import { NextResponse } from "next/server";
import { getCached, setCached, cacheKey } from "@/lib/cache";

interface RdapEvent {
  eventAction: string; // registration | expiration | "last changed" | transfer
  eventDate: string; // ISO
  eventActor?: string;
}

interface RdapEntity {
  handle: string;
  roles: string[]; // registrar | registrant | administrative | technical | abuse | billing
  vcard?: any[]; // vcardArray
  entities?: RdapEntity[];
}

interface RdapNameserver {
  ldhName: string;
  unicodeName?: string;
  ips?: string[];
}

interface WhoisResult {
  domain: string;
  available: boolean;
  // Headline fields
  registrar?: string;
  registeredOn?: string; // ISO date
  expiresOn?: string;
  lastUpdated?: string;
  // Status codes (EPP)
  statusCodes: string[];
  // Nameservers
  nameservers: string[];
  // Registrant info (often redacted)
  registrant?: {
    name?: string;
    email?: string;
    organization?: string;
    country?: string;
  };
  // Raw entities for advanced users
  entities: Array<{
    roles: string[];
    name?: string;
    email?: string;
    handle?: string;
  }>;
  // Booleans
  isRedacted: boolean; // true if WHOIS privacy is detected
  domainAgeDays?: number;
  daysUntilExpiry?: number;
  // Source
  rdapUrl?: string;
  error?: string;
}

const RDAP_BOOTSTRAP = "https://rdap.org/domain/";

function extractVcard(vcardArray: any[]): Record<string, string> {
  // vcardArray is ["vcard", [ ["type", {}, "text", "value"], ... ]]
  const out: Record<string, string> = {};
  if (!Array.isArray(vcardArray) || vcardArray.length < 2) return out;
  const entries = vcardArray[1] || [];
  for (const e of entries) {
    if (Array.isArray(e) && e.length >= 4) {
      const key = e[0];
      const val = e[3];
      out[key] = String(val);
    }
  }
  return out;
}

function flattenEntities(
  ents: RdapEntity[] | undefined,
  acc: WhoisResult["entities"] = []
): WhoisResult["entities"] {
  if (!ents) return acc;
  for (const ent of ents) {
    const vcard = ent.vcard ? extractVcard(ent.vcard) : {};
    acc.push({
      roles: ent.roles || [],
      name: vcard.fn || vcard.org,
      email: vcard.email,
      handle: ent.handle,
    });
    if (ent.entities && ent.entities.length > 0) {
      flattenEntities(ent.entities, acc);
    }
  }
  return acc;
}

function calculateAgeDays(dateStr: string | undefined): number | undefined {
  if (!dateStr) return undefined;
  const t = new Date(dateStr).getTime();
  if (isNaN(t)) return undefined;
  return Math.floor((Date.now() - t) / (24 * 60 * 60 * 1000));
}

function calculateDaysUntil(dateStr: string | undefined): number | undefined {
  if (!dateStr) return undefined;
  const t = new Date(dateStr).getTime();
  if (isNaN(t)) return undefined;
  return Math.floor((t - Date.now()) / (24 * 60 * 60 * 1000));
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

  // Basic domain validation
  if (!/^[a-z0-9.-]+\.[a-z]{2,}$/i.test(domain) || domain.includes("..")) {
    return NextResponse.json(
      { error: "invalid_domain", hint: `Not a valid domain: ${domain}` },
      { status: 400 }
    );
  }

  // Cache check — 1 hour TTL (WHOIS records rarely change)
  const cacheK = cacheKey("whois", domain);
  const cached = getCached<WhoisResult>(cacheK);
  if (cached) return NextResponse.json({ ...cached, cached: true });

  try {
    // rdap.org redirects (302) to the authoritative RDAP server. We follow
    // the redirect and use the final response.
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 8000);
    const res = await fetch(`${RDAP_BOOTSTRAP}${encodeURIComponent(domain)}`, {
      signal: controller.signal,
      redirect: "follow",
      headers: {
        Accept: "application/rdap+json,application/json",
        "User-Agent": "MONITOR-THREAT/2.0 (RDAP)",
      },
    });
    clearTimeout(timeout);

    if (res.status === 404) {
      return NextResponse.json({
        domain,
        available: false,
        statusCodes: [],
        nameservers: [],
        entities: [],
        isRedacted: false,
        error: "domain_not_registered",
      });
    }
    if (!res.ok) {
      return NextResponse.json({
        domain,
        available: false,
        statusCodes: [],
        nameservers: [],
        entities: [],
        isRedacted: false,
        error: `rdap_error_${res.status}`,
      });
    }

    const data = await res.json();
    const events: RdapEvent[] = data.events || [];
    const getEvent = (action: string) => events.find((e) => e.eventAction === action);
    const regEvent = getEvent("registration");
    const expEvent = getEvent("expiration");
    const changedEvent = getEvent("last changed");

    // Nameservers
    const nameservers: string[] = (data.nameservers || []).map((ns: RdapNameserver) =>
      (ns.unicodeName || ns.ldhName || "").toLowerCase()
    );

    // Flatten entities for easier consumption
    const flatEntities = flattenEntities(data.entities);

    // Look for the registrant — could be in any entity with role "registrant"
    // In .com Verisign RDAP, registrant info is redacted (privacy by default)
    const registrantEntity = flatEntities.find((e) => e.roles.includes("registrant")) || null;

    // Find registrar name (entity with role "registrar")
    const registrarEntity = flatEntities.find((e) => e.roles.includes("registrar"));

    // Detect redaction (WHOIS privacy)
    const isRedacted = !registrantEntity?.email && !registrantEntity?.name;

    const result: WhoisResult = {
      domain,
      available: true,
      registrar: registrarEntity?.name,
      registeredOn: regEvent?.eventDate,
      expiresOn: expEvent?.eventDate,
      lastUpdated: changedEvent?.eventDate,
      statusCodes: data.status || [],
      nameservers,
      registrant: registrantEntity
        ? {
            name: registrantEntity.name,
            email: registrantEntity.email,
          }
        : undefined,
      entities: flatEntities,
      isRedacted,
      domainAgeDays: calculateAgeDays(regEvent?.eventDate),
      daysUntilExpiry: calculateDaysUntil(expEvent?.eventDate),
      rdapUrl: `${RDAP_BOOTSTRAP}${encodeURIComponent(domain)}`,
    };

    setCached(cacheK, result, 60 * 60 * 1000);
    return NextResponse.json(result);
  } catch (err: any) {
    return NextResponse.json(
      {
        domain,
        available: false,
        statusCodes: [],
        nameservers: [],
        entities: [],
        isRedacted: false,
        error: "rdap_unreachable",
        hint: err.message,
      },
      { status: 502 }
    );
  }
}
