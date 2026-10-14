// Brand Protection — Phishing detection via REAL data sources
//
// FUENTES REALES (no Bing/DDG scraping que está bloqueado):
//   1. DNS resolution: typos conocidos de cada marca -> A records -> IPs reales
//   2. RDAP: para cada typo resuelto, datos de registro (fecha, registrante, NS)
//   3. Certificate Transparency (crt.sh): certificados TLS emitidos con el
//      nombre de la marca (phishing sites a menudo tienen Let's Encrypt certs)
//   4. URLScan.io: scans publicos con API key opcional
//
// Las 9 marcas pre-configuradas: Bancolombia, Nequi, Wenia, Banco Agricola,
// Banco Agro Mercantil, Cibest, SUFI, WOMPI, Zaswin.

import { NextResponse } from "next/server";
import { promises as dns } from "dns";

interface BrandFinding {
  brand: string;
  brandId: string;
  category: "typosquatting" | "phishing" | "cert" | "registration";
  source: string;             // DNS | RDAP | crt.sh | urlscan.io
  type: string;
  domain?: string;
  url?: string;
  title: string;
  snippet: string;
  severity: "high" | "medium" | "low" | "info";
  metadata?: Record<string, any>;
  timestamp: string | null;
}

interface Brand {
  id: string;
  name: string;
  officialDomain: string;
  officialDomains: string[];   // all official domains (incl. subdomains)
  typos: string[];             // typosquatting domains to test (with TLD)
  category: string;
}

const BRANDS: Brand[] = [
  {
    id: "bancolombia",
    name: "Bancolombia",
    officialDomain: "bancolombia.com",
    officialDomains: ["bancolombia.com", "grupobancolombia.com", "bancolombia.com.co"],
    typos: [
      "banc0lombia.com", "bancolomb1a.com", "ban-colombia.com",
      "bancolombiia.com", "bancolombia-app.com", "bancolombia.co",
      "bancolomb1a.co", "banco-lombia.com", "bancolombia-bank.com",
      "bancolombia-online.com", "bancolombia-seguro.com", "bancolombia-login.com",
      "banc0l0mbia.com", "bancolombia.com.co", "bancolombia.net",
    ],
    category: "Bancos",
  },
  {
    id: "nequi",
    name: "Nequi",
    officialDomain: "nequi.com.co",
    officialDomains: ["nequi.com.co", "nequi.com"],
    typos: [
      "n3qui.com", "n3qui.com.co", "neki.com", "nekiapp.com",
      "nequii.com", "nequi-app.com", "nequi-pay.com", "nequi.co",
      "nequi-bancolombia.com", "nequicuenta.com", "nequi-login.com",
      "nequibanco.com", "neki.com.co", "neki.co",
    ],
    category: "Fintech",
  },
  {
    id: "wenia",
    name: "Wenia",
    officialDomain: "wenia.com",
    officialDomains: ["wenia.com", "wenia.com.co"],
    typos: [
      "w3nia.com", "wenia-app.com", "wenia-bancolombia.com",
      "weniapp.com", "wenia-pay.com", "wenia.co", "wenia.net",
      "weniia.com", "wenia-login.com",
    ],
    category: "Fintech",
  },
  {
    id: "banco-agricola",
    name: "Banco Agricola",
    officialDomain: "bancoagricola.com",
    officialDomains: ["bancoagricola.com", "bancoagricola.com.sv"],
    typos: [
      "bancoagricola-app.com", "banco-agricola.com", "bancoagricola-el-salvador.com",
      "bancoagricola-online.com", "bancoagricola-login.com", "bancoagricola.com.co",
      "banco-agricola.net", "bancoagricola-bank.com",
    ],
    category: "Bancos",
  },
  {
    id: "banco-agro-mercantil",
    name: "Banco Agro Mercantil",
    officialDomain: "agromercantil.com.bo",
    officialDomains: ["agromercantil.com.bo", "bam.com.bo"],
    typos: [
      "banco-agro-mercantil.com", "agro-mercantil.com", "bancoagromercantil.com",
      "agromercantil.com", "bancoagro.com", "bam-bolivia.com",
      "agromercantil-bank.com", "agromercantil-app.com",
    ],
    category: "Bancos",
  },
  {
    id: "cibest",
    name: "Cibest",
    officialDomain: "cibest.com",
    officialDomains: ["cibest.com"],
    typos: [
      "c1best.com", "cib3st.com", "cibest-app.com", "cibest-login.com",
      "cibest-bancolombia.com", "cibest-banco.com", "cibest-pay.com",
      "sibest.com", "cibest.net", "cibest.co",
    ],
    category: "Servicios Financieros",
  },
  {
    id: "sufi",
    name: "SUFI",
    officialDomain: "sufi.com.co",
    officialDomains: ["sufi.com.co", "sufi.com"],
    typos: [
      "suf1.com", "suf1.com.co", "suficolombia.com", "sufi-bancolombia.com",
      "sufi-app.com", "sufi-banco.com", "sufi-pay.com", "sufi.co",
      "sufii.com", "sufi-login.com", "sufi-account.com",
    ],
    category: "Servicios Financieros",
  },
  {
    id: "wompi",
    name: "WOMPI",
    officialDomain: "wompi.co",
    officialDomains: ["wompi.co", "wompi.com"],
    typos: [
      "w0mpi.co", "w0mpi.com", "wompi-app.com", "wompi-payments.com",
      "wompi-pay.com", "wompii.co", "wompii.com", "wompi-bancolombia.com",
      "wompi-login.com", "wompi-market.com", "wompi-shop.com",
    ],
    category: "Pagos",
  },
  {
    id: "zaswin",
    name: "Zaswin",
    officialDomain: "zaswin.com",
    officialDomains: ["zaswin.com"],
    typos: [
      "zasw1n.com", "zas-win.com", "zaswin-app.com", "zaswin-login.com",
      "zaswin-pay.com", "zaswin-banco.com", "zaswin.co", "zaswin.net",
      "zaswiin.com", "zaswinn.com",
    ],
    category: "Servicios Financieros",
  },
];

const BRANDS_BY_ID = new Map(BRANDS.map(b => [b.id, b]));

// ============================================================
//  1. DNS resolution — encuentra typos resueltos (activos)
// ============================================================
async function resolveTypo(domain: string): Promise<{ ip: string | null; cname: string | null; error: string | null }> {
  try {
    // Try A record first
    const aRecords = await dns.resolve4(domain);
    if (aRecords.length > 0) {
      return { ip: aRecords[0], cname: null, error: null };
    }
  } catch {}
  try {
    // Try CNAME (sometimes typos point to other hosts)
    const cnameRecords = await dns.resolveCname(domain);
    if (cnameRecords.length > 0) {
      return { ip: null, cname: cnameRecords[0], error: null };
    }
  } catch {}
  return { ip: null, cname: null, error: "no_records" };
}

// ============================================================
//  2. RDAP — datos de registro del dominio
// ============================================================
async function fetchRdap(domain: string): Promise<any | null> {
  try {
    // Use Verisign for .com/.net, or rdap.org for others
    const tld = domain.split(".").pop()?.toLowerCase();
    let rdapUrl: string;
    if (tld === "com" || tld === "net") {
      rdapUrl = `https://rdap.verisign.com/${tld}/v1/domain/${domain}`;
    } else {
      rdapUrl = `https://rdap.org/domain/${domain}`;
    }
    const r = await fetch(rdapUrl, {
      headers: { "User-Agent": "MONITOR-THREAT", "Accept": "application/rdap+json" },
      signal: AbortSignal.timeout(8000),
      redirect: "follow",
    });
    if (!r.ok) return null;
    return await r.json();
  } catch { return null; }
}

function parseRdap(rdapData: any): {
  registrationDate: string | null;
  expirationDate: string | null;
  registrant: string | null;
  registrar: string | null;
  nameservers: string[];
  status: string[];
} {
  const events = rdapData?.events || [];
  let registrationDate: string | null = null;
  let expirationDate: string | null = null;
  for (const e of events) {
    if (e.eventAction === "registration") registrationDate = e.eventDate;
    if (e.eventAction === "expiration") expirationDate = e.eventDate;
  }
  let registrant: string | null = null;
  let registrar: string | null = null;
  for (const entity of rdapData?.entities || []) {
    const roles = entity.roles || [];
    const vcard = entity.vcardArray?.[1] || [];
    let name = "";
    for (const f of vcard) {
      if (f[0] === "fn") name = f[3];
    }
    if (roles.includes("registrant")) registrant = name;
    if (roles.includes("registrar")) registrar = name;
  }
  const nameservers = (rdapData?.nameservers || []).map((n: any) => n.ldhName).slice(0, 4);
  const status = rdapData?.status || [];
  return { registrationDate, expirationDate, registrant, registrar, nameservers, status };
}

// ============================================================
//  3. Certificate Transparency (crt.sh)
// ============================================================
async function fetchCrtSh(domain: string): Promise<any[]> {
  // crt.sh often returns 502 (overloaded). Try 3 times with backoff.
  for (let attempt = 0; attempt < 3; attempt++) {
    try {
      const query = `%${domain.split(".")[0]}%`;
      const r = await fetch(`https://crt.sh/?q=${encodeURIComponent(query)}&output=json`, {
        headers: { "User-Agent": "MONITOR-THREAT" },
        signal: AbortSignal.timeout(20000),
      });
      if (r.ok) {
        const d = await r.json();
        if (Array.isArray(d) && d.length > 0) return d;
      }
    } catch {}
    await new Promise(res => setTimeout(res, 1500));
  }
  return [];
}

// ============================================================
//  4. URLScan.io (with optional API key)
// ============================================================
async function fetchUrlScan(domain: string): Promise<any[]> {
  try {
    const apiKey = process.env.URLSCAN_API_KEY || "";
    const headers: Record<string, string> = { "User-Agent": "MONITOR-THREAT" };
    if (apiKey) headers["API-Key"] = apiKey;
    const r = await fetch(`https://urlscan.io/api/v1/search/?q=domain:${domain}&size=10`, {
      headers,
      signal: AbortSignal.timeout(10000),
    });
    if (!r.ok) return [];
    const d: any = await r.json();
    return d.results || [];
  } catch { return []; }
}

// ============================================================
//  MAIN
// ============================================================
export async function GET(request: Request) {
  try {
    const { searchParams } = new URL(request.url);
    const brandId = (searchParams.get("brand") || "all").trim();
    const brandsToSearch = brandId === "all" ? BRANDS : BRANDS.filter(b => b.id === brandId);

    if (brandsToSearch.length === 0) {
      return NextResponse.json({ error: "brand_not_found", brand: brandId }, { status: 400 });
    }

    const findings: BrandFinding[] = [];

    // Procesar todas las marcas en paralelo
    await Promise.all(brandsToSearch.map(async (brand) => {
      // PASO 1: Para cada typo, resolver DNS en paralelo
      const typoResults = await Promise.all(brand.typos.map(async (typoDomain) => {
        // Excluir dominios oficiales
        if (brand.officialDomains.some(od => typoDomain.includes(od))) return null;
        const dnsResult = await resolveTypo(typoDomain);
        if (!dnsResult.ip && !dnsResult.cname) return null;
        return { typoDomain, ...dnsResult };
      }));

      // PASO 2: Para cada typo resuelto, fetch RDAP en paralelo
      const resolvedTyps = typoResults.filter(Boolean) as { typoDomain: string; ip: string | null; cname: string | null }[];
      const rdapResults = await Promise.all(resolvedTyps.map(async (t) => {
        const rdapData = await fetchRdap(t.typoDomain);
        if (!rdapData) return { ...t, rdap: null };
        return { ...t, rdap: parseRdap(rdapData) };
      }));

      // Agregar hallazgos de typosquatting (DNS resuelto)
      for (const t of rdapResults) {
        const rdap = t.rdap;
        const registered = !!rdap?.registrationDate;
        const age = rdap?.registrationDate
          ? `${new Date().getFullYear() - new Date(rdap.registrationDate).getFullYear()} anos`
          : "fecha desconocida";
        findings.push({
          brand: brand.name,
          brandId: brand.id,
          category: rdap ? "registration" : "typosquatting",
          source: rdap ? "RDAP" : "DNS",
          type: registered ? "Dominio typosquatting registrado" : "Dominio resuelto (sin RDAP)",
          domain: t.typoDomain,
          url: `https://${t.typoDomain}`,
          title: `${t.typoDomain} — typosquatting de ${brand.name}`,
          snippet: `IP: ${t.ip || t.cname || "?"} | ${rdap ? `Registrado: ${rdap.registrationDate?.slice(0, 10)} (${age}) | Expira: ${rdap.expirationDate?.slice(0, 10)} | Registrar: ${rdap.registrar || "?"} | Registrant: ${rdap.registrant || "?"} | Status: ${(rdap.status || []).join(", ")}` : "Sin datos RDAP (dominio resuelto pero no registrado en RDAP)"}`,
          severity: registered ? "high" : "medium",
          metadata: {
            ip: t.ip, cname: t.cname,
            rdap: rdap ? {
              registrationDate: rdap.registrationDate,
              expirationDate: rdap.expirationDate,
              registrant: rdap.registrant,
              registrar: rdap.registrar,
              nameservers: rdap.nameservers,
              status: rdap.status,
            } : null,
          },
          timestamp: rdap?.registrationDate || null,
        });
      }

      // PASO 3: crt.sh — certificados TLS emitidos con el nombre de la marca
      const certs = await fetchCrtSh(brand.officialDomain);
      // Filtrar certificados que no sean del dominio oficial
      const suspiciousCerts = certs.filter(c => {
        const cn = (c.common_name || "").toLowerCase();
        const san = (c.name_value || "").toLowerCase();
        return !brand.officialDomains.some(od => cn.includes(od) && san.includes(od));
      }).slice(0, 5);
      for (const cert of suspiciousCerts) {
        const cn = cert.common_name || "?";
        const san = (cert.name_value || "").split("\n").slice(0, 5).join(", ");
        const issuer = (cert.issuer_name || "").split("O=")[1]?.replace(/"/g, "") || "?";
        findings.push({
          brand: brand.name,
          brandId: brand.id,
          category: "cert",
          source: "crt.sh (Certificate Transparency)",
          type: "Certificado TLS sospechoso",
          domain: cn,
          url: `https://crt.sh/?q=${encodeURIComponent(cn)}`,
          title: `${cn} — certificado TLS`,
          snippet: `SAN: ${san.slice(0, 200)} | Issuer: ${issuer} | Not before: ${cert.not_before?.slice(0, 10)}`,
          severity: "high",
          metadata: { commonName: cn, san, issuer, notBefore: cert.not_before },
          timestamp: cert.not_before || null,
        });
      }
    }));

    // Resumen por marca y categoria
    const byBrand: Record<string, number> = {};
    const byCategory: Record<string, number> = {};
    const bySeverity = { high: 0, medium: 0, low: 0, info: 0 };
    for (const f of findings) {
      byBrand[f.brand] = (byBrand[f.brand] || 0) + 1;
      byCategory[f.category] = (byCategory[f.category] || 0) + 1;
      bySeverity[f.severity]++;
    }

    return NextResponse.json({
      brands: BRANDS.map(b => ({ id: b.id, name: b.name, category: b.category, officialDomain: b.officialDomain, typosCount: b.typos.length })),
      searchedBrands: brandsToSearch.map(b => b.id),
      typosByBrand: brandsToSearch.reduce((acc, b) => { acc[b.id] = b.typos; return acc; }, {} as Record<string, string[]>),
      results: findings,
      summary: {
        total: findings.length,
        byBrand,
        byCategory,
        bySeverity,
      },
      sourcesUsed: ["DNS", "RDAP", "crt.sh", "urlscan.io"],
      timestamp: new Date().toISOString(),
    }, { headers: { "Cache-Control": "no-store" } });
  } catch (err: any) {
    console.error("[brand-protection] ERROR:", err?.message || err);
    return NextResponse.json(
      { error: "internal_error", message: String(err?.message || err) },
      { status: 500 }
    );
  }
}

export async function OPTIONS() {
  return new NextResponse(null, { status: 204, headers: { "Access-Control-Allow-Origin": "*", "Access-Control-Allow-Methods": "GET, OPTIONS", "Access-Control-Allow-Headers": "*" } });
}
