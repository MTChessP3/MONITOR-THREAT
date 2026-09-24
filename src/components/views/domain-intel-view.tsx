"use client";

import * as React from "react";
import {
  Globe,
  Loader2,
  AlertTriangle,
  ExternalLink,
  Printer,
  Server,
  ShieldCheck,
  Mail,
  Fingerprint,
  FileText,
  Search,
  Network,
} from "lucide-react";
import { jsPDF } from "jspdf";
import autoTable from "jspdf-autotable";

import {
  ModuleShell,
  Panel,
  FieldRow,
  EmptyModuleState,
} from "@/components/module-shell";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Separator } from "@/components/ui/separator";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";

// ---------- Types matching the API response ----------

interface WhoisResult {
  domain: string;
  available: boolean;
  registrar?: string;
  registeredOn?: string;
  expiresOn?: string;
  lastUpdated?: string;
  statusCodes: string[];
  nameservers: string[];
  registrant?: { name?: string; email?: string; organization?: string; country?: string };
  entities: Array<{ roles: string[]; name?: string; email?: string; handle?: string }>;
  isRedacted: boolean;
  domainAgeDays?: number;
  daysUntilExpiry?: number;
  rdapUrl?: string;
  error?: string;
}

interface DnsRecord { type: string; name: string; ttl: number; data: string; }
interface DnsResult {
  domain: string;
  available: boolean;
  records: Record<string, DnsRecord[]>;
  email: {
    spf?: { record: string; mechanism: string[] };
    dkim?: { selector: string; record: string; keyType?: string };
    dmarc?: { record: string; policy: "none" | "quarantine" | "reject" | "missing"; pct?: number };
    mtaSts?: { record: string; id: string };
    bimi?: { record: string };
    mxCount: number;
    mxProviders: string[];
  };
  dnssec: boolean;
  hasSpf: boolean;
  hasDmarc: boolean;
  hasDkim: boolean;
  emailSecurityScore: 0 | 1 | 2 | 3 | 4;
  error?: string;
}

interface SubdomainEntry { name: string; source: string; resolves: boolean; ips?: string[]; }
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

interface CertEntry {
  id: number;
  issuer: string;
  commonName: string;
  sanNames: string[];
  notBefore: string;
  notAfter: string;
  serialNumber: string;
  isWildcard: boolean;
  isExpired: boolean;
  isCurrentlyValid: boolean;
}
interface CertsResult {
  domain: string;
  available: boolean;
  totalCerts: number;
  currentlyValidCerts: number;
  expiredCerts: number;
  wildcardCerts: number;
  uniqueIssuers: Array<{ name: string; count: number }>;
  uniqueSanDomains: string[];
  certs: CertEntry[];
  crtShOk: boolean;
  error?: string;
}

interface VtDomainResult {
  domain: string;
  available: boolean;
  lastAnalysisStats: { malicious: number; suspicious: number; harmless: number; undetected: number; timeout: number };
  totalEngines: number;
  flaggedEnginesCount: number;
  flaggedEngines: Array<{ engine: string; category: string; result: string }>;
  categories: Array<{ source: string; category: string }>;
  reputation: number;
  totalVotes: { harmless: number; malicious: number };
  lastAnalysisDate?: string;
  classification: "BENIGN" | "SUSPICIOUS" | "MALICIOUS";
  error?: string;
}

interface HostingResult {
  domain: string;
  available: boolean;
  ip?: string;
  finalUrl?: string;
  redirectCount: number;
  webServer?: string;
  poweredBy?: string;
  generator?: string;
  cdn?: string;
  cdnEdge?: string;
  technologies: Array<{ name: string; evidence: string }>;
  securityHeaders: Record<string, string | undefined>;
  securityScore: number;
  title?: string;
  faviconHash?: string;
  httpStatus?: number;
  responseTimeMs?: number;
  pivotHints: Record<string, string | undefined>;
  error?: string;
}

interface EmailResult {
  domain: string;
  available: boolean;
  spf: { present: boolean; record?: string; strength: "none" | "weak" | "medium" | "strong"; mechanisms?: string[] };
  dkim: { present: boolean; selector?: string; record?: string; keyType?: string };
  dmarc: { present: boolean; record?: string; policy?: string; strength: "none" | "monitor" | "weak" | "strong"; pct?: number };
  mtaSts: { present: boolean; record?: string; id?: string };
  bimi: { record: string } | null;
  mx: { count: number; providers: string[] };
  emailSecurityScore: number;
  recommendation: string;
}

interface BlacklistResult {
  domain: string;
  available: boolean;
  totalChecked: number;
  listedCount: number;
  entries: Array<{ zone: string; listed: boolean; reason?: string }>;
  isBlacklisted: boolean;
  error?: string;
}

interface AggregateResult {
  domain: string;
  whois: WhoisResult;
  dns: DnsResult;
  subdomains: SubdomainResult;
  certs: CertsResult;
  reputation: VtDomainResult;
  hosting: HostingResult;
  email: EmailResult;
  blacklists: BlacklistResult;
  timestamp: string;
}

// ---------- PDF report generator ----------
function classifyColor(c: string): [number, number, number] {
  if (c === "MALICIOUS") return [220, 38, 38];
  if (c === "SUSPICIOUS") return [202, 138, 4];
  return [22, 163, 74];
}

function downloadPdfReport(d: AggregateResult) {
  const doc = new jsPDF({ unit: "pt", format: "a4" });
  const pageWidth = doc.internal.pageSize.getWidth();
  const pageHeight = doc.internal.pageSize.getHeight();
  const margin = 40;
  const contentWidth = pageWidth - margin * 2;
  let y = margin;

  // Header
  doc.setFont("helvetica", "bold");
  doc.setFontSize(22);
  doc.setTextColor(15, 23, 42);
  doc.text("Domain Intelligence Report", margin, y + 8);
  doc.setFont("helvetica", "normal");
  doc.setFontSize(11);
  doc.setTextColor(220, 38, 38);
  doc.text("MONITOR-THREAT", margin, y + 26);
  doc.setTextColor(100, 116, 139);
  doc.text("Cyber Threat Intelligence Platform · v2.0", margin + 105, y + 26);
  const ts = new Date(d.timestamp).toLocaleString();
  doc.setFontSize(10);
  doc.setTextColor(71, 85, 105);
  doc.text(`Report generated: ${ts}`, pageWidth - margin, y + 8, { align: "right" });
  doc.text(`Target domain: ${d.domain}`, pageWidth - margin, y + 22, { align: "right" });
  y += 48;
  doc.setDrawColor(220, 220, 220);
  doc.setLineWidth(0.5);
  doc.line(margin, y, pageWidth - margin, y);
  y += 28;

  const sectionHeading = (label: string) => {
    if (y > pageHeight - margin - 120) { doc.addPage(); y = margin + 6; }
    else { y += 20; }
    doc.setFont("helvetica", "bold");
    doc.setFontSize(13);
    doc.setTextColor(220, 38, 38);
    doc.text(label, margin, y);
    doc.setDrawColor(220, 38, 38);
    doc.setLineWidth(1);
    doc.line(margin, y + 4, pageWidth - margin, y + 4);
    y += 16;
    doc.setFont("helvetica", "normal");
    doc.setFontSize(10);
    doc.setTextColor(51, 65, 85);
  };
  const kvTable = (rows: Array<[string, string]>) => {
    autoTable(doc, {
      startY: y, head: [["Field", "Value"]], body: rows,
      theme: "striped", margin: { left: margin, right: margin },
      styles: { fontSize: 10, cellPadding: 6, textColor: [30, 41, 59], lineColor: [226, 232, 240], lineWidth: 0.5 },
      headStyles: { fillColor: [241, 245, 249], textColor: [71, 85, 105], fontStyle: "bold", fontSize: 10 },
      columnStyles: { 0: { cellWidth: contentWidth * 0.32, fontStyle: "bold", textColor: [100, 116, 139] } },
    });
    // @ts-ignore
    y = (doc as any).lastAutoTable.finalY + 18;
  };

  // 1. WHOIS
  sectionHeading("1. WHOIS & Registration");
  const w = d.whois;
  if (w.available) {
    kvTable([
      ["Domain", w.domain],
      ["Registrar", w.registrar || "-"],
      ["Registered", w.registeredOn || "-"],
      ["Domain age (days)", String(w.domainAgeDays ?? "-")],
      ["Expires", w.expiresOn || "-"],
      ["Days until expiry", String(w.daysUntilExpiry ?? "-")],
      ["Last updated", w.lastUpdated || "-"],
      ["WHOIS privacy", w.isRedacted ? "Yes (redacted)" : "No (visible)"],
      ["Status codes", w.statusCodes.join(", ") || "-"],
      ["Nameservers", w.nameservers.join(", ") || "-"],
    ]);
  } else {
    doc.setTextColor(148, 163, 184);
    doc.text(`WHOIS lookup failed: ${w.error || "no data"}`, margin, y);
    y += 18;
  }

  // 2. DNS Records
  sectionHeading("2. DNS Records");
  const dns = d.dns;
  if (dns.available) {
    const r = dns.records;
    kvTable([
      ["A records", (r.A || []).map((x) => x.data).join(", ") || "-"],
      ["AAAA records", (r.AAAA || []).map((x) => x.data).join(", ") || "-"],
      ["MX records", (r.MX || []).map((x) => x.data).join(", ") || "-"],
      ["NS records", (r.NS || []).map((x) => x.data).join(", ") || "-"],
      ["TXT records count", String((r.TXT || []).length)],
      ["CNAME records", (r.CNAME || []).map((x) => x.data).join(", ") || "-"],
      ["SOA", (r.SOA || []).map((x) => x.data).join(", ") || "-"],
      ["CAA records", (r.CAA || []).map((x) => x.data).join(", ") || "-"],
      ["DNSSEC", dns.dnssec ? "Signed (yes)" : "Unsigned (no)"],
    ]);
  } else {
    doc.setTextColor(148, 163, 184);
    doc.text(`DNS lookup failed: ${dns.error || "no data"}`, margin, y);
    y += 18;
  }

  // 3. Subdomains
  sectionHeading("3. Subdomain Enumeration");
  const sub = d.subdomains;
  if (sub.available) {
    kvTable([
      ["Total subdomains", String(sub.total)],
      ["Active (resolving)", String(sub.active)],
      ["Historical (no resolve)", String(sub.historical)],
      ["Source: crt.sh", sub.crtShOk ? "OK" : "Failed (fallback used)"],
      ["Source: hackertarget", sub.hackertargetOk ? "OK" : "Failed"],
    ]);
    if (sub.subdomains.length > 0) {
      autoTable(doc, {
        startY: y, head: [["Subdomain", "Source", "Status", "IP(s)"]],
        body: sub.subdomains.slice(0, 30).map((s) => [
          s.name, s.source, s.resolves ? "Active" : "Historical",
          (s.ips || []).join(", ") || "-",
        ]),
        theme: "grid", margin: { left: margin, right: margin },
        styles: { fontSize: 9, cellPadding: 5, textColor: [30, 41, 59], lineColor: [226, 232, 240], lineWidth: 0.5 },
        headStyles: { fillColor: [241, 245, 249], textColor: [71, 85, 105], fontStyle: "bold", fontSize: 10 },
        columnStyles: { 1: { cellWidth: 80 }, 2: { cellWidth: 80 } },
      });
      // @ts-ignore
      y = (doc as any).lastAutoTable.finalY + 18;
      if (sub.subdomains.length > 30) {
        doc.setFontSize(9);
        doc.setTextColor(148, 163, 184);
        doc.text(`+ ${sub.subdomains.length - 30} more`, margin, y);
        y += 18;
      }
    }
  } else {
    doc.setTextColor(148, 163, 184);
    doc.text(`Subdomain enumeration failed: ${sub.error || "no data"}`, margin, y);
    y += 18;
  }

  // 4. SSL Certificate Transparency
  sectionHeading("4. SSL Certificates (Certificate Transparency)");
  const certs = d.certs;
  if (certs.available) {
    kvTable([
      ["Total certificates", String(certs.totalCerts)],
      ["Currently valid", String(certs.currentlyValidCerts)],
      ["Expired", String(certs.expiredCerts)],
      ["Wildcard certificates", String(certs.wildcardCerts)],
      ["Unique issuers", String(certs.uniqueIssuers.length)],
      ["Unique SAN pivot domains", String(certs.uniqueSanDomains.length)],
    ]);
    if (certs.uniqueSanDomains.length > 0) {
      doc.setFontSize(9);
      doc.setTextColor(15, 23, 42);
      doc.setFont("helvetica", "bold");
      doc.text("Pivot domains (other domains sharing certs with this domain):", margin, y);
      y += 12;
      doc.setFont("helvetica", "normal");
      doc.setTextColor(8, 145, 178);
      doc.text(doc.splitTextToSize(certs.uniqueSanDomains.slice(0, 20).join(", "), contentWidth), margin, y);
      y += 30;
    }
    if (certs.certs.length > 0) {
      autoTable(doc, {
        startY: y, head: [["Issuer", "Common Name", "Not before", "Not after", "Status"]],
        body: certs.certs.slice(0, 10).map((c) => [
          (c.issuer || "").slice(0, 60),
          c.commonName.slice(0, 40),
          c.notBefore ? c.notBefore.slice(0, 10) : "-",
          c.notAfter ? c.notAfter.slice(0, 10) : "-",
          c.isCurrentlyValid ? "Valid" : c.isExpired ? "Expired" : "?",
        ]),
        theme: "grid", margin: { left: margin, right: margin },
        styles: { fontSize: 8, cellPadding: 4, textColor: [30, 41, 59], lineColor: [226, 232, 240], lineWidth: 0.5 },
        headStyles: { fillColor: [241, 245, 249], textColor: [71, 85, 105], fontStyle: "bold", fontSize: 10 },
      });
      // @ts-ignore
      y = (doc as any).lastAutoTable.finalY + 18;
    }
  } else {
    doc.setTextColor(148, 163, 184);
    doc.text(`CT lookup failed: ${certs.error || "no data"}`, margin, y);
    y += 18;
  }

  // 5. Reputation — VirusTotal
  sectionHeading("5. Reputation — VirusTotal");
  const rep = d.reputation;
  if (rep.available) {
    const repColor = classifyColor(rep.classification);
    kvTable([
      ["VT classification", rep.classification],
      ["Flagged engines", `${rep.flaggedEnginesCount} / ${rep.totalEngines}`],
      ["Stats", `malicious=${rep.lastAnalysisStats.malicious} suspicious=${rep.lastAnalysisStats.suspicious} harmless=${rep.lastAnalysisStats.harmless} undetected=${rep.lastAnalysisStats.undetected}`],
      ["Community reputation", String(rep.reputation)],
      ["Community votes", `${rep.totalVotes.harmless} harmless / ${rep.totalVotes.malicious} malicious`],
      ["Last analysis", rep.lastAnalysisDate ? new Date(rep.lastAnalysisDate).toLocaleString() : "-"],
      ["Categories", rep.categories.map((c) => `${c.source}: ${c.category}`).join(", ") || "-"],
    ]);
  } else {
    doc.setTextColor(148, 163, 184);
    doc.text(`VirusTotal not available: ${rep.error || "no data"}`, margin, y);
    y += 18;
  }

  // 6. Hosting & Technologies
  sectionHeading("6. Hosting & Technologies");
  const h = d.hosting;
  if (h.available) {
    kvTable([
      ["IP address", h.ip || "-"],
      ["Final URL", h.finalUrl || "-"],
      ["HTTP status", String(h.httpStatus ?? "-")],
      ["Response time", h.responseTimeMs ? `${h.responseTimeMs} ms` : "-"],
      ["Web server", h.webServer || "-"],
      ["X-Powered-By", h.poweredBy || "-"],
      ["X-Generator", h.generator || "-"],
      ["CDN", h.cdn || "None detected"],
      ["CDN edge", h.cdnEdge || "-"],
      ["Page title", h.title || "-"],
      ["Favicon hash (md5)", h.faviconHash || "-"],
      ["Security headers score", `${h.securityScore} / 6`],
      ["HSTS", h.securityHeaders.hsts || "missing"],
      ["CSP", h.securityHeaders.csp ? "present" : "missing"],
      ["X-Frame-Options", h.securityHeaders.xFrameOptions || "missing"],
    ]);
    if (h.technologies.length > 0) {
      autoTable(doc, {
        startY: y, head: [["Technology", "Evidence"]],
        body: h.technologies.map((t) => [t.name, t.evidence]),
        theme: "grid", margin: { left: margin, right: margin },
        styles: { fontSize: 9, cellPadding: 5, textColor: [30, 41, 59], lineColor: [226, 232, 240], lineWidth: 0.5 },
        headStyles: { fillColor: [241, 245, 249], textColor: [71, 85, 105], fontStyle: "bold", fontSize: 10 },
      });
      // @ts-ignore
      y = (doc as any).lastAutoTable.finalY + 18;
    }
  } else {
    doc.setTextColor(148, 163, 184);
    doc.text(`Hosting lookup failed: ${h.error || "no data"}`, margin, y);
    y += 18;
  }

  // 7. Email Infrastructure
  sectionHeading("7. Email Infrastructure");
  const e = d.email;
  if (e.available) {
    kvTable([
      ["MX count", String(e.mx.count)],
      ["MX providers", e.mx.providers.join(", ") || "-"],
      ["SPF", `${e.spf.present ? "Present" : "Missing"} (${e.spf.strength})`],
      ["SPF record", e.spf.record || "-"],
      ["DKIM", `${e.dkim.present ? `Present (selector: ${e.dkim.selector})` : "Missing"}`],
      ["DMARC", `${e.dmarc.present ? "Present" : "Missing"} (${e.dmarc.strength})`],
      ["DMARC record", e.dmarc.record || "-"],
      ["MTA-STS", e.mtaSts.present ? "Present" : "Missing"],
      ["BIMI", e.bimi ? "Present" : "Missing"],
      ["Email security score", `${e.emailSecurityScore} / 4`],
      ["Recommendation", e.recommendation],
    ]);
  } else {
    doc.setTextColor(148, 163, 184);
    doc.text(`Email lookup failed: ${e.error || "no data"}`, margin, y);
    y += 18;
  }

  // 8. Domain Blacklists
  sectionHeading("8. Domain Blacklists");
  const b = d.blacklists;
  if (b.available) {
    kvTable([
      ["Total checked", String(b.totalChecked)],
      ["Listed count", String(b.listedCount)],
      ["Status", b.isBlacklisted ? "BLACKLISTED" : "Clean"],
    ]);
    autoTable(doc, {
      startY: y, head: [["Zone", "Listed", "Reason"]],
      body: b.entries.map((entry) => [
        entry.zone,
        entry.listed ? "YES" : "no",
        entry.listed ? entry.reason || "Listed" : "-",
      ]),
      theme: "grid", margin: { left: margin, right: margin },
      styles: { fontSize: 9, cellPadding: 5, textColor: [30, 41, 59], lineColor: [226, 232, 240], lineWidth: 0.5 },
      headStyles: { fillColor: [241, 245, 249], textColor: [71, 85, 105], fontStyle: "bold", fontSize: 10 },
      columnStyles: { 0: { cellWidth: 200 } },
    });
    // @ts-ignore
    y = (doc as any).lastAutoTable.finalY + 18;
  } else {
    doc.setTextColor(148, 163, 184);
    doc.text(`Blacklist lookup failed: ${b.error || "no data"}`, margin, y);
    y += 18;
  }

  // 9. Methodology
  sectionHeading("9. Methodology & Sources");
  autoTable(doc, {
    startY: y, head: [["Source", "Use"]],
    body: [
      ["RDAP (rdap.org)", "WHOIS / registration data, official JSON replacement of WHOIS"],
      ["Cloudflare DNS DoH (1.1.1.1)", "DNS records: A, AAAA, MX, NS, TXT, CNAME, SOA, SRV, CAA, DNSKEY, DS, TLSA"],
      ["crt.sh (Sectigo CT log)", "Subdomain enumeration + SSL Certificate Transparency history"],
      ["Hackertarget", "Subdomain enumeration fallback (when crt.sh is down)"],
      ["VirusTotal v3", "Domain reputation, engine verdicts, community votes"],
      ["HTTP HEAD scan", "Web server, CDN detection, security headers, favicon hash"],
      ["DNSBL DNS queries", "Spamhaus DBL, SURBL, URIBL, Mailspike, Suportefap"],
    ],
    theme: "grid", margin: { left: margin, right: margin },
    styles: { fontSize: 9, cellPadding: 5, textColor: [30, 41, 59], lineColor: [226, 232, 240], lineWidth: 0.5 },
    headStyles: { fillColor: [241, 245, 249], textColor: [71, 85, 105], fontStyle: "bold", fontSize: 10 },
    columnStyles: { 0: { cellWidth: 160, fontStyle: "bold" } },
  });
  // @ts-ignore
  y = (doc as any).lastAutoTable.finalY + 20;

  // Footer on every page
  const pageCount = doc.getNumberOfPages();
  for (let i = 1; i <= pageCount; i++) {
    doc.setPage(i);
    doc.setFontSize(8);
    doc.setTextColor(148, 163, 184);
    doc.text(
      `MONITOR-THREAT v2.0  ·  Generated ${ts}  ·  Page ${i} of ${pageCount}`,
      pageWidth / 2, pageHeight - 22, { align: "center" }
    );
    doc.text("This report is for informational purposes only and does not constitute legal advice.", pageWidth / 2, pageHeight - 10, { align: "center" });
  }

  const fname = `MONITOR-THREAT-Domain-Intel-${d.domain.replace(/[^a-z0-9.-]/g, "_")}-${Date.now()}.pdf`;
  doc.save(fname);
}

// ---------- Domain Intel view ----------

export function DomainIntelView() {
  const [input, setInput] = React.useState("");
  const [loading, setLoading] = React.useState(false);
  const [data, setData] = React.useState<AggregateResult | null>(null);
  const [error, setError] = React.useState<string | null>(null);
  const abortRef = React.useRef<AbortController | null>(null);

  async function analyze(domain: string) {
    if (!domain.trim()) return;
    abortRef.current?.abort();
    const ac = new AbortController();
    abortRef.current = ac;
    setLoading(true);
    setError(null);
    try {
      const res = await fetch(
        `/api/domain-intel/aggregate?domain=${encodeURIComponent(domain.trim().toLowerCase())}`,
        { signal: ac.signal }
      );
      const json = await res.json();
      if (!res.ok) {
        setError(json?.error || `HTTP ${res.status}`);
        setData(null);
      } else {
        setData(json);
      }
    } catch (err: any) {
      if (err.name !== "AbortError") {
        setError(err.message || "Fetch failed");
        setData(null);
      }
    } finally {
      if (ac === abortRef.current) setLoading(false);
    }
  }

  return (
    <ModuleShell
      name="Domain Intel"
      description="WHOIS (RDAP), DNS records, subdomain enumeration, SSL Certificate Transparency, VirusTotal reputation, hosting detection, email infrastructure, domain blacklists — all in one report."
      icon={Globe}
      category="INFRASTRUCTURE"
      status={loading ? "QUERYING" : "READY"}
    >
      <div className="flex flex-col gap-2 mb-4">
        <label className="text-xs font-medium text-muted-foreground uppercase tracking-wider">
          Domain name
        </label>
        <div className="flex gap-2">
          <Input
            type="text"
            placeholder="e.g. example.com, google.com, suspicious-domain.xyz"
            className="flex-1 font-mono text-sm"
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && analyze(input)}
            autoFocus
          />
          <Button
            type="button"
            size="sm"
            onClick={() => analyze(input)}
            disabled={loading || !input.trim()}
          >
            {loading ? (
              <><Loader2 className="w-3.5 h-3.5 mr-2 animate-spin" />Analyzing…</>
            ) : (
              <><Search className="w-3.5 h-3.5 mr-2" />Analyze</>
            )}
          </Button>
          <Button
            type="button"
            size="sm"
            variant="outline"
            onClick={() => downloadPdfReport(data!)}
            disabled={!data}
            title={data ? "Download a structured PDF report" : "Run an analysis first"}
          >
            <Printer className="w-3.5 h-3.5 mr-2" />
            Imprimir informe PDF
          </Button>
        </div>
      </div>

      {error && (
        <div className="mb-4 p-3 rounded-md border border-red-500/40 bg-red-500/10 text-red-400 flex items-center gap-2">
          <AlertTriangle className="w-4 h-4 shrink-0" />
          <span className="text-sm">{error}</span>
        </div>
      )}

      {!data && !loading && (
        <div className="flex flex-col items-center justify-center min-h-[400px] text-center gap-3">
          <div className="w-16 h-16 rounded-full bg-muted/50 flex items-center justify-center">
            <Globe className="w-8 h-8 text-muted-foreground" />
          </div>
          <h2 className="text-lg font-semibold">Enter a domain to analyze</h2>
          <p className="text-sm text-muted-foreground max-w-md">
            Will fetch WHOIS / RDAP, DNS records, subdomain enumeration via CT logs,
            SSL Certificate Transparency, VirusTotal reputation, hosting & tech stack,
            email infrastructure, and domain blacklists — all in parallel.
          </p>
        </div>
      )}

      {data && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {/* 1. WHOIS */}
          <Panel title="1. WHOIS & Registration" action={
            data.whois?.rdapUrl ? (
              <a href={data.whois.rdapUrl} target="_blank" rel="noreferrer"
                className="text-xs text-cyan-500 hover:underline flex items-center gap-1">
                RDAP <ExternalLink className="w-3 h-3" />
              </a>
            ) : undefined
          }>
            {data.whois?.available ? (
              <>
                <FieldRow label="Domain" value={data.whois.domain} mono />
                <FieldRow label="Registrar" value={data.whois.registrar || "-"} />
                <FieldRow label="Registered" value={data.whois.registeredOn?.slice(0, 10) || "-"} mono />
                <FieldRow label="Domain age" value={data.whois.domainAgeDays !== undefined ? `${data.whois.domainAgeDays} days` : "-"} mono />
                <FieldRow label="Expires" value={data.whois.expiresOn?.slice(0, 10) || "-"} mono />
                <FieldRow label="Days until expiry" value={data.whois.daysUntilExpiry !== undefined ? `${data.whois.daysUntilExpiry} days` : "-"} mono />
                <FieldRow label="Last updated" value={data.whois.lastUpdated?.slice(0, 10) || "-"} mono />
                <FieldRow label="WHOIS privacy" value={data.whois.isRedacted ? "Yes (redacted)" : "No (visible)"} />
                <div className="pt-2">
                  <div className="text-xs text-muted-foreground mb-1">Status codes (EPP):</div>
                  <div className="flex flex-wrap gap-1">
                    {data.whois.statusCodes.map((s) => (
                      <Badge key={s} variant="outline" className="font-mono text-[10px]">{s}</Badge>
                    ))}
                  </div>
                </div>
                <div className="pt-2">
                  <div className="text-xs text-muted-foreground mb-1">Nameservers ({data.whois.nameservers.length}):</div>
                  <div className="flex flex-col gap-1">
                    {data.whois.nameservers.map((ns) => (
                      <span key={ns} className="font-mono text-xs px-2 py-1 rounded bg-muted/40">{ns}</span>
                    ))}
                  </div>
                </div>
              </>
            ) : (
              <p className="text-sm text-muted-foreground">WHOIS lookup failed: {data.whois?.error}</p>
            )}
          </Panel>

          {/* 2. DNS Records */}
          <Panel title="2. DNS Records">
            {data.dns?.available ? (
              <>
                <FieldRow label="A records" value={data.dns.records.A?.map((r) => r.data).join(", ") || "none"} mono />
                <FieldRow label="AAAA records" value={data.dns.records.AAAA?.map((r) => r.data).join(", ") || "none"} mono />
                <FieldRow label="MX records" value={`${data.dns.records.MX?.length || 0}`} mono />
                <FieldRow label="NS records" value={`${data.dns.records.NS?.length || 0}`} mono />
                <FieldRow label="TXT records" value={`${data.dns.records.TXT?.length || 0}`} mono />
                <FieldRow label="CNAME" value={data.dns.records.CNAME?.map((r) => r.data).join(", ") || "none"} mono />
                <FieldRow label="CAA" value={data.dns.records.CAA?.map((r) => r.data).join(", ") || "none"} mono />
                <FieldRow label="SOA" value={data.dns.records.SOA?.[0]?.data || "none"} mono />
                <FieldRow label="DNSSEC" value={data.dns.dnssec ? "✓ signed" : "✗ unsigned"} />
                <Separator />
                <div className="pt-2">
                  <div className="text-xs text-muted-foreground mb-1">NS list:</div>
                  <div className="flex flex-col gap-1">
                    {data.dns.records.NS?.map((ns) => (
                      <span key={ns.data} className="font-mono text-xs px-2 py-1 rounded bg-muted/40">{ns.data}</span>
                    ))}
                  </div>
                </div>
              </>
            ) : (
              <p className="text-sm text-muted-foreground">DNS lookup failed: {data.dns?.error}</p>
            )}
          </Panel>

          {/* 3. Subdomains */}
          <Panel
            title={`3. Subdomain Enumeration (${data.subdomains?.total || 0})`}
            className="md:col-span-2"
          >
            {data.subdomains?.available ? (
              <>
                <div className="grid grid-cols-2 md:grid-cols-4 gap-2 mb-3">
                  {[
                    { label: "Total", n: data.subdomains.total, cls: "border-border bg-muted/20" },
                    { label: "Active (resolve)", n: data.subdomains.active, cls: "border-emerald-500/40 bg-emerald-500/10 text-emerald-400" },
                    { label: "Historical", n: data.subdomains.historical, cls: "border-yellow-500/40 bg-yellow-500/10 text-yellow-400" },
                    { label: "Source", n: data.subdomains.crtShOk ? "crt.sh" : "hackertarget", cls: "border-blue-500/40 bg-blue-500/10 text-blue-400" },
                  ].map((b) => (
                    <div key={b.label} className={`rounded p-2 border ${b.cls}`}>
                      <div className="text-xl font-bold font-mono leading-none">{b.n}</div>
                      <div className="text-[10px] mt-0.5">{b.label}</div>
                    </div>
                  ))}
                </div>
                {data.subdomains.subdomains.length === 0 ? (
                  <p className="text-sm text-muted-foreground">No subdomains found.</p>
                ) : (
                  <div className="max-h-64 overflow-y-auto">
                    <Table>
                      <TableHeader>
                        <TableRow>
                          <TableHead>Subdomain</TableHead>
                          <TableHead className="w-24">Source</TableHead>
                          <TableHead className="w-24">Status</TableHead>
                          <TableHead>IP(s)</TableHead>
                        </TableRow>
                      </TableHeader>
                      <TableBody>
                        {data.subdomains.subdomains.slice(0, 50).map((s) => (
                          <TableRow key={s.name}>
                            <TableCell className="font-mono text-xs">{s.name}</TableCell>
                            <TableCell className="text-xs">{s.source}</TableCell>
                            <TableCell>
                              <Badge variant={s.resolves ? "secondary" : "outline"} className="text-[10px] font-mono">
                                {s.resolves ? "ACTIVE" : "HISTORICAL"}
                              </Badge>
                            </TableCell>
                            <TableCell className="font-mono text-xs text-muted-foreground">
                              {(s.ips || []).join(", ") || "-"}
                            </TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                    {data.subdomains.subdomains.length > 50 && (
                      <p className="text-[10px] text-muted-foreground mt-2">
                        Showing top 50 of {data.subdomains.subdomains.length}. See full list in the PDF report.
                      </p>
                    )}
                  </div>
                )}
              </>
            ) : (
              <p className="text-sm text-muted-foreground">Subdomain lookup failed: {data.subdomains?.error}</p>
            )}
          </Panel>

          {/* 4. SSL Certificates */}
          <Panel
            title={`4. SSL Certificates (${data.certs?.totalCerts || 0})`}
            className="md:col-span-2"
            action={
              <a href={`https://crt.sh/?q=${encodeURIComponent(data.domain)}`} target="_blank" rel="noreferrer"
                className="text-xs text-cyan-500 hover:underline flex items-center gap-1">
                crt.sh <ExternalLink className="w-3 h-3" />
              </a>
            }
          >
            {data.certs?.available ? (
              <>
                <div className="grid grid-cols-2 md:grid-cols-4 gap-2 mb-3">
                  {[
                    { label: "Total certs", n: data.certs.totalCerts, cls: "border-border bg-muted/20" },
                    { label: "Currently valid", n: data.certs.currentlyValidCerts, cls: "border-emerald-500/40 bg-emerald-500/10 text-emerald-400" },
                    { label: "Expired", n: data.certs.expiredCerts, cls: "border-zinc-500/40 bg-zinc-500/10 text-zinc-400" },
                    { label: "Wildcard", n: data.certs.wildcardCerts, cls: "border-orange-500/40 bg-orange-500/10 text-orange-400" },
                  ].map((b) => (
                    <div key={b.label} className={`rounded p-2 border ${b.cls}`}>
                      <div className="text-xl font-bold font-mono leading-none">{b.n}</div>
                      <div className="text-[10px] mt-0.5">{b.label}</div>
                    </div>
                  ))}
                </div>
                {data.certs.uniqueSanDomains.length > 0 && (
                  <div className="mb-3 p-2 rounded border border-purple-500/40 bg-purple-500/5">
                    <div className="text-xs text-purple-300 font-semibold mb-1 flex items-center gap-1">
                      <Fingerprint className="w-3 h-3" /> Pivot domains ({data.certs.uniqueSanDomains.length})
                    </div>
                    <div className="text-[10px] text-muted-foreground">
                      Other domains sharing the same certs as <code>{data.domain}</code> — same actor/owner likely.
                    </div>
                    <div className="mt-1 flex flex-wrap gap-1">
                      {data.certs.uniqueSanDomains.slice(0, 15).map((d2) => (
                        <a key={d2} href={`https://crt.sh/?q=${encodeURIComponent(d2)}`} target="_blank" rel="noreferrer"
                          className="font-mono text-[10px] px-2 py-0.5 rounded bg-purple-500/10 text-purple-300 hover:underline">
                          {d2}
                        </a>
                      ))}
                      {data.certs.uniqueSanDomains.length > 15 && (
                        <span className="text-[10px] text-muted-foreground">
                          +{data.certs.uniqueSanDomains.length - 15} more
                        </span>
                      )}
                    </div>
                  </div>
                )}
                {data.certs.certs.length > 0 && (
                  <div className="max-h-64 overflow-y-auto">
                    <Table>
                      <TableHeader>
                        <TableRow>
                          <TableHead>Issuer</TableHead>
                          <TableHead>Common Name</TableHead>
                          <TableHead className="w-24">Not before</TableHead>
                          <TableHead className="w-24">Not after</TableHead>
                          <TableHead className="w-20">Status</TableHead>
                        </TableRow>
                      </TableHeader>
                      <TableBody>
                        {data.certs.certs.slice(0, 15).map((c) => (
                          <TableRow key={c.id}>
                            <TableCell className="font-mono text-xs">{c.issuer.slice(0, 50)}…</TableCell>
                            <TableCell className="font-mono text-xs">{c.commonName}</TableCell>
                            <TableCell className="font-mono text-xs">{c.notBefore?.slice(0, 10)}</TableCell>
                            <TableCell className="font-mono text-xs">{c.notAfter?.slice(0, 10)}</TableCell>
                            <TableCell>
                              <Badge
                                variant={c.isCurrentlyValid ? "default" : c.isExpired ? "outline" : "secondary"}
                                className="text-[9px] font-mono"
                              >
                                {c.isCurrentlyValid ? "VALID" : c.isExpired ? "EXPIRED" : "?"}
                              </Badge>
                            </TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </div>
                )}
              </>
            ) : (
              <p className="text-sm text-muted-foreground">CT lookup failed: {data.certs?.error}</p>
            )}
          </Panel>

          {/* 5. Reputation — VirusTotal */}
          <Panel title="5. Reputation — VirusTotal" action={
            data.reputation?.available ? (
              <a href={`https://www.virustotal.com/gui/domain/${data.domain}`} target="_blank" rel="noreferrer"
                className="text-xs text-cyan-500 hover:underline flex items-center gap-1">
                VT report <ExternalLink className="w-3 h-3" />
              </a>
            ) : undefined
          }>
            {data.reputation?.available ? (
              <>
                <div className="flex items-center gap-3 mb-3">
                  <div className={`text-3xl font-mono font-bold ${
                    data.reputation.classification === "MALICIOUS" ? "text-red-500" :
                    data.reputation.classification === "SUSPICIOUS" ? "text-yellow-500" : "text-emerald-500"
                  }`}>
                    {data.reputation.flaggedEnginesCount}
                    <span className="text-base text-muted-foreground">/{data.reputation.totalEngines}</span>
                  </div>
                  <div>
                    <Badge
                      variant={data.reputation.classification === "MALICIOUS" ? "destructive" :
                        data.reputation.classification === "SUSPICIOUS" ? "default" : "secondary"}
                      className="font-mono text-xs"
                    >
                      {data.reputation.classification}
                    </Badge>
                    <div className="text-[10px] text-muted-foreground mt-1">
                      engines flag this domain
                    </div>
                  </div>
                </div>
                <Separator />
                <FieldRow label="Reputation" value={String(data.reputation.reputation)} mono />
                <FieldRow label="Community votes" value={`${data.reputation.totalVotes.harmless} harmless / ${data.reputation.totalVotes.malicious} malicious`} />
                <FieldRow label="Malicious" value={data.reputation.lastAnalysisStats.malicious} mono />
                <FieldRow label="Suspicious" value={data.reputation.lastAnalysisStats.suspicious} mono />
                <FieldRow label="Harmless" value={data.reputation.lastAnalysisStats.harmless} mono />
                <FieldRow label="Undetected" value={data.reputation.lastAnalysisStats.undetected} mono />
                {data.reputation.lastAnalysisDate && (
                  <FieldRow label="Last analysis" value={new Date(data.reputation.lastAnalysisDate).toLocaleString()} />
                )}
                {data.reputation.categories.length > 0 && (
                  <>
                    <Separator />
                    <div className="pt-2">
                      <div className="text-xs text-muted-foreground mb-1">Categorization:</div>
                      {data.reputation.categories.map((c) => (
                        <div key={c.source} className="text-xs">
                          <span className="font-mono text-muted-foreground">[{c.source}]</span> {c.category}
                        </div>
                      ))}
                    </div>
                  </>
                )}
                {data.reputation.flaggedEngines.length > 0 && (
                  <>
                    <Separator />
                    <div className="pt-2">
                      <div className="text-xs text-muted-foreground mb-1">Flagging engines:</div>
                      <div className="flex flex-col gap-1 max-h-32 overflow-y-auto">
                        {data.reputation.flaggedEngines.map((f) => (
                          <div key={f.engine} className="text-xs">
                            <span className="font-mono text-muted-foreground">[{f.engine}]</span>{" "}
                            <span className="text-red-400">{f.result}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  </>
                )}
              </>
            ) : (
              <p className="text-sm text-muted-foreground">VirusTotal not available: {data.reputation?.error}</p>
            )}
          </Panel>

          {/* 6. Hosting & Technologies */}
          <Panel title="6. Hosting & Technologies">
            {data.hosting?.available ? (
              <>
                <FieldRow label="IP address" value={data.hosting.ip || "-"} mono />
                {data.hosting.ip && (
                  <div className="mb-2 ml-auto">
                    <Button size="sm" variant="outline" asChild>
                      <a href={`https://monitor-threat.vercel.app/?ip=${data.hosting.ip}`} target="_blank" rel="noreferrer">
                        → Analyze this IP
                      </a>
                    </Button>
                  </div>
                )}
                <FieldRow label="Final URL" value={data.hosting.finalUrl || "-"} mono />
                <FieldRow label="HTTP status" value={String(data.hosting.httpStatus ?? "-")} mono />
                <FieldRow label="Response time" value={data.hosting.responseTimeMs ? `${data.hosting.responseTimeMs}ms` : "-"} mono />
                <FieldRow label="Web server" value={data.hosting.webServer || "-"} />
                <FieldRow label="X-Powered-By" value={data.hosting.poweredBy || "-"} />
                <FieldRow label="CDN" value={data.hosting.cdn || "none detected"} />
                {data.hosting.cdnEdge && <FieldRow label="CDN edge" value={data.hosting.cdnEdge} mono />}
                <FieldRow label="Page title" value={data.hosting.title || "-"} />
                <FieldRow label="Favicon hash" value={data.hosting.faviconHash || "-"} mono />
                <FieldRow label="Security headers" value={`${data.hosting.securityScore} / 6`} mono />
                {data.hosting.technologies.length > 0 && (
                  <>
                    <Separator />
                    <div className="pt-2">
                      <div className="text-xs text-muted-foreground mb-1">Detected technologies:</div>
                      <div className="flex flex-wrap gap-1">
                        {data.hosting.technologies.map((t, i) => (
                          <Badge key={i} variant="secondary" className="text-[10px] font-mono">
                            {t.name}
                          </Badge>
                        ))}
                      </div>
                    </div>
                  </>
                )}
              </>
            ) : (
              <p className="text-sm text-muted-foreground">Hosting lookup failed: {data.hosting?.error}</p>
            )}
          </Panel>

          {/* 7. Email Infrastructure */}
          <Panel title="7. Email Infrastructure">
            {data.email?.available ? (
              <>
                <FieldRow label="Email security score" value={`${data.email.emailSecurityScore} / 4`} mono />
                <FieldRow label="MX providers" value={data.email.mx.providers.join(", ") || "none"} />
                <FieldRow label="MX count" value={String(data.email.mx.count)} mono />
                <Separator />
                <div className="pt-2">
                  <div className="text-xs text-muted-foreground mb-2 flex items-center gap-1">
                    <Mail className="w-3 h-3" /> SPF / DKIM / DMARC
                  </div>
                  <FieldRow label="SPF" value={data.email.spf.present ? `Present (${data.email.spf.strength})` : "MISSING"} />
                  {data.email.spf.record && (
                    <div className="text-xs font-mono text-muted-foreground mt-1 break-all">{data.email.spf.record}</div>
                  )}
                  <FieldRow label="DKIM" value={data.email.dkim.present ? `Present (selector: ${data.email.dkim.selector})` : "MISSING"} />
                  <FieldRow label="DMARC" value={data.email.dmarc.present ? `Present (${data.email.dmarc.strength})` : "MISSING"} />
                  {data.email.dmarc.record && (
                    <div className="text-xs font-mono text-muted-foreground mt-1 break-all">{data.email.dmarc.record}</div>
                  )}
                  <FieldRow label="MTA-STS" value={data.email.mtaSts.present ? "Present" : "Missing"} />
                  <FieldRow label="BIMI" value={data.email.bimi ? "Present" : "Missing"} />
                </div>
                <Separator />
                <div className="pt-2 text-xs text-muted-foreground italic">
                  💡 {data.email.recommendation}
                </div>
              </>
            ) : (
              <p className="text-sm text-muted-foreground">Email lookup failed: {data.email?.error}</p>
            )}
          </Panel>

          {/* 8. Domain Blacklists */}
          <Panel title="8. Domain Blacklists">
            {data.blacklists?.available ? (
              <>
                <div className={`mb-3 p-2 rounded border ${
                  data.blacklists.isBlacklisted
                    ? "border-red-500/40 bg-red-500/10 text-red-400"
                    : "border-emerald-500/40 bg-emerald-500/10 text-emerald-400"
                }`}>
                  <div className="flex items-center gap-2">
                    {data.blacklists.isBlacklisted ? <AlertTriangle className="w-4 h-4" /> : <ShieldCheck className="w-4 h-4" />}
                    <span className="font-semibold">
                      {data.blacklists.isBlacklisted ? "LISTED" : "CLEAN"} — {data.blacklists.listedCount}/{data.blacklists.totalChecked} blacklists
                    </span>
                  </div>
                </div>
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Zone</TableHead>
                      <TableHead className="w-24">Listed</TableHead>
                      <TableHead>Reason</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {data.blacklists.entries.map((e) => (
                      <TableRow key={e.zone}>
                        <TableCell className="font-mono text-xs">{e.zone}</TableCell>
                        <TableCell>
                          <Badge
                            variant={e.listed ? "destructive" : "outline"}
                            className="text-[9px] font-mono"
                          >
                            {e.listed ? "YES" : "no"}
                          </Badge>
                        </TableCell>
                        <TableCell className="text-xs">{e.listed ? e.reason || "Listed" : "-"}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </>
            ) : (
              <p className="text-sm text-muted-foreground">Blacklist lookup failed: {data.blacklists?.error}</p>
            )}
          </Panel>

          {/* Footer */}
          <div className="md:col-span-2 text-[10px] text-muted-foreground font-mono">
            Query timestamp: {data.timestamp} · Powered by RDAP, Cloudflare DoH, crt.sh, Hackertarget, VirusTotal, DNSBL DNS (Spamhaus DBL, SURBL, URIBL).
          </div>
        </div>
      )}
    </ModuleShell>
  );
}
