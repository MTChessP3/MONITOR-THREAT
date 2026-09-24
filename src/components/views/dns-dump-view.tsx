"use client";

import * as React from "react";
import {
  Server,
  Loader2,
  AlertTriangle,
  Printer,
  Search,
  ShieldCheck,
  Mail,
  Network,
  ExternalLink,
  ShieldAlert,
} from "lucide-react";
import { jsPDF } from "jspdf";
import autoTable from "jspdf-autotable";

import {
  ModuleShell,
  Panel,
  FieldRow,
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

// ---------- Types ----------

interface DnsRecord { type: string; name: string; ttl: number; data: string }

interface AggregateResult {
  domain: string;
  records: {
    available: boolean;
    records: Record<string, DnsRecord[]>;
    recordCounts: Record<string, number>;
    totalRecords: number;
    soa?: { mname?: string; rname?: string; serial?: number; refresh?: number; retry?: number; expire?: number; minimum?: number };
  };
  dnssec: {
    available: boolean;
    signed: boolean;
    dnskeyRecords: Array<{ name: string; ttl: number; data: string; algorithm?: number }>;
    dsRecords: Array<{ name: string; ttl: number; data: string; keyTag?: number; algorithm?: number; digestType?: number }>;
    denialType: string;
    algorithms: string[];
    chainValid: boolean;
  };
  emailInfra: {
    available: boolean;
    spf: { present: boolean; record?: string; strength: string; mechanisms: string[]; totalLookups: number; exceedsRfcLimit: boolean; circularIncludes: boolean; nestedTree?: any };
    dkim: { present: boolean; selector?: string; record?: string; keyType?: string; keySize?: number };
    dmarc: { present: boolean; record?: string; policy: string; strength: string; pct?: number; rua?: string; ruf?: string };
    mtaSts: { present: boolean; record?: string; id?: string };
    bimi: { present: boolean; record?: string };
    tlsRpt: { present: boolean; record?: string; rua?: string };
    mxProvider: string | null;
    emailSecurityScore: number;
    recommendation: string;
  };
  subdomains: {
    available: boolean;
    totalChecked: number;
    totalFound: number;
    takeoverVulnerable: number;
    subdomains: Array<{ name: string; resolves: boolean; recordType: string; data: string; takeoverVulnerable: boolean; takeoverService?: string }>;
  };
  axfr: {
    available: boolean;
    nameservers: string[];
    attempts: Array<{ ns: string; success: boolean; recordCount: number; error?: string }>;
    anySuccess: boolean;
    totalRecords: number;
  };
  passiveDns: {
    available: boolean;
    totalResolutions: number;
    resolutions: Array<{ date: string; ip: string; type: string }>;
    uniqueIps: string[];
    firstSeen?: string;
    lastSeen?: string;
  };
  crossResolver: {
    available: boolean;
    results: Array<{ name: string; ips: string[]; status: number; responseTimeMs: number; error?: string }>;
    allAgree: boolean;
    splitHorizon: boolean;
  };
  timestamp: string;
}

// ---------- PDF ----------

function downloadPdf(d: AggregateResult) {
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
  doc.text("DNS Dump Report", margin, y + 8);
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

  // 1. DNS Records
  sectionHeading("1. DNS Records — All Types");
  const r = d.records;
  if (r.available) {
    kvTable([
      ["Total records", String(r.totalRecords)],
      ["A records", String(r.recordCounts.A || 0)],
      ["AAAA records", String(r.recordCounts.AAAA || 0)],
      ["MX records", String(r.recordCounts.MX || 0)],
      ["NS records", String(r.recordCounts.NS || 0)],
      ["TXT records", String(r.recordCounts.TXT || 0)],
      ["CNAME", String(r.recordCounts.CNAME || 0)],
      ["SOA", String(r.recordCounts.SOA || 0)],
      ["SRV", String(r.recordCounts.SRV || 0)],
      ["CAA", String(r.recordCounts.CAA || 0)],
      ["DNSKEY", String(r.recordCounts.DNSKEY || 0)],
      ["DS", String(r.recordCounts.DS || 0)],
      ["TLSA", String(r.recordCounts.TLSA || 0)],
      ["SSHFP", String(r.recordCounts.SSHFP || 0)],
      ["NAPTR", String(r.recordCounts.NAPTR || 0)],
    ]);
    if (r.soa) {
      kvTable([
        ["SOA mname", r.soa.mname || "-"],
        ["SOA rname", r.soa.rname || "-"],
        ["SOA serial", String(r.soa.serial || "-")],
        ["SOA refresh", r.soa.refresh ? `${r.soa.refresh}s` : "-"],
        ["SOA retry", r.soa.retry ? `${r.soa.retry}s` : "-"],
        ["SOA expire", r.soa.expire ? `${r.soa.expire}s` : "-"],
        ["SOA minimum", r.soa.minimum ? `${r.soa.minimum}s` : "-"],
      ]);
    }
    // Record details table
    const allRecords: Array<[string, string, string, string]> = [];
    for (const [type, recs] of Object.entries(r.records)) {
      for (const rec of recs) {
        allRecords.push([type, rec.name, rec.data.slice(0, 200), `${rec.ttl}s`]);
      }
    }
    if (allRecords.length > 0) {
      autoTable(doc, {
        startY: y, head: [["Type", "Name", "Data", "TTL"]],
        body: allRecords.slice(0, 50),
        theme: "grid", margin: { left: margin, right: margin },
        styles: { fontSize: 8, cellPadding: 4, textColor: [30, 41, 59], lineColor: [226, 232, 240], lineWidth: 0.5 },
        headStyles: { fillColor: [241, 245, 249], textColor: [71, 85, 105], fontStyle: "bold", fontSize: 10 },
        columnStyles: { 0: { cellWidth: 60 }, 1: { cellWidth: 130 }, 3: { cellWidth: 40 } },
      });
      // @ts-ignore
      y = (doc as any).lastAutoTable.finalY + 18;
    }
  }

  // 2. DNSSEC
  sectionHeading("2. DNSSEC Analysis");
  const ds = d.dnssec;
  if (ds.available) {
    kvTable([
      ["DNSSEC signed", ds.signed ? "Yes" : "No"],
      ["Chain valid", ds.chainValid ? "Yes" : "No"],
      ["Denial type", ds.denialType],
      ["Algorithms", ds.algorithms.join(", ") || "-"],
      ["DNSKEY records", String(ds.dnskeyRecords.length)],
      ["DS records", String(ds.dsRecords.length)],
      ["NSEC records", String(ds.nsecRecords || 0)],
      ["NSEC3 records", String(ds.nsec3Records || 0)],
    ]);
  }

  // 3. Email Infrastructure
  sectionHeading("3. Email Infrastructure");
  const e = d.emailInfra;
  if (e.available) {
    kvTable([
      ["Email security score", `${e.emailSecurityScore} / 5`],
      ["MX provider", e.mxProvider || "Unknown"],
      ["SPF present", e.spf.present ? `Yes (${e.spf.strength})` : "No"],
      ["SPF lookups", `${e.spf.totalLookups}${e.spf.exceedsRfcLimit ? " (EXCEEDS RFC 7208 LIMIT!)" : ""}`],
      ["SPF circular", e.spf.circularIncludes ? "YES — SPF is broken" : "No"],
      ["DKIM present", e.dkim.present ? `Yes (selector: ${e.dkim.selector}, key type: ${e.dkim.keyType})` : "No"],
      ["DMARC present", e.dmarc.present ? `Yes (policy: ${e.dmarc.policy}, strength: ${e.dmarc.strength})` : "No"],
      ["DMARC rua", e.dmarc.rua || "-"],
      ["MTA-STS", e.mtaSts.present ? "Yes" : "No"],
      ["BIMI", e.bimi.present ? "Yes" : "No"],
      ["TLSRPT", e.tlsRpt.present ? "Yes" : "No"],
      ["Recommendation", e.recommendation],
    ]);
    if (e.spf.record) {
      doc.setFontSize(8);
      doc.setFont("helvetica", "normal");
      doc.setTextColor(100, 116, 139);
      doc.text(doc.splitTextToSize(`SPF record: ${e.spf.record}`, contentWidth), margin, y);
      y += 16;
    }
    if (e.dmarc.record) {
      doc.text(doc.splitTextToSize(`DMARC record: ${e.dmarc.record}`, contentWidth), margin, y);
      y += 16;
    }
  }

  // 4. Subdomain Brute-force
  sectionHeading("4. Subdomain Brute-force + Takeover Check");
  const sub = d.subdomains;
  if (sub.available) {
    kvTable([
      ["Total checked", String(sub.totalChecked)],
      ["Total found", String(sub.totalFound)],
      ["Takeover vulnerable", sub.takeoverVulnerable > 0 ? `${sub.takeoverVulnerable} (CRITICAL!)` : "0"],
    ]);
    if (sub.subdomains.length > 0) {
      autoTable(doc, {
        startY: y, head: [["Subdomain", "Type", "Data", "Takeover"]],
        body: sub.subdomains.slice(0, 30).map((s) => [
          s.name, s.recordType, s.data.slice(0, 80),
          s.takeoverVulnerable ? `YES — ${s.takeoverService || ""}` : "no",
        ]),
        theme: "grid", margin: { left: margin, right: margin },
        styles: { fontSize: 8, cellPadding: 4, textColor: [30, 41, 59], lineColor: [226, 232, 240], lineWidth: 0.5 },
        headStyles: { fillColor: [241, 245, 249], textColor: [71, 85, 105], fontStyle: "bold", fontSize: 10 },
        columnStyles: { 0: { cellWidth: 160 }, 1: { cellWidth: 50 } },
      });
      // @ts-ignore
      y = (doc as any).lastAutoTable.finalY + 18;
    }
  }

  // 5. AXFR Zone Transfer
  sectionHeading("5. AXFR Zone Transfer Attempt");
  const ax = d.axfr;
  if (ax.available) {
    kvTable([
      ["Nameservers", ax.nameservers.join(", ") || "-"],
      ["Any success", ax.anySuccess ? "YES — ZONE TRANSFER ALLOWED (CRITICAL!)" : "No (all denied)"],
      ["Total records obtained", String(ax.totalRecords)],
    ]);
    autoTable(doc, {
      startY: y, head: [["NS", "Success", "Records", "Error/Message"]],
      body: ax.attempts.map((a) => [a.ns, a.success ? "YES" : "no", String(a.recordCount), a.error || "-"]),
      theme: "grid", margin: { left: margin, right: margin },
      styles: { fontSize: 9, cellPadding: 5, textColor: [30, 41, 59], lineColor: [226, 232, 240], lineWidth: 0.5 },
      headStyles: { fillColor: [241, 245, 249], textColor: [71, 85, 105], fontStyle: "bold", fontSize: 10 },
    });
    // @ts-ignore
    y = (doc as any).lastAutoTable.finalY + 18;
  }

  // 6. Passive DNS History
  sectionHeading("6. Passive DNS History (VirusTotal)");
  const pdns = d.passiveDns;
  if (pdns.available) {
    kvTable([
      ["Total resolutions", String(pdns.totalResolutions)],
      ["Unique IPs", String(pdns.uniqueIps.length)],
      ["First seen", pdns.firstSeen || "-"],
      ["Last seen", pdns.lastSeen || "-"],
    ]);
    if (pdns.resolutions.length > 0) {
      autoTable(doc, {
        startY: y, head: [["Date", "IP", "Type"]],
        body: pdns.resolutions.slice(0, 20).map((r) => [r.date, r.ip, r.type]),
        theme: "grid", margin: { left: margin, right: margin },
        styles: { fontSize: 9, cellPadding: 5, textColor: [30, 41, 59], lineColor: [226, 232, 240], lineWidth: 0.5 },
        headStyles: { fillColor: [241, 245, 249], textColor: [71, 85, 105], fontStyle: "bold", fontSize: 10 },
        columnStyles: { 2: { cellWidth: 50 } },
      });
      // @ts-ignore
      y = (doc as any).lastAutoTable.finalY + 18;
    }
  } else {
    doc.setTextColor(148, 163, 184);
    doc.text(`Passive DNS: ${pdns.error || "not available"}`, margin, y);
    y += 18;
  }

  // 7. Cross-Resolver Comparison
  sectionHeading("7. Cross-Resolver Comparison");
  const cr = d.crossResolver;
  if (cr.available) {
    kvTable([
      ["All agree", cr.allAgree ? "Yes — same IPs across all resolvers" : "No — different IPs detected"],
      ["Split-horizon DNS", cr.splitHorizon ? "YES — possible split-horizon DNS" : "No"],
    ]);
    autoTable(doc, {
      startY: y, head: [["Resolver", "IPs", "Status", "Response Time"]],
      body: cr.results.map((r) => [r.name, r.ips.join(", ") || "-", String(r.status), `${r.responseTimeMs}ms`]),
      theme: "grid", margin: { left: margin, right: margin },
      styles: { fontSize: 9, cellPadding: 5, textColor: [30, 41, 59], lineColor: [226, 232, 240], lineWidth: 0.5 },
      headStyles: { fillColor: [241, 245, 249], textColor: [71, 85, 105], fontStyle: "bold", fontSize: 10 },
      columnStyles: { 0: { cellWidth: 100 }, 3: { cellWidth: 100 } },
    });
    // @ts-ignore
    y = (doc as any).lastAutoTable.finalY + 18;
  }

  // 8. Methodology
  sectionHeading("8. Methodology & Sources");
  autoTable(doc, {
    startY: y, head: [["Source", "Use"]],
    body: [
      ["Cloudflare DoH (1.1.1.1)", "DNS records: A, AAAA, MX, NS, TXT, CNAME, SOA, SRV, CAA, DNSKEY, DS, TLSA, SSHFP, NAPTR, etc."],
      ["DNSSEC analysis", "DS + DNSKEY + NSEC/NSEC3 records, chain validation, algorithm detection"],
      ["Email infra", "SPF (nested resolution), DKIM (15+ selectors), DMARC, MTA-STS, BIMI, TLSRPT"],
      ["Subdomain brute-force", "200 common subdomain names + takeover check for cloud CNAMEs"],
      ["AXFR attempt", "TCP AXFR query to each nameserver — checks for zone transfer misconfiguration"],
      ["VirusTotal v3", "Passive DNS history — all historical IP resolutions"],
      ["Cross-resolver", "Compare A records across Cloudflare, Google, Quad9, OpenDNS — detect split-horizon DNS"],
    ],
    theme: "grid", margin: { left: margin, right: margin },
    styles: { fontSize: 9, cellPadding: 5, textColor: [30, 41, 59], lineColor: [226, 232, 240], lineWidth: 0.5 },
    headStyles: { fillColor: [241, 245, 249], textColor: [71, 85, 105], fontStyle: "bold", fontSize: 10 },
    columnStyles: { 0: { cellWidth: 150, fontStyle: "bold" } },
  });

  // Footer
  const pageCount = doc.getNumberOfPages();
  for (let i = 1; i <= pageCount; i++) {
    doc.setPage(i);
    doc.setFontSize(8);
    doc.setTextColor(148, 163, 184);
    doc.text(`MONITOR-THREAT v2.0  ·  Generated ${ts}  ·  Page ${i} of ${pageCount}`, pageWidth / 2, pageHeight - 22, { align: "center" });
    doc.text("This report is for informational purposes only and does not constitute legal advice.", pageWidth / 2, pageHeight - 10, { align: "center" });
  }

  const fname = `MONITOR-THREAT-DNS-Dump-${d.domain.replace(/[^a-z0-9.-]/g, "_")}-${Date.now()}.pdf`;
  doc.save(fname);
}

// ---------- View ----------

export function DnsDumpView() {
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
      const res = await fetch(`/api/dns-dump/aggregate?domain=${encodeURIComponent(domain.trim().toLowerCase())}`, { signal: ac.signal });
      const json = await res.json();
      if (!res.ok) { setError(json?.error || `HTTP ${res.status}`); setData(null); }
      else { setData(json); }
    } catch (err: any) {
      if (err.name !== "AbortError") { setError(err.message || "Fetch failed"); setData(null); }
    } finally {
      if (ac === abortRef.current) setLoading(false);
    }
  }

  return (
    <ModuleShell
      name="DNS Dump"
      description="Complete DNS dump: all record types, DNSSEC analysis, email infra (SPF/DKIM/DMARC/MTA-STS/BIMI/TLSRPT), subdomain brute-force + takeover check, AXFR zone transfer attempt, passive DNS history (VirusTotal), cross-resolver comparison."
      icon={Server}
      category="INFRASTRUCTURE"
      status={loading ? "QUERYING" : "READY"}
    >
      <div className="flex flex-col gap-2 mb-4">
        <label className="text-xs font-medium text-muted-foreground uppercase tracking-wider">Domain name</label>
        <div className="flex gap-2">
          <Input
            type="text"
            placeholder="e.g. example.com, google.com"
            className="flex-1 font-mono text-sm"
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && analyze(input)}
            autoFocus
          />
          <Button type="button" size="sm" onClick={() => analyze(input)} disabled={loading || !input.trim()}>
            {loading ? <><Loader2 className="w-3.5 h-3.5 mr-2 animate-spin" />Analyzing…</> : <><Search className="w-3.5 h-3.5 mr-2" />Analyze</>}
          </Button>
          <Button type="button" size="sm" variant="outline" onClick={() => downloadPdf(data!)} disabled={!data}
            title={data ? "Download PDF report" : "Run analysis first"}>
            <Printer className="w-3.5 h-3.5 mr-2" />Imprimir informe PDF
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
            <Server className="w-8 h-8 text-muted-foreground" />
          </div>
          <h2 className="text-lg font-semibold">Enter a domain to dump</h2>
          <p className="text-sm text-muted-foreground max-w-md">
            Will fetch all DNS record types, DNSSEC analysis, email infrastructure (SPF/DKIM/DMARC/MTA-STS/BIMI/TLSRPT),
            subdomain brute-force + takeover check, AXFR zone transfer attempt, passive DNS history, and cross-resolver comparison.
          </p>
        </div>
      )}

      {data && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {/* 1. DNS Records */}
          <Panel title="1. DNS Records" className="md:col-span-2">
            {data.records?.available ? (
              <>
                <div className="grid grid-cols-3 md:grid-cols-6 gap-2 mb-3">
                  {Object.entries(data.records.recordCounts).filter(([, n]) => n > 0).map(([type, n]) => (
                    <div key={type} className="rounded p-2 border border-border bg-muted/20">
                      <div className="text-xl font-bold font-mono leading-none">{n}</div>
                      <div className="text-[10px] mt-0.5">{type}</div>
                    </div>
                  ))}
                </div>
                <div className="max-h-64 overflow-y-auto">
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <TableHead className="w-16">Type</TableHead>
                        <TableHead className="w-48">Name</TableHead>
                        <TableHead>Data</TableHead>
                        <TableHead className="w-20">TTL</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {Object.entries(data.records.records).flatMap(([type, recs]) =>
                        recs.map((rec, i) => (
                          <TableRow key={`${type}-${i}`}>
                            <TableCell><Badge variant="outline" className="font-mono text-[10px]">{type}</Badge></TableCell>
                            <TableCell className="font-mono text-xs">{rec.name}</TableCell>
                            <TableCell className="font-mono text-xs break-all">{rec.data.slice(0, 120)}</TableCell>
                            <TableCell className="font-mono text-xs">{rec.ttl}s</TableCell>
                          </TableRow>
                        ))
                      )}
                    </TableBody>
                  </Table>
                </div>
                {data.records.soa && (
                  <>
                    <Separator />
                    <div className="pt-2">
                      <div className="text-xs font-semibold text-muted-foreground mb-1">SOA details:</div>
                      <div className="flex flex-wrap gap-4 text-xs">
                        {data.records.soa.serial && <span>Serial: <code className="font-mono">{data.records.soa.serial}</code></span>}
                        {data.records.soa.mname && <span>mname: <code className="font-mono">{data.records.soa.mname}</code></span>}
                      </div>
                    </div>
                  </>
                )}
              </>
            ) : (
              <p className="text-sm text-muted-foreground">DNS lookup failed: {data.records?.error}</p>
            )}
          </Panel>

          {/* 2. DNSSEC */}
          <Panel title="2. DNSSEC Analysis">
            {data.dnssec?.available ? (
              <>
                <div className={`p-3 rounded border mb-3 ${data.dnssec.signed ? "border-emerald-500/40 bg-emerald-500/10 text-emerald-400" : "border-zinc-500/40 bg-zinc-500/10 text-zinc-400"}`}>
                  <div className="flex items-center gap-2">
                    {data.dnssec.signed ? <ShieldCheck className="w-5 h-5" /> : <ShieldAlert className="w-5 h-5" />}
                    <span className="font-semibold">
                      {data.dnssec.signed ? "DNSSEC Signed" : "DNSSEC Unsigned"}
                    </span>
                  </div>
                </div>
                <FieldRow label="Chain valid" value={data.dnssec.chainValid ? "Yes" : "No"} />
                <FieldRow label="Denial type" value={data.dnssec.denialType} />
                <FieldRow label="Algorithms" value={data.dnssec.algorithms.join(", ") || "-"} />
                <FieldRow label="DNSKEY records" value={String(data.dnssec.dnskeyRecords.length)} mono />
                <FieldRow label="DS records" value={String(data.dnssec.dsRecords.length)} mono />
              </>
            ) : (
              <p className="text-sm text-muted-foreground">DNSSEC lookup failed: {data.dnssec?.error}</p>
            )}
          </Panel>

          {/* 3. Email Infrastructure */}
          <Panel title="3. Email Infrastructure">
            {data.emailInfra?.available ? (
              <>
                <div className="flex items-center gap-3 mb-3">
                  <div className={`text-3xl font-mono font-bold ${
                    data.emailInfra.emailSecurityScore >= 4 ? "text-emerald-500" :
                    data.emailInfra.emailSecurityScore >= 2 ? "text-yellow-500" : "text-red-500"
                  }`}>
                    {data.emailInfra.emailSecurityScore}
                    <span className="text-base text-muted-foreground">/5</span>
                  </div>
                  <div>
                    <Badge variant={data.emailInfra.emailSecurityScore >= 4 ? "default" : data.emailInfra.emailSecurityScore >= 2 ? "secondary" : "destructive"} className="font-mono text-xs">
                      {data.emailInfra.emailSecurityScore >= 4 ? "STRONG" : data.emailInfra.emailSecurityScore >= 2 ? "MODERATE" : "WEAK"}
                    </Badge>
                    <div className="text-[10px] text-muted-foreground mt-1">email security score</div>
                  </div>
                </div>
                <FieldRow label="MX provider" value={data.emailInfra.mxProvider || "Unknown"} />
                <Separator />
                <FieldRow label="SPF" value={data.emailInfra.spf.present ? `${data.emailInfra.spf.strength} (${data.emailInfra.spf.totalLookups} lookups)` : "MISSING"} />
                {data.emailInfra.spf.exceedsRfcLimit && (
                  <div className="text-xs text-red-500 font-semibold mt-1">⚠ Exceeds RFC 7208 limit (10 lookups)!</div>
                )}
                {data.emailInfra.spf.circularIncludes && (
                  <div className="text-xs text-red-500 font-semibold mt-1">⚠ Circular SPF include detected!</div>
                )}
                <FieldRow label="DKIM" value={data.emailInfra.dkim.present ? `Present (${data.emailInfra.dkim.selector})` : "Missing"} />
                <FieldRow label="DMARC" value={data.emailInfra.dmarc.present ? `${data.emailInfra.dmarc.policy} (${data.emailInfra.dmarc.strength})` : "Missing"} />
                <FieldRow label="MTA-STS" value={data.emailInfra.mtaSts.present ? "Present" : "Missing"} />
                <FieldRow label="BIMI" value={data.emailInfra.bimi.present ? "Present" : "Missing"} />
                <FieldRow label="TLSRPT" value={data.emailInfra.tlsRpt.present ? "Present" : "Missing"} />
                <Separator />
                <div className="text-xs text-muted-foreground italic pt-1">{data.emailInfra.recommendation}</div>
              </>
            ) : (
              <p className="text-sm text-muted-foreground">Email infra lookup failed: {data.emailInfra?.error}</p>
            )}
          </Panel>

          {/* 4. Subdomains */}
          <Panel title={`4. Subdomain Brute-force (${data.subdomains?.totalFound || 0} found)`} className="md:col-span-2">
            {data.subdomains?.available ? (
              <>
                <div className="grid grid-cols-3 gap-2 mb-3">
                  <div className="rounded p-2 border border-border bg-muted/20">
                    <div className="text-xl font-bold font-mono">{data.subdomains.totalChecked}</div>
                    <div className="text-[10px]">checked</div>
                  </div>
                  <div className="rounded p-2 border border-emerald-500/40 bg-emerald-500/10 text-emerald-400">
                    <div className="text-xl font-bold font-mono">{data.subdomains.totalFound}</div>
                    <div className="text-[10px]">found</div>
                  </div>
                  <div className={`rounded p-2 border ${data.subdomains.takeoverVulnerable > 0 ? "border-red-500/40 bg-red-500/10 text-red-400" : "border-border bg-muted/20"}`}>
                    <div className="text-xl font-bold font-mono">{data.subdomains.takeoverVulnerable}</div>
                    <div className="text-[10px]">takeover vulnerable</div>
                  </div>
                </div>
                {data.subdomains.takeoverVulnerable > 0 && (
                  <div className="mb-3 p-2 rounded border border-red-500/40 bg-red-500/10 text-red-400 text-xs flex items-center gap-2">
                    <ShieldAlert className="w-4 h-4" />
                    <span>{data.subdomains.takeoverVulnerable} subdomain(s) vulnerable to takeover!</span>
                  </div>
                )}
                {data.subdomains.subdomains.length > 0 ? (
                  <div className="max-h-64 overflow-y-auto">
                    <Table>
                      <TableHeader>
                        <TableRow>
                          <TableHead>Subdomain</TableHead>
                          <TableHead className="w-20">Type</TableHead>
                          <TableHead>Data</TableHead>
                          <TableHead className="w-24">Takeover</TableHead>
                        </TableRow>
                      </TableHeader>
                      <TableBody>
                        {data.subdomains.subdomains.map((s, i) => (
                          <TableRow key={i}>
                            <TableCell className="font-mono text-xs">{s.name}</TableCell>
                            <TableCell><Badge variant="outline" className="font-mono text-[10px]">{s.recordType}</Badge></TableCell>
                            <TableCell className="font-mono text-xs break-all">{s.data.slice(0, 80)}</TableCell>
                            <TableCell>
                              {s.takeoverVulnerable ? (
                                <Badge variant="destructive" className="text-[9px] font-mono">VULNERABLE</Badge>
                              ) : (
                                <span className="text-xs text-muted-foreground">no</span>
                              )}
                            </TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </div>
                ) : (
                  <p className="text-sm text-muted-foreground">No subdomains found from the 200 common names list.</p>
                )}
              </>
            ) : (
              <p className="text-sm text-muted-foreground">Subdomain lookup failed: {data.subdomains?.error}</p>
            )}
          </Panel>

          {/* 5. AXFR */}
          <Panel title="5. AXFR Zone Transfer Attempt">
            {data.axfr?.available ? (
              <>
                <div className={`p-3 rounded border mb-3 ${data.axfr.anySuccess ? "border-red-500/40 bg-red-500/10 text-red-400" : "border-emerald-500/40 bg-emerald-500/10 text-emerald-400"}`}>
                  <div className="flex items-center gap-2">
                    {data.axfr.anySuccess ? <ShieldAlert className="w-5 h-5" /> : <ShieldCheck className="w-5 h-5" />}
                    <span className="font-semibold">
                      {data.axfr.anySuccess ? "ZONE TRANSFER ALLOWED — CRITICAL!" : "Zone transfer denied (good)"}
                    </span>
                  </div>
                </div>
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Nameserver</TableHead>
                      <TableHead className="w-24">Result</TableHead>
                      <TableHead>Message</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {data.axfr.attempts.map((a, i) => (
                      <TableRow key={i}>
                        <TableCell className="font-mono text-xs">{a.ns}</TableCell>
                        <TableCell>
                          <Badge variant={a.success ? "destructive" : "secondary"} className="text-[10px] font-mono">
                            {a.success ? "ALLOWED" : "denied"}
                          </Badge>
                        </TableCell>
                        <TableCell className="text-xs text-muted-foreground">{a.error || "-"}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </>
            ) : (
              <p className="text-sm text-muted-foreground">AXFR lookup failed: {data.axfr?.error}</p>
            )}
          </Panel>

          {/* 6. Passive DNS */}
          <Panel title="6. Passive DNS History (VirusTotal)">
            {data.passiveDns?.available ? (
              <>
                <div className="grid grid-cols-2 gap-2 mb-3">
                  <div className="rounded p-2 border border-border bg-muted/20">
                    <div className="text-xl font-bold font-mono">{data.passiveDns.totalResolutions}</div>
                    <div className="text-[10px]">resolutions</div>
                  </div>
                  <div className="rounded p-2 border border-border bg-muted/20">
                    <div className="text-xl font-bold font-mono">{data.passiveDns.uniqueIps.length}</div>
                    <div className="text-[10px]">unique IPs</div>
                  </div>
                </div>
                {data.passiveDns.firstSeen && <FieldRow label="First seen" value={data.passiveDns.firstSeen.slice(0, 10)} mono />}
                {data.passiveDns.lastSeen && <FieldRow label="Last seen" value={data.passiveDns.lastSeen.slice(0, 10)} mono />}
                <Separator />
                <div className="pt-2 max-h-32 overflow-y-auto">
                  {data.passiveDns.resolutions.slice(0, 10).map((r, i) => (
                    <div key={i} className="text-xs flex justify-between py-1 border-b border-border/30">
                      <span className="font-mono">{r.ip}</span>
                      <span className="text-muted-foreground">{r.date.slice(0, 10)}</span>
                    </div>
                  ))}
                </div>
              </>
            ) : (
              <p className="text-sm text-muted-foreground">Passive DNS: {data.passiveDns?.error || "not available"}</p>
            )}
          </Panel>

          {/* 7. Cross-Resolver */}
          <Panel title="7. Cross-Resolver Comparison" className="md:col-span-2">
            {data.crossResolver?.available ? (
              <>
                <div className={`p-2 rounded border mb-3 ${data.crossResolver.splitHorizon ? "border-yellow-500/40 bg-yellow-500/10 text-yellow-400" : "border-emerald-500/40 bg-emerald-500/10 text-emerald-400"}`}>
                  <span className="font-semibold">
                    {data.crossResolver.splitHorizon ? "⚠ Split-horizon DNS detected — resolvers return different IPs" : "✓ All resolvers agree"}
                  </span>
                </div>
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Resolver</TableHead>
                      <TableHead>IPs</TableHead>
                      <TableHead className="w-20">Status</TableHead>
                      <TableHead className="w-24">Response</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {data.crossResolver.results.map((r, i) => (
                      <TableRow key={i}>
                        <TableCell className="font-semibold">{r.name}</TableCell>
                        <TableCell className="font-mono text-xs">{r.ips.join(", ") || "(none)"}</TableCell>
                        <TableCell className="font-mono text-xs">{r.status}</TableCell>
                        <TableCell className="font-mono text-xs">{r.responseTimeMs}ms</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </>
            ) : (
              <p className="text-sm text-muted-foreground">Cross-resolver lookup failed: {data.crossResolver?.error}</p>
            )}
          </Panel>

          <div className="md:col-span-2 text-[10px] text-muted-foreground font-mono">
            Query timestamp: {data.timestamp} · Powered by Cloudflare DoH, DNSSEC, VirusTotal passive DNS, 4-resolver cross-check.
          </div>
        </div>
      )}
    </ModuleShell>
  );
}
