"use client";

import * as React from "react";
import {
  Search,
  Loader2,
  AlertTriangle,
  Download,
  Printer,
  FolderArchive,
  Globe,
  Server,
  FileText,
  Fingerprint,
  ExternalLink,
  ShieldAlert,
  ChevronDown,
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

interface HttpHeaderEntry { name: string; value: string }

interface FuzzingResultEntry {
  path: string;
  status: number;
  contentType?: string;
  contentLength?: number;
  server?: string;
  interesting: boolean;
  redirectedTo?: string;
}

interface Attribution {
  googleAnalyticsIds: string[];
  googleAnalytics4Ids: string[];
  metaPixelIds: string[];
  facebookAppIds: string[];
  yandexMetricaIds: string[];
  hotjarIds: string[];
  sentryDsn: string[];
  githubLinks: string[];
  emails: string[];
  phones: string[];
  bitcoinAddresses: string[];
  ethereumAddresses: string[];
  litecoinAddresses: string[];
  htmlComments: string[];
  imageExif: Array<{ url: string; hasGps: boolean; camera?: string; software?: string; date?: string; gpsLat?: string; gpsLon?: string }>;
  techFingerprints: string[];
}

interface ForensicsResult {
  url: string;
  domain: string;
  timestamp: string;
  crawl: {
    pages: number;
    robotsTxt: boolean;
    sitemapXml: boolean;
    errors: string[];
  };
  headers: HttpHeaderEntry[];
  fuzzing: {
    totalProbed: number;
    discovered: number;
    interesting: number;
    redirects: number;
    errors: number;
    interestingPaths: FuzzingResultEntry[];
    discoveredPaths: FuzzingResultEntry[];
  };
  attribution: Attribution;
  findings: string;
  zipBase64: string;
  zipFilename: string;
}

// ---------- Download helpers ----------

function downloadZip(data: ForensicsResult) {
  const bin = atob(data.zipBase64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  const blob = new Blob([bytes], { type: "application/zip" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = data.zipFilename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

// ---------- PDF generator ----------

function downloadPdf(data: ForensicsResult) {
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
  doc.text("Domain Forensics Report", margin, y + 8);
  doc.setFont("helvetica", "normal");
  doc.setFontSize(11);
  doc.setTextColor(220, 38, 38);
  doc.text("MONITOR-THREAT", margin, y + 26);
  doc.setTextColor(100, 116, 139);
  doc.text("Cyber Threat Intelligence Platform · v2.0", margin + 105, y + 26);
  const ts = new Date(data.timestamp).toLocaleString();
  doc.setFontSize(10);
  doc.setTextColor(71, 85, 105);
  doc.text(`Report generated: ${ts}`, pageWidth - margin, y + 8, { align: "right" });
  doc.text(`Target: ${data.url}`, pageWidth - margin, y + 22, { align: "right" });
  y += 48;
  doc.setDrawColor(220, 220, 220);
  doc.setLineWidth(0.5);
  doc.line(margin, y, pageWidth - margin, y);
  y += 28;

  // Section heading helper
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

  // 1. Executive summary
  sectionHeading("1. Executive Summary");
  kvTable([
    ["Target URL", data.url],
    ["Domain", data.domain],
    ["Pages crawled", String(data.crawl.pages)],
    ["Paths fuzzed", String(data.fuzzing.totalProbed)],
    ["Paths discovered (200)", String(data.fuzzing.discovered)],
    ["Interesting paths", String(data.fuzzing.interesting)],
    ["Errors found", String(data.fuzzing.errors)],
    ["Generated at", ts],
  ]);

  // Risk assessment
  const riskSignals: string[] = [];
  if (data.fuzzing.interesting > 0) riskSignals.push(`${data.fuzzing.interesting} sensitive paths exposed (admin panels, backups, .git/, etc.)`);
  if (data.attribution.emails.length > 0) riskSignals.push(`${data.attribution.emails.length} email(s) found in HTML`);
  if (data.attribution.bitcoinAddresses.length > 0) riskSignals.push("Bitcoin address detected (potential extortion/scam)");
  if (data.attribution.githubLinks.length > 0) riskSignals.push(`${data.attribution.githubLinks.length} GitHub link(s) found (developer attribution)`);
  if (data.attribution.googleAnalyticsIds.length > 0 || data.attribution.googleAnalytics4Ids.length > 0)
    riskSignals.push("Google Analytics ID found (pivot to find other sites owned by same actor)");
  if (data.attribution.metaPixelIds.length > 0) riskSignals.push("Meta Pixel ID found (pivot to other sites with same Pixel)");

  doc.setFontSize(10);
  if (riskSignals.length === 0) {
    doc.setTextColor(22, 163, 74);
    doc.text("No high-risk findings detected. The site appears to follow basic security practices.", margin, y);
    y += 18;
  } else {
    doc.setTextColor(220, 38, 38);
    doc.setFont("helvetica", "bold");
    doc.text(`${riskSignals.length} risk signal(s) detected:`, margin, y);
    y += 14;
    doc.setFont("helvetica", "normal");
    doc.setTextColor(51, 65, 85);
    for (const s of riskSignals) {
      const wrapped = doc.splitTextToSize(`• ${s}`, contentWidth);
      doc.text(wrapped, margin, y);
      y += wrapped.length * 12 + 2;
    }
    y += 6;
  }

  // 2. Crawl summary
  sectionHeading("2. Mirror / Crawl");
  kvTable([
    ["Pages crawled", String(data.crawl.pages)],
    ["robots.txt", data.crawl.robotsTxt ? "Present" : "Missing"],
    ["sitemap.xml", data.crawl.sitemapXml ? "Present" : "Missing"],
    ["Crawl errors", String(data.crawl.errors.length)],
  ]);

  // 3. HTTP headers
  sectionHeading("3. HTTP Headers");
  if (data.headers.length > 0) {
    autoTable(doc, {
      startY: y, head: [["Header", "Value"]],
      body: data.headers.map((h) => [h.name, h.value.slice(0, 200)]),
      theme: "grid", margin: { left: margin, right: margin },
      styles: { fontSize: 9, cellPadding: 5, textColor: [30, 41, 59], lineColor: [226, 232, 240], lineWidth: 0.5 },
      headStyles: { fillColor: [241, 245, 249], textColor: [71, 85, 105], fontStyle: "bold", fontSize: 10 },
      columnStyles: { 0: { cellWidth: 160, fontStyle: "bold" } },
    });
    // @ts-ignore
    y = (doc as any).lastAutoTable.finalY + 18;
  } else {
    doc.setTextColor(148, 163, 184);
    doc.text("(no headers captured)", margin, y);
    y += 18;
  }

  // 4. Fuzzing
  sectionHeading("4. Fuzzing Results");
  kvTable([
    ["Total paths probed", String(data.fuzzing.totalProbed)],
    ["Discovered (200 OK)", String(data.fuzzing.discovered)],
    ["Interesting paths", String(data.fuzzing.interesting)],
    ["Redirects (3xx)", String(data.fuzzing.redirects)],
    ["Errors (4xx/5xx)", String(data.fuzzing.errors)],
  ]);
  if (data.fuzzing.interestingPaths.length > 0) {
    autoTable(doc, {
      startY: y,
      head: [["Path", "Status", "Content-Type", "Server", "Redirected To"]],
      body: data.fuzzing.interestingPaths.slice(0, 30).map((p) => [
        p.path, String(p.status), (p.contentType || "-").slice(0, 50), p.server || "-", p.redirectedTo || "-",
      ]),
      theme: "grid", margin: { left: margin, right: margin },
      styles: { fontSize: 8, cellPadding: 4, textColor: [30, 41, 59], lineColor: [226, 232, 240], lineWidth: 0.5 },
      headStyles: { fillColor: [241, 245, 249], textColor: [71, 85, 105], fontStyle: "bold", fontSize: 10 },
      columnStyles: { 0: { cellWidth: 140 }, 1: { cellWidth: 40 }, 2: { cellWidth: 130 }, 3: { cellWidth: 90 } },
    });
    // @ts-ignore
    y = (doc as any).lastAutoTable.finalY + 18;
    if (data.fuzzing.interestingPaths.length > 30) {
      doc.setFontSize(9);
      doc.setTextColor(148, 163, 184);
      doc.text(`+ ${data.fuzzing.interestingPaths.length - 30} more (see the ZIP file for the full list).`, margin, y);
      y += 18;
    }
  }

  // 5. Attribution
  sectionHeading("5. Attribution Fingerprints");
  const a = data.attribution;
  autoTable(doc, {
    startY: y,
    head: [["Type", "Value"]],
    body: [
      ...a.googleAnalyticsIds.map((v) => ["Google Analytics (UA)", v] as [string, string]),
      ...a.googleAnalytics4Ids.map((v) => ["Google Analytics 4", v] as [string, string]),
      ...a.metaPixelIds.map((v) => ["Meta Pixel", v] as [string, string]),
      ...a.facebookAppIds.map((v) => ["Facebook App ID", v] as [string, string]),
      ...a.yandexMetricaIds.map((v) => ["Yandex Metrica", v] as [string, string]),
      ...a.hotjarIds.map((v) => ["Hotjar", v] as [string, string]),
      ...a.sentryDsn.map((v) => ["Sentry DSN", v] as [string, string]),
      ...a.githubLinks.map((v) => ["GitHub link", v] as [string, string]),
      ...a.emails.map((v) => ["Email", v] as [string, string]),
      ...a.phones.map((v) => ["Phone", v] as [string, string]),
      ...a.bitcoinAddresses.map((v) => ["Bitcoin address", v] as [string, string]),
      ...a.ethereumAddresses.map((v) => ["Ethereum address", v] as [string, string]),
      ...a.litecoinAddresses.map((v) => ["Litecoin address", v] as [string, string]),
    ],
    theme: "grid", margin: { left: margin, right: margin },
    styles: { fontSize: 9, cellPadding: 5, textColor: [30, 41, 59], lineColor: [226, 232, 240], lineWidth: 0.5 },
    headStyles: { fillColor: [241, 245, 249], textColor: [71, 85, 105], fontStyle: "bold", fontSize: 10 },
    columnStyles: { 0: { cellWidth: 160, fontStyle: "bold" } },
  });
  // @ts-ignore
  y = (doc as any).lastAutoTable.finalY + 18;

  // 6. Tech stack
  sectionHeading("6. Tech Stack Fingerprints");
  if (a.techFingerprints.length > 0) {
    autoTable(doc, {
      startY: y, head: [["Technology"]],
      body: a.techFingerprints.map((t) => [t]),
      theme: "grid", margin: { left: margin, right: margin },
      styles: { fontSize: 10, cellPadding: 6, textColor: [30, 41, 59], lineColor: [226, 232, 240], lineWidth: 0.5 },
      headStyles: { fillColor: [241, 245, 249], textColor: [71, 85, 105], fontStyle: "bold", fontSize: 10 },
    });
    // @ts-ignore
    y = (doc as any).lastAutoTable.finalY + 18;
  } else {
    doc.setTextColor(148, 163, 184);
    doc.text("(no clear tech stack fingerprints detected)", margin, y);
    y += 18;
  }

  // 7. HTML comments
  sectionHeading("7. HTML Comments (potential dev leaks)");
  if (a.htmlComments.length > 0) {
    autoTable(doc, {
      startY: y, head: [["Comment"]],
      body: a.htmlComments.slice(0, 15).map((c) => [c.replace(/\s+/g, " ").slice(0, 200)]),
      theme: "grid", margin: { left: margin, right: margin },
      styles: { fontSize: 9, cellPadding: 5, textColor: [30, 41, 59], lineColor: [226, 232, 240], lineWidth: 0.5 },
      headStyles: { fillColor: [241, 245, 249], textColor: [71, 85, 105], fontStyle: "bold", fontSize: 10 },
    });
    // @ts-ignore
    y = (doc as any).lastAutoTable.finalY + 18;
  } else {
    doc.setTextColor(148, 163, 184);
    doc.text("(no HTML comments found)", margin, y);
    y += 18;
  }

  // 8. Recommendations
  sectionHeading("8. Recommendations");
  const recs: string[] = [];
  if (data.fuzzing.interesting > 0) recs.push("HIGH: Restrict access to the sensitive paths listed in section 4 (admin panels, backups, .git/, .env, etc.).");
  if (a.emails.length > 0) recs.push("MEDIUM: Email addresses found in HTML — verify they are intended to be public.");
  if (a.bitcoinAddresses.length > 0 || a.ethereumAddresses.length > 0) recs.push("HIGH: Cryptocurrency address found — investigate if the site is being used for extortion or scam.");
  if (a.htmlComments.length > 0) recs.push("LOW: HTML comments may leak development information. Strip before production deploy.");
  if (a.googleAnalyticsIds.length > 0 || a.metaPixelIds.length > 0) recs.push("INFO: Use tracker IDs to pivot and find other sites owned by the same actor.");
  if (recs.length === 0) recs.push("No critical recommendations. Site appears to follow basic security practices.");
  doc.setFontSize(10);
  doc.setTextColor(51, 65, 85);
  for (const r of recs) {
    const wrapped = doc.splitTextToSize(`• ${r}`, contentWidth);
    doc.text(wrapped, margin, y);
    y += wrapped.length * 12 + 4;
  }

  // 9. Methodology
  sectionHeading("9. Methodology & Sources");
  autoTable(doc, {
    startY: y, head: [["Step", "Description"]],
    body: [
      ["Mirror", "Fetch robots.txt + sitemap.xml + up to 50 internal pages (depth 2) + linked assets"],
      ["Headers", "Capture all HTTP response headers from the initial URL"],
      ["Fuzzing", "Probe ~250 sensitive paths: admin panels, backups, configs, SCM metadata, API endpoints, CMS-specific, framework-specific"],
      ["Attribution", "Extract Google Analytics IDs, GA4, Meta Pixel, FB App ID, Yandex Metrica, Hotjar, Sentry DSN, GitHub links, emails, phones, crypto addresses, HTML comments, image EXIF"],
      ["FINDINGS.md", "Executive summary + risk signals + all sections consolidated into Markdown"],
      ["ZIP bundle", "All artifacts bundled into a downloadable .zip with mirror/, fuzzing/, headers/, attribution/ folders"],
    ],
    theme: "grid", margin: { left: margin, right: margin },
    styles: { fontSize: 9, cellPadding: 5, textColor: [30, 41, 59], lineColor: [226, 232, 240], lineWidth: 0.5 },
    headStyles: { fillColor: [241, 245, 249], textColor: [71, 85, 105], fontStyle: "bold", fontSize: 10 },
    columnStyles: { 0: { cellWidth: 100, fontStyle: "bold" } },
  });

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

  const fname = `MONITOR-THREAT-Domain-Forensics-${data.domain.replace(/[^a-z0-9.-]/g, "_")}-${Date.now()}.pdf`;
  doc.save(fname);
}

// ---------- Main view ----------

export function DomainForensicsView() {
  const [input, setInput] = React.useState("");
  const [loading, setLoading] = React.useState(false);
  const [data, setData] = React.useState<ForensicsResult | null>(null);
  const [error, setError] = React.useState<string | null>(null);
  const abortRef = React.useRef<AbortController | null>(null);

  async function analyze(url: string) {
    if (!url.trim()) return;
    abortRef.current?.abort();
    const ac = new AbortController();
    abortRef.current = ac;
    setLoading(true);
    setError(null);
    try {
      const res = await fetch(
        `/api/domain-forensics/analyze?url=${encodeURIComponent(url.trim())}`,
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
      name="Domain Forensics"
      description="Automated web investigation: static mirror + HTTP headers inspection + path fuzzing + attribution extraction (GA IDs, Meta Pixel, code comments, image EXIF). Downloads a structured ZIP + a PDF report."
      icon={Search}
      category="INFRASTRUCTURE"
      status={loading ? "QUERYING" : "READY"}
    >
      <div className="flex flex-col gap-2 mb-4">
        <label className="text-xs font-medium text-muted-foreground uppercase tracking-wider">
          Target URL
        </label>
        <div className="flex gap-2">
          <Input
            type="text"
            placeholder="e.g. https://example.com, https://suspicious-site.com/login"
            className="flex-1 font-mono text-sm"
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && analyze(input)}
            autoFocus
          />
          <Button type="button" size="sm" onClick={() => analyze(input)} disabled={loading || !input.trim()}>
            {loading ? (
              <><Loader2 className="w-3.5 h-3.5 mr-2 animate-spin" />Investigating…</>
            ) : (
              <><Search className="w-3.5 h-3.5 mr-2" />Investigate</>
            )}
          </Button>
          <Button type="button" size="sm" variant="outline"
            onClick={() => downloadZip(data!)} disabled={!data}
            title={data ? "Download a ZIP with mirror/, fuzzing/, headers/, attribution/ folders + FINDINGS.md" : "Run an investigation first"}
          >
            <FolderArchive className="w-3.5 h-3.5 mr-2" />
            Descargar ZIP
          </Button>
          <Button type="button" size="sm" variant="outline"
            onClick={() => downloadPdf(data!)} disabled={!data}
            title={data ? "Download a structured PDF report" : "Run an investigation first"}
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
            <Search className="w-8 h-8 text-muted-foreground" />
          </div>
          <h2 className="text-lg font-semibold">Enter a URL to investigate</h2>
          <p className="text-sm text-muted-foreground max-w-md">
            Will mirror static pages + assets, capture HTTP headers, fuzz ~250 sensitive paths
            (/admin, /backup, .git/, .env, /api, etc.), and extract attribution fingerprints
            (GA IDs, Meta Pixel, GitHub links, emails, crypto addresses, HTML comments, image EXIF).
            Output: a structured ZIP + this on-screen report + a printable PDF.
          </p>
        </div>
      )}

      {data && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {/* Executive summary cards */}
          <Panel title="Executive Summary" className="md:col-span-2">
            <div className="grid grid-cols-2 md:grid-cols-5 gap-2">
              {[
                { label: "Pages crawled", n: data.crawl.pages, cls: "border-border bg-muted/20" },
                { label: "Paths fuzzed", n: data.fuzzing.totalProbed, cls: "border-border bg-muted/20" },
                { label: "Interesting paths", n: data.fuzzing.interesting, cls: "border-red-500/40 bg-red-500/10 text-red-400" },
                { label: "Discovered (200)", n: data.fuzzing.discovered, cls: "border-orange-500/40 bg-orange-500/10 text-orange-400" },
                { label: "Attribution signals", n:
                  data.attribution.googleAnalyticsIds.length +
                  data.attribution.googleAnalytics4Ids.length +
                  data.attribution.metaPixelIds.length +
                  data.attribution.githubLinks.length +
                  data.attribution.emails.length +
                  data.attribution.bitcoinAddresses.length +
                  data.attribution.ethereumAddresses.length,
                  cls: "border-purple-500/40 bg-purple-500/10 text-purple-400" },
              ].map((b) => (
                <div key={b.label} className={`rounded p-2 border ${b.cls}`}>
                  <div className="text-xl font-bold font-mono leading-none">{b.n}</div>
                  <div className="text-[10px] mt-0.5">{b.label}</div>
                </div>
              ))}
            </div>
            <Separator />
            <div className="text-xs text-muted-foreground">
              <span className="font-mono">{data.domain}</span> · crawled {data.crawl.pages} pages · fuzzed {data.fuzzing.totalProbed} paths
            </div>
          </Panel>

          {/* Mirror / Crawl */}
          <Panel title="1. Mirror / Crawl">
            <FieldRow label="Pages crawled" value={data.crawl.pages} mono />
            <FieldRow label="robots.txt" value={data.crawl.robotsTxt ? "Present" : "Missing"} />
            <FieldRow label="sitemap.xml" value={data.crawl.sitemapXml ? "Present" : "Missing"} />
            <FieldRow label="Crawl errors" value={data.crawl.errors.length} mono />
            {data.crawl.errors.length > 0 && (
              <>
                <Separator />
                <div className="pt-2">
                  <div className="text-xs text-muted-foreground mb-1">Errors:</div>
                  <div className="max-h-32 overflow-y-auto text-[10px] font-mono text-muted-foreground">
                    {data.crawl.errors.slice(0, 10).map((e, i) => <div key={i}>{e}</div>)}
                  </div>
                </div>
              </>
            )}
          </Panel>

          {/* HTTP Headers */}
          <Panel title="2. HTTP Headers">
            {data.headers.length > 0 ? (
              <div className="max-h-64 overflow-y-auto">
                {data.headers.map((h, i) => (
                  <FieldRow key={i} label={h.name} value={h.value.slice(0, 80)} mono />
                ))}
              </div>
            ) : (
              <p className="text-sm text-muted-foreground">(no headers captured)</p>
            )}
          </Panel>

          {/* Fuzzing */}
          <Panel title={`3. Fuzzing Results — ${data.fuzzing.interesting} interesting`} className="md:col-span-2">
            <div className="grid grid-cols-2 md:grid-cols-4 gap-2 mb-3">
              {[
                { label: "Total probed", n: data.fuzzing.totalProbed, cls: "border-border bg-muted/20" },
                { label: "Discovered (200)", n: data.fuzzing.discovered, cls: "border-emerald-500/40 bg-emerald-500/10 text-emerald-400" },
                { label: "Interesting", n: data.fuzzing.interesting, cls: "border-red-500/40 bg-red-500/10 text-red-400" },
                { label: "Errors (4xx/5xx)", n: data.fuzzing.errors, cls: "border-zinc-500/40 bg-zinc-500/10 text-zinc-400" },
              ].map((b) => (
                <div key={b.label} className={`rounded p-2 border ${b.cls}`}>
                  <div className="text-xl font-bold font-mono leading-none">{b.n}</div>
                  <div className="text-[10px] mt-0.5">{b.label}</div>
                </div>
              ))}
            </div>
            {data.fuzzing.interestingPaths.length > 0 ? (
              <>
                <div className="text-xs text-muted-foreground mb-2 font-semibold">
                  Interesting paths (admin panels, backups, .git/, .env, API endpoints, etc.):
                </div>
                <div className="max-h-96 overflow-y-auto">
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <TableHead className="w-16">Status</TableHead>
                        <TableHead>Path</TableHead>
                        <TableHead className="w-32">Content-Type</TableHead>
                        <TableHead>Redirected To</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {data.fuzzing.interestingPaths.map((p, i) => (
                        <TableRow key={i}>
                          <TableCell>
                            <Badge
                              variant={p.status === 200 ? "destructive" : p.status === 401 || p.status === 403 ? "default" : "secondary"}
                              className="text-[10px] font-mono"
                            >
                              {p.status}
                            </Badge>
                          </TableCell>
                          <TableCell className="font-mono text-xs">{p.path}</TableCell>
                          <TableCell className="text-xs text-muted-foreground">{p.contentType || "-"}</TableCell>
                          <TableCell className="font-mono text-xs">{p.redirectedTo || "-"}</TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </div>
              </>
            ) : (
              <p className="text-sm text-emerald-500 flex items-center gap-2">
                <ShieldAlert className="w-4 h-4" />
                No interesting paths found. The site appears to follow standard hardening practices.
              </p>
            )}
          </Panel>

          {/* Attribution */}
          <Panel title="4. Attribution Fingerprints" className="md:col-span-2">
            <div className="grid grid-cols-2 md:grid-cols-4 gap-2 mb-3">
              {[
                { label: "GA / GA4 IDs", n: data.attribution.googleAnalyticsIds.length + data.attribution.googleAnalytics4Ids.length, cls: "border-blue-500/40 bg-blue-500/10 text-blue-400" },
                { label: "Meta Pixel", n: data.attribution.metaPixelIds.length, cls: "border-blue-500/40 bg-blue-500/10 text-blue-400" },
                { label: "GitHub links", n: data.attribution.githubLinks.length, cls: "border-purple-500/40 bg-purple-500/10 text-purple-400" },
                { label: "Emails / Phones", n: data.attribution.emails.length + data.attribution.phones.length, cls: "border-orange-500/40 bg-orange-500/10 text-orange-400" },
              ].map((b) => (
                <div key={b.label} className={`rounded p-2 border ${b.cls}`}>
                  <div className="text-xl font-bold font-mono leading-none">{b.n}</div>
                  <div className="text-[10px] mt-0.5">{b.label}</div>
                </div>
              ))}
            </div>
            <Separator />
            {/* Tracker IDs */}
            <div className="pt-2">
              <div className="text-xs font-semibold text-muted-foreground mb-1 flex items-center gap-1">
                <Fingerprint className="w-3 h-3" /> Tracker IDs
              </div>
              <div className="flex flex-wrap gap-1">
                {data.attribution.googleAnalyticsIds.map((v) => (
                  <Badge key={v} variant="secondary" className="font-mono text-[10px]">GA {v}</Badge>
                ))}
                {data.attribution.googleAnalytics4Ids.map((v) => (
                  <Badge key={v} variant="secondary" className="font-mono text-[10px]">GA4 {v}</Badge>
                ))}
                {data.attribution.metaPixelIds.map((v) => (
                  <Badge key={v} variant="secondary" className="font-mono text-[10px]">FB Pixel {v}</Badge>
                ))}
                {data.attribution.facebookAppIds.map((v) => (
                  <Badge key={v} variant="secondary" className="font-mono text-[10px]">FB App {v}</Badge>
                ))}
                {data.attribution.yandexMetricaIds.map((v) => (
                  <Badge key={v} variant="secondary" className="font-mono text-[10px]">YM {v}</Badge>
                ))}
                {data.attribution.hotjarIds.map((v) => (
                  <Badge key={v} variant="secondary" className="font-mono text-[10px]">Hotjar {v}</Badge>
                ))}
                {data.attribution.sentryDsn.map((v, i) => (
                  <Badge key={i} variant="secondary" className="font-mono text-[10px]">Sentry {v.slice(0, 30)}…</Badge>
                ))}
                {data.attribution.googleAnalyticsIds.length === 0 &&
                 data.attribution.googleAnalytics4Ids.length === 0 &&
                 data.attribution.metaPixelIds.length === 0 &&
                 data.attribution.facebookAppIds.length === 0 &&
                 data.attribution.yandexMetricaIds.length === 0 &&
                 data.attribution.hotjarIds.length === 0 &&
                 data.attribution.sentryDsn.length === 0 && (
                  <span className="text-xs text-muted-foreground">(no trackers found)</span>
                )}
              </div>
            </div>
            {/* Developer attribution */}
            {data.attribution.githubLinks.length > 0 && (
              <div className="pt-2">
                <div className="text-xs font-semibold text-muted-foreground mb-1">GitHub links (developer attribution):</div>
                <div className="flex flex-col gap-1">
                  {data.attribution.githubLinks.slice(0, 5).map((l) => (
                    <a key={l} href={l} target="_blank" rel="noreferrer"
                      className="text-xs text-cyan-500 hover:underline flex items-center gap-1">
                      <ExternalLink className="w-3 h-3" /> {l}
                    </a>
                  ))}
                </div>
              </div>
            )}
            {/* Contact info */}
            {(data.attribution.emails.length > 0 || data.attribution.phones.length > 0) && (
              <div className="pt-2">
                <div className="text-xs font-semibold text-muted-foreground mb-1">Contact info:</div>
                <div className="flex flex-wrap gap-1">
                  {data.attribution.emails.slice(0, 5).map((e) => (
                    <Badge key={e} variant="secondary" className="font-mono text-[10px]">{e}</Badge>
                  ))}
                  {data.attribution.phones.slice(0, 5).map((p) => (
                    <Badge key={p} variant="secondary" className="font-mono text-[10px]">{p}</Badge>
                  ))}
                </div>
              </div>
            )}
            {/* Crypto addresses */}
            {(data.attribution.bitcoinAddresses.length > 0 || data.attribution.ethereumAddresses.length > 0 || data.attribution.litecoinAddresses.length > 0) && (
              <div className="pt-2 rounded border border-red-500/40 bg-red-500/5 p-2">
                <div className="text-xs font-semibold text-red-400 mb-1 flex items-center gap-1">
                  <ShieldAlert className="w-3 h-3" /> Cryptocurrency addresses detected (potential extortion/scam)
                </div>
                <div className="flex flex-col gap-1">
                  {data.attribution.bitcoinAddresses.map((b) => (
                    <div key={b} className="text-xs font-mono">BTC: {b}</div>
                  ))}
                  {data.attribution.ethereumAddresses.map((b) => (
                    <div key={b} className="text-xs font-mono">ETH: {b}</div>
                  ))}
                  {data.attribution.litecoinAddresses.map((b) => (
                    <div key={b} className="text-xs font-mono">LTC: {b}</div>
                  ))}
                </div>
              </div>
            )}
            {/* Tech stack */}
            {data.attribution.techFingerprints.length > 0 && (
              <div className="pt-2">
                <div className="text-xs font-semibold text-muted-foreground mb-1">Tech fingerprints:</div>
                <div className="flex flex-wrap gap-1">
                  {data.attribution.techFingerprints.map((t) => (
                    <Badge key={t} variant="secondary" className="text-[10px]">{t}</Badge>
                  ))}
                </div>
              </div>
            )}
            {/* HTML comments */}
            {data.attribution.htmlComments.length > 0 && (
              <div className="pt-2">
                <div className="text-xs font-semibold text-muted-foreground mb-1">
                  HTML comments (potential dev leaks): {data.attribution.htmlComments.length}
                </div>
                <div className="max-h-32 overflow-y-auto rounded border border-border p-2 bg-muted/30">
                  {data.attribution.htmlComments.slice(0, 10).map((c, i) => (
                    <div key={i} className="text-[10px] font-mono text-muted-foreground whitespace-pre-wrap break-all">
                      {c.slice(0, 200)}{c.length > 200 ? "…" : ""}
                    </div>
                  ))}
                </div>
              </div>
            )}
            {/* Image EXIF */}
            {data.attribution.imageExif.length > 0 && (
              <div className="pt-2">
                <div className="text-xs font-semibold text-muted-foreground mb-1">
                  Image EXIF metadata: {data.attribution.imageExif.length} images
                </div>
                <div className="max-h-32 overflow-y-auto">
                  {data.attribution.imageExif.slice(0, 5).map((e, i) => (
                    <div key={i} className="text-[10px] font-mono">
                      {e.url} — GPS: {e.hasGps ? "yes" : "no"} {e.camera ? `· ${e.camera}` : ""} {e.software ? `· ${e.software}` : ""}
                    </div>
                  ))}
                </div>
              </div>
            )}
          </Panel>

          {/* FINDINGS.md preview */}
          <Panel title="5. FINDINGS.md Preview" className="md:col-span-2">
            <div className="max-h-96 overflow-y-auto rounded border border-border p-3 bg-muted/20">
              <pre className="text-[10px] font-mono whitespace-pre-wrap break-words">{data.findings}</pre>
            </div>
          </Panel>

          {/* Footer */}
          <div className="md:col-span-2 text-[10px] text-muted-foreground font-mono">
            Generated: {data.timestamp} · All artifacts bundled in the downloadable ZIP ({data.zipFilename}).
          </div>
        </div>
      )}
    </ModuleShell>
  );
}
