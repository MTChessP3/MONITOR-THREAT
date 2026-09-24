"use client";

import * as React from "react";
import {
  Link as LinkIcon,
  Loader2,
  AlertTriangle,
  Printer,
  Search,
  ShieldAlert,
  ShieldCheck,
  ExternalLink,
  Shield,
  FileCode,
  Eye,
  AlertOctagon,
} from "lucide-react";
import { jsPDF } from "jspdf";
import autoTable from "jspdf-autotable";

import { ModuleShell, Panel, FieldRow } from "@/components/module-shell";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Separator } from "@/components/ui/separator";
import {
  Table, TableBody, TableCell, TableHead, TableHeader, TableRow,
} from "@/components/ui/table";

// ---------- Types ----------

interface RiskIndicator { indicator: string; weight: number; detail: string }

interface UrlParse {
  scheme: string; host: string; port: string; path: string; query: string;
  fragment: string; pathname: string; fullUrl: string; hostname: string;
  domain: string; tld: string; subdomainDepth: number; urlLength: number;
  pathLength: number; queryParamCount: number; hasIpAsHost: boolean;
  hasPort: boolean; hasCredentials: boolean; hasTrackingParams: boolean;
  hasPunycode: boolean; hasHomoglyph: boolean; suspiciousKeywords: string[];
  isShortened: boolean;
}

interface RedirectHop { url: string; status: number; headers: Record<string, string> }

interface ContentExtraction {
  title: string; description: string;
  forms: Array<{ action: string; method: string; inputCount: number; hasPasswordField: boolean; externalAction: boolean }>;
  externalLinks: string[]; scripts: string[];
  iframes: Array<{ src: string; hidden: boolean }>;
  trackingPixels: number; emails: string[]; cryptoAddresses: string[];
  googleAnalyticsIds: string[]; metaPixelIds: string[]; htmlComments: string[];
  hasFavicon: boolean; hasViewport: boolean;
  bodyHashMd5: string; bodyHashSha256: string; bodySize: number;
}

interface VtUrlResult {
  available: boolean; url: string;
  lastAnalysisStats: { malicious: number; suspicious: number; harmless: number; undetected: number; timeout: number };
  totalEngines: number; flaggedEnginesCount: number;
  flaggedEngines: Array<{ engine: string; category: string; result: string }>;
  reputation: number; totalVotes: { harmless: number; malicious: number };
  categories: Array<{ source: string; category: string }>;
  classification: string; error?: string;
}

interface UrlScanResult {
  url: string; timestamp: string;
  parse: UrlParse; riskIndicators: RiskIndicator[];
  riskScore: number; riskClassification: "SAFE" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  verdict: string;
  fetch: {
    available: boolean; finalUrl: string; redirectChain: RedirectHop[];
    redirectCount: number; finalStatus: number; responseTimeMs: number;
    contentType: string; server: string; headers: Record<string, string>; bodySize: number;
  };
  content: ContentExtraction;
  virusTotal: VtUrlResult;
  openPhish: { checked: boolean; isPhishing: boolean; matchCount: number; matches: string[] };
}

// ---------- PDF ----------

function downloadPdf(d: UrlScanResult) {
  const doc = new jsPDF({ unit: "pt", format: "a4" });
  const pageWidth = doc.internal.pageSize.getWidth();
  const pageHeight = doc.internal.pageSize.getHeight();
  const margin = 40;
  const contentWidth = pageWidth - margin * 2;
  let y = margin;

  doc.setFont("helvetica", "bold"); doc.setFontSize(22); doc.setTextColor(15, 23, 42);
  doc.text("URL Scanner Report", margin, y + 8);
  doc.setFont("helvetica", "normal"); doc.setFontSize(11); doc.setTextColor(220, 38, 38);
  doc.text("MONITOR-THREAT", margin, y + 26);
  doc.setTextColor(100, 116, 139);
  doc.text("Cyber Threat Intelligence Platform · v2.0", margin + 105, y + 26);
  const ts = new Date(d.timestamp).toLocaleString();
  doc.setFontSize(10); doc.setTextColor(71, 85, 105);
  doc.text(`Report generated: ${ts}`, pageWidth - margin, y + 8, { align: "right" });
  doc.text(`Target URL: ${d.url.slice(0, 60)}`, pageWidth - margin, y + 22, { align: "right" });
  y += 48;
  doc.setDrawColor(220, 220, 220); doc.setLineWidth(0.5);
  doc.line(margin, y, pageWidth - margin, y); y += 28;

  const sectionHeading = (label: string) => {
    if (y > pageHeight - margin - 120) { doc.addPage(); y = margin + 6; } else { y += 20; }
    doc.setFont("helvetica", "bold"); doc.setFontSize(13); doc.setTextColor(220, 38, 38);
    doc.text(label, margin, y); doc.setDrawColor(220, 38, 38); doc.setLineWidth(1);
    doc.line(margin, y + 4, pageWidth - margin, y + 4); y += 16;
    doc.setFont("helvetica", "normal"); doc.setFontSize(10); doc.setTextColor(51, 65, 85);
  };
  const kvTable = (rows: Array<[string, string]>) => {
    autoTable(doc, { startY: y, head: [["Field", "Value"]], body: rows, theme: "striped",
      margin: { left: margin, right: margin },
      styles: { fontSize: 10, cellPadding: 6, textColor: [30, 41, 59], lineColor: [226, 232, 240], lineWidth: 0.5 },
      headStyles: { fillColor: [241, 245, 249], textColor: [71, 85, 105], fontStyle: "bold", fontSize: 10 },
      columnStyles: { 0: { cellWidth: contentWidth * 0.32, fontStyle: "bold", textColor: [100, 116, 139] } },
    });
    // @ts-ignore
    y = (doc as any).lastAutoTable.finalY + 18;
  };

  // Risk score
  sectionHeading("Risk Assessment");
  const scoreColors: Record<string, [number, number, number]> = {
    SAFE: [22, 163, 74], LOW: [34, 197, 94], MEDIUM: [202, 138, 4],
    HIGH: [220, 38, 38], CRITICAL: [153, 27, 27],
  };
  const sc = scoreColors[d.riskClassification] || [100, 116, 139];
  kvTable([
    ["Risk score", `${d.riskScore} / 100`],
    ["Classification", d.riskClassification],
    ["Verdict", d.verdict],
  ]);
  doc.setTextColor(sc[0], sc[1], sc[2]); doc.setFontSize(12); doc.setFont("helvetica", "bold");
  doc.text(`Classification: ${d.riskClassification}`, margin, y); y += 16;
  doc.setFont("helvetica", "normal"); doc.setFontSize(9); doc.setTextColor(51, 65, 85);
  const verdictWrapped = doc.splitTextToSize(d.verdict, contentWidth);
  doc.text(verdictWrapped, margin, y); y += verdictWrapped.length * 11 + 8;

  // 1. URL Parse & Risk Indicators
  sectionHeading("1. URL Parse & Risk Indicators");
  const p = d.parse;
  kvTable([
    ["Full URL", p.fullUrl], ["Scheme", p.scheme], ["Hostname", p.hostname],
    ["Domain", p.domain], ["TLD", p.tld], ["Port", p.port],
    ["Path", p.path || "/"], ["Query params", String(p.queryParamCount)],
    ["URL length", `${p.urlLength} chars`], ["Subdomain depth", String(p.subdomainDepth)],
    ["IP as host", p.hasIpAsHost ? "YES — suspicious" : "no"],
    ["Port specified", p.hasPort ? "yes" : "no"],
    ["Embedded credentials", p.hasCredentials ? "YES — suspicious" : "no"],
    ["Punycode/IDN", p.hasPunycode ? "YES — homograph risk" : "no"],
    ["Homoglyph", p.hasHomoglyph ? "YES — lookalike domain" : "no"],
    ["URL shortener", p.isShortened ? "yes — destination hidden" : "no"],
    ["Tracking params", p.hasTrackingParams ? "yes" : "no"],
    ["Suspicious keywords", p.suspiciousKeywords.join(", ") || "none found"],
  ]);
  if (d.riskIndicators.length > 0) {
    autoTable(doc, { startY: y, head: [["Indicator", "Weight", "Detail"]],
      body: d.riskIndicators.map(i => [i.indicator, `+${i.weight}`, i.detail]),
      theme: "grid", margin: { left: margin, right: margin },
      styles: { fontSize: 9, cellPadding: 5, textColor: [30, 41, 59], lineColor: [226, 232, 240], lineWidth: 0.5 },
      headStyles: { fillColor: [241, 245, 249], textColor: [71, 85, 105], fontStyle: "bold", fontSize: 10 },
      columnStyles: { 0: { cellWidth: 130 }, 1: { cellWidth: 50 } },
    });
    // @ts-ignore
    y = (doc as any).lastAutoTable.finalY + 18;
  }

  // 2. HTTP Fetch & Redirect Chain
  sectionHeading("2. HTTP Fetch & Redirect Chain");
  const f = d.fetch;
  kvTable([
    ["Available", f.available ? "yes" : "no"], ["Final URL", f.finalUrl],
    ["Redirect count", String(f.redirectCount)], ["Final status", String(f.finalStatus)],
    ["Response time", f.responseTimeMs ? `${f.responseTimeMs}ms` : "-"],
    ["Content-Type", f.contentType || "-"], ["Server", f.server || "-"],
    ["Body size", f.bodySize ? `${f.bodySize} bytes` : "-"],
  ]);
  if (f.redirectChain.length > 0) {
    autoTable(doc, { startY: y, head: [["Status", "URL"]],
      body: f.redirectChain.map(h => [String(h.status), h.url.slice(0, 200)]),
      theme: "grid", margin: { left: margin, right: margin },
      styles: { fontSize: 8, cellPadding: 4, textColor: [30, 41, 59], lineColor: [226, 232, 240], lineWidth: 0.5 },
      headStyles: { fillColor: [241, 245, 249], textColor: [71, 85, 105], fontStyle: "bold", fontSize: 10 },
      columnStyles: { 0: { cellWidth: 50 } },
    });
    // @ts-ignore
    y = (doc as any).lastAutoTable.finalY + 18;
  }

  // 3. Content Extraction
  sectionHeading("3. Content Extraction");
  const c = d.content;
  kvTable([
    ["Title", c.title || "(empty — suspicious)"],
    ["Description", c.description || "(empty)"],
    ["Forms", String(c.forms.length)],
    ["Forms with password field", String(c.forms.filter(f2 => f2.hasPasswordField).length)],
    ["Forms with external action", String(c.forms.filter(f2 => f2.externalAction).length)],
    ["External links", String(c.externalLinks.length)],
    ["Scripts", String(c.scripts.length)],
    ["Iframes", String(c.iframes.length)],
    ["Hidden iframes", String(c.iframes.filter(i => i.hidden).length)],
    ["Tracking pixels", String(c.trackingPixels)],
    ["Emails found", String(c.emails.length)],
    ["Crypto addresses", String(c.cryptoAddresses.length)],
    ["GA IDs", c.googleAnalyticsIds.join(", ") || "none"],
    ["Meta Pixel IDs", c.metaPixelIds.join(", ") || "none"],
    ["HTML comments", String(c.htmlComments.length)],
    ["Has favicon", c.hasFavicon ? "yes" : "no"],
    ["Has viewport meta", c.hasViewport ? "yes" : "no"],
    ["Body MD5", c.bodyHashMd5 || "-"],
    ["Body SHA-256", c.bodyHashSha256 || "-"],
  ]);
  if (c.forms.length > 0) {
    autoTable(doc, { startY: y, head: [["Action", "Method", "Inputs", "Password", "External Action"]],
      body: c.forms.map(f2 => [f2.action.slice(0, 100) || "(same page)", f2.method, String(f2.inputCount),
        f2.hasPasswordField ? "YES" : "no", f2.externalAction ? "YES — phishing risk" : "no"]),
      theme: "grid", margin: { left: margin, right: margin },
      styles: { fontSize: 8, cellPadding: 4, textColor: [30, 41, 59], lineColor: [226, 232, 240], lineWidth: 0.5 },
      headStyles: { fillColor: [241, 245, 249], textColor: [71, 85, 105], fontStyle: "bold", fontSize: 10 },
    });
    // @ts-ignore
    y = (doc as any).lastAutoTable.finalY + 18;
  }

  // 4. VirusTotal URL Report
  sectionHeading("4. VirusTotal URL Report");
  const vt = d.virusTotal;
  if (vt.available) {
    kvTable([
      ["Classification", vt.classification],
      ["Flagged engines", `${vt.flaggedEnginesCount} / ${vt.totalEngines}`],
      ["Stats", `mal=${vt.lastAnalysisStats.malicious} susp=${vt.lastAnalysisStats.suspicious} harm=${vt.lastAnalysisStats.harmless} undet=${vt.lastAnalysisStats.undetected}`],
      ["Reputation", String(vt.reputation)],
      ["Community votes", `${vt.totalVotes.harmless} harmless / ${vt.totalVotes.malicious} malicious`],
      ["Categories", vt.categories.map(cat => `${cat.source}: ${cat.category}`).join(", ") || "-"],
    ]);
    if (vt.flaggedEngines.length > 0) {
      autoTable(doc, { startY: y, head: [["Engine", "Category", "Result"]],
        body: vt.flaggedEngines.slice(0, 15).map(e => [e.engine, e.category, e.result.slice(0, 60)]),
        theme: "grid", margin: { left: margin, right: margin },
        styles: { fontSize: 9, cellPadding: 5, textColor: [30, 41, 59], lineColor: [226, 232, 240], lineWidth: 0.5 },
        headStyles: { fillColor: [241, 245, 249], textColor: [71, 85, 105], fontStyle: "bold", fontSize: 10 },
      });
      // @ts-ignore
      y = (doc as any).lastAutoTable.finalY + 18;
    }
  } else {
    doc.setTextColor(148, 163, 184);
    doc.text(`VirusTotal: ${vt.error || "not available"}`, margin, y); y += 18;
  }

  // 5. OpenPhish
  sectionHeading("5. OpenPhish Check");
  kvTable([
    ["Checked", d.openPhish.checked ? "yes" : "no"],
    ["Is phishing", d.openPhish.isPhishing ? "YES — KNOWN PHISHING URL" : "no"],
    ["Match count", String(d.openPhish.matchCount)],
  ]);
  if (d.openPhish.matches.length > 0) {
    doc.setFontSize(9); doc.setTextColor(220, 38, 38);
    for (const m of d.openPhish.matches) {
      doc.text(doc.splitTextToSize(`Match: ${m}`, contentWidth), margin, y); y += 14;
    }
    y += 4;
  }

  // Footer
  const pageCount = doc.getNumberOfPages();
  for (let i = 1; i <= pageCount; i++) {
    doc.setPage(i); doc.setFontSize(8); doc.setTextColor(148, 163, 184);
    doc.text(`MONITOR-THREAT v2.0  ·  Generated ${ts}  ·  Page ${i} of ${pageCount}`, pageWidth / 2, pageHeight - 22, { align: "center" });
    doc.text("This report is for informational purposes only and does not constitute legal advice.", pageWidth / 2, pageHeight - 10, { align: "center" });
  }
  doc.save(`MONITOR-THREAT-URL-Scanner-${Date.now()}.pdf`);
}

// ---------- View ----------

const riskColors: Record<string, string> = {
  SAFE: "text-emerald-500", LOW: "text-green-500", MEDIUM: "text-yellow-500",
  HIGH: "text-orange-500", CRITICAL: "text-red-500",
};

export function UrlScannerView() {
  const [input, setInput] = React.useState("");
  const [loading, setLoading] = React.useState(false);
  const [data, setData] = React.useState<UrlScanResult | null>(null);
  const [error, setError] = React.useState<string | null>(null);
  const abortRef = React.useRef<AbortController | null>(null);

  async function analyze(url: string) {
    if (!url.trim()) return;
    abortRef.current?.abort();
    const ac = new AbortController(); abortRef.current = ac;
    setLoading(true); setError(null);
    try {
      const res = await fetch(`/api/url-scanner/analyze?url=${encodeURIComponent(url.trim())}`, { signal: ac.signal });
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
      name="URL Scanner"
      description="Static and dynamic analysis of suspicious URLs: URL parsing & risk indicators, HTTP redirect chain, content extraction (forms, scripts, iframes, trackers), VirusTotal URL reputation, OpenPhish phishing database check, composite risk score."
      icon={LinkIcon}
      category="INFRASTRUCTURE"
      status={loading ? "QUERYING" : "READY"}
    >
      <div className="flex flex-col gap-2 mb-4">
        <label className="text-xs font-medium text-muted-foreground uppercase tracking-wider">URL to scan</label>
        <div className="flex gap-2">
          <Input type="text" placeholder="e.g. https://suspicious-site.com/login?token=abc123"
            className="flex-1 font-mono text-sm" value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && analyze(input)} autoFocus />
          <Button type="button" size="sm" onClick={() => analyze(input)} disabled={loading || !input.trim()}>
            {loading ? <><Loader2 className="w-3.5 h-3.5 mr-2 animate-spin" />Scanning…</> : <><Search className="w-3.5 h-3.5 mr-2" />Scan</>}
          </Button>
          <Button type="button" size="sm" variant="outline" onClick={() => downloadPdf(data!)} disabled={!data}
            title={data ? "Download PDF report" : "Run a scan first"}>
            <Printer className="w-3.5 h-3.5 mr-2" />Imprimir informe PDF
          </Button>
        </div>
      </div>

      {error && (
        <div className="mb-4 p-3 rounded-md border border-red-500/40 bg-red-500/10 text-red-400 flex items-center gap-2">
          <AlertTriangle className="w-4 h-4 shrink-0" /><span className="text-sm">{error}</span>
        </div>
      )}

      {!data && !loading && (
        <div className="flex flex-col items-center justify-center min-h-[400px] text-center gap-3">
          <div className="w-16 h-16 rounded-full bg-muted/50 flex items-center justify-center">
            <LinkIcon className="w-8 h-8 text-muted-foreground" />
          </div>
          <h2 className="text-lg font-semibold">Enter a URL to scan</h2>
          <p className="text-sm text-muted-foreground max-w-md">
            Will parse the URL for risk indicators, follow redirect chains, extract content (forms, scripts, iframes, trackers),
            check VirusTotal URL reputation, verify against OpenPhish phishing database, and compute a composite risk score.
          </p>
        </div>
      )}

      {data && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {/* Risk Score Banner */}
          <Panel title="Risk Assessment" className="md:col-span-2">
            <div className="flex items-start gap-4">
              <div className="flex flex-col items-center gap-1 shrink-0">
                <div className={`text-5xl font-mono font-bold ${riskColors[data.riskClassification] || "text-muted-foreground"}`}>
                  {data.riskScore}
                </div>
                <div className="text-base text-muted-foreground">/ 100</div>
                <Badge
                  variant={data.riskClassification === "CRITICAL" || data.riskClassification === "HIGH" ? "destructive" :
                    data.riskClassification === "MEDIUM" ? "default" : "secondary"}
                  className="font-mono text-xs mt-1"
                >
                  {data.riskClassification}
                </Badge>
              </div>
              <div className="flex-1">
                <div className="text-sm text-muted-foreground mb-1 font-semibold">Verdict:</div>
                <p className="text-sm">{data.verdict}</p>
                {data.riskIndicators.length > 0 && (
                  <>
                    <Separator />
                    <div className="pt-2 flex flex-wrap gap-1.5">
                      {data.riskIndicators.map((ind, i) => (
                        <Badge key={i} variant={ind.weight >= 20 ? "destructive" : ind.weight >= 10 ? "default" : "secondary"}
                          className="text-[10px] font-mono" title={ind.detail}>
                          {ind.indicator} +{ind.weight}
                        </Badge>
                      ))}
                    </div>
                  </>
                )}
              </div>
            </div>
          </Panel>

          {/* 1. URL Parse */}
          <Panel title="1. URL Parse & Structure">
            <FieldRow label="Full URL" value={data.parse.fullUrl.slice(0, 80)} mono />
            <FieldRow label="Scheme" value={data.parse.scheme} mono />
            <FieldRow label="Hostname" value={data.parse.hostname} mono />
            <FieldRow label="Domain" value={data.parse.domain} mono />
            <FieldRow label="TLD" value={data.parse.tld} mono />
            <FieldRow label="Port" value={data.parse.port} mono />
            <FieldRow label="Path" value={data.parse.path || "/"} mono />
            <FieldRow label="Query params" value={String(data.parse.queryParamCount)} mono />
            <FieldRow label="URL length" value={`${data.parse.urlLength} chars`} mono />
            <FieldRow label="Subdomain depth" value={String(data.parse.subdomainDepth)} mono />
            <Separator />
            {data.parse.hasIpAsHost && <div className="text-xs text-red-500 font-semibold">⚠ IP as host</div>}
            {data.parse.hasPunycode && <div className="text-xs text-red-500 font-semibold">⚠ Punycode/IDN</div>}
            {data.parse.hasHomoglyph && <div className="text-xs text-red-500 font-semibold">⚠ Homoglyph detected</div>}
            {data.parse.hasCredentials && <div className="text-xs text-red-500 font-semibold">⚠ Embedded credentials</div>}
            {data.parse.suspiciousKeywords.length > 0 && (
              <div className="text-xs text-orange-500">
                Suspicious keywords: {data.parse.suspiciousKeywords.join(", ")}
              </div>
            )}
            {data.parse.isShortened && <div className="text-xs text-yellow-500">⚠ URL shortener (destination hidden)</div>}
          </Panel>

          {/* 2. HTTP Fetch & Redirect Chain */}
          <Panel title="2. HTTP Fetch & Redirect Chain">
            {data.fetch.available ? (
              <>
                <FieldRow label="Final URL" value={data.fetch.finalUrl.slice(0, 80)} mono />
                <FieldRow label="Status" value={String(data.fetch.finalStatus)} mono />
                <FieldRow label="Redirects" value={String(data.fetch.redirectCount)} mono />
                <FieldRow label="Response time" value={`${data.fetch.responseTimeMs}ms`} mono />
                <FieldRow label="Content-Type" value={data.fetch.contentType || "-"} />
                <FieldRow label="Server" value={data.fetch.server || "-"} />
                <FieldRow label="Body size" value={data.fetch.bodySize ? `${data.fetch.bodySize} bytes` : "-"} mono />
                {data.fetch.redirectChain.length > 1 && (
                  <>
                    <Separator />
                    <div className="pt-2">
                      <div className="text-xs text-muted-foreground mb-1">Redirect chain:</div>
                      {data.fetch.redirectChain.map((hop, i) => (
                        <div key={i} className="text-xs flex items-center gap-2 py-1">
                          <Badge variant={hop.status >= 300 && hop.status < 400 ? "secondary" : "outline"} className="font-mono text-[10px]">
                            {hop.status}
                          </Badge>
                          <span className="font-mono text-xs truncate">{hop.url.slice(0, 100)}</span>
                        </div>
                      ))}
                    </div>
                  </>
                )}
              </>
            ) : (
              <p className="text-sm text-muted-foreground">URL could not be fetched (timeout or connection error)</p>
            )}
          </Panel>

          {/* 3. Content Extraction */}
          <Panel title="3. Content Extraction" className="md:col-span-2">
            <div className="grid grid-cols-2 md:grid-cols-4 gap-2 mb-3">
              {[
                { label: "Forms", n: data.content.forms.length, cls: data.content.forms.some(f => f.hasPasswordField && f.externalAction) ? "border-red-500/40 bg-red-500/10 text-red-400" : "border-border bg-muted/20" },
                { label: "External links", n: data.content.externalLinks.length, cls: "border-border bg-muted/20" },
                { label: "Scripts", n: data.content.scripts.length, cls: "border-border bg-muted/20" },
                { label: "Iframes", n: data.content.iframes.length, cls: data.content.iframes.some(i => i.hidden) ? "border-red-500/40 bg-red-500/10 text-red-400" : "border-border bg-muted/20" },
                { label: "Tracking pixels", n: data.content.trackingPixels, cls: "border-border bg-muted/20" },
                { label: "Emails", n: data.content.emails.length, cls: "border-border bg-muted/20" },
                { label: "Crypto addresses", n: data.content.cryptoAddresses.length, cls: data.content.cryptoAddresses.length > 0 ? "border-red-500/40 bg-red-500/10 text-red-400" : "border-border bg-muted/20" },
                { label: "GA/Meta IDs", n: data.content.googleAnalyticsIds.length + data.content.metaPixelIds.length, cls: "border-purple-500/40 bg-purple-500/10 text-purple-400" },
              ].map((b) => (
                <div key={b.label} className={`rounded p-2 border ${b.cls}`}>
                  <div className="text-xl font-bold font-mono leading-none">{b.n}</div>
                  <div className="text-[10px] mt-0.5">{b.label}</div>
                </div>
              ))}
            </div>
            <FieldRow label="Title" value={data.content.title || "(empty)"} />
            <FieldRow label="Has favicon" value={data.content.hasFavicon ? "yes" : "no — suspicious"} />
            <FieldRow label="Has viewport" value={data.content.hasViewport ? "yes" : "no — suspicious"} />
            <FieldRow label="Body MD5" value={data.content.bodyHashMd5 || "-"} mono />
            {data.content.forms.length > 0 && (
              <>
                <Separator />
                <div className="pt-2">
                  <div className="text-xs text-muted-foreground mb-1 font-semibold">Forms:</div>
                  {data.content.forms.map((form, i) => (
                    <div key={i} className={`rounded p-2 border mb-1 ${form.hasPasswordField && form.externalAction ? "border-red-500/40 bg-red-500/5" : "border-border"}`}>
                      <div className="flex items-center gap-2 flex-wrap">
                        <Badge variant="outline" className="font-mono text-[10px]">{form.method}</Badge>
                        <span className="font-mono text-xs">{form.action || "(same page)"}</span>
                        <Badge variant="outline" className="font-mono text-[10px]">{form.inputCount} inputs</Badge>
                        {form.hasPasswordField && <Badge variant="destructive" className="text-[10px]">PASSWORD</Badge>}
                        {form.externalAction && <Badge variant="destructive" className="text-[10px]">EXTERNAL ACTION — phishing risk</Badge>}
                      </div>
                    </div>
                  ))}
                </div>
              </>
            )}
            {data.content.iframes.length > 0 && data.content.iframes.some(i => i.hidden) && (
              <div className="mt-2 p-2 rounded border border-red-500/40 bg-red-500/5 text-xs text-red-400">
                ⚠ Hidden iframes detected — possible clickjacking
              </div>
            )}
            {data.content.cryptoAddresses.length > 0 && (
              <div className="mt-2 p-2 rounded border border-red-500/40 bg-red-500/5 text-xs text-red-400">
                ⚠ Cryptocurrency addresses found — possible crypto scam/extortion: {data.content.cryptoAddresses.join(", ")}
              </div>
            )}
          </Panel>

          {/* 4. VirusTotal */}
          <Panel title="4. VirusTotal URL Report" action={
            data.virusTotal.available ? (
              <a href={`https://www.virustotal.com/gui/url/${Buffer.from(data.url).toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "")}`}
                target="_blank" rel="noreferrer"
                className="text-xs text-cyan-500 hover:underline flex items-center gap-1">
                VT report <ExternalLink className="w-3 h-3" />
              </a>
            ) : undefined
          }>
            {data.virusTotal.available ? (
              <>
                <div className="flex items-center gap-3 mb-3">
                  <div className={`text-3xl font-mono font-bold ${
                    data.virusTotal.classification === "MALICIOUS" ? "text-red-500" :
                    data.virusTotal.classification === "SUSPICIOUS" ? "text-yellow-500" : "text-emerald-500"
                  }`}>
                    {data.virusTotal.flaggedEnginesCount}
                    <span className="text-base text-muted-foreground">/{data.virusTotal.totalEngines}</span>
                  </div>
                  <div>
                    <Badge variant={data.virusTotal.classification === "MALICIOUS" ? "destructive" : data.virusTotal.classification === "SUSPICIOUS" ? "default" : "secondary"} className="font-mono text-xs">
                      {data.virusTotal.classification}
                    </Badge>
                    <div className="text-[10px] text-muted-foreground mt-1">engines flag this URL</div>
                  </div>
                </div>
                <Separator />
                <FieldRow label="Reputation" value={String(data.virusTotal.reputation)} mono />
                <FieldRow label="Community votes" value={`${data.virusTotal.totalVotes.harmless} harmless / ${data.virusTotal.totalVotes.malicious} malicious`} />
                <FieldRow label="Malicious" value={data.virusTotal.lastAnalysisStats.malicious} mono />
                <FieldRow label="Suspicious" value={data.virusTotal.lastAnalysisStats.suspicious} mono />
                <FieldRow label="Harmless" value={data.virusTotal.lastAnalysisStats.harmless} mono />
                {data.virusTotal.categories.length > 0 && (
                  <>
                    <Separator />
                    <div className="pt-2 text-xs text-muted-foreground">
                      Categories: {data.virusTotal.categories.map(c => `${c.source}: ${c.category}`).join(", ")}
                    </div>
                  </>
                )}
                {data.virusTotal.flaggedEngines.length > 0 && (
                  <>
                    <Separator />
                    <div className="pt-2 max-h-32 overflow-y-auto">
                      {data.virusTotal.flaggedEngines.map((e, i) => (
                        <div key={i} className="text-xs py-0.5">
                          <span className="font-mono text-muted-foreground">[{e.engine}]</span>{" "}
                          <span className="text-red-400">{e.result}</span>
                        </div>
                      ))}
                    </div>
                  </>
                )}
              </>
            ) : (
              <p className="text-sm text-muted-foreground">VirusTotal: {data.virusTotal?.error || "not available"}</p>
            )}
          </Panel>

          {/* 5. OpenPhish */}
          <Panel title="5. OpenPhish Phishing Check">
            <div className={`p-3 rounded border mb-3 ${
              data.openPhish.isPhishing
                ? "border-red-500/40 bg-red-500/10 text-red-400"
                : "border-emerald-500/40 bg-emerald-500/10 text-emerald-400"
            }`}>
              <div className="flex items-center gap-2">
                {data.openPhish.isPhishing ? <ShieldAlert className="w-5 h-5" /> : <ShieldCheck className="w-5 h-5" />}
                <span className="font-semibold">
                  {data.openPhish.isPhishing
                    ? "PHISHING URL DETECTED — matches known phishing feed"
                    : "Not in OpenPhish phishing database"}
                </span>
              </div>
            </div>
            <FieldRow label="Checked" value={data.openPhish.checked ? "yes" : "no"} />
            <FieldRow label="Matches" value={String(data.openPhish.matchCount)} mono />
            {data.openPhish.matches.length > 0 && (
              <div className="mt-2 text-xs text-red-400">
                Matches: {data.openPhish.matches.join(", ")}
              </div>
            )}
          </Panel>

          <div className="md:col-span-2 text-[10px] text-muted-foreground font-mono">
            Query timestamp: {data.timestamp} · Powered by URL parsing, HTTP fetch, content extraction, VirusTotal URL API, OpenPhish feed.
          </div>
        </div>
      )}
    </ModuleShell>
  );
}
