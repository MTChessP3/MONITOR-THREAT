"use client";

import * as React from "react";
import {
  MapPin,
  Globe,
  Search,
  Server,
  Link as LinkIcon,
  Box,
  ShieldOff,
  ShieldCheck,
  Network,
  Loader2,
  AlertTriangle,
  ExternalLink,
  ShieldAlert,
  Printer,
} from "lucide-react";

import {
  ModuleShell,
  Panel,
  FieldRow,
  SearchBar,
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

import {
  DOMAIN_INTEL_RESULT,
  URL_SCANNER_RESULT,
  TAKEDOWN_REQUESTS,
} from "@/lib/mock-data";

const PORT_SERVICES: Record<number, string> = {
  21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
  80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS",
  465: "SMTPS", 587: "SMTP Submission", 993: "IMAPS", 995: "POP3S",
  1433: "MSSQL", 1521: "Oracle", 3306: "MySQL", 3389: "RDP",
  5432: "PostgreSQL", 5900: "VNC", 6379: "Redis",
  8080: "HTTP Alt", 8443: "HTTPS Alt",
  9001: "Tor ORPort", 9030: "Tor DirPort", 27017: "MongoDB",
};

// ---- Types for the real IP Intel API response ----
interface GeoResult {
  ip: string;
  country: string;
  countryCode: string;
  region?: string;
  city: string;
  latitude: number;
  longitude: number;
  asn?: number;
  organization?: string;
  isp?: string;
  domain?: string;
  timezone?: string;
  reverse?: string;
  flagEmoji?: string;
  provider: string;
  error?: string;
}

interface BlacklistEntry {
  rid: string;
  zone: string;
  url?: string;
  result: string;
  category: "black" | "brown" | "yellow" | "white" | "neutral" | "not_listed" | "failed";
  reason?: string;
}

interface BlacklistResult {
  ip: string;
  summary: {
    total: number;
    blacklisted: number;
    brownlisted: number;
    yellowlisted: number;
    whitelisted: number;
    neutrallisted: number;
    notListed: number;
    failed: number;
  };
  entries: BlacklistEntry[];
  embedded_url: string;
  error?: string;
}

interface PortsResult {
  ip: string;
  ports: number[];
  hostnames: string[];
  tags: string[];
  vulns: string[];
  cpes: string[];
  error?: string;
}

interface ReputationResult {
  ip: string;
  score: number;
  classification: "BENIGN" | "SUSPICIOUS" | "MALICIOUS";
  virusTotal: {
    score: number;
    classification: "BENIGN" | "SUSPICIOUS" | "MALICIOUS";
    reputation: number;
    lastAnalysisStats: {
      malicious: number;
      suspicious: number;
      undetected: number;
      harmless: number;
      timeout: number;
    };
    totalVotes: { harmless: number; malicious: number };
    totalEngines: number;
    flaggedEnginesCount: number;
    lastAnalysisDate?: string;
    available: boolean;
    error?: string;
  };
  abuseipdb: {
    available: boolean;
    abuseConfidenceScore: number;
    totalReports: number;
    numDistinctUsers: number;
    lastReportedAt?: string;
    countryCode?: string;
    usageType?: string;
    isp?: string;
    domain?: string;
    isWhitelisted?: boolean;
    classification: "BENIGN" | "SUSPICIOUS" | "MALICIOUS";
    recentReports: Array<{
      reporter: string;
      reportedAt: string;
      categories: number[];
      comment?: string;
    }>;
    error?: string;
  };
  signals: Array<{ source: string; weight: number; detail: string }>;
  tags: string[];
  threatIntel: Array<{ source: string; verdict: string; details?: string }>;
  error?: string;
}

interface AggregateResult {
  ip: string;
  geo: GeoResult;
  blacklists: BlacklistResult;
  ports: PortsResult;
  reputation: ReputationResult;
  cves: CveAssessment;
  tags: string[];
  timestamp: string;
}

interface CveDetail {
  id: string;
  source: "nvd" | "shodan";
  description?: string;
  cvssScore?: number;
  cvssSeverity?: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  cvssVector?: string;
  attackVector?: "NETWORK" | "ADJACENT" | "LOCAL" | "PHYSICAL";
  publishedDate?: string;
  lastModified?: string;
  cwe?: string;
  references?: Array<{ url: string; source?: string; tags?: string[] }>;
  affectedProducts?: string[];
  // Exploitation enrichment
  inKev?: boolean;
  kevEntry?: {
    dateAdded: string;
    dueDate: string;
    knownRansomwareCampaignUse: "Known" | "Unknown";
    requiredAction: string;
    shortDescription: string;
  };
  epss?: number;
  epssPercentile?: number;
  pocAvailable?: boolean;
  pocRepoCount?: number;
  pocTopRepos?: Array<{ name: string; url: string; stars: number; description?: string }>;
  isRecent: boolean;
  ageDays?: number;
}

interface CveAssessment {
  ip: string;
  available: boolean;
  totalCves: number;
  recentCves: number;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  kevCount: number;
  highEpssCount: number;
  pocCount: number;
  topSeverity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "NONE";
  kevCatalogVersion?: string;
  kevCatalogCount?: number;
  cves: CveDetail[];
  shodanOk: boolean;
  error?: string;
}

const CATEGORY_BADGE: Record<BlacklistEntry["category"], { label: string; cls: string }> = {
  black: { label: "BLACKLISTED", cls: "bg-red-500 text-white" },
  brown: { label: "BROWNLISTED", cls: "bg-orange-600 text-white" },
  yellow: { label: "YELLOWLISTED", cls: "bg-yellow-500 text-black" },
  white: { label: "WHITELISTED", cls: "bg-emerald-500 text-white" },
  neutral: { label: "NEUTRAL", cls: "bg-cyan-500 text-white" },
  not_listed: { label: "NOT LISTED", cls: "bg-muted text-muted-foreground" },
  failed: { label: "FAILED", cls: "bg-zinc-700 text-zinc-400" },
};

// ---------- PDF report generator (jsPDF) ----------
// Generates a structured PDF report directly in the browser and triggers
// a download. No popup window, no print dialog — the file lands in the
// user's Downloads folder as `MONITOR-THREAT-IP-Intel-<ip>-<timestamp>.pdf`.

import { jsPDF } from "jspdf";
import autoTable from "jspdf-autotable";

function classifyColorRgb(c: string): [number, number, number] {
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

  // ---------- Header ----------
  doc.setFont("helvetica", "bold");
  doc.setFontSize(22);
  doc.setTextColor(15, 23, 42);
  doc.text("IP Intelligence Report", margin, y + 8);
  doc.setFontSize(11);
  doc.setFont("helvetica", "normal");
  doc.setTextColor(220, 38, 38);
  doc.text("MONITOR-THREAT", margin, y + 26);
  doc.setTextColor(100, 116, 139);
  doc.text("Cyber Threat Intelligence Platform · v2.0", margin + 105, y + 26);

  // Right side: meta
  const ts = new Date(d.timestamp).toLocaleString();
  doc.setFontSize(10);
  doc.setTextColor(71, 85, 105);
  doc.text(`Report generated: ${ts}`, pageWidth - margin, y + 8, { align: "right" });
  doc.text(`Target IP: ${d.ip}`, pageWidth - margin, y + 22, { align: "right" });

  y += 48;
  doc.setDrawColor(220, 220, 220);
  doc.setLineWidth(0.5);
  doc.line(margin, y, pageWidth - margin, y);
  y += 28;

  // ---------- Helper: section heading ----------
  // Flow naturally down the page; only break to a new page when there's
  // not enough room for the heading + at least one row of content.
  const sectionHeading = (label: string) => {
    if (y > pageHeight - margin - 120) {
      doc.addPage();
      y = margin + 6;
    } else {
      // proportional breathing room between sections — not a forced new page
      y += 20;
    }
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

  // ---------- Helper: kv table ----------
  const kvTable = (rows: Array<[string, string]>) => {
    autoTable(doc, {
      startY: y,
      head: [["Field", "Value"]],
      body: rows.map(([k, v]) => [k, v]),
      theme: "striped",
      margin: { left: margin, right: margin },
      styles: { fontSize: 10, cellPadding: 6, textColor: [30, 41, 59], lineColor: [226, 232, 240], lineWidth: 0.5 },
      headStyles: { fillColor: [241, 245, 249], textColor: [71, 85, 105], fontStyle: "bold", fontSize: 10 },
      columnStyles: { 0: { cellWidth: contentWidth * 0.32, fontStyle: "bold", textColor: [100, 116, 139] } },
    });
    // @ts-ignore — autoTable augments doc with lastAutoTable
    y = (doc as any).lastAutoTable.finalY + 18;
  };

  // ---------- 1. Executive Summary ----------
  sectionHeading("1. Executive Summary");

  const rep = d.reputation;
  const vt = rep?.virusTotal;
  const verdictColor = classifyColorRgb(rep?.classification || "");

  // Three summary cards in a row — taller, with bigger labels and value text.
  const cardGap = 16;
  const cardW = (contentWidth - cardGap * 2) / 3;
  const cardH = 72;
  // Card 1: composite score
  doc.setFillColor(248, 250, 252);
  doc.setDrawColor(220, 220, 220);
  doc.setLineWidth(0.5);
  doc.roundedRect(margin, y, cardW, cardH, 6, 6, "FD");
  doc.setFont("helvetica", "normal");
  doc.setFontSize(9);
  doc.setTextColor(100, 116, 139);
  doc.text("COMPOSITE SCORE", margin + 12, y + 18);
  doc.setFont("helvetica", "bold");
  doc.setFontSize(26);
  doc.setTextColor(15, 23, 42);
  doc.text(`${rep?.score ?? "-"}`, margin + 12, y + 48);
  doc.setFont("helvetica", "normal");
  doc.setFontSize(11);
  doc.setTextColor(148, 163, 184);
  doc.text("/100", margin + 12 + doc.getTextWidth(`${rep?.score ?? "-"}`) * 1.05, y + 48);

  // Card 2: classification (color-coded, bold border)
  doc.setFillColor(248, 250, 252);
  doc.setDrawColor(verdictColor[0], verdictColor[1], verdictColor[2]);
  doc.setLineWidth(2);
  doc.roundedRect(margin + cardW + cardGap, y, cardW, cardH, 6, 6, "FD");
  doc.setLineWidth(0.5);
  doc.setFont("helvetica", "normal");
  doc.setFontSize(9);
  doc.setTextColor(100, 116, 139);
  doc.text("CLASSIFICATION", margin + cardW + cardGap + 12, y + 18);
  doc.setFont("helvetica", "bold");
  doc.setFontSize(22);
  doc.setTextColor(verdictColor[0], verdictColor[1], verdictColor[2]);
  doc.text(rep?.classification || "—", margin + cardW + cardGap + 12, y + 48);

  // Card 3: VT engines
  doc.setFillColor(248, 250, 252);
  doc.setDrawColor(220, 220, 220);
  doc.roundedRect(margin + (cardW + cardGap) * 2, y, cardW, cardH, 6, 6, "FD");
  doc.setFont("helvetica", "normal");
  doc.setFontSize(9);
  doc.setTextColor(100, 116, 139);
  doc.text("VIRUSTOTAL ENGINES", margin + (cardW + cardGap) * 2 + 12, y + 18);
  doc.setFont("helvetica", "bold");
  doc.setFontSize(26);
  doc.setTextColor(15, 23, 42);
  doc.text(
    `${vt?.flaggedEnginesCount ?? "-"}/${vt?.totalEngines ?? "-"}`,
    margin + (cardW + cardGap) * 2 + 12,
    y + 48
  );

  y += cardH + 24;

  // Verdict narrative — more space around it
  const verdict =
    rep?.classification === "MALICIOUS"
      ? "Multiple sources agree this IP is associated with malicious activity. Immediate containment and investigation are recommended."
      : rep?.classification === "SUSPICIOUS"
      ? "Some sources flagged this IP. Investigate before allowing traffic from this host."
      : "No source flagged this IP as malicious. Treat as benign unless new intelligence emerges.";
  doc.setFont("helvetica", "normal");
  doc.setFontSize(10);
  doc.setTextColor(51, 65, 85);
  const wrapped = doc.splitTextToSize(verdict, contentWidth);
  doc.text(wrapped, margin, y);
  y += wrapped.length * 14 + 18;

  // ---------- 2. Geolocation & ASN ----------
  sectionHeading("2. Geolocation & ASN");
  const geo = d.geo;
  if (geo && !geo.error) {
    kvTable([
      ["IP", geo.ip],
      ["Country", `${geo.flagEmoji || ""} ${geo.country} (${geo.countryCode})`],
      ["Region", geo.region || "-"],
      ["City", geo.city],
      ["Coordinates", `${geo.latitude}, ${geo.longitude}`],
      ["ASN", `AS${geo.asn || "-"}`],
      ["Organization", geo.organization || "-"],
      ["ISP", geo.isp || "-"],
      ["Domain", geo.domain || "-"],
      ["Timezone", geo.timezone || "-"],
      ["rDNS", geo.reverse || "-"],
    ]);
    doc.setFontSize(9);
    doc.setTextColor(148, 163, 184);
    doc.text(`Source: ${geo.provider || "ipwho.is"}`, margin, y);
    y += 22;
  } else {
    doc.setTextColor(148, 163, 184);
    doc.text(`Geolocation lookup failed: ${geo?.error || "no data"}`, margin, y);
    y += 22;
  }

  // ---------- 3. Open Ports & Services ----------
  sectionHeading("3. Open Ports & Services");
  const ports = d.ports;
  if (ports && !ports.error) {
    const portsStr =
      (ports.ports || []).length > 0
        ? (ports.ports || [])
            .map((p) => `:${p}${PORT_SERVICES[p] ? ` (${PORT_SERVICES[p]})` : ""}`)
            .join("  ")
        : "none recorded";
    kvTable([
      ["Open ports", `${ports.ports?.length || 0} — ${portsStr}`],
      ["Hostnames", (ports.hostnames || []).join(", ") || "-"],
      ["Known CVEs", (ports.vulns || []).slice(0, 15).join(", ") || "none"],
      ["CPEs", (ports.cpes || []).slice(0, 5).join(", ") || "-"],
    ]);
    doc.setFontSize(9);
    doc.setTextColor(148, 163, 184);
    doc.text(
      `Source: Shodan InternetDB · ${ports.ports?.length || 0} ports · ${ports.hostnames?.length || 0} hostnames · ${ports.vulns?.length || 0} CVEs`,
      margin,
      y
    );
    y += 22;
  } else {
    doc.setTextColor(148, 163, 184);
    doc.text(`Shodan lookup failed: ${ports?.error || "no data"}`, margin, y);
    y += 22;
  }

  // ---------- 4. Reputation — VirusTotal ----------
  sectionHeading("4. Reputation — VirusTotal");
  if (vt?.available) {
    const stats = vt.lastAnalysisStats;
    kvTable([
      ["VT Score (composite)", `${vt.score}/100 — ${vt.classification}`],
      ["Flagging engines", `${vt.flaggedEnginesCount} / ${vt.totalEngines}`],
      [
        "Engine breakdown",
        `Malicious: ${stats.malicious}  ·  Suspicious: ${stats.suspicious}  ·  Undetected: ${stats.undetected}  ·  Harmless: ${stats.harmless}  ·  Timeout: ${stats.timeout}`,
      ],
      ["Community reputation", `${vt.reputation > 0 ? "+" : ""}${vt.reputation}`],
      [
        "Community votes",
        `${vt.totalVotes.harmless} harmless · ${vt.totalVotes.malicious} malicious`,
      ],
      ["Last analysis", vt.lastAnalysisDate ? new Date(vt.lastAnalysisDate).toLocaleString() : "-"],
    ]);
    doc.setFontSize(9);
    doc.setTextColor(8, 145, 178);
    doc.textWithLink(
      `Open full VirusTotal report ↗`,
      margin,
      y,
      { url: `https://www.virustotal.com/gui/ip-address/${encodeURIComponent(d.ip)}` }
    );
    y += 22;
  } else {
    doc.setTextColor(148, 163, 184);
    doc.text(`VirusTotal not available: ${vt?.error || "no data"}`, margin, y);
    y += 22;
  }

  // ---------- 5. Reputation — AbuseIPDB ----------
  sectionHeading("5. Reputation — AbuseIPDB");
  const ab = d.reputation?.abuseipdb;
  if (ab?.available) {
    const abColor = classifyColorRgb(ab.classification || "");
    // Composite score card
    const abCardH = 60;
    doc.setFillColor(248, 250, 252);
    doc.setDrawColor(abColor[0], abColor[1], abColor[2]);
    doc.setLineWidth(2);
    doc.roundedRect(margin, y, contentWidth, abCardH, 6, 6, "FD");
    doc.setLineWidth(0.5);

    doc.setFont("helvetica", "normal");
    doc.setFontSize(9);
    doc.setTextColor(100, 116, 139);
    doc.text("ABUSE CONFIDENCE", margin + 14, y + 16);
    doc.setFont("helvetica", "bold");
    doc.setFontSize(26);
    doc.setTextColor(abColor[0], abColor[1], abColor[2]);
    doc.text(`${ab.abuseConfidenceScore}%`, margin + 14, y + 44);
    doc.setFont("helvetica", "normal");
    doc.setFontSize(10);
    doc.setTextColor(15, 23, 42);
    doc.text(`Classification: ${ab.classification}`, margin + 150, y + 18);
    doc.text(
      `${ab.totalReports} reports by ${ab.numDistinctUsers} distinct users in last 90 days`,
      margin + 150,
      y + 32
    );
    if (ab.lastReportedAt) {
      doc.text(
        `Last report: ${new Date(ab.lastReportedAt).toLocaleString()}`,
        margin + 150,
        y + 46
      );
    }
    if (ab.isWhitelisted) {
      doc.setTextColor(22, 163, 74);
      doc.text("Whitelisted by AbuseIPDB", margin + 150, y + 58);
    }
    y += abCardH + 18;

    // Network metadata
    kvTable([
      ["Country", ab.countryCode || "-"],
      ["Usage type", ab.usageType || "-"],
      ["ISP", ab.isp || "-"],
      ["Domain", ab.domain || "-"],
    ]);

    // Recent reports
    if (ab.recentReports.length > 0) {
      if (y > pageHeight - 100) {
        doc.addPage();
        y = margin + 6;
      }
      doc.setFont("helvetica", "bold");
      doc.setFontSize(11);
      doc.setTextColor(15, 23, 42);
      doc.text(`Recent reports (${ab.recentReports.length})`, margin, y);
      y += 8;
      autoTable(doc, {
        startY: y,
        head: [["Reporter", "Date", "Comment"]],
        body: ab.recentReports.map((r: any) => [
          r.reporter,
          r.reportedAt ? r.reportedAt.slice(0, 16).replace("T", " ") : "-",
          r.comment || `Categories: ${(r.categories || []).join(", ")}`,
        ]),
        theme: "grid",
        margin: { left: margin, right: margin },
        styles: { fontSize: 9, cellPadding: 5, textColor: [30, 41, 59], lineColor: [226, 232, 240], lineWidth: 0.5 },
        headStyles: { fillColor: [241, 245, 249], textColor: [71, 85, 105], fontStyle: "bold", fontSize: 10 },
        columnStyles: { 0: { cellWidth: 90 }, 1: { cellWidth: 130 } },
      });
      // @ts-ignore
      y = (doc as any).lastAutoTable.finalY + 18;
    }
    doc.setFontSize(9);
    doc.setTextColor(8, 145, 178);
    doc.textWithLink(
      `Open full AbuseIPDB report ↗`,
      margin,
      y,
      { url: `https://www.abuseipdb.com/check/${encodeURIComponent(d.ip)}` }
    );
    y += 22;
  } else {
    doc.setTextColor(148, 163, 184);
    doc.text(`AbuseIPDB not available: ${ab?.error || "no data"}`, margin, y);
    y += 22;
  }

  // ---------- 6. DNSBL / Blacklist Summary ----------
  sectionHeading("6. DNSBL / Blacklist Summary");
  const bl = d.blacklists;
  if (bl && !bl.error) {
    const s = bl.summary;
    kvTable([
      ["Total zones checked", String(s.total)],
      ["Blacklisted", String(s.blacklisted)],
      ["Brownlisted", String(s.brownlisted)],
      ["Yellowlisted", String(s.yellowlisted)],
      ["Whitelisted", String(s.whitelisted)],
      ["Not listed", String(s.notListed)],
      ["Failed queries", String(s.failed)],
    ]);

    // Flagged zones table
    const blListed = (bl.entries || []).filter(
      (e) => e.category === "black" || e.category === "brown" || e.category === "yellow"
    );
    if (blListed.length > 0) {
      if (y > pageHeight - 100) {
        doc.addPage();
        y = margin;
      }
      doc.setFont("helvetica", "bold");
      doc.setFontSize(11);
      doc.setTextColor(15, 23, 42);
      doc.text(`Flagged DNSBL zones (${blListed.length})`, margin, y);
      y += 8;
      autoTable(doc, {
        startY: y,
        head: [["Status", "Zone", "Reason"]],
        body: blListed.slice(0, 30).map((e) => [
          CATEGORY_BADGE[e.category].label,
          e.zone,
          e.reason || e.result,
        ]),
        theme: "grid",
        margin: { left: margin, right: margin },
        styles: { fontSize: 9, cellPadding: 5, textColor: [30, 41, 59], lineColor: [226, 232, 240], lineWidth: 0.5 },
        headStyles: { fillColor: [241, 245, 249], textColor: [71, 85, 105], fontStyle: "bold", fontSize: 10 },
        columnStyles: { 0: { cellWidth: 100 }, 1: { cellWidth: 170 } },
      });
      // @ts-ignore
      y = (doc as any).lastAutoTable.finalY + 8;
      if (blListed.length > 30) {
        doc.setFontSize(9);
        doc.setTextColor(148, 163, 184);
        doc.text(
          `+ ${blListed.length - 30} more — see full report on multirbl.valli.org.`,
          margin,
          y
        );
        y += 16;
      }
    } else {
      doc.setFontSize(10);
      doc.setTextColor(148, 163, 184);
      doc.text("No DNSBL zone flagged this IP.", margin, y);
      y += 22;
    }
    doc.setFontSize(9);
    doc.setTextColor(8, 145, 178);
    doc.textWithLink("Open full multirbl.valli.org report ↗", margin, y, { url: bl.embedded_url });
    y += 22;
  } else {
    doc.setTextColor(148, 163, 184);
    doc.text(`Blacklist lookup failed: ${bl?.error || "no data"}`, margin, y);
    y += 22;
  }

  // ---------- 7. Threat Intel Sources ----------
  sectionHeading("7. Threat Intel Sources");
  if (rep?.threatIntel && rep.threatIntel.length > 0) {
    autoTable(doc, {
      startY: y,
      head: [["Source", "Verdict", "Details"]],
      body: rep.threatIntel.map((t) => [t.source, t.verdict, t.details || "-"]),
      theme: "grid",
      margin: { left: margin, right: margin },
      styles: { fontSize: 9, cellPadding: 5, textColor: [30, 41, 59], lineColor: [226, 232, 240], lineWidth: 0.5 },
      headStyles: { fillColor: [241, 245, 249], textColor: [71, 85, 105], fontStyle: "bold", fontSize: 10 },
      columnStyles: { 0: { cellWidth: 120, fontStyle: "bold" }, 1: { cellWidth: 100 } },
    });
    // @ts-ignore
    y = (doc as any).lastAutoTable.finalY + 18;
  } else {
    doc.setTextColor(148, 163, 184);
    doc.text("No threat intel data.", margin, y);
    y += 22;
  }

  // ---------- 8. Additional Signals ----------
  sectionHeading("8. Additional Signals");
  if (rep?.signals && rep.signals.length > 0) {
    autoTable(doc, {
      startY: y,
      head: [["Source", "Weight", "Detail"]],
      body: rep.signals.map((s) => [s.source, `+${s.weight}`, s.detail]),
      theme: "grid",
      margin: { left: margin, right: margin },
      styles: { fontSize: 9, cellPadding: 5, textColor: [30, 41, 59], lineColor: [226, 232, 240], lineWidth: 0.5 },
      headStyles: { fillColor: [241, 245, 249], textColor: [71, 85, 105], fontStyle: "bold", fontSize: 10 },
      columnStyles: { 0: { cellWidth: 120, fontStyle: "bold" }, 1: { cellWidth: 60 } },
    });
    // @ts-ignore
    y = (doc as any).lastAutoTable.finalY + 18;
  } else {
    doc.setTextColor(148, 163, 184);
    doc.text("No additional signals.", margin, y);
    y += 22;
  }

  // ---------- 9. Methodology & Sources ----------
  sectionHeading("9. Methodology & Sources");
  doc.setFontSize(10);
  doc.setTextColor(51, 65, 85);
  const methodology =
    "This report was generated by aggregating live data from the following open and free-tier intelligence services:";
  doc.text(doc.splitTextToSize(methodology, contentWidth), margin, y);
  y += 24;

  autoTable(doc, {
    startY: y,
    head: [["Source", "Use"]],
    body: [
      ["ipwho.is / ip-api.com", "IP geolocation and ASN (free, no API key)"],
      ["multirbl.valli.org", "DNSBL lookup across 200+ blacklist zones, plus direct DNSBL DNS checks against 15 well-known zones (Spamhaus, SpamCop, SORBS, Barracuda, UCEProtect, CBL, Mailspike, SpamRats, ...)"],
      ["Shodan InternetDB", "Open ports, hostnames, tags and known CVEs (free, no API key)"],
      ["VirusTotal v3", "Last analysis stats, per-engine verdicts, community votes and reputation score"],
      ["AbuseIPDB", "Abuse reports in the last 90 days (optional, when ABUSEIPDB_API_KEY is configured)"],
    ],
    theme: "grid",
    margin: { left: margin, right: margin },
    styles: { fontSize: 9, cellPadding: 5, textColor: [30, 41, 59], lineColor: [226, 232, 240], lineWidth: 0.5 },
    headStyles: { fillColor: [241, 245, 249], textColor: [71, 85, 105], fontStyle: "bold", fontSize: 10 },
    columnStyles: { 0: { cellWidth: 140, fontStyle: "bold" } },
  });
  // @ts-ignore
  y = (doc as any).lastAutoTable.finalY + 20;

  doc.setFontSize(9);
  doc.setTextColor(100, 116, 139);
  doc.text(
    doc.splitTextToSize(
      "Composite score = VirusTotal score (primary) + weighted signals from DNSBL, Shodan and AbuseIPDB (capped at 100). Classification thresholds: BENIGN < 5, SUSPICIOUS 5-19, MALICIOUS >= 20.",
      contentWidth
    ),
    margin,
    y
  );
  y += 32;

  // ---------- Footer on every page ----------
  const pageCount = doc.getNumberOfPages();
  for (let i = 1; i <= pageCount; i++) {
    doc.setPage(i);
    doc.setFontSize(8);
    doc.setTextColor(148, 163, 184);
    doc.text(
      `MONITOR-THREAT v2.0  ·  Generated ${ts}  ·  Page ${i} of ${pageCount}`,
      pageWidth / 2,
      pageHeight - 22,
      { align: "center" }
    );
    doc.text("This report is for informational purposes only and does not constitute legal advice.", pageWidth / 2, pageHeight - 10, { align: "center" });
  }

  // ---------- Trigger download ----------
  const safeIp = d.ip.replace(/[^a-zA-Z0-9._:-]/g, "_");
  const fname = `MONITOR-THREAT-IP-Intel-${safeIp}-${Date.now()}.pdf`;
  doc.save(fname);
}

// ---------- IP Intel (real APIs) ----------
export function IpIntelView() {
  const [input, setInput] = React.useState("");
  const [loading, setLoading] = React.useState(false);
  const [data, setData] = React.useState<AggregateResult | null>(null);
  const [error, setError] = React.useState<string | null>(null);
  const abortRef = React.useRef<AbortController | null>(null);

  async function analyze(ip: string) {
    if (!ip.trim()) return;
    abortRef.current?.abort();
    const ac = new AbortController();
    abortRef.current = ac;

    setLoading(true);
    setError(null);
    try {
      const res = await fetch(
        `/api/ip-intel/aggregate?ip=${encodeURIComponent(ip.trim())}`,
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

  // No auto-query on mount — the user must enter an IP and click Analyze.
  // This way the module does not get stuck on the last query of a previous session.

  return (
    <ModuleShell
      name="IP Intel"
      description="Geolocation, ASN, open ports, reputation and threat intel for an IP address. Powered by VirusTotal, multirbl.valli.org, ipwho.is and Shodan InternetDB."
      icon={MapPin}
      category="INFRASTRUCTURE"
      status={loading ? "QUERYING" : "READY"}
    >
      <div className="flex flex-col gap-2 mb-4">
        <label className="text-xs font-medium text-muted-foreground uppercase tracking-wider">
          IP address (IPv4 / IPv6)
        </label>
        <div className="flex gap-2">
          <Input
            type="text"
            placeholder="e.g. 8.8.8.8, 185.220.101.34, 2001:4860:4860::8888"
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
              <>
                <Loader2 className="w-3.5 h-3.5 mr-2 animate-spin" />
                Analyzing…
              </>
            ) : (
              <>
                <Search className="w-3.5 h-3.5 mr-2" />
                Analyze
              </>
            )}
          </Button>
          <Button
            type="button"
            size="sm"
            variant="outline"
            onClick={() => downloadPdfReport(data!)}
            disabled={!data}
            title={data ? "Download a structured PDF report (saves to your Downloads folder)" : "Run an analysis first"}
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

      {data && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {/* Geolocation & ASN */}
          <Panel
            title="Geolocation & ASN"
            action={
              data.geo?.latitude && data.geo?.longitude ? (
                <a
                  href={`https://www.openstreetmap.org/?mlat=${data.geo.latitude}&mlon=${data.geo.longitude}#map=12/${data.geo.latitude}/${data.geo.longitude}`}
                  target="_blank"
                  rel="noreferrer"
                  className="text-xs text-cyan-500 hover:underline flex items-center gap-1"
                >
                  OpenStreetMap <ExternalLink className="w-3 h-3" />
                </a>
              ) : undefined
            }
          >
            {data.geo?.error ? (
              <p className="text-sm text-muted-foreground">{data.geo.error}</p>
            ) : data.geo ? (
              <>
                <FieldRow label="IP" value={data.geo.ip} mono />
                <FieldRow
                  label="Country"
                  value={`${data.geo.flagEmoji || "🌐"} ${data.geo.country} (${data.geo.countryCode})`}
                />
                {data.geo.region && (
                  <FieldRow label="Region" value={data.geo.region} />
                )}
                <FieldRow label="City" value={data.geo.city} />
                <FieldRow
                  label="Coordinates"
                  value={`${data.geo.latitude}, ${data.geo.longitude}`}
                  mono
                />
                {data.geo.asn && (
                  <FieldRow label="ASN" value={`AS${data.geo.asn}`} mono />
                )}
                {data.geo.organization && (
                  <FieldRow label="Organization" value={data.geo.organization} />
                )}
                {data.geo.isp && <FieldRow label="ISP" value={data.geo.isp} />}
                {data.geo.domain && (
                  <FieldRow label="Domain" value={data.geo.domain} mono />
                )}
                {data.geo.timezone && (
                  <FieldRow label="Timezone" value={data.geo.timezone} mono />
                )}
                {data.geo.reverse && (
                  <FieldRow label="rDNS" value={data.geo.reverse} mono />
                )}
                <div className="mt-2 pt-2 text-[10px] text-muted-foreground border-t border-border/40">
                  Source: {data.geo.provider}
                </div>
              </>
            ) : (
              <p className="text-sm text-muted-foreground">No data.</p>
            )}
          </Panel>

          {/* OpenStreetMap embed */}
          <Panel title="OpenStreetMap View">
            {data.geo?.latitude && data.geo?.longitude ? (
              <div className="flex flex-col gap-2">
                <div className="rounded-md overflow-hidden border border-border">
                  <iframe
                    title="OpenStreetMap"
                    className="w-full h-[260px]"
                    loading="lazy"
                    src={`https://www.openstreetmap.org/export/embed.html?bbox=${
                      data.geo.longitude - 0.15
                    }%2C${data.geo.latitude - 0.1}%2C${
                      data.geo.longitude + 0.15
                    }%2C${data.geo.latitude + 0.1}&layer=mapnik&marker=${data.geo.latitude}%2C${data.geo.longitude}`}
                  />
                </div>
                <Button variant="outline" size="sm" asChild>
                  <a
                    href={`https://www.openstreetmap.org/?mlat=${data.geo.latitude}&mlon=${data.geo.longitude}#map=12/${data.geo.latitude}/${data.geo.longitude}`}
                    target="_blank"
                    rel="noreferrer"
                  >
                    <ExternalLink className="w-3 h-3 mr-1" />
                    Open in OpenStreetMap
                  </a>
                </Button>
              </div>
            ) : (
              <p className="text-sm text-muted-foreground">
                No coordinates available.
              </p>
            )}
          </Panel>

          {/* Open Ports */}
          <Panel title="Open Ports & Services">
            {data.ports?.error ? (
              <p className="text-sm text-muted-foreground">{data.ports.error}</p>
            ) : data.ports ? (
              <>
                <div className="flex flex-wrap gap-1.5 mb-3">
                  {data.ports.ports.length > 0 ? (
                    data.ports.ports.map((p) => (
                      <Badge
                        key={p}
                        variant="outline"
                        className="font-mono text-xs"
                        title={PORT_SERVICES[p] || ""}
                      >
                        :{p}{" "}
                        {PORT_SERVICES[p] && (
                          <span className="text-muted-foreground ml-1">
                            {PORT_SERVICES[p]}
                          </span>
                        )}
                      </Badge>
                    ))
                  ) : (
                    <span className="text-sm text-muted-foreground">
                      No open ports recorded by Shodan.
                    </span>
                  )}
                </div>
                {data.ports.hostnames.length > 0 && (
                  <>
                    <Separator />
                    <div className="pt-2">
                      <span className="text-xs text-muted-foreground">Hostnames:</span>
                      <div className="flex flex-wrap gap-1 mt-1">
                        {data.ports.hostnames.map((h) => (
                          <Badge key={h} variant="secondary" className="font-mono text-[10px]">
                            {h}
                          </Badge>
                        ))}
                      </div>
                    </div>
                  </>
                )}
                {data.ports.vulns.length > 0 && (
                  <div className="mt-2 pt-2 border-t border-border/40">
                    <span className="text-xs text-red-500">Known CVEs:</span>
                    <div className="flex flex-wrap gap-1 mt-1">
                      {data.ports.vulns.slice(0, 12).map((v) => (
                        <Badge
                          key={v}
                          variant="destructive"
                          className="font-mono text-[10px]"
                        >
                          {v}
                        </Badge>
                      ))}
                    </div>
                  </div>
                )}
                <div className="mt-2 pt-2 text-[10px] text-muted-foreground border-t border-border/40">
                  Source: Shodan InternetDB · {data.ports.ports.length} ports ·{" "}
                  {data.ports.hostnames.length} hostnames
                </div>
              </>
            ) : (
              <p className="text-sm text-muted-foreground">No data.</p>
            )}
          </Panel>

          {/* Vulnerability Assessment (CVE) */}
          <Panel
            title="Vulnerability Assessment (CVE)"
            className="md:col-span-2"
            action={
              data.cves?.available ? (
                <a
                  href={`https://internetdb.shodan.io/${data.ip}`}
                  target="_blank"
                  rel="noreferrer"
                  className="text-xs text-cyan-500 hover:underline flex items-center gap-1"
                >
                  Shodan raw vuln list <ExternalLink className="w-3 h-3" />
                </a>
              ) : undefined
            }
          >
            {data.cves?.error && !data.cves.available ? (
              <p className="text-sm text-muted-foreground">
                CVE assessment failed: {data.cves.error}
              </p>
            ) : data.cves ? (
              <div className="flex flex-col gap-3">
                {/* Summary cards — now 8 cards showing all enrichment dimensions */}
                <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-8 gap-2">
                  {[
                    { label: "Total CVEs", n: data.cves.totalCves, cls: "border-border bg-muted/20" },
                    { label: "Recent (<2 mo)", n: data.cves.recentCves, cls: "border-yellow-500/40 bg-yellow-500/10 text-yellow-400" },
                    { label: "Critical", n: data.cves.criticalCount, cls: "border-red-500/40 bg-red-500/10 text-red-400" },
                    { label: "High", n: data.cves.highCount, cls: "border-orange-500/40 bg-orange-500/10 text-orange-400" },
                    { label: "CISA KEV", n: data.cves.kevCount, cls: "border-fuchsia-500/60 bg-fuchsia-500/10 text-fuchsia-400" },
                    { label: "High EPSS", n: data.cves.highEpssCount, cls: "border-pink-500/40 bg-pink-500/10 text-pink-400" },
                    { label: "PoC public", n: data.cves.pocCount, cls: "border-emerald-500/40 bg-emerald-500/10 text-emerald-400" },
                    { label: "Medium / Low", n: data.cves.mediumCount + data.cves.lowCount, cls: "border-blue-500/40 bg-blue-500/10 text-blue-400" },
                  ].map((b) => (
                    <div key={b.label} className={`rounded p-2 border ${b.cls}`}>
                      <div className="text-xl font-bold font-mono leading-none">{b.n}</div>
                      <div className="text-[10px] mt-0.5">{b.label}</div>
                    </div>
                  ))}
                </div>

                {/* CISA KEV catalog banner when KEV CVEs are present */}
                {data.cves.kevCount > 0 && data.cves.kevCatalogVersion && (
                  <div className="rounded border border-fuchsia-500/40 bg-fuchsia-500/10 p-2 text-xs flex items-center gap-2">
                    <AlertTriangle className="w-4 h-4 text-fuchsia-500" />
                    <span className="text-fuchsia-300">
                      <strong className="font-mono">{data.cves.kevCount}</strong> CVE
                      {data.cves.kevCount !== 1 ? "s" : ""} on this IP match the CISA Known
                      Exploited Vulnerabilities catalog (v{data.cves.kevCatalogVersion}, {data.cves.kevCatalogCount} entries).
                      These are being actively exploited in the wild.
                    </span>
                  </div>
                )}

                {data.cves.totalCves === 0 ? (
                  <p className="text-sm text-emerald-500 flex items-center gap-2">
                    <ShieldCheck className="w-4 h-4" />
                    No known CVEs associated with this IP per Shodan InternetDB.
                  </p>
                ) : (
                  <div className="flex flex-col gap-2 max-h-[600px] overflow-y-auto">
                    {data.cves.cves.map((cve) => (
                      <div
                        key={cve.id}
                        className={`rounded border p-3 ${
                          cve.inKev
                            ? "border-fuchsia-500/60 bg-fuchsia-500/5"
                            : cve.isRecent
                            ? "border-yellow-500/60 bg-yellow-500/5"
                            : cve.cvssSeverity === "CRITICAL"
                            ? "border-red-500/40 bg-red-500/5"
                            : cve.cvssSeverity === "HIGH"
                            ? "border-orange-500/40 bg-orange-500/5"
                            : "border-border"
                        }`}
                      >
                        <div className="flex items-start gap-3">
                          <div className="shrink-0 flex flex-col items-center">
                            {cve.cvssScore !== undefined && (
                              <div
                                className={`text-xl font-mono font-bold leading-none ${
                                  cve.cvssSeverity === "CRITICAL"
                                    ? "text-red-500"
                                    : cve.cvssSeverity === "HIGH"
                                    ? "text-orange-500"
                                    : cve.cvssSeverity === "MEDIUM"
                                    ? "text-yellow-500"
                                    : "text-blue-500"
                                }`}
                              >
                                {cve.cvssScore}
                              </div>
                            )}
                            {cve.cvssSeverity && (
                              <Badge
                                variant={
                                  cve.cvssSeverity === "CRITICAL"
                                    ? "destructive"
                                    : cve.cvssSeverity === "HIGH"
                                    ? "default"
                                    : "secondary"
                                }
                                className="font-mono text-[9px] mt-1"
                              >
                                {cve.cvssSeverity}
                              </Badge>
                            )}
                          </div>
                          <div className="flex-1 min-w-0">
                            <div className="flex items-center gap-2 flex-wrap">
                              <a
                                href={`https://nvd.nist.gov/vuln/detail/${cve.id}`}
                                target="_blank"
                                rel="noreferrer"
                                className="font-mono text-sm text-cyan-500 hover:underline"
                              >
                                {cve.id}
                              </a>
                              {cve.inKev && (
                                <Badge
                                  variant="destructive"
                                  className="text-[9px] font-mono bg-fuchsia-600 hover:bg-fuchsia-600"
                                  title={`In CISA KEV since ${cve.kevEntry?.dateAdded}. Ransomware use: ${cve.kevEntry?.knownRansomwareCampaignUse || "Unknown"}. Required action: ${cve.kevEntry?.requiredAction || ""}`}
                                >
                                  CISA KEV · RANSOMWARE {cve.kevEntry?.knownRansomwareCampaignUse === "Known" ? "✓" : "?"}
                                </Badge>
                              )}
                              {cve.epssPercentile !== undefined && (
                                <Badge
                                  variant="outline"
                                  className={`text-[9px] font-mono ${
                                    cve.epssPercentile >= 0.95
                                      ? "text-pink-500 border-pink-500/60"
                                      : cve.epssPercentile >= 0.5
                                      ? "text-orange-500 border-orange-500/40"
                                      : "text-muted-foreground"
                                  }`}
                                  title={`EPSS probability of exploitation in next 30 days: ${(cve.epss * 100).toFixed(2)}% (percentile ${(cve.epssPercentile * 100).toFixed(2)}%)`}
                                >
                                  EPSS {(cve.epssPercentile * 100).toFixed(1)}%
                                </Badge>
                              )}
                              {cve.pocAvailable && (
                                <Badge
                                  variant="outline"
                                  className="text-[9px] font-mono text-emerald-500 border-emerald-500/40"
                                  title={`${cve.pocRepoCount} public PoC repo(s) on GitHub`}
                                >
                                  PoC × {cve.pocRepoCount}
                                </Badge>
                              )}
                              {cve.isRecent && (
                                <Badge
                                  variant="outline"
                                  className="text-[9px] font-mono text-yellow-500 border-yellow-500/40"
                                >
                                  RECENT · {cve.ageDays}d ago
                                </Badge>
                              )}
                              {cve.attackVector && (
                                <Badge variant="outline" className="text-[9px] font-mono">
                                  {cve.attackVector}
                                </Badge>
                              )}
                              {cve.cwe && (
                                <Badge variant="outline" className="text-[9px] font-mono">
                                  {cve.cwe}
                                </Badge>
                              )}
                            </div>
                            {cve.description && (
                              <p className="text-xs text-muted-foreground mt-1 line-clamp-3">
                                {cve.description}
                              </p>
                            )}
                            {cve.affectedProducts && cve.affectedProducts.length > 0 && (
                              <div className="mt-1 flex flex-wrap gap-1">
                                {cve.affectedProducts.slice(0, 5).map((p) => (
                                  <Badge
                                    key={p}
                                    variant="secondary"
                                    className="font-mono text-[9px]"
                                  >
                                    {p}
                                  </Badge>
                                ))}
                              </div>
                            )}
                            {cve.inKev && cve.kevEntry && (
                              <div className="mt-2 rounded p-2 bg-fuchsia-500/5 border border-fuchsia-500/20 text-xs">
                                <div className="text-fuchsia-300 font-semibold mb-1">
                                  CISA KEV entry
                                </div>
                                <div className="text-muted-foreground">
                                  <span className="font-mono">Added:</span> {cve.kevEntry.dateAdded}{" "}
                                  · <span className="font-mono">Due:</span> {cve.kevEntry.dueDate}{" "}
                                  · <span className="font-mono">Ransomware:</span>{" "}
                                  <span className={cve.kevEntry.knownRansomwareCampaignUse === "Known" ? "text-red-500 font-semibold" : "text-muted-foreground"}>
                                    {cve.kevEntry.knownRansomwareCampaignUse}
                                  </span>
                                </div>
                                <div className="mt-1 text-muted-foreground">
                                  <span className="font-mono">Required:</span> {cve.kevEntry.requiredAction}
                                </div>
                              </div>
                            )}
                            {cve.pocAvailable && cve.pocTopRepos && cve.pocTopRepos.length > 0 && (
                              <div className="mt-2 flex flex-col gap-1">
                                <div className="text-[10px] text-muted-foreground font-semibold">
                                  Public PoC repositories:
                                </div>
                                {cve.pocTopRepos.slice(0, 3).map((r) => (
                                  <a
                                    key={r.url}
                                    href={r.url}
                                    target="_blank"
                                    rel="noreferrer"
                                    className="text-[10px] text-emerald-500 hover:underline flex items-center gap-1"
                                  >
                                    <span>★ {r.stars}</span>
                                    <span className="font-mono">{r.name}</span>
                                  </a>
                                ))}
                              </div>
                            )}
                            {cve.publishedDate && (
                              <div className="text-[10px] text-muted-foreground mt-1">
                                Published: {new Date(cve.publishedDate).toLocaleDateString()}
                                {cve.cvssVector && (
                                  <span className="ml-2 font-mono">[{cve.cvssVector}]</span>
                                )}
                              </div>
                            )}
                            {cve.references && cve.references.length > 0 && (
                              <div className="mt-1 flex flex-wrap gap-x-3 gap-y-1">
                                {cve.references.slice(0, 3).map((r) => (
                                  <a
                                    key={r.url}
                                    href={r.url}
                                    target="_blank"
                                    rel="noreferrer"
                                    className="text-[10px] text-cyan-500 hover:underline truncate max-w-md"
                                  >
                                    ↗ {r.url.replace(/^https?:\/\//, "").slice(0, 60)}
                                    {r.url.length > 60 ? "…" : ""}
                                  </a>
                                ))}
                              </div>
                            )}
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            ) : (
              <p className="text-sm text-muted-foreground">No CVE data.</p>
            )}
          </Panel>

          {/* Reputation — VirusTotal powered */}
          <Panel
            title="Reputation"
            className="md:col-span-2"
            action={
              data.reputation?.virusTotal?.available ? (
                <a
                  href={`https://www.virustotal.com/gui/ip-address/${data.ip}`}
                  target="_blank"
                  rel="noreferrer"
                  className="text-xs text-cyan-500 hover:underline flex items-center gap-1"
                >
                  VirusTotal report <ExternalLink className="w-3 h-3" />
                </a>
              ) : undefined
            }
          >
            {data.reputation?.error ? (
              <p className="text-sm text-muted-foreground">{data.reputation.error}</p>
            ) : data.reputation ? (
              <div className="flex flex-col gap-4">
                {/* Headline score */}
                <div className="flex items-start gap-4">
                  <div className="flex flex-col items-center gap-1 shrink-0">
                    <div
                      className={`text-4xl font-mono font-bold leading-none ${
                        data.reputation.classification === "MALICIOUS"
                          ? "text-red-500"
                          : data.reputation.classification === "SUSPICIOUS"
                          ? "text-yellow-500"
                          : "text-emerald-500"
                      }`}
                    >
                      {data.reputation.score}
                      <span className="text-base text-muted-foreground">/100</span>
                    </div>
                    <Badge
                      variant={
                        data.reputation.classification === "MALICIOUS"
                          ? "destructive"
                          : data.reputation.classification === "SUSPICIOUS"
                          ? "default"
                          : "secondary"
                      }
                      className="font-mono text-xs"
                    >
                      {data.reputation.classification}
                    </Badge>
                    <div className="text-[10px] text-muted-foreground">
                      composite score
                    </div>
                  </div>
                  <div className="flex-1">
                    {/* VirusTotal block */}
                    {data.reputation.virusTotal?.available ? (
                      <div className="flex flex-col gap-3">
                        <div className="flex items-center gap-2">
                          <Badge
                            variant="outline"
                            className="font-mono text-[10px] text-cyan-500 border-cyan-500/40"
                          >
                            VirusTotal
                          </Badge>
                          <Badge
                            variant={
                              data.reputation.virusTotal.classification === "MALICIOUS"
                                ? "destructive"
                                : data.reputation.virusTotal.classification === "SUSPICIOUS"
                                ? "default"
                                : "secondary"
                            }
                            className="font-mono text-[10px]"
                          >
                            {data.reputation.virusTotal.classification}
                          </Badge>
                          <span className="text-xs text-muted-foreground">
                            {data.reputation.virusTotal.flaggedEnginesCount}/
                            {data.reputation.virusTotal.totalEngines} engines flag this IP
                          </span>
                        </div>

                        {/* Analysis stats grid */}
                        <div className="grid grid-cols-5 gap-1.5">
                          {[
                            { label: "Malicious", n: data.reputation.virusTotal.lastAnalysisStats.malicious, cls: "bg-red-500/15 text-red-400" },
                            { label: "Suspicious", n: data.reputation.virusTotal.lastAnalysisStats.suspicious, cls: "bg-orange-500/15 text-orange-400" },
                            { label: "Undetected", n: data.reputation.virusTotal.lastAnalysisStats.undetected, cls: "bg-yellow-500/15 text-yellow-400" },
                            { label: "Harmless", n: data.reputation.virusTotal.lastAnalysisStats.harmless, cls: "bg-emerald-500/15 text-emerald-400" },
                            { label: "Timeout", n: data.reputation.virusTotal.lastAnalysisStats.timeout, cls: "bg-zinc-500/15 text-zinc-400" },
                          ].map((b) => (
                            <div
                              key={b.label}
                              className={`rounded p-1.5 border border-border ${b.cls}`}
                            >
                              <div className="text-base font-bold font-mono leading-none">
                                {b.n}
                              </div>
                              <div className="text-[10px] mt-0.5">{b.label}</div>
                            </div>
                          ))}
                        </div>

                        {/* Community votes + reputation */}
                        <div className="flex flex-wrap gap-4 text-xs">
                          <div>
                            <span className="text-muted-foreground">Community votes:</span>{" "}
                            <span className="text-emerald-500 font-mono">
                              {data.reputation.virusTotal.totalVotes.harmless} harmless
                            </span>{" "}
                            <span className="text-muted-foreground">/</span>{" "}
                            <span className="text-red-500 font-mono">
                              {data.reputation.virusTotal.totalVotes.malicious} malicious
                            </span>
                          </div>
                          <div>
                            <span className="text-muted-foreground">Reputation:</span>{" "}
                            <span
                              className={`font-mono ${
                                data.reputation.virusTotal.reputation < 0
                                  ? "text-red-500"
                                  : data.reputation.virusTotal.reputation > 0
                                  ? "text-emerald-500"
                                  : "text-muted-foreground"
                              }`}
                            >
                              {data.reputation.virusTotal.reputation > 0 ? "+" : ""}
                              {data.reputation.virusTotal.reputation}
                            </span>
                          </div>
                          {data.reputation.virusTotal.lastAnalysisDate && (
                            <div>
                              <span className="text-muted-foreground">Last scan:</span>{" "}
                              <span className="font-mono">
                                {new Date(
                                  data.reputation.virusTotal.lastAnalysisDate
                                ).toLocaleString()}
                              </span>
                            </div>
                          )}
                        </div>
                      </div>
                    ) : (
                      <div className="flex items-center gap-2">
                        <Badge
                          variant="outline"
                          className="font-mono text-[10px] text-muted-foreground"
                        >
                          VirusTotal
                        </Badge>
                        <span className="text-xs text-muted-foreground">
                          {data.reputation.virusTotal?.error || "unavailable"}
                        </span>
                      </div>
                    )}
                  </div>
                </div>

                {/* Secondary signals */}
                {data.reputation.signals.length > 0 && (
                  <>
                    <Separator />
                    <div>
                      <div className="text-xs font-medium text-muted-foreground uppercase tracking-wider mb-2">
                        Additional signals
                      </div>
                      <div className="flex flex-col gap-1.5 max-h-32 overflow-y-auto">
                        {data.reputation.signals.map((s, i) => (
                          <div
                            key={i}
                            className="flex items-start gap-2 text-xs"
                          >
                            <ShieldAlert
                              className={`w-3 h-3 shrink-0 mt-0.5 ${
                                s.weight > 20
                                  ? "text-red-500"
                                  : s.weight > 5
                                  ? "text-yellow-500"
                                  : "text-muted-foreground"
                              }`}
                            />
                            <div className="flex-1">
                              <span className="font-mono text-[10px] text-cyan-500">
                                [{s.source}]
                              </span>{" "}
                              <span>{s.detail}</span>
                              <Badge variant="outline" className="ml-1 font-mono text-[9px]">
                                +{s.weight}
                              </Badge>
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>
                  </>
                )}
              </div>
            ) : (
              <p className="text-sm text-muted-foreground">No data.</p>
            )}
          </Panel>

          {/* Reputation — AbuseIPDB powered */}
          <Panel
            title="Reputation — AbuseIPDB"
            className="md:col-span-2"
            action={
              data.reputation?.abuseipdb?.available ? (
                <a
                  href={`https://www.abuseipdb.com/check/${data.ip}`}
                  target="_blank"
                  rel="noreferrer"
                  className="text-xs text-cyan-500 hover:underline flex items-center gap-1"
                >
                  AbuseIPDB report <ExternalLink className="w-3 h-3" />
                </a>
              ) : undefined
            }
          >
            {data.reputation?.abuseipdb?.available ? (
              <div className="flex flex-col gap-3">
                <div className="flex items-start gap-4">
                  <div className="flex flex-col items-center gap-1 shrink-0">
                    <div
                      className={`text-4xl font-mono font-bold leading-none ${
                        data.reputation.abuseipdb.classification === "MALICIOUS"
                          ? "text-red-500"
                          : data.reputation.abuseipdb.classification === "SUSPICIOUS"
                          ? "text-yellow-500"
                          : "text-emerald-500"
                      }`}
                    >
                      {data.reputation.abuseipdb.abuseConfidenceScore}
                      <span className="text-base text-muted-foreground">%</span>
                    </div>
                    <Badge
                      variant={
                        data.reputation.abuseipdb.classification === "MALICIOUS"
                          ? "destructive"
                          : data.reputation.abuseipdb.classification === "SUSPICIOUS"
                          ? "default"
                          : "secondary"
                      }
                      className="font-mono text-xs"
                    >
                      {data.reputation.abuseipdb.classification}
                    </Badge>
                    <div className="text-[10px] text-muted-foreground">
                      abuse confidence
                    </div>
                  </div>
                  <div className="flex-1 flex flex-col gap-3">
                    <div className="grid grid-cols-2 md:grid-cols-4 gap-2">
                      {[
                        { label: "Total reports", n: data.reputation.abuseipdb.totalReports },
                        { label: "Distinct users", n: data.reputation.abuseipdb.numDistinctUsers },
                        {
                          label: "Last report",
                          n: data.reputation.abuseipdb.lastReportedAt
                            ? data.reputation.abuseipdb.lastReportedAt.slice(0, 10)
                            : "—",
                        },
                        {
                          label: "Whitelisted",
                          n: data.reputation.abuseipdb.isWhitelisted ? "yes" : "no",
                        },
                      ].map((b) => (
                        <div
                          key={b.label}
                          className="rounded p-2 border border-border bg-muted/20"
                        >
                          <div className="text-sm font-mono font-bold leading-none">
                            {b.n}
                          </div>
                          <div className="text-[10px] text-muted-foreground mt-0.5">
                            {b.label}
                          </div>
                        </div>
                      ))}
                    </div>
                    <div className="flex flex-wrap gap-3 text-xs">
                      {data.reputation.abuseipdb.usageType && (
                        <div>
                          <span className="text-muted-foreground">Usage type:</span>{" "}
                          <span className="font-mono">{data.reputation.abuseipdb.usageType}</span>
                        </div>
                      )}
                      {data.reputation.abuseipdb.isp && (
                        <div>
                          <span className="text-muted-foreground">ISP:</span>{" "}
                          <span>{data.reputation.abuseipdb.isp}</span>
                        </div>
                      )}
                      {data.reputation.abuseipdb.domain && (
                        <div>
                          <span className="text-muted-foreground">Domain:</span>{" "}
                          <span className="font-mono">{data.reputation.abuseipdb.domain}</span>
                        </div>
                      )}
                      {data.reputation.abuseipdb.countryCode && (
                        <div>
                          <span className="text-muted-foreground">Country:</span>{" "}
                          <span className="font-mono">{data.reputation.abuseipdb.countryCode}</span>
                        </div>
                      )}
                    </div>
                  </div>
                </div>
                {data.reputation.abuseipdb.recentReports.length > 0 && (
                  <>
                    <Separator />
                    <div>
                      <div className="text-xs font-medium text-muted-foreground uppercase tracking-wider mb-2">
                        Recent reports (top {data.reputation.abuseipdb.recentReports.length})
                      </div>
                      <div className="max-h-44 overflow-y-auto">
                        <Table>
                          <TableHeader>
                            <TableRow>
                              <TableHead className="w-20">Reporter</TableHead>
                              <TableHead className="w-32">Date</TableHead>
                              <TableHead>Comment</TableHead>
                            </TableRow>
                          </TableHeader>
                          <TableBody>
                            {data.reputation.abuseipdb.recentReports.map((r, i) => (
                              <TableRow key={i}>
                                <TableCell className="font-mono text-xs">
                                  {r.reporter}
                                </TableCell>
                                <TableCell className="font-mono text-xs">
                                  {r.reportedAt.slice(0, 16).replace("T", " ")}
                                </TableCell>
                                <TableCell className="text-xs text-muted-foreground">
                                  {r.comment || `Categories: ${r.categories.join(", ")}`}
                                </TableCell>
                              </TableRow>
                            ))}
                          </TableBody>
                        </Table>
                      </div>
                    </div>
                  </>
                )}
              </div>
            ) : (
              <div className="flex items-center gap-2 text-sm text-muted-foreground">
                <AlertTriangle className="w-4 h-4 shrink-0" />
                <span>
                  AbuseIPDB not available:{" "}
                  <code className="text-xs">
                    {data.reputation?.abuseipdb?.error || "no_data"}
                  </code>
                  . Set <code className="text-xs">ABUSEIPDB_API_KEY</code> env var to
                  enable.
                </span>
              </div>
            )}
          </Panel>

          {/* Threat Intel */}
          <Panel title="Threat Intel Sources">
            {data.reputation && Array.isArray(data.reputation.threatIntel) ? (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Source</TableHead>
                    <TableHead>Verdict</TableHead>
                    <TableHead>Details</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {data.reputation.threatIntel.map((t, i) => (
                    <TableRow key={i}>
                      <TableCell className="font-mono text-xs">{t.source}</TableCell>
                      <TableCell>
                        <Badge
                          variant={
                            t.verdict === "malicious" || t.verdict === "blacklisted"
                              ? "destructive"
                              : t.verdict === "suspicious" || t.verdict === "tagged"
                              ? "default"
                              : "secondary"
                          }
                          className="font-mono text-[10px]"
                        >
                          {t.verdict}
                        </Badge>
                      </TableCell>
                      <TableCell className="text-xs text-muted-foreground">
                        {t.details || "-"}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            ) : (
              <p className="text-sm text-muted-foreground">No data.</p>
            )}
          </Panel>

          {/* Blacklists summary */}
          <Panel
            title="DNSBL / Blacklist Summary"
            className="md:col-span-2"
            action={
              data.blacklists?.embedded_url ? (
                <a
                  href={data.blacklists.embedded_url}
                  target="_blank"
                  rel="noreferrer"
                  className="text-xs text-cyan-500 hover:underline flex items-center gap-1"
                >
                  multirbl.valli.org <ExternalLink className="w-3 h-3" />
                </a>
              ) : undefined
            }
          >
            {data.blacklists?.error ? (
              <p className="text-sm text-muted-foreground">{data.blacklists.error}</p>
            ) : data.blacklists ? (
              <>
                <div className="grid grid-cols-2 md:grid-cols-4 gap-2 mb-3">
                  {[
                    { label: "Blacklisted", n: data.blacklists.summary.blacklisted, cls: "bg-red-500/15 text-red-400" },
                    { label: "Brownlisted", n: data.blacklists.summary.brownlisted, cls: "bg-orange-500/15 text-orange-400" },
                    { label: "Yellowlisted", n: data.blacklists.summary.yellowlisted, cls: "bg-yellow-500/15 text-yellow-400" },
                    { label: "Whitelisted", n: data.blacklists.summary.whitelisted, cls: "bg-emerald-500/15 text-emerald-400" },
                  ].map((b) => (
                    <div
                      key={b.label}
                      className={`rounded-md p-2 border border-border ${b.cls}`}
                    >
                      <div className="text-xl font-bold font-mono">{b.n}</div>
                      <div className="text-xs">{b.label}</div>
                    </div>
                  ))}
                </div>
                <div className="text-xs text-muted-foreground mb-2">
                  Total zones checked: {data.blacklists.summary.total} · Not listed:{" "}
                  {data.blacklists.summary.notListed} · Failed:{" "}
                  {data.blacklists.summary.failed}
                </div>
                <Separator />
                <div className="mt-2 max-h-72 overflow-y-auto">
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <TableHead className="w-32">Status</TableHead>
                        <TableHead>Zone</TableHead>
                        <TableHead>Reason</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {data.blacklists.entries
                        .filter((e, i) => e.category !== "not_listed" || i < 5)
                        .slice(0, 50)
                        .map((e) => {
                          const badge = CATEGORY_BADGE[e.category];
                          return (
                            <TableRow key={e.rid}>
                              <TableCell>
                                <span
                                  className={`inline-block px-1.5 py-0.5 rounded text-[10px] font-mono ${badge.cls}`}
                                >
                                  {badge.label}
                                </span>
                              </TableCell>
                              <TableCell className="font-mono text-xs">
                                {e.url ? (
                                  <a
                                    href={e.url}
                                    target="_blank"
                                    rel="noreferrer"
                                    className="text-cyan-500 hover:underline"
                                  >
                                    {e.zone}
                                  </a>
                                ) : (
                                  e.zone
                                )}
                              </TableCell>
                              <TableCell className="text-xs text-muted-foreground">
                                {e.reason || e.result}
                              </TableCell>
                            </TableRow>
                          );
                        })}
                    </TableBody>
                  </Table>
                </div>
                <div className="mt-2 pt-2 text-[10px] text-muted-foreground border-t border-border/40">
                  Source: multirbl.valli.org + direct DNSBL (15 zones)
                </div>
              </>
            ) : (
              <p className="text-sm text-muted-foreground">No data.</p>
            )}
          </Panel>

          <div className="md:col-span-2 text-[10px] text-muted-foreground font-mono">
            Query timestamp: {data.timestamp} · Powered by VirusTotal, ipwho.is, multirbl.valli.org,
            Shodan InternetDB, AbuseIPDB (optional).
          </div>
        </div>
      )}
    </ModuleShell>
  );
}

// ---------- Domain Intel (re-export from dedicated file) ----------
// The DomainIntelView is now in src/components/views/domain-intel-view.tsx
// because it grew to ~700 lines with all the real-data panels and the PDF
// report generator. Re-export it here so the existing import in
// src/app/page.tsx still resolves.
export { DomainIntelView } from "@/components/views/domain-intel-view";

// ---------- Domain Forensics (placeholder) ----------
export function DomainForensicsView() {
  return (
    <ModuleShell
      name="Domain Forensics"
      description="Deep forensic analysis of domains: infrastructure, hosting and pivots."
      icon={Search}
      category="INFRASTRUCTURE"
    >
      <SearchBar label="Domain" placeholder="example.com" />
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mt-4">
        <Panel title="Passive DNS">
          <EmptyModuleState
            icon={Search}
            name="No data yet"
            description="Enter a domain to pivot through passive DNS history."
          />
        </Panel>
        <Panel title="Infrastructure graph">
          <EmptyModuleState
            icon={Network}
            name="Graph view"
            description="Render hosting, ASN and certificate relationships as a graph."
          />
        </Panel>
        <Panel title="Pivot recommendations">
          <EmptyModuleState
            icon={Search}
            name="Pivots"
            description="Suggested pivots based on shared infrastructure will appear here."
          />
        </Panel>
      </div>
    </ModuleShell>
  );
}

// ---------- DNS Dump (mock) ----------
export function DnsDumpView() {
  const records = [
    { type: "A", name: "@", value: "185.220.101.34", ttl: 3600 },
    { type: "AAAA", name: "@", value: "2001:db8::1", ttl: 3600 },
    { type: "MX", name: "@", value: "10 mail.example.com", ttl: 3600 },
    { type: "NS", name: "@", value: "ns1.example.com", ttl: 86400 },
    { type: "TXT", name: "@", value: "v=spf1 include:_spf.example.com ~all", ttl: 3600 },
    { type: "SOA", name: "@", value: "ns1.example.com admin.example.com", ttl: 3600 },
    { type: "CNAME", name: "www", value: "example.com", ttl: 3600 },
    { type: "SRV", name: "_sip._tcp", value: "10 5060 sip.example.com", ttl: 3600 },
    { type: "CAA", name: "@", value: "0 issue letsencrypt.org", ttl: 3600 },
    { type: "PTR", name: "1.0.0.0", value: "host.example.com", ttl: 3600 },
  ];
  return (
    <ModuleShell
      name="DNS Dump"
      description="Full dump of DNS records for a domain across all record types."
      icon={Server}
      category="INFRASTRUCTURE"
    >
      <SearchBar label="Domain" placeholder="example.com" />
      <Panel title="Records" className="mt-4">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead className="w-20">Type</TableHead>
              <TableHead className="w-32">Name</TableHead>
              <TableHead>Value</TableHead>
              <TableHead className="w-24">TTL</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {records.map((r, i) => (
              <TableRow key={i}>
                <TableCell>
                  <Badge variant="outline" className="font-mono">
                    {r.type}
                  </Badge>
                </TableCell>
                <TableCell className="font-mono text-sm">{r.name}</TableCell>
                <TableCell className="font-mono text-sm">{r.value}</TableCell>
                <TableCell className="font-mono text-sm">{r.ttl}</TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </Panel>
    </ModuleShell>
  );
}

// ---------- URL Scanner (mock) ----------
export function UrlScannerView() {
  const r = URL_SCANNER_RESULT;
  return (
    <ModuleShell
      name="URL Scanner"
      description="Static and dynamic analysis of suspicious URLs."
      icon={LinkIcon}
      category="INFRASTRUCTURE"
    >
      <SearchBar label="URL" placeholder="https://example.com/path" />
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mt-4">
        <Panel title="HTTP Response">
          <FieldRow label="Final URL" value={r.finalUrl} mono />
          <FieldRow label="Status" value={r.httpStatus} mono />
          <FieldRow label="Redirects" value={r.redirects} mono />
          <FieldRow label="Response time" value={`${r.responseTime}ms`} mono />
          <FieldRow
            label="SSL"
            value={
              r.ssl.valid
                ? `Valid · ${r.ssl.issuer}`
                : "Invalid"
            }
          />
        </Panel>
        <Panel title="Technologies">
          <div className="flex flex-wrap gap-1.5">
            {r.technologies.map((t) => (
              <Badge key={t} variant="secondary" className="font-mono">
                {t}
              </Badge>
            ))}
          </div>
        </Panel>
        <Panel title="Verdicts">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Source</TableHead>
                <TableHead>Verdict</TableHead>
                <TableHead>Details</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {r.verdicts.map((v) => (
                <TableRow key={v.source}>
                  <TableCell>{v.source}</TableCell>
                  <TableCell>
                    <Badge
                      variant={v.verdict === "malicious" ? "destructive" : "secondary"}
                      className="font-mono text-[10px]"
                    >
                      {v.verdict}
                    </Badge>
                  </TableCell>
                  <TableCell className="text-xs">
                    {"positives" in v
                      ? `${v.positives}/${v.total}`
                      : "score" in v
                      ? `score: ${v.score}`
                      : "listed: " + (v.listed ? "yes" : "no")}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </Panel>
        <Panel title="Extracted Content">
          <FieldRow label="Emails" value={r.extracted.emails.length} mono />
          <FieldRow label="Phones" value={r.extracted.phones.length} mono />
          <FieldRow label="IPs" value={r.extracted.ips.length} mono />
          <FieldRow label="Forms" value={r.extracted.forms} mono />
          <FieldRow label="Iframes" value={r.extracted.iframes} mono />
          <FieldRow label="Scripts" value={r.extracted.scripts} mono />
        </Panel>
      </div>
    </ModuleShell>
  );
}

// ---------- URL Sandbox (placeholder) ----------
export function UrlSandboxView() {
  return (
    <ModuleShell
      name="URL Sandbox"
      description="Isolated sandbox execution: network behavior, file system activity and process tree."
      icon={Box}
      category="INFRASTRUCTURE"
    >
      <SearchBar label="URL or file" placeholder="https://example.com/sample.exe" />
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mt-4">
        <Panel title="Network Activity">
          <EmptyModuleState
            icon={Network}
            name="No samples"
            description="Submit a URL or upload a file to see DNS queries, HTTP requests and C2 traffic."
          />
        </Panel>
        <Panel title="Filesystem Activity">
          <EmptyModuleState
            icon={Box}
            name="No samples"
            description="See file creation, modification, deletion and persistence changes."
          />
        </Panel>
        <Panel title="Process Tree">
          <EmptyModuleState
            icon={Box}
            name="No samples"
            description="Process spawn tree with arguments, exit codes and child processes."
          />
        </Panel>
        <Panel title="Behavioral Summary">
          <EmptyModuleState
            icon={Box}
            name="No samples"
            description="MITRE ATT&CK mapping and behavioral verdict after execution."
          />
        </Panel>
      </div>
    </ModuleShell>
  );
}

// ---------- TakeDown URL (mock) ----------
export function TakedownUrlView() {
  return (
    <ModuleShell
      name="TakeDown URL"
      description="Manage takedown requests for malicious content across providers."
      icon={ShieldOff}
      category="INFRASTRUCTURE"
    >
      <div className="flex items-center justify-between">
        <SearchBar label="Filter" placeholder="Search requests..." />
        <Button size="sm">+ New request</Button>
      </div>
      <Panel title="Recent Requests" className="mt-4">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>ID</TableHead>
              <TableHead>URL</TableHead>
              <TableHead>Target</TableHead>
              <TableHead>Provider</TableHead>
              <TableHead>Status</TableHead>
              <TableHead>Priority</TableHead>
              <TableHead>Submitted</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {TAKEDOWN_REQUESTS.map((t) => (
              <TableRow key={t.id}>
                <TableCell className="font-mono text-xs">{t.id}</TableCell>
                <TableCell className="font-mono text-xs">{t.url}</TableCell>
                <TableCell className="text-sm">{t.target}</TableCell>
                <TableCell className="text-sm">{t.provider}</TableCell>
                <TableCell>
                  <Badge
                    variant={
                      t.status === "approved"
                        ? "default"
                        : t.status === "rejected"
                        ? "destructive"
                        : "secondary"
                    }
                    className="font-mono text-[10px]"
                  >
                    {t.status}
                  </Badge>
                </TableCell>
                <TableCell>
                  <Badge
                    variant={t.priority === "critical" ? "destructive" : "outline"}
                    className="font-mono text-[10px]"
                  >
                    {t.priority}
                  </Badge>
                </TableCell>
                <TableCell className="font-mono text-xs">
                  {t.submittedAt.slice(0, 10)}
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </Panel>
      <Separator />
      <div className="flex gap-2 mt-2">
        <Button variant="outline" size="sm">
          Export CSV
        </Button>
        <Button variant="outline" size="sm">
          Sync with provider
        </Button>
      </div>
    </ModuleShell>
  );
}
