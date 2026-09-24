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
  signals: Array<{ source: string; weight: number; detail: string }>;
  tags: string[];
  threatIntel: Array<{ source: string; verdict: string; details?: string }>;
  abuseipdb?: {
    score: number;
    totalReports: number;
    abuseConfidenceScore: number;
  } | null;
  error?: string;
}

interface AggregateResult {
  ip: string;
  geo: GeoResult;
  blacklists: BlacklistResult;
  ports: PortsResult;
  reputation: ReputationResult;
  tags: string[];
  timestamp: string;
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

// ---------- Printable HTML report ----------
// Builds a self-contained, print-friendly HTML report from a successful
// aggregate query and opens it in a new window. The user can then use the
// browser's "Save as PDF" (or print) dialog to export it.

function classifyColor(c: string): string {
  if (c === "MALICIOUS") return "#dc2626";
  if (c === "SUSPICIOUS") return "#ca8a04";
  return "#16a34a";
}

function escapeHtml(s: string): string {
  return String(s)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function buildReportHtml(d: AggregateResult): string {
  const vt = d.reputation?.virusTotal;
  const geo = d.geo;
  const ports = d.ports;
  const bl = d.blacklists;
  const rep = d.reputation;
  const ts = new Date(d.timestamp).toLocaleString();

  // VT stats row
  const vtStats = vt?.lastAnalysisStats;
  const vtStatsHtml = vtStats
    ? `
      <table class="stats-grid">
        <tr>
          <td><div class="stat stat-mal">${vtStats.malicious}</div><div class="lbl">Malicious</div></td>
          <td><div class="stat stat-sus">${vtStats.suspicious}</div><div class="lbl">Suspicious</div></td>
          <td><div class="stat stat-und">${vtStats.undetected}</div><div class="lbl">Undetected</div></td>
          <td><div class="stat stat-har">${vtStats.harmless}</div><div class="lbl">Harmless</div></td>
          <td><div class="stat stat-tmo">${vtStats.timeout}</div><div class="lbl">Timeout</div></td>
        </tr>
      </table>`
    : "";

  // Blacklist summary
  const blSummary = bl?.summary;
  const blSummaryHtml = blSummary
    ? `
      <table class="stats-grid">
        <tr>
          <td><div class="stat stat-mal">${blSummary.blacklisted}</div><div class="lbl">Blacklisted</div></td>
          <td><div class="stat stat-sus">${blSummary.brownlisted}</div><div class="lbl">Brownlisted</div></td>
          <td><div class="stat stat-und">${blSummary.yellowlisted}</div><div class="lbl">Yellowlisted</div></td>
          <td><div class="stat stat-har">${blSummary.whitelisted}</div><div class="lbl">Whitelisted</div></td>
          <td><div class="stat stat-tmo">${blSummary.notListed}</div><div class="lbl">Not listed</div></td>
        </tr>
      </table>`
    : "";

  // Flagged DNSBL entries (only listed ones, top 20)
  const blListed = (bl?.entries || []).filter(
    (e) => e.category === "black" || e.category === "brown" || e.category === "yellow"
  );
  const blEntriesHtml = blListed.length
    ? `
        <h3>Flagged DNSBL zones (${blListed.length})</h3>
        <table class="data-table">
          <thead>
            <tr><th>Status</th><th>Zone</th><th>Reason</th></tr>
          </thead>
          <tbody>
            ${blListed
              .slice(0, 20)
              .map(
                (e) => `<tr>
              <td><span class="badge badge-${e.category}">${escapeHtml(
                CATEGORY_BADGE[e.category].label
              )}</span></td>
              <td><code>${escapeHtml(e.zone)}</code></td>
              <td>${escapeHtml(e.reason || e.result)}</td>
            </tr>`
              )
              .join("")}
          </tbody>
        </table>
        ${blListed.length > 20 ? `<p class="muted">+ ${blListed.length - 20} more (see full report on multirbl.valli.org).</p>` : ""}`
    : `<p class="muted">No DNSBL zone flagged this IP.</p>`;

  // Threat intel table
  const tiHtml = (rep?.threatIntel || [])
    .map(
      (t) => `<tr>
      <td><code>${escapeHtml(t.source)}</code></td>
      <td><span class="badge badge-${t.verdict === "malicious" || t.verdict === "blacklisted" ? "black" : t.verdict === "suspicious" || t.verdict === "tagged" ? "yellow" : "white"}">${escapeHtml(t.verdict)}</span></td>
      <td>${escapeHtml(t.details || "-")}</td>
    </tr>`
    )
    .join("");

  // Secondary signals
  const sigHtml = (rep?.signals || [])
    .map(
      (s) => `<tr>
      <td><code>${escapeHtml(s.source)}</code></td>
      <td>+${s.weight}</td>
      <td>${escapeHtml(s.detail)}</td>
    </tr>`
    )
    .join("");

  // Ports
  const portsHtml = (ports?.ports || [])
    .map((p) => `<span class="port">:${escapeHtml(String(p))}${PORT_SERVICES[p] ? ` <em>${escapeHtml(PORT_SERVICES[p])}</em>` : ""}</span>`)
    .join(" ");

  const hostnamesHtml = (ports?.hostnames || [])
    .map((h) => `<code>${escapeHtml(h)}</code>`)
    .join(", ");

  const vulnsHtml = (ports?.vulns || []).length
    ? (ports?.vulns || [])
        .slice(0, 15)
        .map((v) => `<span class="cve">${escapeHtml(v)}</span>`)
        .join(" ")
    : "";

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8" />
<title>IP Intel Report — ${escapeHtml(d.ip)}</title>
<style>
  * { box-sizing: border-box; }
  body { font-family: -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; color: #1a1a1a; margin: 32px; line-height: 1.5; }
  h1 { font-size: 22px; margin: 0 0 4px 0; }
  h2 { font-size: 16px; margin: 24px 0 8px 0; padding-bottom: 4px; border-bottom: 2px solid #dc2626; }
  h3 { font-size: 13px; margin: 16px 0 6px 0; color: #555; text-transform: uppercase; letter-spacing: 0.5px; }
  .header { display: flex; justify-content: space-between; align-items: flex-start; padding-bottom: 16px; border-bottom: 1px solid #ddd; margin-bottom: 16px; }
  .brand { font-size: 12px; color: #666; }
  .brand strong { color: #dc2626; font-size: 14px; letter-spacing: 0.5px; }
  .meta { font-size: 11px; color: #666; text-align: right; }
  .summary { display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 12px; margin-bottom: 16px; }
  .summary-card { border: 1px solid #ddd; border-radius: 6px; padding: 10px 14px; }
  .summary-card .label { font-size: 10px; color: #666; text-transform: uppercase; letter-spacing: 0.5px; }
  .summary-card .value { font-size: 18px; font-weight: 700; margin-top: 2px; font-family: ui-monospace, "SF Mono", Menlo, monospace; }
  .verdict { text-align: center; border: 2px solid; }
  .verdict .value { font-size: 28px; }
  .stats-grid { width: 100%; border-collapse: separate; border-spacing: 6px; margin: 8px 0; }
  .stats-grid td { text-align: center; border: 1px solid #ddd; border-radius: 4px; padding: 6px; }
  .stat { font-size: 20px; font-weight: 700; font-family: ui-monospace, "SF Mono", Menlo, monospace; }
  .stat-mal { color: #dc2626; }
  .stat-sus { color: #ea580c; }
  .stat-und { color: #ca8a04; }
  .stat-har { color: #16a34a; }
  .stat-tmo { color: #6b7280; }
  .lbl { font-size: 10px; color: #666; text-transform: uppercase; }
  .data-table { width: 100%; border-collapse: collapse; margin: 6px 0; font-size: 11px; }
  .data-table th, .data-table td { border: 1px solid #ddd; padding: 5px 8px; text-align: left; vertical-align: top; }
  .data-table th { background: #f5f5f5; font-weight: 600; }
  .kv { width: 100%; border-collapse: collapse; font-size: 11px; }
  .kv td { border: 1px solid #eee; padding: 4px 8px; }
  .kv td:first-child { background: #fafafa; font-weight: 600; width: 30%; color: #555; }
  .badge { display: inline-block; padding: 1px 6px; border-radius: 3px; font-size: 9px; font-family: ui-monospace, "SF Mono", Menlo, monospace; text-transform: uppercase; color: #fff; }
  .badge-black { background: #dc2626; }
  .badge-brown { background: #ea580c; }
  .badge-yellow { background: #ca8a04; color: #000; }
  .badge-white { background: #16a34a; }
  .badge-neutral { background: #0891b2; }
  .badge-not_listed { background: #d4d4d4; color: #666; }
  .badge-failed { background: #525252; }
  code { font-family: ui-monospace, "SF Mono", Menlo, monospace; font-size: 10px; background: #f5f5f5; padding: 1px 4px; border-radius: 2px; }
  .port { display: inline-block; padding: 2px 6px; margin: 2px; border: 1px solid #ddd; border-radius: 3px; font-family: ui-monospace, "SF Mono", Menlo, monospace; font-size: 11px; }
  .port em { color: #666; font-style: normal; font-size: 10px; margin-left: 4px; }
  .cve { display: inline-block; padding: 1px 5px; margin: 2px; background: #fee2e2; color: #991b1b; border-radius: 2px; font-family: ui-monospace, "SF Mono", Menlo, monospace; font-size: 10px; }
  .muted { color: #666; font-size: 10px; }
  .map-link { font-size: 11px; color: #0891b2; text-decoration: none; }
  .section-note { font-size: 10px; color: #999; margin-top: 4px; }
  @media print {
    body { margin: 12mm; }
    h2 { page-break-after: avoid; }
    h3 { page-break-after: avoid; }
    table { page-break-inside: avoid; }
  }
  @page { margin: 18mm; }
</style>
</head>
<body>
  <div class="header">
    <div>
      <h1>IP Intelligence Report</h1>
      <div class="brand"><strong>MONITOR-THREAT</strong> · Cyber Threat Intelligence Platform · v2.0</div>
    </div>
    <div class="meta">
      <div><strong>Report generated:</strong> ${ts}</div>
      <div><strong>Target IP:</strong> <code>${escapeHtml(d.ip)}</code></div>
    </div>
  </div>

  <!-- 1. Executive Summary -->
  <h2>1. Executive Summary</h2>
  <div class="summary">
    <div class="summary-card">
      <div class="label">Composite Score</div>
      <div class="value">${rep?.score ?? "-"}/100</div>
    </div>
    <div class="summary-card verdict" style="border-color: ${classifyColor(rep?.classification || "")};">
      <div class="label">Classification</div>
      <div class="value" style="color: ${classifyColor(rep?.classification || "")};">${escapeHtml(rep?.classification || "—")}</div>
    </div>
    <div class="summary-card">
      <div class="label">VirusTotal Engines</div>
      <div class="value">${vt?.flaggedEnginesCount ?? "-"}/${vt?.totalEngines ?? "-"}</div>
    </div>
  </div>
  <p>Report for IP address <code>${escapeHtml(d.ip)}</code>, correlated across VirusTotal, multirbl.valli.org (DNSBL), Shodan InternetDB and ipwho.is geolocation. ${
    rep?.classification === "MALICIOUS"
      ? "Multiple sources agree this IP is associated with malicious activity. Immediate containment and investigation are recommended."
      : rep?.classification === "SUSPICIOUS"
      ? "Some sources flagged this IP. Investigate before allowing traffic from this host."
      : "No source flagged this IP as malicious. Treat as benign unless new intelligence emerges."
  }</p>

  <!-- 2. Geolocation & ASN -->
  <h2>2. Geolocation & ASN</h2>
  ${geo && !geo.error ? `
  <table class="kv">
    <tr><td>IP</td><td><code>${escapeHtml(geo.ip)}</code></td></tr>
    <tr><td>Country</td><td>${escapeHtml(geo.flagEmoji || "")} ${escapeHtml(geo.country)} (${escapeHtml(geo.countryCode)})</td></tr>
    <tr><td>Region</td><td>${escapeHtml(geo.region || "-")}</td></tr>
    <tr><td>City</td><td>${escapeHtml(geo.city)}</td></tr>
    <tr><td>Coordinates</td><td><code>${geo.latitude}, ${geo.longitude}</code> · <a class="map-link" href="https://www.openstreetmap.org/?mlat=${geo.latitude}&mlon=${geo.longitude}#map=12/${geo.latitude}/${geo.longitude}" target="_blank">View on OpenStreetMap ↗</a></td></tr>
    <tr><td>ASN</td><td><code>AS${escapeHtml(String(geo.asn || "-"))}</code></td></tr>
    <tr><td>Organization</td><td>${escapeHtml(geo.organization || "-")}</td></tr>
    <tr><td>ISP</td><td>${escapeHtml(geo.isp || "-")}</td></tr>
    ${geo.domain ? `<tr><td>Domain</td><td><code>${escapeHtml(geo.domain)}</code></td></tr>` : ""}
    <tr><td>Timezone</td><td>${escapeHtml(geo.timezone || "-")}</td></tr>
    ${geo.reverse ? `<tr><td>rDNS</td><td><code>${escapeHtml(geo.reverse)}</code></td></tr>` : ""}
  </table>
  <div class="section-note">Source: ${escapeHtml(geo.provider || "ipwho.is")}</div>
  ` : `<p class="muted">Geolocation lookup failed: ${escapeHtml(geo?.error || "no data")}</p>`}

  <!-- 3. Open Ports & Services -->
  <h2>3. Open Ports & Services</h2>
  ${ports && !ports.error ? `
  <p><strong>Open ports (${ports.ports?.length || 0}):</strong> ${portsHtml || "<em class='muted'>none recorded</em>"}</p>
  ${hostnamesHtml ? `<p><strong>Hostnames:</strong> ${hostnamesHtml}</p>` : ""}
  ${vulnsHtml ? `<p><strong>Known CVEs:</strong> ${vulnsHtml}</p>` : ""}
  <div class="section-note">Source: Shodan InternetDB · ${ports.ports?.length || 0} ports · ${ports.hostnames?.length || 0} hostnames · ${ports.vulns?.length || 0} known CVEs</div>
  ` : `<p class="muted">Shodan lookup failed: ${escapeHtml(ports?.error || "no data")}</p>`}

  <!-- 4. Reputation (VirusTotal) -->
  <h2>4. Reputation — VirusTotal</h2>
  ${vt?.available ? `
  <table class="kv">
    <tr><td>VT Score (composite)</td><td><strong style="color: ${classifyColor(vt.classification)};">${vt.score}/100 — ${escapeHtml(vt.classification)}</strong></td></tr>
    <tr><td>Flagging engines</td><td>${vt.flaggedEnginesCount} / ${vt.totalEngines}</td></tr>
    <tr><td>Community reputation</td><td>${vt.reputation > 0 ? "+" : ""}${vt.reputation}</td></tr>
    <tr><td>Community votes</td><td>${vt.totalVotes.harmless} harmless · ${vt.totalVotes.malicious} malicious</td></tr>
    ${vt.lastAnalysisDate ? `<tr><td>Last analysis</td><td>${new Date(vt.lastAnalysisDate).toLocaleString()}</td></tr>` : ""}
  </table>
  ${vtStatsHtml}
  <div class="section-note"><a class="map-link" href="https://www.virustotal.com/gui/ip-address/${encodeURIComponent(d.ip)}" target="_blank">Open full VirusTotal report ↗</a></div>
  ` : `<p class="muted">VirusTotal not available: ${escapeHtml(vt?.error || "no data")}</p>`}

  <!-- 5. DNSBL / Blacklist Summary -->
  <h2>5. DNSBL / Blacklist Summary</h2>
  ${bl && !bl.error ? `
  ${blSummaryHtml}
  <table class="kv">
    <tr><td>Total zones checked</td><td>${bl.summary.total}</td></tr>
    <tr><td>Not listed</td><td>${bl.summary.notListed}</td></tr>
    <tr><td>Failed queries</td><td>${bl.summary.failed}</td></tr>
  </table>
  ${blEntriesHtml}
  <div class="section-note"><a class="map-link" href="${escapeHtml(bl.embedded_url)}" target="_blank">Open full multirbl.valli.org report ↗</a></div>
  ` : `<p class="muted">Blacklist lookup failed: ${escapeHtml(bl?.error || "no data")}</p>`}

  <!-- 6. Threat Intel Sources -->
  <h2>6. Threat Intel Sources</h2>
  <table class="data-table">
    <thead>
      <tr><th>Source</th><th>Verdict</th><th>Details</th></tr>
    </thead>
    <tbody>
      ${tiHtml || `<tr><td colspan="3" class="muted">No threat intel data.</td></tr>`}
    </tbody>
  </table>

  <!-- 7. Additional Signals -->
  <h2>7. Additional Signals</h2>
  <table class="data-table">
    <thead>
      <tr><th>Source</th><th>Weight</th><th>Detail</th></tr>
    </thead>
    <tbody>
      ${sigHtml || `<tr><td colspan="3" class="muted">No additional signals.</td></tr>`}
    </tbody>
  </table>

  <!-- 8. Methodology -->
  <h2>8. Methodology & Sources</h2>
  <p>This report was generated by aggregating live data from the following open and free-tier intelligence services:</p>
  <ul style="font-size: 11px; padding-left: 18px;">
    <li><strong>ipwho.is / ip-api.com</strong> — IP geolocation and ASN (free, no API key).</li>
    <li><strong>multirbl.valli.org</strong> — DNSBL lookup across 200+ blacklist zones, plus direct DNSBL DNS checks against 15 well-known zones (Spamhaus, SpamCop, SORBS, Barracuda, UCEProtect, CBL, Mailspike, SpamRats, …).</li>
    <li><strong>Shodan InternetDB</strong> — open ports, hostnames, tags and known CVEs (free, no API key).</li>
    <li><strong>VirusTotal v3</strong> — last analysis stats, per-engine verdicts, community votes and reputation score.</li>
    <li><strong>AbuseIPDB</strong> — abuse reports in the last 90 days (optional, when ABUSEIPDB_API_KEY is configured).</li>
  </ul>
  <p class="section-note">Composite score = VirusTotal score (primary) + weighted signals from DNSBL, Shodan and AbuseIPDB (capped at 100). Classification thresholds: BENIGN &lt; 5, SUSPICIOUS 5–19, MALICIOUS ≥ 20.</p>

  <div style="margin-top: 32px; padding-top: 12px; border-top: 1px solid #ddd; font-size: 10px; color: #999; text-align: center;">
    MONITOR-THREAT v2.0 · Generated ${ts} · This report is for informational purposes only and does not constitute legal advice.
  </div>
</body>
</html>`;
}

function printReport(d: AggregateResult | null) {
  if (!d) return;
  const html = buildReportHtml(d);
  const w = window.open("", "_blank", "noopener,noreferrer,width=1024,height=768");
  if (!w) {
    alert(
      "Please allow pop-ups to open the print report window. The browser blocked it."
    );
    return;
  }
  w.document.open();
  w.document.write(html);
  w.document.close();
  // Give the document a beat to render before triggering print.
  setTimeout(() => {
    w.focus();
    w.print();
  }, 400);
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
            onClick={() => printReport(data)}
            disabled={!data}
            title={data ? "Open a printable HTML report in a new window" : "Run an analysis first"}
          >
            <Printer className="w-3.5 h-3.5 mr-2" />
            Imprimir informe HTML
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

// ---------- Domain Intel (mock) ----------
export function DomainIntelView() {
  const r = DOMAIN_INTEL_RESULT;
  return (
    <ModuleShell
      name="Domain Intel"
      description="WHOIS, DNS, subdomains, SSL certificates and historical records."
      icon={Globe}
      category="INFRASTRUCTURE"
    >
      <SearchBar label="Domain" placeholder="example.com" />
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mt-4">
        <Panel title="WHOIS">
          <FieldRow label="Domain" value={r.domain} mono />
          <FieldRow label="Registered" value={r.registered} mono />
          <FieldRow label="Registrar" value={r.registrar} />
          <FieldRow label="Registrant country" value={r.registrantCountry} mono />
          <FieldRow label="Nameservers" value={r.nameservers.join(", ")} mono />
        </Panel>
        <Panel title="DNS Records">
          <FieldRow label="A" value={r.dns.A.join(", ")} mono />
          <FieldRow label="MX" value={r.dns.MX.join(", ")} mono />
          <FieldRow label="NS" value={r.dns.NS.join(", ")} mono />
          <FieldRow label="TXT" value={r.dns.TXT[0]} mono />
        </Panel>
        <Panel title="SSL Certificate">
          <FieldRow label="Issuer" value={r.ssl.issuer} />
          <FieldRow label="Valid from" value={r.ssl.validFrom} mono />
          <FieldRow label="Valid to" value={r.ssl.validTo} mono />
          <FieldRow label="Serial" value={r.ssl.serial} mono />
        </Panel>
        <Panel title="Subdomains">
          <div className="flex flex-col gap-1">
            {r.subdomains.map((s) => (
              <span key={s} className="font-mono text-xs px-2 py-1 rounded bg-muted/40">
                {s}
              </span>
            ))}
          </div>
        </Panel>
      </div>
      <Panel title="History" className="mt-4">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Date</TableHead>
              <TableHead>Event</TableHead>
              <TableHead>From</TableHead>
              <TableHead>To</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {r.history.map((h) => (
              <TableRow key={h.date + h.event}>
                <TableCell className="font-mono">{h.date}</TableCell>
                <TableCell>{h.event}</TableCell>
                <TableCell className="font-mono text-xs">{h.from}</TableCell>
                <TableCell className="font-mono text-xs">{h.to}</TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </Panel>
    </ModuleShell>
  );
}

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
