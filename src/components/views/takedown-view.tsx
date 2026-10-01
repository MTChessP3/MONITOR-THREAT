"use client";

import * as React from "react";
import {
  ShieldOff,
  Upload,
  Send,
  Trash2,
  Loader2,
  Printer,
  AlertTriangle,
  ExternalLink,
  Mail,
  Eye,
  Globe,
  Server,
  ShieldAlert,
  CheckCircle2,
  XCircle,
  Clock,
  RefreshCw,
  Filter,
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

type Platform = "urlhaus" | "virustotal" | "cleanmx" | "phishtank";
type PrefillPlatform =
  | "google_phish" | "google_malware" | "microsoft" | "apwg" | "stopbadware"
  | "spam404" | "netcraft" | "kaspersky" | "talos" | "fortiguard" | "mcafee" | "sucuri";
type EmailTemplate = "phishing" | "malware" | "scam" | "copyright";

interface EnrichData {
  hostname: string;
  screenshotUrl: string;
  vt: { malicious: number; suspicious: number; harmless: number; undetected: number; lastAnalysisDate: string | null; permalink: string | null; error?: string };
  whois: { registrar: string | null; abuseEmail: string | null; createdDate: string | null; error?: string };
  hosting: { asn: string | null; asnOrg: string | null; isp: string | null; abuseEmail: string | null; error?: string };
  cloudflare: boolean;
  classification: "phishing" | "malware" | "scam" | "unknown";
  classificationReason: string;
  redirectChain: Array<{ url: string; status: number }>;
  finalUrl: string;
  error?: string;
}

interface SubmitResult {
  platform: Platform;
  status: "success" | "failed" | "skipped" | "error" | "pending";
  message?: string;
  permalink?: string | null;
  timestamp: string;
}

interface UrlEntry {
  url: string;
  status: "pending" | "enriching" | "enriched" | "failed";
  enrich?: EnrichData;
  submits: SubmitResult[];
  prefillOpened: PrefillPlatform[];
  emailsGenerated: EmailTemplate[];
  addedAt: string;
}

// ---------- Constants ----------

const STORAGE_KEY = "monitor-threat-takedown-v1";
const RECHECK_INTERVAL_MS = 7 * 24 * 60 * 60 * 1000; // 7 days

const PREFILL_PLATFORMS: Array<{ id: PrefillPlatform; name: string; url: (u: string) => string; category: string }> = [
  { id: "google_phish", name: "Google Safe Browsing (Phishing)", category: "browser", url: u => `https://safebrowsing.google.com/safebrowsing/report_phish/?url=${encodeURIComponent(u)}` },
  { id: "google_malware", name: "Google Safe Browsing (Malware)", category: "browser", url: u => `https://safebrowsing.google.com/safebrowsing/report_badware/?url=${encodeURIComponent(u)}` },
  { id: "microsoft", name: "Microsoft SmartScreen", category: "browser", url: u => `https://www.microsoft.com/en-us/wdsi/support/report-unsafe-site-guest?url=${encodeURIComponent(u)}` },
  { id: "apwg", name: "APWG (Anti-Phishing Working Group)", category: "phishing", url: u => `https://apwg.org/reportphishing/review/?url=${encodeURIComponent(u)}` },
  { id: "stopbadware", name: "StopBadware", category: "abuse", url: u => `https://www.stopbadware.org/report?url=${encodeURIComponent(u)}` },
  { id: "spam404", name: "Spam404", category: "spam", url: u => `https://www.spam404.com/report.html?url=${encodeURIComponent(u)}` },
  { id: "netcraft", name: "Netcraft", category: "takedown", url: u => `https://report.netcraft.com/report?url=${encodeURIComponent(u)}` },
  { id: "kaspersky", name: "Kaspersky VirusDesk", category: "antivirus", url: u => `https://virusdesk.kaspersky.com/?url=${encodeURIComponent(u)}` },
  { id: "talos", name: "Cisco Talos", category: "antivirus", url: u => `https://talosintelligence.com/submit?ioc=${encodeURIComponent(u)}` },
  { id: "fortiguard", name: "Fortinet FortiGuard", category: "antivirus", url: u => `https://www.forticourt.com/fortiguard/url_tag_form.php?url=${encodeURIComponent(u)}` },
  { id: "mcafee", name: "McAfee WebAdvisor", category: "antivirus", url: u => `https://trustedsource.org/submitURL.html?url=${encodeURIComponent(u)}` },
  { id: "sucuri", name: "Sucuri SiteCheck (scan)", category: "scanner", url: u => `https://sitecheck.sucuri.net/results/${u}` },
];

const API_PLATFORMS: Array<{ id: Platform; name: string }> = [
  { id: "urlhaus", name: "URLhaus (abuse.ch)" },
  { id: "virustotal", name: "VirusTotal" },
  { id: "cleanmx", name: "Clean-MX" },
  { id: "phishtank", name: "PhishTank" },
];

const EMAIL_TEMPLATES: Record<EmailTemplate, { name: string; subject: (url: string, host: string) => string; body: (url: string, host: string, evidence: string) => string }> = {
  phishing: {
    name: "Phishing (robo de credenciales)",
    subject: (u, h) => `ABUSE REPORT — Phishing site hosted on ${h}`,
    body: (u, h, ev) => `Dear Abuse Team,

I am writing to report a phishing website hosted on ${h}.

URL: ${u}
Detected: ${new Date().toISOString()}

Evidence:
${ev}

This site is impersonating a legitimate service to steal user credentials.
We request that you immediately suspend this account and take down the
phishing content. Please reply to confirm receipt and action taken.

Thank you,
MONITOR-THREAT (https://monitor-threat.vercel.app)`,
  },
  malware: {
    name: "Malware (distribución de software malicioso)",
    subject: (u, h) => `ABUSE REPORT — Malware distribution on ${h}`,
    body: (u, h, ev) => `Dear Abuse Team,

I am writing to report a website distributing malware hosted on ${h}.

URL: ${u}
Detected: ${new Date().toISOString()}

Evidence:
${ev}

This site is distributing malicious software (drive-by download,
trojan, ransomware, etc.). We request that you immediately suspend
this account and remove the malicious content.

Thank you,
MONITOR-THREAT (https://monitor-threat.vercel.app)`,
  },
  scam: {
    name: "Scam / Fraude (engaño financiero)",
    subject: (u, h) => `ABUSE REPORT — Fraudulent site on ${h}`,
    body: (u, h, ev) => `Dear Abuse Team,

I am writing to report a fraudulent website hosted on ${h}.

URL: ${u}
Detected: ${new Date().toISOString()}

Evidence:
${ev}

This site is operating a financial scam (lottery, investment fraud,
get-rich-quick, fake prizes, etc.). We request that you immediately
suspend this account and take down the fraudulent content.

Thank you,
MONITOR-THREAT (https://monitor-threat.vercel.app)`,
  },
  copyright: {
    name: "Copyright / Piratería",
    subject: (u, h) => `DMCA NOTICE — Copyright infringement on ${h}`,
    body: (u, h, ev) => `Dear Abuse Team,

I am writing to report copyright infringement on ${h}.

URL: ${u}
Detected: ${new Date().toISOString()}

Evidence:
${ev}

This site is distributing copyrighted material without authorization
(pirated software, copyrighted media, counterfeit goods, etc.).
We request that you immediately remove the infringing content.

Thank you,
MONITOR-THREAT (https://monitor-threat.vercel.app)`,
  },
};

// ---------- Helpers ----------

function normalizeUrl(raw: string): string | null {
  let s = raw.trim();
  if (!s) return null;
  if (!/^https?:\/\//i.test(s)) s = "http://" + s;
  try {
    const u = new URL(s);
    if (!u.hostname || !u.hostname.includes(".")) return null;
    return u.href;
  } catch {
    return null;
  }
}

function parseUrls(text: string): { valid: string[]; invalid: string[] } {
  const lines = text.split(/\r?\n/).map(l => l.trim()).filter(Boolean);
  const valid: string[] = [];
  const invalid: string[] = [];
  const seen = new Set<string>();
  for (const line of lines) {
    const n = normalizeUrl(line);
    if (n && !seen.has(n)) {
      seen.add(n);
      valid.push(n);
    } else if (!n && line) {
      invalid.push(line);
    }
  }
  return { valid, invalid };
}

function loadFromStorage(): UrlEntry[] {
  if (typeof window === "undefined") return [];
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return [];
    return JSON.parse(raw);
  } catch {
    return [];
  }
}

function saveToStorage(entries: UrlEntry[]) {
  if (typeof window === "undefined") return;
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(entries));
  } catch {}
}

async function enrichUrl(url: string): Promise<EnrichData> {
  const r = await fetch(`/api/takedown/enrich?url=${encodeURIComponent(url)}`);
  if (!r.ok) throw new Error(`enrich failed: ${r.status}`);
  return await r.json();
}

async function submitUrl(url: string, platform: Platform, threatType: string): Promise<SubmitResult> {
  const r = await fetch("/api/takedown/submit", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ platform, url, threatType }),
  });
  const j: any = await r.json();
  return {
    platform,
    status: j.status || "failed",
    message: j.message || (j.response ? JSON.stringify(j.response).slice(0, 200) : ""),
    permalink: j.permalink || null,
    timestamp: new Date().toISOString(),
  };
}

function buildEvidence(entry: UrlEntry): string {
  const e = entry.enrich;
  if (!e) return `- URL: ${entry.url}`;
  const lines = [`- URL: ${entry.url}`, `- Hostname: ${e.hostname}`];
  if (e.cloudflare) lines.push("- Detected behind: Cloudflare (also contact abuse@cloudflare.com)");
  if (e.vt?.malicious) lines.push(`- VirusTotal: ${e.vt.malicious} security vendors flag this URL as malicious`);
  if (e.vt?.permalink) lines.push(`- VT permalink: ${e.vt.permalink}`);
  if (e.whois?.registrar) lines.push(`- Registrar: ${e.whois.registrar}`);
  if (e.hosting?.asnOrg) lines.push(`- Hosting provider: ${e.hosting.asnOrg} (${e.hosting.asn || "?"})`);
  if (e.redirectChain.length > 1) lines.push(`- Redirect chain: ${e.redirectChain.map(c => `${c.status}→${c.url.slice(0, 60)}`).join(" → ")}`);
  if (e.classification !== "unknown") lines.push(`- Auto-classification: ${e.classification.toUpperCase()} (${e.classificationReason})`);
  lines.push(`- Screenshot: ${entry.url} (capture available in PDF report)`);
  return lines.join("\n");
}

// ---------- Component ----------

export function TakedownUrlView() {
  const [textareaInput, setTextareaInput] = React.useState("");
  const [entries, setEntries] = React.useState<UrlEntry[]>([]);
  const [loading, setLoading] = React.useState(false);
  const [filter, setFilter] = React.useState("");
  const [bulkSubmitting, setBulkSubmitting] = React.useState(false);
  const [progress, setProgress] = React.useState({ done: 0, total: 0, step: "" });
  const fileInputRef = React.useRef<HTMLInputElement>(null);

  // Load from localStorage on mount
  React.useEffect(() => {
    const stored = loadFromStorage();
    if (stored.length > 0) {
      setEntries(stored);
    }
  }, []);

  // Persist to localStorage on change
  React.useEffect(() => {
    saveToStorage(entries);
  }, [entries]);

  // ---- URL loading ----
  const handleLoadFromTextarea = () => {
    if (!textareaInput.trim()) return;
    const { valid, invalid } = parseUrls(textareaInput);
    if (valid.length === 0) {
      alert("No valid URLs found. Each line must be a URL (with or without http(s)://).");
      return;
    }
    const newEntries: UrlEntry[] = valid.map(u => ({
      url: u,
      status: "pending",
      submits: [],
      prefillOpened: [],
      emailsGenerated: [],
      addedAt: new Date().toISOString(),
    }));
    setEntries(prev => {
      const existing = new Set(prev.map(e => e.url));
      const toAdd = newEntries.filter(e => !existing.has(e.url));
      return [...prev, ...toAdd];
    });
    if (invalid.length > 0) {
      alert(`${valid.length} URL(s) cargadas. ${invalid.length} inválida(s) ignorada(s):\n${invalid.slice(0, 5).join("\n")}${invalid.length > 5 ? "\n..." : ""}`);
    }
    setTextareaInput("");
  };

  const handleLoadFromFile = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    const text = await file.text();
    setTextareaInput(text);
    handleLoadFromTextarea();
    if (fileInputRef.current) fileInputRef.current.value = "";
  };

  const handleClearAll = () => {
    if (confirm(`¿Eliminar las ${entries.length} URLs del historial?`)) {
      setEntries([]);
    }
  };

  // ---- Enrichment ----
  const enrichOne = async (url: string) => {
    setEntries(prev => prev.map(e => e.url === url ? { ...e, status: "enriching" } : e));
    try {
      const enrich = await enrichUrl(url);
      setEntries(prev => prev.map(e => e.url === url ? { ...e, status: "enriched", enrich } : e));
    } catch (err: any) {
      setEntries(prev => prev.map(e => e.url === url ? { ...e, status: "failed", enrich: { ...e.enrich, error: String(err?.message || err) } as EnrichData } : e));
    }
  };

  const enrichAll = async () => {
    setLoading(true);
    const toEnrich = entries.filter(e => e.status === "pending");
    setProgress({ done: 0, total: toEnrich.length, step: "Enriqueciendo URLs..." });
    let done = 0;
    // Run in batches of 5 to avoid overwhelming the server
    const batchSize = 5;
    for (let i = 0; i < toEnrich.length; i += batchSize) {
      const batch = toEnrich.slice(i, i + batchSize);
      await Promise.all(batch.map(async e => {
        await enrichOne(e.url);
        done++;
        setProgress({ done, total: toEnrich.length, step: `Enriquecido ${e.url.slice(0, 50)}...` });
      }));
    }
    setLoading(false);
    setProgress({ done: 0, total: 0, step: "" });
  };

  // ---- Auto-submit ----
  const submitOne = async (entry: UrlEntry) => {
    const threatType = entry.enrich?.classification === "malware" ? "malware_url"
      : entry.enrich?.classification === "scam" ? "scam_url"
      : "phishing_url";
    const platforms: Platform[] = ["urlhaus", "virustotal", "cleanmx", "phishtank"];
    for (const p of platforms) {
      const result = await submitUrl(entry.url, p, threatType);
      setEntries(prev => prev.map(e => e.url === entry.url ? {
        ...e,
        submits: [...e.submits.filter(s => s.platform !== p), result],
      } : e));
    }
  };

  const submitAll = async () => {
    setBulkSubmitting(true);
    const enriched = entries.filter(e => e.status === "enriched");
    setProgress({ done: 0, total: enriched.length, step: "Enviando a plataformas API..." });
    let done = 0;
    for (const entry of enriched) {
      await submitOne(entry);
      done++;
      setProgress({ done, total: enriched.length, step: `Enviado ${entry.url.slice(0, 50)}...` });
    }
    setBulkSubmitting(false);
    setProgress({ done: 0, total: 0, step: "" });
  };

  // ---- Pre-fill forms ----
  const openPrefill = (entry: UrlEntry, platform: PrefillPlatform) => {
    const cfg = PREFILL_PLATFORMS.find(p => p.id === platform);
    if (!cfg) return;
    window.open(cfg.url(entry.url), "_blank");
    setEntries(prev => prev.map(e => e.url === entry.url ? {
      ...e,
      prefillOpened: e.prefillOpened.includes(platform) ? e.prefillOpened : [...e.prefillOpened, platform],
    } : e));
  };

  const openAllPrefills = (entry: UrlEntry) => {
    // Open up to 6 in parallel (browser popup limits)
    const toOpen = PREFILL_PLATFORMS.filter(p => !entry.prefillOpened.includes(p.id)).slice(0, 6);
    if (toOpen.length === 0) {
      alert("Todas las plataformas ya fueron abiertas para esta URL.");
      return;
    }
    if (confirm(`Se abrirán ${toOpen.length} pestañas. ¿Continuar? (algunas plataformas requieren confirmación manual del formulario)`)) {
      toOpen.forEach(p => window.open(p.url(entry.url), "_blank"));
      setEntries(prev => prev.map(e => e.url === entry.url ? {
        ...e,
        prefillOpened: [...e.prefillOpened, ...toOpen.map(p => p.id)],
      } : e));
    }
  };

  // ---- Abuse emails ----
  const openAbuseEmail = (entry: UrlEntry, template: EmailTemplate) => {
    const e = entry.enrich;
    const hostname = e?.hostname || "";
    // Build recipient list
    const recipients = new Set<string>();
    if (e?.whois?.abuseEmail) recipients.add(e.whois.abuseEmail);
    if (e?.hosting?.abuseEmail) recipients.add(e.hosting.abuseEmail);
    if (e?.cloudflare) recipients.add("abuse@cloudflare.com");
    // Fallback to abuse@<hostname-domain>
    if (recipients.size === 0) {
      try {
        const parts = hostname.split(".");
        if (parts.length >= 2) {
          const domain = parts.slice(-2).join(".");
          recipients.add(`abuse@${domain}`);
        }
      } catch {}
    }
    if (recipients.size === 0) {
      alert("No se pudo determinar el correo de abuse. Enriquece la URL primero.");
      return;
    }
    const to = Array.from(recipients).join(",");
    const evidence = buildEvidence(entry);
    const t = EMAIL_TEMPLATES[template];
    const subject = t.subject(entry.url, hostname);
    const body = t.body(entry.url, hostname, evidence);
    window.location.href = `mailto:${to}?subject=${encodeURIComponent(subject)}&body=${encodeURIComponent(body)}`;
    setEntries(prev => prev.map(en => en.url === entry.url ? {
      ...en,
      emailsGenerated: en.emailsGenerated.includes(template) ? en.emailsGenerated : [...en.emailsGenerated, template],
    } : en));
  };

  // ---- Re-check ----
  const recheckOld = async () => {
    const now = Date.now();
    const old = entries.filter(e => now - new Date(e.addedAt).getTime() > RECHECK_INTERVAL_MS);
    if (old.length === 0) {
      alert("No hay URLs con más de 7 días para re-verificar.");
      return;
    }
    if (confirm(`¿Re-enriquecer ${old.length} URLs antiguas (más de 7 días)?`)) {
      setLoading(true);
      for (const e of old) {
        await enrichOne(e.url);
      }
      setLoading(false);
    }
  };

  // ---- PDF ----
  const generatePdf = () => {
    const doc = new jsPDF({ unit: "pt", format: "a4" });
    const pageWidth = doc.internal.pageSize.getWidth();
    const pageHeight = doc.internal.pageSize.getHeight();
    const margin = 40;
    const contentWidth = pageWidth - margin * 2;
    let y = margin;

    // ---------- Cover ----------
    doc.setFont("helvetica", "bold"); doc.setFontSize(22); doc.setTextColor(15, 23, 42);
    doc.text("TakeDown Report", margin, y + 8);
    doc.setFont("helvetica", "normal"); doc.setFontSize(11); doc.setTextColor(220, 38, 38);
    doc.text("MONITOR-THREAT", margin, y + 26);
    doc.setTextColor(100, 116, 139);
    doc.text("Cyber Threat Intelligence Platform · Takedown Management", margin + 105, y + 26);
    const ts = new Date().toLocaleString();
    doc.setFontSize(10); doc.setTextColor(71, 85, 105);
    doc.text(`Generado: ${ts}`, pageWidth - margin, y + 8, { align: "right" });
    doc.text(`URLs: ${entries.length}`, pageWidth - margin, y + 22, { align: "right" });
    y += 48; doc.setDrawColor(220, 220, 220); doc.setLineWidth(0.5);
    doc.line(margin, y, pageWidth - margin, y); y += 28;

    const sectionHeading = (label: string) => {
      if (y > pageHeight - margin - 120) { doc.addPage(); y = margin + 6; } else { y += 20; }
      doc.setFont("helvetica", "bold"); doc.setFontSize(13); doc.setTextColor(220, 38, 38);
      doc.text(label, margin, y); doc.setDrawColor(220, 38, 38); doc.setLineWidth(1);
      doc.line(margin, y + 4, pageWidth - margin, y + 4); y += 16;
      doc.setFont("helvetica", "normal"); doc.setFontSize(10); doc.setTextColor(51, 65, 85);
    };

    const kvTable = (rows: Array<[string, string]>) => {
      autoTable(doc, { startY: y, head: [["Campo", "Valor"]], body: rows, theme: "striped",
        margin: { left: margin, right: margin },
        styles: { fontSize: 9, cellPadding: 5, textColor: [30, 41, 59] },
        headStyles: { fillColor: [241, 245, 249], textColor: [71, 85, 105], fontSize: 9 },
        columnStyles: { 0: { cellWidth: contentWidth * 0.32, fontStyle: "bold", textColor: [100, 116, 139] } },
      });
      // @ts-ignore
      y = (doc as any).lastAutoTable.finalY + 18;
    };

    // ---------- Section 1: ¿Dónde se reportó cada URL? (RESUMEN DE DESTINOS) ----------
    sectionHeading("¿Dónde fue reportada cada URL?");

    // Build a matrix of all platforms × all URLs
    const apiPlatforms = ["urlhaus", "virustotal", "cleanmx", "phishtank"];
    const allPlatforms = [
      ...apiPlatforms.map(p => ({ id: p, name: API_PLATFORMS.find(x => x.id === p)?.name || p, type: "API" })),
      ...PREFILL_PLATFORMS.map(p => ({ id: p.id, name: p.name, type: "Form" })),
      { id: "abuse-email" as any, name: "Correo de Abuse (registrar + hosting)", type: "Email" },
    ];

    // Summary table: Platform | Reportados | Fallidos | Pendientes
    const summaryRows: Array<[string, string, string, string]> = [];
    for (const p of allPlatforms) {
      let success = 0, failed = 0, pending = 0;
      for (const entry of entries) {
        if (p.type === "API") {
          const s = entry.submits.find(x => x.platform === p.id);
          if (s?.status === "success") success++;
          else if (s?.status === "failed" || s?.status === "error") failed++;
          else if (s?.status === "skipped") pending++;
          else pending++;
        } else if (p.type === "Form") {
          if (entry.prefillOpened.includes(p.id as PrefillPlatform)) success++;
          else pending++;
        } else if (p.type === "Email") {
          if (entry.emailsGenerated.length > 0) success++;
          else pending++;
        }
      }
      if (success > 0 || pending > 0) {
        summaryRows.push([`${p.name}  [${p.type}]`, String(success), String(failed), String(pending)]);
      }
    }
    autoTable(doc, {
      startY: y,
      head: [["Plataforma (API / Formulario / Email)", "✓ Reportado", "✗ Fallido", "○ Pendiente"]],
      body: summaryRows,
      theme: "grid",
      margin: { left: margin, right: margin },
      styles: { fontSize: 9, cellPadding: 5, textColor: [30, 41, 59], lineColor: [226, 232, 240], lineWidth: 0.5 },
      headStyles: { fillColor: [220, 38, 38], textColor: [255, 255, 255], fontStyle: "bold", fontSize: 9 },
      columnStyles: {
        0: { cellWidth: contentWidth * 0.55 },
        1: { cellWidth: contentWidth * 0.15, halign: "center", textColor: [22, 163, 74] },
        2: { cellWidth: contentWidth * 0.15, halign: "center", textColor: [220, 38, 38] },
        3: { cellWidth: contentWidth * 0.15, halign: "center", textColor: [161, 98, 7] },
      },
    });
    // @ts-ignore
    y = (doc as any).lastAutoTable.finalY + 18;

    // ---------- Section 2: Detalle por URL — ¿a dónde fue reportada cada una? ----------
    sectionHeading("Detalle por URL — ¿a dónde fue reportada cada una?");

    for (const entry of entries.slice(0, 50)) {
      // URL header
      doc.setFont("helvetica", "bold"); doc.setFontSize(11); doc.setTextColor(15, 23, 42);
      if (y > pageHeight - margin - 200) { doc.addPage(); y = margin + 6; }
      doc.text(`URL: ${entry.url.slice(0, 90)}`, margin, y);
      y += 14;
      doc.setFont("helvetica", "normal"); doc.setFontSize(8); doc.setTextColor(100, 116, 139);
      if (entry.enrich?.hostname) {
        doc.text(`Hostname: ${entry.enrich.hostname}  ·  Class: ${entry.enrich.classification || "?"}  ·  VT: ${entry.enrich.vt?.malicious || 0} malicious`, margin, y);
        y += 12;
      }
      if (entry.enrich?.finalUrl && entry.enrich.finalUrl !== entry.url) {
        doc.setTextColor(220, 38, 38);
        doc.text(`→ URL final (después de redirects): ${entry.enrich.finalUrl.slice(0, 90)}`, margin, y);
        y += 12;
        doc.setTextColor(100, 116, 139);
      }
      y += 4;

      // Where it was reported (matrix row)
      const reportedRows: Array<[string, string, string]> = [];

      // APIs
      for (const p of apiPlatforms) {
        const name = API_PLATFORMS.find(x => x.id === p)?.name || p;
        const s = entry.submits.find(x => x.platform === p);
        if (s?.status === "success") {
          const link = s.permalink || (p === "virustotal" && entry.enrich?.vt?.permalink) || entry.enrich?.vt?.permalink || "—";
          reportedRows.push([name, "✓ REPORTADO", link && link !== "—" ? link.slice(0, 60) : "OK"]);
        } else if (s?.status === "failed" || s?.status === "error") {
          reportedRows.push([name, "✗ FALLÓ", (s.message || "error").slice(0, 60)]);
        } else if (s?.status === "skipped") {
          reportedRows.push([name, "○ SKIPPED", (s.message || "API key no configurada").slice(0, 60)]);
        } else {
          reportedRows.push([name, "○ PENDIENTE", "—"]);
        }
      }

      // Pre-fill forms
      for (const p of PREFILL_PLATFORMS) {
        const wasOpened = entry.prefillOpened.includes(p.id);
        const link = p.url(entry.url);
        reportedRows.push([p.name, wasOpened ? "✓ ABIERTO" : "○ NO ABIERTO", link.slice(0, 80)]);
      }

      // Abuse email
      if (entry.emailsGenerated.length > 0) {
        const recipients = new Set<string>();
        if (entry.enrich?.whois?.abuseEmail) recipients.add(entry.enrich.whois.abuseEmail);
        if (entry.enrich?.hosting?.abuseEmail) recipients.add(entry.enrich.hosting.abuseEmail);
        if (entry.enrich?.cloudflare) recipients.add("abuse@cloudflare.com");
        if (recipients.size === 0) {
          try {
            const parts = entry.enrich?.hostname?.split(".") || [];
            if (parts.length >= 2) recipients.add(`abuse@${parts.slice(-2).join(".")}`);
          } catch {}
        }
        reportedRows.push([
          "Correo de Abuse (" + entry.emailsGenerated.map(t => EMAIL_TEMPLATES[t].name.split(" ")[0]).join(", ") + ")",
          "✓ GENERADO",
          Array.from(recipients).join(", ").slice(0, 60),
        ]);
      } else {
        reportedRows.push(["Correo de Abuse", "○ NO GENERADO", "—"]);
      }

      autoTable(doc, {
        startY: y,
        head: [["Plataforma / Destino", "Estado", "Link / Detalle"]],
        body: reportedRows,
        theme: "striped",
        margin: { left: margin, right: margin },
        styles: { fontSize: 8, cellPadding: 4, textColor: [30, 41, 59], lineColor: [226, 232, 240], lineWidth: 0.3 },
        headStyles: { fillColor: [241, 245, 249], textColor: [71, 85, 105], fontSize: 8 },
        columnStyles: {
          0: { cellWidth: contentWidth * 0.40, fontStyle: "bold" },
          1: { cellWidth: contentWidth * 0.18, halign: "center" },
          2: { cellWidth: contentWidth * 0.42, textColor: [59, 130, 246] },
        },
        didParseCell: (data: any) => {
          if (data.section === "body" && data.column.index === 1) {
            const v = String(data.cell.raw || "");
            if (v.startsWith("✓")) data.cell.styles.textColor = [22, 163, 74];
            else if (v.startsWith("✗")) data.cell.styles.textColor = [220, 38, 38];
            else if (v.startsWith("○")) data.cell.styles.textColor = [161, 98, 7];
          }
        },
      });
      // @ts-ignore
      y = (doc as any).lastAutoTable.finalY + 18;
    }

    // ---------- Section 3: Datos de enriquecimiento (registrar, hosting, etc.) ----------
    sectionHeading("Datos de Enriquecimiento (registrar, hosting, VirusTotal)");

    for (const entry of entries.slice(0, 50)) {
      const e = entry.enrich;
      if (!e) continue;
      if (y > pageHeight - margin - 100) { doc.addPage(); y = margin + 6; }
      doc.setFont("helvetica", "bold"); doc.setFontSize(10); doc.setTextColor(15, 23, 42);
      doc.text(entry.url.slice(0, 80), margin, y);
      y += 12;
      kvTable([
        ["Hostname", e.hostname || "?"],
        ["Clasificación", `${e.classification} (${e.classificationReason})`],
        ["VirusTotal", e.vt ? `${e.vt.malicious} malicious / ${e.vt.suspicious} suspicious / ${e.vt.undetected} undetected` : "?"],
        ["VT permalink", e.vt?.permalink || "?"],
        ["Registrar", e.whois?.registrar || "?"],
        ["Abuse email (registrar)", e.whois?.abuseEmail || "?"],
        ["Hosting provider", e.hosting ? `${e.hosting.asnOrg || "?"} (${e.hosting.asn || "?"})` : "?"],
        ["ISP", e.hosting?.isp || "?"],
        ["Detrás de Cloudflare", e.cloudflare ? "SÍ — también contactar abuse@cloudflare.com" : "no"],
        ["URL final (después de redirects)", e.finalUrl || entry.url],
      ]);
    }

    // ---------- Footer on each page ----------
    const pageCount = doc.getNumberOfPages();
    for (let i = 1; i <= pageCount; i++) {
      doc.setPage(i);
      doc.setFont("helvetica", "normal"); doc.setFontSize(8); doc.setTextColor(150, 150, 150);
      doc.text(`MONITOR-THREAT · TakeDown Report · Página ${i} de ${pageCount}`, pageWidth / 2, pageHeight - 20, { align: "center" });
    }

    doc.save(`takedown-report-${Date.now()}.pdf`);
  };

  // ---- Filtering ----
  const filtered = React.useMemo(() => {
    if (!filter.trim()) return entries;
    const f = filter.toLowerCase();
    return entries.filter(e => e.url.toLowerCase().includes(f) || e.enrich?.hostname?.toLowerCase().includes(f));
  }, [entries, filter]);

  const stats = {
    total: entries.length,
    enriched: entries.filter(e => e.status === "enriched").length,
    pending: entries.filter(e => e.status === "pending").length,
    phishing: entries.filter(e => e.enrich?.classification === "phishing").length,
    malware: entries.filter(e => e.enrich?.classification === "malware").length,
    scam: entries.filter(e => e.enrich?.classification === "scam").length,
    cf: entries.filter(e => e.enrich?.cloudflare).length,
    submits: entries.reduce((s, e) => s + e.submits.filter(x => x.status === "success").length, 0),
    forms: entries.reduce((s, e) => s + e.prefillOpened.length, 0),
    emails: entries.reduce((s, e) => s + e.emailsGenerated.length, 0),
  };

  // ---- Compute wizard step status ----
  const step1Done = entries.length > 0;       // URLs loaded
  const step2Done = stats.enriched > 0;        // Enriched
  const step3Done = stats.submits > 0 || stats.forms > 0;  // Reported
  const step4Done = stats.emails > 0;          // Abuse emails generated
  const step5Done = false;                     // PDF downloaded (always allow)

  return (
    <ModuleShell
      name="TakeDown URL"
      description="Gestión de takedown — carga URLs desde .txt, enriquece, reporta a 16 plataformas (Google, Microsoft, URLhaus, VirusTotal + 12 más) y genera correos de abuse."
      icon={ShieldOff}
      category="INFRASTRUCTURE"
    >
      {/* ---------- Wizard step bar (always visible) ---------- */}
      <div className="flex flex-wrap items-center gap-2 p-3 rounded-lg border border-border bg-muted/20 text-[11px]">
        <StepBar label="1. Cargar URLs" done={step1Done} />
        <StepBar label="2. Enriquecer" done={step2Done} />
        <StepBar label="3. Reportar a plataformas" done={step3Done} />
        <StepBar label="4. Generar correos de abuse" done={step4Done} />
        <StepBar label="5. Imprimir PDF" done={step5Done} last />
      </div>

      {/* ---------- Step 1: Load URLs ---------- */}
      <Panel
        title="PASO 1 — Cargar URLs a reportar"
        className="md:col-span-2"
        action={<div className="flex gap-2">
          <input type="file" accept=".txt,text/plain" ref={fileInputRef} onChange={handleLoadFromFile} className="hidden" />
          <Button size="sm" variant="outline" onClick={() => fileInputRef.current?.click()}>
            <Upload className="w-3.5 h-3.5 mr-1.5" /> Cargar .txt
          </Button>
          <Button size="sm" onClick={handleLoadFromTextarea} disabled={!textareaInput.trim()}>
            <Send className="w-3.5 h-3.5 mr-1.5" /> Agregar URLs
          </Button>
        </div>}
      >
        <div className="text-xs text-muted-foreground mb-2 p-2 rounded bg-blue-500/5 border border-blue-500/20">
          <strong>Cómo funciona:</strong> Pegá una URL por línea (o cargá un archivo .txt). Las URLs se normalizan automáticamente
          (si no tienen <code className="text-cyan-500">http://</code> se lo agregamos) y se deduplican. Las inválidas se ignoran.
        </div>
        <textarea
          value={textareaInput}
          onChange={e => setTextareaInput(e.target.value)}
          placeholder={"http://phishing-site.com/login\nfake-bank.com\nmalware-site.net/download\n\n(una URL por línea)"}
          className="w-full h-32 p-3 rounded border border-border bg-background font-mono text-xs resize-y"
        />
      </Panel>

      {/* ---------- Step 2: Enrich ---------- */}
      {step1Done && (
        <Panel
          title="PASO 2 — Enriquecer las URLs (VirusTotal, Whois, hosting, screenshot)"
          className="md:col-span-2"
          action={
            <Button size="sm" onClick={enrichAll} disabled={loading || stats.pending === 0}>
              {loading ? <><Loader2 className="w-3 h-3 mr-1.5 animate-spin" /> {progress.done}/{progress.total}</> : <><RefreshCw className="w-3 h-3 mr-1.5" /> Enriquecer todas</>}
            </Button>
          }
        >
          <div className="text-xs text-muted-foreground mb-3 p-2 rounded bg-blue-500/5 border border-blue-500/20">
            <strong>Qué hace este paso:</strong> Para cada URL, consulta VirusTotal (cuántos antivirus la marcan como maliciosa),
            obtiene el registrar y email de abuse vía Whois, identifica el hosting provider (ASN), detecta si está detrás de Cloudflare,
            clasifica la URL (phishing/malware/scam) y toma un screenshot visual del sitio.
          </div>
          {(loading || bulkSubmitting) && (
            <div className="text-xs font-mono mb-3 text-yellow-500">
              {progress.step} — progreso: {progress.done}/{progress.total}
            </div>
          )}
          {/* Stats grid */}
          <div className="grid grid-cols-2 md:grid-cols-5 lg:grid-cols-10 gap-2 mb-3">
            <StatBox label="Total URLs" value={stats.total} color="cyan" />
            <StatBox label="Enriquecidas ✓" value={stats.enriched} color="green" />
            <StatBox label="Pendientes" value={stats.pending} color="yellow" />
            <StatBox label="Phishing" value={stats.phishing} color="red" />
            <StatBox label="Malware" value={stats.malware} color="red" />
            <StatBox label="Scam" value={stats.scam} color="orange" />
            <StatBox label="Cloudflare" value={stats.cf} color="purple" />
            <StatBox label="APIs enviados ✓" value={stats.submits} color="green" />
            <StatBox label="Forms abiertos" value={stats.forms} color="blue" />
            <StatBox label="Emails generados" value={stats.emails} color="pink" />
          </div>
        </Panel>
      )}

      {/* ---------- Step 3: Report to platforms ---------- */}
      {step2Done && (
        <Panel
          title="PASO 3 — Reportar a las plataformas de takedown"
          className="md:col-span-2"
          action={
            <div className="flex gap-2">
              <Button size="sm" onClick={submitAll} disabled={bulkSubmitting || stats.enriched === 0}>
                {bulkSubmitting ? <><Loader2 className="w-3 h-3 mr-1.5 animate-spin" /> {progress.done}/{progress.total}</> : <><Send className="w-3 h-3 mr-1.5" /> Auto-submit a APIs</>}
              </Button>
              <Button size="sm" variant="outline" onClick={recheckOld}>
                <Clock className="w-3 h-3 mr-1.5" /> Re-check +7 días
              </Button>
            </div>
          }
        >
          <div className="text-xs text-muted-foreground mb-3 p-2 rounded bg-blue-500/5 border border-blue-500/20">
            <strong>Tres formas de reportar:</strong>
            <ul className="list-disc ml-4 mt-1 space-y-0.5">
              <li><strong className="text-green-500">Auto-submit a APIs</strong> (botón arriba): envía la URL automáticamente a URLhaus, VirusTotal, Clean-MX y PhishTank. Requiere API keys (ver nota abajo).</li>
              <li><strong className="text-blue-500">Pre-fill forms</strong> (botón "12 forms" por URL): abre el navegador con el formulario de Google, Microsoft, APWG, Netcraft, Kaspersky, etc. ya cargado con la URL. Vos confirmás con 1 click.</li>
              <li><strong className="text-purple-500">Correo de abuse</strong> (botón "Emails" por URL): genera un mailto: al abuse@ del registrar/hosting con template + evidencia. Vos mandás el correo desde tu cliente de mail.</li>
            </ul>
          </div>
          <div className="text-[10px] text-yellow-500 mb-3">
            ⚠ APIs que requieren keys: URLhaus (registrate en auth.abuse.ch), PhishTank (registrate en phishtank.com/developer.php).
            Sin keys, esas plataformas se marcan como "skipped" pero VirusTotal y Clean-MX funcionan sin keys adicionales.
          </div>
        </Panel>
      )}

      {/* ---------- Step 4 & 5: Per-URL table with actions ---------- */}
      {step1Done && (
        <Panel
          title={`URLs Cargadas — ${filtered.length}/${entries.length} — Acciones por URL`}
          className="md:col-span-2"
          action={
            <div className="flex gap-2">
              <Input type="text" placeholder="Filtrar..." value={filter} onChange={e => setFilter(e.target.value)} className="h-7 text-xs w-40" />
              <Button size="sm" variant="outline" onClick={generatePdf}>
                <Printer className="w-3 h-3 mr-1.5" /> Imprimir PDF (PASO 5)
              </Button>
              <Button size="sm" variant="ghost" onClick={handleClearAll}>
                <Trash2 className="w-3 h-3 mr-1.5" /> Limpiar
              </Button>
            </div>
          }
        >
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="w-[35%]">URL</TableHead>
                  <TableHead>Class</TableHead>
                  <TableHead>VT</TableHead>
                  <TableHead>Hosting</TableHead>
                  <TableHead>CF</TableHead>
                  <TableHead>APIs (auto-submit)</TableHead>
                  <TableHead>PASO 3: Reportar</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {filtered.slice(0, 100).map(entry => (
                  <React.Fragment key={entry.url}>
                    <TableRow>
                      <TableCell className="font-mono text-[11px]">
                        <div className="flex items-center gap-2">
                          {entry.status === "enriching" && <Loader2 className="w-3 h-3 animate-spin text-yellow-500 shrink-0" />}
                          {entry.status === "enriched" && <CheckCircle2 className="w-3 h-3 text-green-500 shrink-0" />}
                          {entry.status === "failed" && <XCircle className="w-3 h-3 text-red-500 shrink-0" />}
                          {entry.status === "pending" && <Clock className="w-3 h-3 text-muted-foreground shrink-0" />}
                          <span className="truncate" title={entry.url}>{entry.url}</span>
                        </div>
                        {entry.enrich?.finalUrl && entry.enrich.finalUrl !== entry.url && (
                          <div className="text-[10px] text-cyan-500 mt-0.5">→ {entry.enrich.finalUrl.slice(0, 80)}</div>
                        )}
                      </TableCell>
                      <TableCell>
                        <Badge variant={entry.enrich?.classification === "phishing" || entry.enrich?.classification === "malware" ? "destructive" : entry.enrich?.classification === "scam" ? "default" : "secondary"} className="text-[9px] font-mono">
                          {entry.enrich?.classification || "?"}
                        </Badge>
                      </TableCell>
                      <TableCell className="text-xs">
                        {entry.enrich?.vt ? (
                          <span className={`font-mono ${entry.enrich.vt.malicious > 0 ? "text-red-500 font-bold" : "text-green-500"}`}>
                            {entry.enrich.vt.malicious}/{entry.enrich.vt.malicious + entry.enrich.vt.suspicious + entry.enrich.vt.undetected}
                          </span>
                        ) : "?"}
                      </TableCell>
                      <TableCell className="text-[10px] font-mono">
                        {entry.enrich?.hosting?.asnOrg?.slice(0, 18) || "?"}
                        {entry.enrich?.hosting?.asn && <div className="text-muted-foreground">{entry.enrich.hosting.asn}</div>}
                      </TableCell>
                      <TableCell>
                        {entry.enrich?.cloudflare ? (
                          <Badge variant="outline" className="text-[9px] font-mono text-orange-500 border-orange-500/40">CF</Badge>
                        ) : <span className="text-muted-foreground text-[10px]">—</span>}
                      </TableCell>
                      <TableCell>
                        <div className="flex gap-1 flex-wrap">
                          {API_PLATFORMS.map(p => {
                            const s = entry.submits.find(x => x.platform === p.id);
                            return (
                              <Badge
                                key={p.id}
                                variant={s?.status === "success" ? "default" : s?.status === "failed" ? "destructive" : s?.status === "skipped" ? "outline" : "secondary"}
                                className="text-[8px] font-mono"
                                title={s?.message || (s ? "" : "Click en Auto-submit a APIs (arriba)")}
                              >
                                {p.id} {s ? (s.status === "success" ? "✓" : s.status === "failed" ? "✗" : s.status === "skipped" ? "○" : "·") : "?"}
                              </Badge>
                            );
                          })}
                        </div>
                      </TableCell>
                      <TableCell>
                        <div className="flex gap-1 items-center">
                          {entry.status === "pending" && (
                            <Button size="sm" variant="outline" className="h-7 text-[10px]" onClick={() => enrichOne(entry.url)}>
                              <Eye className="w-3 h-3 mr-1" /> Enriquecer
                            </Button>
                          )}
                          {entry.status === "enriched" && (
                            <>
                              <Button size="sm" variant="outline" className="h-7 text-[10px]" onClick={() => openAllPrefills(entry)} title="Abrir formularios pre-fill en navegador (6 pestañas por vez)">
                                <Globe className="w-3 h-3 mr-1" /> 12 forms
                              </Button>
                              <EmailButtons entry={entry} onOpen={openAbuseEmail} />
                            </>
                          )}
                          {entry.status === "failed" && (
                            <Button size="sm" variant="outline" className="h-7 text-[10px]" onClick={() => enrichOne(entry.url)}>
                              <RefreshCw className="w-3 h-3 mr-1" /> Reintentar
                            </Button>
                          )}
                        </div>
                      </TableCell>
                    </TableRow>
                    {entry.status === "enriched" && entry.enrich && (
                      <TableRow className="bg-muted/20">
                        <TableCell colSpan={7} className="p-3">
                          <div className="grid grid-cols-1 md:grid-cols-3 gap-3 text-[10px]">
                            {/* Screenshot */}
                            <div className="md:col-span-1">
                              <div className="text-muted-foreground mb-1">Screenshot visual del sitio:</div>
                              <img src={entry.enrich.screenshotUrl} alt="screenshot" className="rounded border border-border w-full max-h-32 object-cover" loading="lazy" />
                            </div>
                            {/* Details */}
                            <div className="md:col-span-2 space-y-1">
                              <FieldRow label="Registrar" value={entry.enrich.whois?.registrar || "?"} mono />
                              <FieldRow label="Abuse email (registrar)" value={entry.enrich.whois?.abuseEmail || "?"} mono />
                              <FieldRow label="Hosting" value={`${entry.enrich.hosting?.asnOrg || "?"} (${entry.enrich.hosting?.asn || "?"})`} mono />
                              <FieldRow label="ISP" value={entry.enrich.hosting?.isp || "?"} mono />
                              <FieldRow label="Detrás de Cloudflare" value={entry.enrich.cloudflare ? "SÍ — también contactar abuse@cloudflare.com" : "no"} mono />
                              <FieldRow label="VirusTotal" value={entry.enrich.vt ? `${entry.enrich.vt.malicious} malicious, ${entry.enrich.vt.suspicious} suspicious` : "?"} mono />
                              {entry.enrich.vt?.permalink && (
                                <a href={entry.enrich.vt.permalink} target="_blank" rel="noreferrer" className="text-cyan-500 hover:underline inline-flex items-center gap-1 text-[10px]">
                                  <ExternalLink className="w-3 h-3" /> Ver reporte completo en VirusTotal
                                </a>
                              )}
                              {entry.enrich.redirectChain.length > 1 && (
                                <div>
                                  <div className="text-muted-foreground mb-0.5">Cadena de redirecciones HTTP:</div>
                                  <div className="font-mono text-[9px] text-yellow-500">
                                    {entry.enrich.redirectChain.map(c => `${c.status}→${c.url.slice(0, 50)}`).join(" → ")}
                                  </div>
                                </div>
                              )}
                            </div>
                          </div>
                        </TableCell>
                      </TableRow>
                    )}
                  </React.Fragment>
                ))}
              </TableBody>
            </Table>
            {filtered.length > 100 && (
              <div className="text-[10px] text-muted-foreground text-center mt-2">
                Mostrando las primeras 100 de {filtered.length}. Usá el filtro para acotar.
              </div>
            )}
          </div>
        </Panel>
      )}

      {/* ---------- Empty state with platform list ---------- */}
      {entries.length === 0 && (
        <Panel title="Plataformas de Takedown (¿a dónde se reporta?)" className="md:col-span-2">
          <div className="flex flex-col items-center justify-center py-8 text-center gap-3">
            <ShieldOff className="w-12 h-12 text-muted-foreground/50" />
            <h3 className="text-base font-semibold">Cargá URLs para iniciar el takedown</h3>
            <p className="text-xs text-muted-foreground max-w-2xl">
              Pegá una URL por línea en el textarea de arriba (o cargá un archivo .txt).
              Después, enriquecé cada URL automáticamente (VirusTotal, Whois, screenshot, hosting, Cloudflare detection)
              y reportá a las siguientes 16 plataformas:
            </p>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-2 text-left text-[11px] mt-4">
              <PlatformGroup title="Auto-submit APIs (4)" items={["URLhaus (abuse.ch)", "VirusTotal", "Clean-MX", "PhishTank"]} note="Automático, vía POST (necesita keys)" />
              <PlatformGroup title="Pre-fill forms (6)" items={["Google Safe Browsing (Phishing)", "Google Safe Browsing (Malware)", "Microsoft SmartScreen", "APWG", "StopBadware", "Spam404", "Netcraft"]} note="Se abre formulario pre-cargado" />
              <PlatformGroup title="Antivirus forms (5)" items={["Kaspersky VirusDesk", "Cisco Talos", "Fortinet FortiGuard", "McAfee WebAdvisor", "Sucuri SiteCheck"]} note="Se abre formulario" />
              <PlatformGroup title="Abuse emails (4)" items={["Phishing (robo credenciales)", "Malware (distribución)", "Scam (fraude financiero)", "Copyright/DMCA"]} note="mailto: con plantilla" />
            </div>
          </div>
        </Panel>
      )}
    </ModuleShell>
  );
}

function StepBar({ label, done, last }: { label: string; done: boolean; last?: boolean }) {
  return (
    <div className="flex items-center gap-2">
      <div className={`flex items-center gap-1.5 px-2.5 py-1 rounded-full text-[10px] font-mono ${done ? "bg-green-500/15 text-green-500 border border-green-500/30" : "bg-muted text-muted-foreground border border-border"}`}>
        {done ? <CheckCircle2 className="w-3 h-3" /> : <Clock className="w-3 h-3" />}
        {label}
      </div>
      {!last && <span className="text-muted-foreground text-[10px]">→</span>}
    </div>
  );
}

function StatBox({ label, value, color }: { label: string; value: number; color: string }) {
  const colorMap: Record<string, string> = {
    cyan: "border-cyan-500/40 bg-cyan-500/5 text-cyan-400",
    green: "border-green-500/40 bg-green-500/5 text-green-400",
    yellow: "border-yellow-500/40 bg-yellow-500/5 text-yellow-400",
    red: "border-red-500/40 bg-red-500/5 text-red-400",
    orange: "border-orange-500/40 bg-orange-500/5 text-orange-400",
    purple: "border-purple-500/40 bg-purple-500/5 text-purple-400",
    blue: "border-blue-500/40 bg-blue-500/5 text-blue-400",
    pink: "border-pink-500/40 bg-pink-500/5 text-pink-400",
  };
  return (
    <div className={`rounded p-2 border ${colorMap[color] || "border-border bg-muted/20"}`}>
      <div className="text-lg font-bold font-mono">{value}</div>
      <div className="text-[10px]">{label}</div>
    </div>
  );
}

function EmailButtons({ entry, onOpen }: { entry: UrlEntry; onOpen: (e: UrlEntry, t: EmailTemplate) => void }) {
  const [open, setOpen] = React.useState(false);
  return (
    <>
      <Button size="sm" variant="outline" className="h-7 text-[10px]" onClick={() => setOpen(o => !o)}>
        <Mail className="w-3 h-3 mr-1" /> Emails {entry.emailsGenerated.length > 0 && `(${entry.emailsGenerated.length})`}
      </Button>
      {open && (
        <div className="absolute z-50 mt-1 ml-12 bg-background border border-border rounded shadow-lg p-2 flex flex-col gap-1 min-w-[220px]">
          {(Object.keys(EMAIL_TEMPLATES) as EmailTemplate[]).map(t => (
            <button key={t} onClick={() => { onOpen(entry, t); setOpen(false); }}
              className={`text-left text-[11px] px-2 py-1 rounded hover:bg-muted ${entry.emailsGenerated.includes(t) ? "text-green-500" : ""}`}>
              {entry.emailsGenerated.includes(t) ? "✓ " : ""}{EMAIL_TEMPLATES[t].name}
            </button>
          ))}
        </div>
      )}
    </>
  );
}

function PlatformGroup({ title, items, note }: { title: string; items: string[]; note: string }) {
  return (
    <div className="rounded border border-border p-2 bg-muted/20">
      <div className="font-semibold text-[11px] mb-1">{title}</div>
      <ul className="space-y-0.5">
        {items.map(i => <li key={i} className="text-muted-foreground">• {i}</li>)}
      </ul>
      <div className="text-[10px] text-cyan-500 mt-1">{note}</div>
    </div>
  );
}
