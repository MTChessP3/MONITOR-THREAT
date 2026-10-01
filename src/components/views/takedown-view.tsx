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

type Platform = "virustotal" | "urlscan";
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

const PREFILL_PLATFORMS: Array<{ id: PrefillPlatform; name: string; shortName: string; url: (u: string) => string; category: string }> = [
  { id: "google_phish", name: "Google Safe Browsing (Phishing)", shortName: "Google", category: "browser", url: u => `https://safebrowsing.google.com/safebrowsing/report_phish/?url=${encodeURIComponent(u)}` },
  { id: "google_malware", name: "Google Safe Browsing (Malware)", shortName: "Google", category: "browser", url: u => `https://safebrowsing.google.com/safebrowsing/report_badware/?url=${encodeURIComponent(u)}` },
  { id: "microsoft", name: "Microsoft SmartScreen", shortName: "Microsoft", category: "browser", url: u => `https://www.microsoft.com/en-us/wdsi/support/report-unsafe-site-guest?url=${encodeURIComponent(u)}` },
];

const API_PLATFORMS: Array<{ id: Platform; name: string; needsKey?: string; note?: string }> = [
  { id: "virustotal", name: "VirusTotal", needsKey: "VIRUSTOTAL_API_KEY", note: "POST → 70+ antivirus escanean la URL" },
  { id: "urlscan", name: "URLscan.io", needsKey: "URLSCAN_API_KEY", note: "Escanea la URL + crea reporte PÚBLICO accesible por cualquiera" },
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
    const parsed: UrlEntry[] = JSON.parse(raw);
    // Repair stale status: if entry.enrich exists and has no error,
    // the URL is effectively enriched — fix the status field. Otherwise,
    // if status is "enriching" (stuck from a previous session), reset
    // to "pending" so the user can re-enrich.
    return parsed.map(e => {
      if (e.enrich && !e.enrich.error) {
        return { ...e, status: "enriched" as const };
      }
      if (e.status === "enriching") {
        return { ...e, status: "pending" as const };
      }
      return e;
    });
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
  const [statModal, setStatModal] = React.useState<{ key: string; label: string; description: string } | null>(null);
  const [expandedUrls, setExpandedUrls] = React.useState<Set<string>>(new Set());
  const [imagePreview, setImagePreview] = React.useState<{ url: string; src: string; caption?: string } | null>(null);
  const [bulkSubmitting, setBulkSubmitting] = React.useState(false);
  const [autoTakedownRunning, setAutoTakedownRunning] = React.useState(false);
  const [progress, setProgress] = React.useState({ done: 0, total: 0, step: "" });
  const [apiKeyStatus, setApiKeyStatus] = React.useState<{ summary: { total: number; configured: number; missing: number }; keys: Array<{ id: string; name: string; envVar: string; registerUrl: string; note: string; configured: boolean; fromCookie: boolean; fromEnv: boolean; sharedWith?: string }> } | null>(null);
  const [keysForm, setKeysForm] = React.useState<Record<string, string>>({});
  const [savingKeys, setSavingKeys] = React.useState(false);
  const [keysSavedMsg, setKeysSavedMsg] = React.useState<string | null>(null);
  const [showKeysForm, setShowKeysForm] = React.useState(false);
  const fileInputRef = React.useRef<HTMLInputElement>(null);

  // Load from localStorage on mount
  React.useEffect(() => {
    const stored = loadFromStorage();
    if (stored.length > 0) {
      setEntries(stored);
    }
    // Fetch the API keys status from the backend — shows the user
    // which keys are configured (✓) and which are missing (✗) with
    // setup links, so they know what's actually being reported.
    refreshKeyStatus();
  }, []);

  const refreshKeyStatus = () => {
    fetch("/api/takedown/status").then(r => r.json()).then(setApiKeyStatus).catch(() => {});
  };

  // Save the API keys form to the backend (sets httpOnly cookies for
  // the user's session — no need to redeploy Vercel).
  const saveKeys = async () => {
    setSavingKeys(true);
    setKeysSavedMsg(null);
    try {
      const r = await fetch("/api/takedown/keys", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(keysForm),
      });
      const j: any = await r.json();
      if (j.success) {
        setKeysSavedMsg(`✓ ${j.set.length} key(s) configurada(s) en tu sesión. Las APIs ya están activas.`);
        setKeysForm({});
        setShowKeysForm(false);
        refreshKeyStatus();
      } else {
        setKeysSavedMsg(`✗ Error: ${j.error || "no se pudo guardar"}`);
      }
    } catch (e: any) {
      setKeysSavedMsg(`✗ Error: ${String(e?.message || e)}`);
    }
    setSavingKeys(false);
    setTimeout(() => setKeysSavedMsg(null), 5000);
  };

  // Persist to localStorage on change
  React.useEffect(() => {
    saveToStorage(entries);
  }, [entries]);

  // Close image preview on Escape key
  React.useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if (e.key === "Escape" && imagePreview) setImagePreview(null);
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, [imagePreview]);

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
    // Enrich any URL that is NOT yet enriched (pending, failed, or stuck
    // in "enriching" state from a previous session).
    const toEnrich = entries.filter(e => e.status !== "enriched");
    setProgress({ done: 0, total: toEnrich.length, step: `Enriqueciendo ${toEnrich.length} URL(s)...` });
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
    const platforms: Platform[] = ["virustotal", "urlscan"];
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

  const runFullTakedown = async () => {
    if (entries.length === 0) {
      alert("Primero cargá las URLs a reportar (PASO 1).");
      return;
    }
    if (!confirm(
      `Se va a ejecutar el TAKEDOWN AUTOMATICO para ${entries.length} URL(s).\n\n` +
      `Pasos:\n` +
      `  1. Enriquecer cada URL (VirusTotal, Whois, hosting, screenshot, Cloudflare)\n` +
      `  2. Reportar automaticamente a 2 APIs (VirusTotal, URLscan.io)\n\n` +
      `Si alguna API key no esta configurada, esa plataforma se marcara como "Salteado (sin key)" (no falla el resto).\n` +
      `Despues de los APIs automaticos, vas a ver 2 botones por URL (Google y Microsoft) para abrirlos manualmente cuando quieras.\n\n` +
      `¿Continuar?`
    )) {
      return;
    }
    setAutoTakedownRunning(true);
    setLoading(true);

    const total = entries.length;
    setProgress({ done: 0, total, step: `Iniciando takedown automatico de ${total} URL(s)...` });

    // Step 1: Enrich all
    let done = 0;
    setProgress({ done: 0, total, step: `[1/2] Enriqueciendo URLs (VirusTotal, Whois, hosting, screenshot)...` });
    const toEnrich = entries.filter(e => e.status !== "enriched");
    for (const e of toEnrich) {
      await enrichOne(e.url);
      done++;
      setProgress({ done, total, step: `[1/2] Enriquecido ${e.url.slice(0, 60)}... (${done}/${total})` });
    }

    // Step 2: Auto-submit to the 3 APIs ONLY (no Google/Microsoft auto-open — user does it manually per URL)
    setProgress({ done: 0, total, step: `[2/2] Reportando a 2 APIs (VirusTotal, URLscan)...` });
    done = 0;
    await new Promise(r => setTimeout(r, 100));
    const currentEntries = (await new Promise<UrlEntry[]>(resolve => {
      setEntries(prev => { resolve(prev); return prev; });
    }));
    for (const entry of currentEntries.filter(e => e.status === "enriched")) {
      await submitOne(entry);
      done++;
      setProgress({ done, total, step: `[2/2] Reportado ${entry.url.slice(0, 60)}... (${done}/${total})` });
    }

    // Done — show a summary alert, but DO NOT auto-generate the PDF.
    // The user generates the PDF themselves with the "Imprimir PDF" button.
    setLoading(false);
    setAutoTakedownRunning(false);
    setProgress({ done: 0, total: 0, step: "" });

    // Compute summary stats for the alert
    const allSubmits = currentEntries.flatMap(e => e.submits);
    const ok = allSubmits.filter(s => s.status === "success").length;
    const fail = allSubmits.filter(s => s.status === "failed").length;
    const skipped = allSubmits.filter(s => s.status === "skipped").length;
    alert(
      `Takedown automatico completado para ${total} URL(s).\n\n` +
      `Reportes a APIs (automatico):\n` +
      `  ${ok} reportados exitosamente\n` +
      `  ${fail} fallaron\n` +
      `  ${skipped} salteados (sin API key)\n\n` +
      `Para reportar a Google y Microsoft: usa los botones 'Google' y 'Microsoft' que aparecen al lado de cada URL en la tabla de abajo.\n` +
      `Para generar el PDF: hace click en el boton 'Imprimir PDF'.`
    );
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
    doc.text("Cyber Threat Intelligence Platform - Takedown Management", margin + 105, y + 26);
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

    // ---------- Section 1: Resumen de reportes ----------
    sectionHeading("Resumen de Reportes a APIs");

    // Only the 3 API platforms (no pre-fill forms, no emails — those
    // are not automatic and don't belong in this report).
    const apiPlatforms = ["virustotal", "urlscan"];

    // Summary table: Platform | Reportados | Fallidos | Salteados
    const summaryRows: Array<[string, string, string, string]> = [];
    for (const p of apiPlatforms) {
      const name = API_PLATFORMS.find(x => x.id === p)?.name || p;
      let success = 0, failed = 0, skipped = 0;
      for (const entry of entries) {
        const s = entry.submits.find(x => x.platform === p);
        if (s?.status === "success") success++;
        else if (s?.status === "failed" || s?.status === "error") failed++;
        else if (s?.status === "skipped") skipped++;
        else skipped++; // no submit attempted yet = counted as skipped
      }
      summaryRows.push([name, String(success), String(failed), String(skipped)]);
    }
    autoTable(doc, {
      startY: y,
      head: [["Plataforma API", "Reportado OK", "Fallo", "Salteado (sin key)"]],
      body: summaryRows,
      theme: "grid",
      margin: { left: margin, right: margin },
      styles: { fontSize: 10, cellPadding: 6, textColor: [30, 41, 59], lineColor: [226, 232, 240], lineWidth: 0.5 },
      headStyles: { fillColor: [220, 38, 38], textColor: [255, 255, 255], fontStyle: "bold", fontSize: 10 },
      columnStyles: {
        0: { cellWidth: contentWidth * 0.45, fontStyle: "bold" },
        1: { cellWidth: contentWidth * 0.18, halign: "center", textColor: [22, 163, 74] },
        2: { cellWidth: contentWidth * 0.18, halign: "center", textColor: [220, 38, 38] },
        3: { cellWidth: contentWidth * 0.19, halign: "center", textColor: [161, 98, 7] },
      },
    });
    // @ts-ignore
    y = (doc as any).lastAutoTable.finalY + 18;

    // Total counts
    const totalOk = entries.flatMap(e => e.submits).filter(s => s.status === "success").length;
    const totalFail = entries.flatMap(e => e.submits).filter(s => s.status === "failed" || s.status === "error").length;
    const totalSkip = entries.flatMap(e => e.submits).filter(s => s.status === "skipped").length;
    doc.setFont("helvetica", "bold"); doc.setFontSize(11); doc.setTextColor(15, 23, 42);
    doc.text(`Total: ${totalOk} reportes OK, ${totalFail} fallos, ${totalSkip} salteados (sin API key)`, margin, y);
    y += 18;

    // ---------- Section 2: Detalle por URL ----------
    sectionHeading("Detalle por URL - Estado de Reporte");

    for (const entry of entries.slice(0, 50)) {
      // URL header
      doc.setFont("helvetica", "bold"); doc.setFontSize(11); doc.setTextColor(15, 23, 42);
      if (y > pageHeight - margin - 120) { doc.addPage(); y = margin + 6; }
      doc.text(`URL: ${entry.url.slice(0, 90)}`, margin, y);
      y += 14;
      doc.setFont("helvetica", "normal"); doc.setFontSize(8); doc.setTextColor(100, 116, 139);
      if (entry.enrich?.hostname) {
        doc.text(`Hostname: ${entry.enrich.hostname}  -  Clase: ${entry.enrich.classification || "?"}  -  VT: ${entry.enrich.vt?.malicious || 0} malicious`, margin, y);
        y += 12;
      }
      if (entry.enrich?.finalUrl && entry.enrich.finalUrl !== entry.url) {
        doc.setTextColor(220, 38, 38);
        doc.text(`URL final (despues de redirects): ${entry.enrich.finalUrl.slice(0, 90)}`, margin, y);
        y += 12;
        doc.setTextColor(100, 116, 139);
      }
      y += 4;

      // Per-URL status table — 3 automatic APIs first, then 3 manual forms (Google Phishing, Google Malware, Microsoft)
      const reportedRows: Array<[string, string, string]> = [];

      // Auto APIs
      for (const p of apiPlatforms) {
        const name = API_PLATFORMS.find(x => x.id === p)?.name || p;
        const s = entry.submits.find(x => x.platform === p);
        let status = "Pendiente";
        let detail = "-";
        if (s?.status === "success") {
          status = "Reportado OK";
          const link = s.permalink || (p === "virustotal" && entry.enrich?.vt?.permalink) || entry.enrich?.vt?.permalink;
          detail = link && link !== "-" ? link.slice(0, 70) : "OK";
        } else if (s?.status === "failed" || s?.status === "error") {
          status = "Fallo";
          detail = (s.message || "error desconocido").slice(0, 70);
        } else if (s?.status === "skipped") {
          status = "Salteado (sin key)";
          detail = (s.message || "API key no configurada").slice(0, 70);
        }
        reportedRows.push([name, status, detail]);
      }

      // Manual forms: Google Phishing, Google Malware, Microsoft
      for (const p of PREFILL_PLATFORMS) {
        const wasOpened = entry.prefillOpened.includes(p.id);
        const link = p.url(entry.url);
        reportedRows.push([
          p.name + " (manual)",
          wasOpened ? "Form abierto" : "No abierto",
          link.slice(0, 70),
        ]);
      }

      autoTable(doc, {
        startY: y,
        head: [["Plataforma", "Estado", "Detalle / Link al reporte"]],
        body: reportedRows,
        theme: "striped",
        margin: { left: margin, right: margin },
        styles: { fontSize: 9, cellPadding: 5, textColor: [30, 41, 59], lineColor: [226, 232, 240], lineWidth: 0.3 },
        headStyles: { fillColor: [241, 245, 249], textColor: [71, 85, 105], fontSize: 9, fontStyle: "bold" },
        columnStyles: {
          0: { cellWidth: contentWidth * 0.30, fontStyle: "bold" },
          1: { cellWidth: contentWidth * 0.20, halign: "center" },
          2: { cellWidth: contentWidth * 0.50, textColor: [59, 130, 246] },
        },
        didParseCell: (data: any) => {
          if (data.section === "body" && data.column.index === 1) {
            const v = String(data.cell.raw || "");
            if (v.startsWith("Reportado")) data.cell.styles.textColor = [22, 163, 74];
            else if (v.startsWith("Fallo")) data.cell.styles.textColor = [220, 38, 38];
            else if (v.startsWith("Salteado") || v.startsWith("Pendiente") || v.startsWith("No")) data.cell.styles.textColor = [161, 98, 7];
            else if (v.startsWith("Form")) data.cell.styles.textColor = [59, 130, 246]; // blue for manual open
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
        ["Clasificacion", `${e.classification} (${e.classificationReason})`],
        ["VirusTotal", e.vt ? `${e.vt.malicious} malicious / ${e.vt.suspicious} suspicious / ${e.vt.undetected} undetected` : "?"],
        ["VT permalink", e.vt?.permalink || "?"],
        ["Registrar", e.whois?.registrar || "?"],
        ["Abuse email (registrar)", e.whois?.abuseEmail || "?"],
        ["Hosting provider", e.hosting ? `${e.hosting.asnOrg || "?"} (${e.hosting.asn || "?"})` : "?"],
        ["ISP", e.hosting?.isp || "?"],
        ["Detras de Cloudflare", e.cloudflare ? "SI - tambien contactar abuse@cloudflare.com" : "no"],
        ["URL final (despues de redirects)", e.finalUrl || entry.url],
      ]);
    }

    // ---------- Footer on each page ----------
    const pageCount = doc.getNumberOfPages();
    for (let i = 1; i <= pageCount; i++) {
      doc.setPage(i);
      doc.setFont("helvetica", "normal"); doc.setFontSize(8); doc.setTextColor(150, 150, 150);
      doc.text(`MONITOR-THREAT - TakeDown Report - Pagina ${i} de ${pageCount}`, pageWidth / 2, pageHeight - 20, { align: "center" });
    }

    doc.save(`takedown-report-${Date.now()}.pdf`);
  };

  // ---- Filtering ----
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

  // ---- Helper: toggle expansion of a URL row ----
  const toggleExpand = (url: string) => {
    setExpandedUrls(prev => {
      const next = new Set(prev);
      if (next.has(url)) next.delete(url);
      else next.add(url);
      return next;
    });
  };

  // ---- Stat metadata (label, description, predicate) for the modal ----
  const STAT_META: Record<string, { label: string; description: string; predicate: (e: UrlEntry) => boolean; bulkAction?: string }> = {
    total:      { label: "Total URLs",          description: "Todas las URLs cargadas en el sistema.", predicate: () => true },
    enriched:   { label: "Enriquecidas ✓",      description: "URLs con enriquecimiento completo (VirusTotal, Whois, hosting, screenshot, clasificación, Cloudflare).", predicate: e => e.status === "enriched" },
    pending:    { label: "Pendientes",          description: "URLs cargadas pero todavía no enriquecidas. Hacé click en 'Enriquecer todas' (arriba) o en 'Enriquecer' por cada URL.", predicate: e => e.status === "pending" || e.status === "failed", bulkAction: "enrich" },
    phishing:   { label: "Phishing",            description: "URLs clasificadas como phishing (robo de credenciales) por patrones en la URL (login, paypal, bank, etc.).", predicate: e => e.enrich?.classification === "phishing" },
    malware:    { label: "Malware",             description: "URLs clasificadas como distribución de malware (download, crack, keygen, exe, etc.).", predicate: e => e.enrich?.classification === "malware" },
    scam:       { label: "Scam",                description: "URLs clasificadas como scam/fraude financiero (prize, winner, lottery, investment, etc.).", predicate: e => e.enrich?.classification === "scam" },
    cloudflare: { label: "Cloudflare",          description: "URLs detectadas detrás de Cloudflare. Además del abuse del registrar/hosting, también contactar abuse@cloudflare.com.", predicate: e => !!e.enrich?.cloudflare },
    submits:    { label: "APIs enviados ✓",     description: "URLs reportadas exitosamente a al menos una API (VirusTotal, URLscan).", predicate: e => e.submits.some(s => s.status === "success") },
    forms:      { label: "Forms abiertos",      description: "URLs donde se abrió al menos un formulario pre-fill (Google, Microsoft, APWG, etc.).", predicate: e => e.prefillOpened.length > 0 },
    emails:     { label: "Emails generados",    description: "URLs donde se generó al menos un correo de abuse (phishing, malware, scam, copyright).", predicate: e => e.emailsGenerated.length > 0 },
  };

  // ---- Helper: open stat modal ----
  const openStatModal = (key: string) => {
    const meta = STAT_META[key];
    if (!meta) return;
    setStatModal({ key, label: meta.label, description: meta.description });
  };

  // ---- Bulk action from modal: enrich all URLs in the modal ----
  const bulkEnrichFromModal = async (urls: string[]) => {
    setLoading(true);
    setProgress({ done: 0, total: urls.length, step: `Enriqueciendo ${urls.length} URL(s)...` });
    let done = 0;
    for (const url of urls) {
      await enrichOne(url);
      done++;
      setProgress({ done, total: urls.length, step: `Enriquecido ${url.slice(0, 50)}...` });
    }
    setLoading(false);
    setProgress({ done: 0, total: 0, step: "" });
  };

  // ---- Bulk action from modal: submit all URLs in the modal to APIs ----
  const bulkSubmitFromModal = async (modalEntries: UrlEntry[]) => {
    setBulkSubmitting(true);
    setProgress({ done: 0, total: modalEntries.length, step: `Enviando ${modalEntries.length} URL(s) a APIs...` });
    let done = 0;
    for (const entry of modalEntries) {
      await submitOne(entry);
      done++;
      setProgress({ done, total: modalEntries.length, step: `Enviado ${entry.url.slice(0, 50)}...` });
    }
    setBulkSubmitting(false);
    setProgress({ done: 0, total: 0, step: "" });
  };

  // ---- Bulk action from modal: open 12 forms for all URLs in the modal ----
  const bulkPrefillsFromModal = (modalEntries: UrlEntry[]) => {
    if (modalEntries.length > 3) {
      if (!confirm(`Se abrirán hasta ${modalEntries.length * 6} pestañas (6 por URL). ¿Continuar? (el browser puede bloquear popups)`)) return;
    }
    modalEntries.slice(0, 5).forEach(entry => openAllPrefills(entry));
  };

  // ---- Compute filtered list (text filter only) ----
  const filtered = React.useMemo(() => {
    if (!filter.trim()) return entries;
    const f = filter.toLowerCase();
    return entries.filter(e => e.url.toLowerCase().includes(f) || e.enrich?.hostname?.toLowerCase().includes(f));
  }, [entries, filter]);

  // ---- Compute modal entries (matching the stat key) ----
  const modalEntries = React.useMemo(() => {
    if (!statModal) return [];
    const meta = STAT_META[statModal.key];
    if (!meta) return [];
    return entries.filter(meta.predicate);
  }, [entries, statModal]);

  return (
    <ModuleShell
      name="TakeDown URL"
      description="Carga URLs desde .txt o pega una por linea. El sistema las enriquece y reporta automaticamente a 2 APIs (VirusTotal, URLscan) con trazabilidad completa."
      icon={ShieldOff}
      category="INFRASTRUCTURE"
    >
      {/* ---------- Wizard step bar (always visible) ---------- */}
      <div className="flex flex-wrap items-center gap-2 p-3 rounded-lg border border-border bg-muted/20 text-[11px]">
        <StepBar label="1. Cargar URLs" done={step1Done} />
        <StepBar label="2. Enriquecer (auto)" done={step2Done} />
        <StepBar label="3. Reportar 2 APIs (auto)" done={step3Done} />
        <StepBar label="4. Google/Microsoft (manual)" done={false} />
        <StepBar label="5. Imprimir PDF" done={step5Done} last />
      </div>

      {/* Hint banner: simple workflow */}
      <div className="flex items-start gap-2 p-3 rounded-lg bg-cyan-500/10 border border-cyan-500/30 text-[11px]">
        <div className="text-cyan-500 font-bold shrink-0">💡</div>
        <div className="text-muted-foreground">
          <strong>PASO 1</strong>: Carga las URLs (textarea o .txt) - una por linea. Despues hace click en el boton <strong className="text-cyan-500">🚀 Takedown automatico completo</strong> que aparece abajo. El sistema ejecuta todo solo: enriquece cada URL + reporta a 2 APIs (VirusTotal, URLscan). Para Google y Microsoft, usa los botones al lado de cada URL en la tabla (manual).
        </div>
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

      {/* ---------- BIG AUTO-TAKEDOWN BUTTON — runs the entire pipeline ---------- */}
      {step1Done && (
        <Panel
          title="🚀 Takedown automático completo (UN solo botón)"
          className="md:col-span-2"
        >
          <div className="flex flex-col gap-3">
            <div className="text-xs text-muted-foreground p-3 rounded bg-cyan-500/5 border border-cyan-500/30">
              <strong className="text-cyan-500">Qué hace este botón:</strong>
              <ol className="list-decimal ml-4 mt-1 space-y-0.5 text-[11px]">
                <li><strong>Enriquece</strong> cada URL - VirusTotal, Whois, hosting, screenshot, Cloudflare, clasificacion</li>
                <li><strong>Reporta a 2 APIs (automatico)</strong> - VirusTotal, URLscan.io (cada una devuelve link al reporte publico)</li>
              </ol>
              <div className="mt-2 text-[10px] text-muted-foreground">
                NO abre Google ni Microsoft automaticamente. Para esos, usa los botones 'Google' y 'Microsoft' al lado de cada URL en la tabla.
              </div>
            </div>
            <div className="flex items-center gap-3 flex-wrap">
              <Button
                size="lg"
                onClick={runFullTakedown}
                disabled={autoTakedownRunning || loading || entries.length === 0}
                className="bg-cyan-600 hover:bg-cyan-700 text-white font-bold py-3 px-6 text-base"
              >
                {autoTakedownRunning || loading ? (
                  <><Loader2 className="w-4 h-4 mr-2 animate-spin" /> Ejecutando takedown automático... {progress.done}/{progress.total}</>
                ) : (
                  <><Send className="w-4 h-4 mr-2" /> 🚀 Ejecutar takedown automático completo ({entries.length} URL{entries.length === 1 ? "" : "s"})</>
                )}
              </Button>
            </div>
            {(autoTakedownRunning || (loading && progress.step)) && (
              <div className="p-3 rounded bg-yellow-500/10 border border-yellow-500/40 text-xs font-mono text-yellow-600">
                <div className="font-bold mb-1">Progreso en tiempo real:</div>
                <div>{progress.step}</div>
                <div className="mt-2 w-full bg-yellow-500/20 rounded-full h-1.5 overflow-hidden">
                  <div className="bg-yellow-500 h-full transition-all" style={{ width: `${progress.total > 0 ? (progress.done / progress.total) * 100 : 0}%` }} />
                </div>
              </div>
            )}
          </div>
        </Panel>
      )}

      {/* ---------- Step 2: Enrich ---------- */}
      {step1Done && (
        <Panel
          title="PASO 2 — Enriquecer las URLs (VirusTotal, Whois, hosting, screenshot)"
          className="md:col-span-2"
          action={
            <Button size="sm" onClick={enrichAll} disabled={loading || entries.every(e => e.status === "enriched")}>
              {loading ? <><Loader2 className="w-3 h-3 mr-1.5 animate-spin" /> {progress.done}/{progress.total}</> : <><RefreshCw className="w-3 h-3 mr-1.5" /> Enriquecer todas ({entries.filter(e => e.status !== "enriched").length} pendientes)</>}
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
          {/* Stats grid — clickeables, abren modal con info + acciones */}
          <div className="text-xs text-muted-foreground mb-2 p-2 rounded bg-cyan-500/5 border border-cyan-500/20">
            💡 Click en cualquier stat para ver las URLs de esa categoría y gestionarlas (enriquecer, abrir forms, generar emails).
          </div>
          <div className="grid grid-cols-2 md:grid-cols-5 lg:grid-cols-10 gap-2 mb-3">
            <StatBox label="Total URLs" value={stats.total} color="cyan" filterKey="total" onClick={openStatModal} />
            <StatBox label="Enriquecidas ✓" value={stats.enriched} color="green" filterKey="enriched" onClick={openStatModal} />
            <StatBox label="Pendientes" value={stats.pending} color="yellow" filterKey="pending" onClick={openStatModal} />
            <StatBox label="Phishing" value={stats.phishing} color="red" filterKey="phishing" onClick={openStatModal} />
            <StatBox label="Malware" value={stats.malware} color="red" filterKey="malware" onClick={openStatModal} />
            <StatBox label="Scam" value={stats.scam} color="orange" filterKey="scam" onClick={openStatModal} />
            <StatBox label="Cloudflare" value={stats.cf} color="purple" filterKey="cloudflare" onClick={openStatModal} />
            <StatBox label="APIs enviados ✓" value={stats.submits} color="green" filterKey="submits" onClick={openStatModal} />
            <StatBox label="Forms abiertos" value={stats.forms} color="blue" filterKey="forms" onClick={openStatModal} />
            <StatBox label="Emails generados" value={stats.emails} color="pink" filterKey="emails" onClick={openStatModal} />
          </div>
        </Panel>
      )}

      {/* ---------- Step 3: Auto-report to APIs (solo APIs automáticas) ---------- */}
      {step2Done && (
        <Panel
          title="PASO 3 - Reporte a 2 APIs (automatico) - Google/Microsoft son manuales"
          className="md:col-span-2"
          action={
            <div className="flex gap-2">
              <Button size="sm" onClick={submitAll} disabled={bulkSubmitting || stats.enriched === 0}>
                {bulkSubmitting ? <><Loader2 className="w-3 h-3 mr-1.5 animate-spin" /> {progress.done}/{progress.total}</> : <><Send className="w-3 h-3 mr-1.5" /> Reportar a las 2 APIs</>}
              </Button>
              <Button size="sm" variant="outline" onClick={recheckOld}>
                <Clock className="w-3 h-3 mr-1.5" /> Re-check +7 días
              </Button>
            </div>
          }
        >
          {/* API Keys status panel — shows ✓/✗ for each key + inline config form */}
          {apiKeyStatus && (
            <div className="mb-3 p-3 rounded border border-border bg-muted/20">
              <div className="flex items-center justify-between mb-2">
                <div className="text-xs font-semibold">
                  Estado de las API Keys:{" "}
                  <span className="text-green-500">{apiKeyStatus.summary.configured} configuradas</span>
                  {" / "}
                  <span className="text-yellow-500">{apiKeyStatus.summary.missing} faltantes</span>
                </div>
                <div className="flex gap-2">
                  {apiKeyStatus.summary.missing > 0 && (
                    <Button size="sm" variant={showKeysForm ? "outline" : "default"} className="h-7 text-[10px]" onClick={() => setShowKeysForm(!showKeysForm)}>
                      {showKeysForm ? "✕ Cerrar formulario" : "⚙ Configurar keys acá"}
                    </Button>
                  )}
                </div>
              </div>

              {/* Status grid (compact) */}
              <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-7 gap-1.5">
                {apiKeyStatus.keys.map(k => (
                  <div key={k.id} className={`flex items-center gap-1.5 p-1.5 rounded border text-[10px] ${k.configured ? "border-green-500/30 bg-green-500/5" : "border-yellow-500/30 bg-yellow-500/5"}`}>
                    <span className={k.configured ? "text-green-500" : "text-yellow-500"}>{k.configured ? "✓" : "✗"}</span>
                    <span className="font-mono font-bold">{k.id}</span>
                    {k.fromCookie && <span className="text-cyan-500 text-[8px]">(session)</span>}
                    {k.fromEnv && !k.fromCookie && <span className="text-muted-foreground text-[8px]">(env)</span>}
                  </div>
                ))}
              </div>

              {/* Inline form to set keys — replaces the need for Vercel config */}
              {showKeysForm && (
                <div className="mt-3 p-3 rounded border border-cyan-500/30 bg-cyan-500/5">
                  <div className="text-xs text-muted-foreground mb-2">
                    Pegá acá las API keys que obtuviste de los sitios de cada plataforma. Se guardan en una cookie de tu sesión (no en Vercel) y se usan automáticamente al reportar. Si cerrás el navegador las keys se borran.
                  </div>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                    {apiKeyStatus.keys.filter(k => k.envVar && !k.configured).flatMap(k => {
                      // PhishTank has 2 keys (split by " + ")
                      return k.envVar.split(" + ").map(envVar => (
                        <div key={envVar} className="flex flex-col gap-1">
                          <label className="text-[10px] font-mono text-cyan-500">{envVar}</label>
                          <Input
                            type="password"
                            placeholder={envVar.includes("APP_ID") ? "PhishTank App ID" : `Pegá tu ${envVar}`}
                            value={keysForm[envVar] || ""}
                            onChange={e => setKeysForm({ ...keysForm, [envVar]: e.target.value })}
                            className="h-8 text-xs font-mono"
                          />
                          {k.registerUrl && (
                            <a href={k.registerUrl} target="_blank" rel="noreferrer" className="text-[10px] text-cyan-500 hover:underline inline-flex items-center gap-1">
                              <ExternalLink className="w-2.5 h-2.5" /> Registrarme en {k.name}
                            </a>
                          )}
                        </div>
                      ));
                    })}
                    {apiKeyStatus.keys.filter(k => k.envVar && !k.configured).length === 0 && (
                      <div className="col-span-2 text-xs text-green-500 text-center py-3">
                        ✓ Todas las API keys están configuradas. Ya podés reportar a las 7 plataformas.
                      </div>
                    )}
                  </div>
                  {apiKeyStatus.keys.some(k => k.envVar && !k.configured) && (
                    <div className="flex gap-2 mt-3 items-center">
                      <Button size="sm" onClick={saveKeys} disabled={savingKeys || Object.values(keysForm).every(v => !v.trim())}>
                        {savingKeys ? <><Loader2 className="w-3 h-3 mr-1.5 animate-spin" /> Guardando...</> : "💾 Guardar keys"}
                      </Button>
                      <Button size="sm" variant="ghost" onClick={() => { setKeysForm({}); setShowKeysForm(false); }}>
                        Cancelar
                      </Button>
                      {keysSavedMsg && <span className={`text-xs ${keysSavedMsg.startsWith("✓") ? "text-green-500" : "text-red-500"}`}>{keysSavedMsg}</span>}
                    </div>
                  )}
                </div>
              )}
            </div>
          )}
        </Panel>
      )}

      {/* ---------- Step 4 & 5: Per-URL table with actions ---------- */}
      {step1Done && (
        <Panel
          title={`URLs Cargadas — ${filtered.length}/${entries.length} — click en una fila para ver detalle`}
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
          <div className="text-[10px] text-muted-foreground mb-2">
            💡 Click en una fila para expandir/colapsar el detalle (screenshot, registrar, hosting, VirusTotal, redirects).
          </div>
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="w-[35%]">URL (click para expandir)</TableHead>
                  <TableHead>Class</TableHead>
                  <TableHead>VT</TableHead>
                  <TableHead>Hosting</TableHead>
                  <TableHead>CF</TableHead>
                  <TableHead>APIs (auto-submit)</TableHead>
                  <TableHead>PASO 3: Reportar</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {filtered.slice(0, 100).map(entry => {
                  const isExpanded = expandedUrls.has(entry.url);
                  return (
                    <React.Fragment key={entry.url}>
                      <TableRow
                        className={isExpanded ? "bg-muted/30 cursor-pointer" : "cursor-pointer hover:bg-muted/20"}
                        onClick={() => toggleExpand(entry.url)}
                      >
                        <TableCell className="font-mono text-[11px]">
                          <div className="flex items-center gap-2">
                            {isExpanded ? (
                              <span className="text-cyan-500 text-[10px] shrink-0">▼</span>
                            ) : (
                              <span className="text-muted-foreground text-[10px] shrink-0">▶</span>
                            )}
                            {entry.status === "enriching" && <Loader2 className="w-3 h-3 animate-spin text-yellow-500 shrink-0" />}
                            {entry.status === "enriched" && <CheckCircle2 className="w-3 h-3 text-green-500 shrink-0" />}
                            {entry.status === "failed" && <XCircle className="w-3 h-3 text-red-500 shrink-0" />}
                            {entry.status === "pending" && <Clock className="w-3 h-3 text-muted-foreground shrink-0" />}
                            <span className="truncate" title={entry.url}>{entry.url}</span>
                          </div>
                          {entry.enrich?.finalUrl && entry.enrich.finalUrl !== entry.url && (
                            <div className="text-[10px] text-cyan-500 mt-0.5 ml-5">→ {entry.enrich.finalUrl.slice(0, 80)}</div>
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
                        <TableCell onClick={(e) => e.stopPropagation()}>
                          <div className="flex gap-1 flex-wrap">
                            {API_PLATFORMS.map(p => {
                              const s = entry.submits.find(x => x.platform === p.id);
                              let label = `${p.id}: ?`;
                              let variant: "default" | "destructive" | "outline" | "secondary" = "secondary";
                              let colorClass = "text-muted-foreground";
                              if (s?.status === "success") {
                                label = `${p.id}: OK`;
                                variant = "default";
                                colorClass = "text-green-500";
                              } else if (s?.status === "failed") {
                                label = `${p.id}: Fallo`;
                                variant = "destructive";
                                colorClass = "text-red-500";
                              } else if (s?.status === "skipped") {
                                label = `${p.id}: Sin key`;
                                variant = "outline";
                                colorClass = "text-yellow-500";
                              } else if (s?.status === "pending" || s?.status === "error") {
                                label = `${p.id}: Pendiente`;
                                variant = "secondary";
                                colorClass = "text-muted-foreground";
                              }
                              return (
                                <Badge
                                  key={p.id}
                                  variant={variant}
                                  className={`text-[8px] font-mono ${colorClass}`}
                                  title={s?.message || (s ? "" : "Hace click en 'Reportar APIs' para enviar")}
                                >
                                  {label}
                                </Badge>
                              );
                            })}
                          </div>
                        </TableCell>
                        <TableCell onClick={(e) => e.stopPropagation()}>
                          <div className="flex gap-1 items-center">
                            {entry.status === "pending" && (
                              <Button size="sm" variant="outline" className="h-7 text-[10px]" onClick={() => enrichOne(entry.url)}>
                                <Eye className="w-3 h-3 mr-1" /> Enriquecer
                              </Button>
                            )}
                            {entry.status === "enriched" && (
                              <>
                                <Button size="sm" variant="outline" className="h-7 text-[10px] text-blue-500 border-blue-500/40" onClick={() => openPrefill(entry, "google_phish")} title="Abrir formulario de Google Safe Browsing (Phishing) para reportar manualmente">
                                  <Globe className="w-3 h-3 mr-1" /> Google
                                </Button>
                                <Button size="sm" variant="outline" className="h-7 text-[10px] text-cyan-500 border-cyan-500/40" onClick={() => openPrefill(entry, "microsoft")} title="Abrir formulario de Microsoft SmartScreen para reportar manualmente">
                                  <Globe className="w-3 h-3 mr-1" /> Microsoft
                                </Button>
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
                      {isExpanded && entry.status === "enriched" && entry.enrich && (
                        <TableRow className="bg-muted/30 border-l-4 border-l-cyan-500">
                          <TableCell colSpan={7} className="p-3">
                            <div className="grid grid-cols-1 md:grid-cols-3 gap-3 text-[10px]">
                              {/* Screenshot — clickable to open preview modal */}
                              <div className="md:col-span-1">
                                <div className="text-muted-foreground mb-1 flex items-center gap-1">
                                  <Eye className="w-3 h-3" /> Screenshot visual (click para ampliar):
                                </div>
                                <button
                                  type="button"
                                  onClick={() => setImagePreview({ url: entry.url, src: entry.enrich!.screenshotUrl, caption: entry.url })}
                                  className="block w-full rounded border border-border overflow-hidden hover:border-cyan-500 hover:shadow-md transition-all cursor-zoom-in group relative"
                                  title="Click para ver la imagen en tamaño completo"
                                >
                                  <img src={entry.enrich.screenshotUrl} alt="screenshot" className="w-full max-h-48 object-cover group-hover:opacity-90" loading="lazy" />
                                  <div className="absolute inset-0 bg-black/0 group-hover:bg-black/30 transition-colors flex items-center justify-center">
                                    <span className="opacity-0 group-hover:opacity-100 text-white text-xs bg-black/70 px-2 py-1 rounded transition-opacity">
                                      🔍 Click para ampliar
                                    </span>
                                  </div>
                                </button>
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
                      {isExpanded && entry.status === "pending" && (
                        <TableRow className="bg-muted/30 border-l-4 border-l-cyan-500">
                          <TableCell colSpan={7} className="p-3 text-center text-xs text-muted-foreground">
                            Esta URL todavía no fue enriquecida. Hacé click en "Enriquecer" o en "Enriquecer todas" (arriba) para obtener los datos.
                          </TableCell>
                        </TableRow>
                      )}
                      {isExpanded && entry.status === "failed" && (
                        <TableRow className="bg-red-500/5 border-l-4 border-l-red-500">
                          <TableCell colSpan={7} className="p-3 text-center text-xs text-red-500">
                            Falló el enriquecimiento. Hacé click en "Reintentar" para volver a intentarlo.
                          </TableCell>
                        </TableRow>
                      )}
                    </React.Fragment>
                  );
                })}
              </TableBody>
            </Table>
            {filtered.length > 100 && (
              <div className="text-[10px] text-muted-foreground text-center mt-2">
                Mostrando las primeras 100 de {filtered.length}. Usá el filtro para acotar.
              </div>
            )}
            {filtered.length === 0 && entries.length > 0 && (
              <div className="text-center py-6 text-xs text-muted-foreground">
                No hay URLs que cargadas. Cargá URLs en el PASO 1.
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
              y reportá a las siguientes 19 plataformas:
            </p>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-2 text-left text-[11px] mt-4">
              <PlatformGroup title="Auto-submit APIs (2) - 100% automatico" items={["VirusTotal", "URLscan.io (reporte publico)"]} note="POST directo, devuelven link al reporte" />
              <PlatformGroup title="Pre-fill forms (6)" items={["Google Safe Browsing (Phishing)", "Google Safe Browsing (Malware)", "Microsoft SmartScreen", "APWG", "StopBadware", "Spam404", "Netcraft"]} note="Se abre formulario pre-cargado" />
              <PlatformGroup title="Antivirus forms (5)" items={["Kaspersky VirusDesk", "Cisco Talos", "Fortinet FortiGuard", "McAfee WebAdvisor", "Sucuri SiteCheck"]} note="Se abre formulario" />
              <PlatformGroup title="Abuse emails (4)" items={["Phishing (robo credenciales)", "Malware (distribución)", "Scam (fraude financiero)", "Copyright/DMCA"]} note="mailto: con plantilla" />
            </div>
          </div>
        </Panel>
      )}

      {/* ---------- Stat Modal: shows URLs matching a stat + actions ---------- */}
      {statModal && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4"
          onClick={() => setStatModal(null)}
        >
          <div
            className="bg-background border border-border rounded-lg shadow-2xl max-w-4xl w-full max-h-[80vh] flex flex-col"
            onClick={(e) => e.stopPropagation()}
          >
            {/* Modal header */}
            <div className="flex items-center justify-between p-4 border-b border-border">
              <div>
                <h2 className="text-lg font-bold flex items-center gap-2">
                  <Filter className="w-4 h-4 text-cyan-500" />
                  {statModal.label} ({modalEntries.length})
                </h2>
                <p className="text-xs text-muted-foreground mt-1">{statModal.description}</p>
              </div>
              <button onClick={() => setStatModal(null)} className="text-muted-foreground hover:text-foreground p-2 rounded hover:bg-muted">
                ✕
              </button>
            </div>

            {/* Modal bulk actions */}
            {modalEntries.length > 0 && (
              <div className="flex flex-wrap gap-2 p-3 border-b border-border bg-muted/20">
                <Button size="sm" variant="outline" onClick={() => bulkEnrichFromModal(modalEntries.filter(e => e.status !== "enriched").map(e => e.url))} disabled={loading || modalEntries.every(e => e.status === "enriched")}>
                  <RefreshCw className="w-3 h-3 mr-1.5" /> Enriquecer las {modalEntries.filter(e => e.status !== "enriched").length} URL(s) no enriquecidas
                </Button>
                {modalEntries.some(e => e.status === "enriched") && (
                  <Button size="sm" onClick={() => bulkSubmitFromModal(modalEntries.filter(e => e.status === "enriched"))} disabled={bulkSubmitting}>
                    <Send className="w-3 h-3 mr-1.5" /> Reportar a las 2 APIs ({modalEntries.filter(e => e.status === "enriched").length} URLs)
                  </Button>
                )}
              </div>
            )}

            {/* Progress bar inside modal */}
            {(loading || bulkSubmitting) && (
              <div className="px-3 py-2 bg-yellow-500/10 border-b border-yellow-500/30 text-xs font-mono text-yellow-500">
                {progress.step} — {progress.done}/{progress.total}
              </div>
            )}

            {/* Modal body: list of URLs */}
            <div className="overflow-y-auto p-3 flex-1">
              {modalEntries.length === 0 ? (
                <div className="text-center py-8 text-sm text-muted-foreground">
                  No hay URLs en esta categoría.
                </div>
              ) : (
                <div className="space-y-2">
                  {modalEntries.map(entry => {
                    const e = entry.enrich;
                    return (
                      <div key={entry.url} className="rounded border border-border p-3 bg-card hover:bg-muted/20">
                        <div className="flex items-start justify-between gap-2 mb-2">
                          <div className="font-mono text-xs break-all flex-1">
                            <span className="text-cyan-500">{entry.url}</span>
                            {e?.finalUrl && e.finalUrl !== entry.url && (
                              <div className="text-[10px] text-cyan-500 mt-0.5">→ {e.finalUrl}</div>
                            )}
                          </div>
                          <Badge variant={entry.status === "enriched" ? "default" : entry.status === "pending" ? "secondary" : "destructive"} className="text-[9px] font-mono shrink-0">
                            {entry.status}
                          </Badge>
                        </div>
                        {e && (
                          <div className="grid grid-cols-2 md:grid-cols-4 gap-2 text-[10px] mb-2">
                            <div>
                              <span className="text-muted-foreground">Class:</span>{" "}
                              <Badge variant={e.classification === "phishing" || e.classification === "malware" ? "destructive" : "secondary"} className="text-[8px] font-mono">
                                {e.classification}
                              </Badge>
                            </div>
                            <div>
                              <span className="text-muted-foreground">VT:</span>{" "}
                              <span className={`font-mono ${e.vt?.malicious ? "text-red-500 font-bold" : "text-green-500"}`}>
                                {e.vt?.malicious || 0}/{(e.vt?.malicious || 0) + (e.vt?.suspicious || 0) + (e.vt?.undetected || 0)}
                              </span>
                            </div>
                            <div>
                              <span className="text-muted-foreground">Hosting:</span>{" "}
                              <span className="font-mono">{e.hosting?.asnOrg?.slice(0, 18) || "?"}</span>
                            </div>
                            <div>
                              <span className="text-muted-foreground">Cloudflare:</span>{" "}
                              {e.cloudflare ? <span className="text-orange-500 font-bold">SÍ</span> : <span className="text-muted-foreground">no</span>}
                            </div>
                          </div>
                        )}
                        {e && (
                          <div className="text-[10px] text-muted-foreground mb-2 font-mono">
                            <div>Registrar: {e.whois?.registrar || "?"} · Abuse: {e.whois?.abuseEmail || "?"}</div>
                          </div>
                        )}
                        {/* Screenshot thumbnail — clickable to open preview modal */}
                        {entry.status === "enriched" && (
                          <div className="mb-2">
                            <button
                              type="button"
                              onClick={() => setImagePreview({ url: entry.url, src: entry.enrich!.screenshotUrl, caption: entry.url })}
                              className="block w-full rounded border border-border overflow-hidden hover:border-cyan-500 hover:shadow-md transition-all cursor-zoom-in group relative"
                              title="Click para ver la imagen en tamaño completo"
                            >
                              <img src={entry.enrich!.screenshotUrl} alt="screenshot" className="w-full max-h-32 object-cover group-hover:opacity-90" loading="lazy" />
                              <div className="absolute inset-0 bg-black/0 group-hover:bg-black/30 transition-colors flex items-center justify-center">
                                <span className="opacity-0 group-hover:opacity-100 text-white text-[10px] bg-black/70 px-2 py-1 rounded transition-opacity">
                                  🔍 Click para ampliar
                                </span>
                              </div>
                            </button>
                          </div>
                        )}
                        {/* Per-URL actions */}
                        <div className="flex flex-wrap gap-2">
                          {entry.status === "pending" && (
                            <Button size="sm" variant="outline" className="h-7 text-[10px]" onClick={() => enrichOne(entry.url)}>
                              <Eye className="w-3 h-3 mr-1" /> Enriquecer
                            </Button>
                          )}
                          {entry.status === "enriched" && (
                            <>
                              <Button size="sm" variant="outline" className="h-7 text-[10px] text-blue-500 border-blue-500/40" onClick={() => openPrefill(entry, "google_phish")}>
                                <Globe className="w-3 h-3 mr-1" /> Google
                              </Button>
                              <Button size="sm" variant="outline" className="h-7 text-[10px] text-cyan-500 border-cyan-500/40" onClick={() => openPrefill(entry, "microsoft")}>
                                <Globe className="w-3 h-3 mr-1" /> Microsoft
                              </Button>
                              {e?.vt?.permalink && (
                                <a href={e.vt.permalink} target="_blank" rel="noreferrer" className="inline-flex items-center gap-1 text-[10px] text-cyan-500 hover:underline px-2 py-1">
                                  <ExternalLink className="w-3 h-3" /> VT
                                </a>
                              )}
                              <Button size="sm" variant="outline" className="h-7 text-[10px]" onClick={() => toggleExpand(entry.url)}>
                                Ver detalle completo (en tabla)
                              </Button>
                            </>
                          )}
                          {entry.status === "failed" && (
                            <Button size="sm" variant="outline" className="h-7 text-[10px]" onClick={() => enrichOne(entry.url)}>
                              <RefreshCw className="w-3 h-3 mr-1" /> Reintentar
                            </Button>
                          )}
                        </div>
                      </div>
                    );
                  })}
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* ---------- Image Preview Modal: full-size screenshot ---------- */}
      {imagePreview && (
        <div
          className="fixed inset-0 z-[60] flex items-center justify-center bg-black/90 backdrop-blur-sm p-4"
          onClick={() => setImagePreview(null)}
        >
          <button
            onClick={() => setImagePreview(null)}
            className="absolute top-4 right-4 text-white/80 hover:text-white bg-white/10 hover:bg-white/20 rounded-full p-2 transition-colors z-10"
            title="Cerrar (Esc)"
          >
            <XCircle className="w-6 h-6" />
          </button>
          <div
            className="relative max-w-[95vw] max-h-[90vh] flex flex-col items-center"
            onClick={(e) => e.stopPropagation()}
          >
            <img
              src={imagePreview.src}
              alt={imagePreview.caption || "screenshot"}
              className="max-w-full max-h-[80vh] object-contain rounded shadow-2xl border-2 border-cyan-500/40"
            />
            {imagePreview.caption && (
              <div className="mt-3 px-4 py-2 rounded bg-black/60 backdrop-blur-sm max-w-full overflow-x-auto">
                <div className="text-xs font-mono text-cyan-300 break-all">
                  📸 {imagePreview.caption}
                </div>
                <div className="text-[10px] text-white/60 mt-1">
                  Click fuera de la imagen o presioná Esc para cerrar.
                </div>
              </div>
            )}
          </div>
        </div>
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

function StatBox({ label, value, color, filterKey, onClick }: { label: string; value: number; color: string; filterKey?: string; onClick?: (k: string) => void }) {
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
  const isClickable = !!onClick && !!filterKey && value > 0;
  return (
    <button
      type="button"
      disabled={!isClickable}
      onClick={() => isClickable && onClick!(filterKey!)}
      className={`rounded p-2 border text-left transition-all ${colorMap[color] || "border-border bg-muted/20"} ${
        isClickable ? "hover:scale-105 hover:shadow-md hover:border-cyan-500 cursor-pointer" : "cursor-default opacity-50"
      }`}
      title={isClickable ? `Click para ver las ${value} URL(s) de esta categoría + gestionarlas` : "Sin URLs en esta categoría"}
    >
      <div className="text-lg font-bold font-mono flex items-center gap-1">
        {value}
        {isClickable && (
          <span className="text-[10px] text-muted-foreground/60">→</span>
        )}
      </div>
      <div className="text-[10px]">{label}</div>
    </button>
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
