"use client";

import * as React from "react";
import {
  ShieldCheck, Search, Loader2, Printer, AlertTriangle, ExternalLink, Globe,
  ShieldAlert, KeyRound, Calendar, Building2,
} from "lucide-react";
import { jsPDF } from "jspdf";
import autoTable from "jspdf-autotable";

import { ModuleShell, Panel } from "@/components/module-shell";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Table, TableBody, TableCell, TableHead, TableHeader, TableRow,
} from "@/components/ui/table";

interface BrandFinding {
  brand: string;
  brandId: string;
  category: "typosquatting" | "phishing" | "cert" | "registration";
  source: string;
  type: string;
  domain?: string;
  url?: string;
  title: string;
  snippet: string;
  severity: "high" | "medium" | "low" | "info";
  metadata?: {
    ip?: string;
    cname?: string;
    rdap?: {
      registrationDate?: string;
      expirationDate?: string;
      registrant?: string;
      registrar?: string;
      nameservers?: string[];
      status?: string[];
    } | null;
    commonName?: string;
    san?: string;
    issuer?: string;
    notBefore?: string;
  };
  timestamp: string | null;
}

interface Brand {
  id: string;
  name: string;
  category: string;
  officialDomain: string;
  typosCount: number;
}

const CAT_LABELS: Record<string, string> = {
  typosquatting: "Typosquatting (DNS resuelto)",
  phishing: "Phishing",
  registration: "Dominio registrado (RDAP)",
  cert: "Certificado TLS",
};

const CAT_ICONS: Record<string, React.ReactNode> = {
  typosquatting: <Globe className="w-3 h-3" />,
  phishing: <ShieldAlert className="w-3 h-3" />,
  registration: <Building2 className="w-3 h-3" />,
  cert: <KeyRound className="w-3 h-3" />,
};

export function BrandProtectionView() {
  const [loading, setLoading] = React.useState(false);
  const [results, setResults] = React.useState<BrandFinding[]>([]);
  const [brands, setBrands] = React.useState<Brand[]>([]);
  const [summary, setSummary] = React.useState<{
    total: number;
    byBrand: Record<string, number>;
    byCategory: Record<string, number>;
    bySeverity: { high: number; medium: number; low: number; info: number };
  } | null>(null);
  const [error, setError] = React.useState<string | null>(null);
  const [searched, setSearched] = React.useState(false);
  const [activeBrand, setActiveBrand] = React.useState<string>("all");
  const [activeCategory, setActiveCategory] = React.useState<string>("all");

  const search = async (brandId: string = "all") => {
    setLoading(true);
    setError(null);
    setResults([]);
    setBrands([]);
    setSummary(null);
    setSearched(true);
    setActiveBrand("all");
    setActiveCategory("all");
    try {
      const r = await fetch(`/api/brand-protection/search?brand=${encodeURIComponent(brandId)}`);
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      const j = await r.json();
      setResults(j.results || []);
      setBrands(j.brands || []);
      setSummary(j.summary || null);
    } catch (e: any) {
      setError(String(e?.message || e));
    }
    setLoading(false);
  };

  const sevColors: Record<string, "destructive" | "default" | "secondary" | "outline"> = {
    high: "destructive", medium: "default", low: "secondary", info: "outline",
  };
  const sevText: Record<string, string> = { high: "ALTA", medium: "MEDIA", low: "BAJA", info: "INFO" };

  const generatePdf = () => {
    if (results.length === 0) return;
    const doc = new jsPDF({ unit: "pt", format: "a4" });
    const pw = doc.internal.pageSize.getWidth(), ph = doc.internal.pageSize.getHeight(), m = 40;
    let y = m;
    doc.setFont("helvetica", "bold"); doc.setFontSize(22); doc.setTextColor(15, 23, 42);
    doc.text("Brand Protection Report", m, y + 8);
    doc.setFont("helvetica", "normal"); doc.setFontSize(11); doc.setTextColor(220, 38, 38);
    doc.text("MONITOR-THREAT", m, y + 26);
    doc.setFontSize(10); doc.setTextColor(71, 85, 105);
    doc.text(`Fecha: ${new Date().toLocaleString()}`, pw - m, y + 8, { align: "right" });
    doc.text(`Fuentes: DNS + RDAP + crt.sh + urlscan.io`, pw - m, y + 22, { align: "right" });
    y += 48; doc.line(m, y, pw - m, y); y += 28;
    autoTable(doc, {
      startY: y, head: [["Brand", "Category", "Severity", "Domain", "IP", "Registration", "Registrar"]],
      body: results.map(r => [
        r.brand, r.category, sevText[r.severity],
        r.domain || "", r.metadata?.ip || r.metadata?.cname || "",
        r.metadata?.rdap?.registrationDate?.slice(0, 10) || "",
        r.metadata?.rdap?.registrar || r.metadata?.issuer || "",
      ]),
      theme: "grid", margin: { left: m, right: m }, styles: { fontSize: 7, cellPadding: 3 },
      headStyles: { fillColor: [220, 38, 38], textColor: [255, 255, 255], fontSize: 7 },
    });
    for (let i = 1; i <= doc.getNumberOfPages(); i++) {
      doc.setPage(i); doc.setFontSize(8); doc.setTextColor(150, 150, 150);
      doc.text(`MONITOR-THREAT - Brand Protection - Pagina ${i} de ${doc.getNumberOfPages()}`, pw / 2, ph - 20, { align: "center" });
    }
    doc.save(`brand-protection-${Date.now()}.pdf`);
  };

  const filteredResults = results.filter(r => {
    if (activeBrand !== "all" && r.brandId !== activeBrand) return false;
    if (activeCategory !== "all" && r.category !== activeCategory) return false;
    return true;
  });

  return (
    <ModuleShell
      name="Brand Protection"
      description="Detecta typosquatting y phishing de 9 marcas financieras via DNS + RDAP + Certificate Transparency (crt.sh) + urlscan.io. Datos REALES, no scraping de motores (que estan bloqueados server-side)."
      icon={ShieldCheck}
      category="OSINT"
    >
      {/* SEARCH PANEL */}
      <Panel title="Buscar phishing por marca" className="md:col-span-2"
        action={
          <Button size="sm" onClick={() => search("all")} disabled={loading}>
            {loading ? <><Loader2 className="w-3.5 h-3.5 mr-1.5 animate-spin" /> Analizando DNS...</> : <><Search className="w-3.5 h-3.5 mr-1.5" /> Buscar todas</>}
          </Button>
        }
      >
        <div className="text-[10px] text-muted-foreground mb-3">
          9 marcas pre-configuradas: Bancolombia, Nequi, Wenia, Banco Agricola, Banco Agro Mercantil, Cibest, SUFI, WOMPI, Zaswin. El modulo resuelve DNS de cada typo conocido de la marca y consulta RDAP para datos de registro reales (fecha, registrante, registrador). Tiempo: ~30s para las 9 marcas.
        </div>
        <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-5 gap-1.5">
          {[
            { id: "bancolombia", name: "Bancolombia", typos: 15 },
            { id: "nequi", name: "Nequi", typos: 14 },
            { id: "wenia", name: "Wenia", typos: 9 },
            { id: "banco-agricola", name: "Banco Agricola", typos: 8 },
            { id: "banco-agro-mercantil", name: "Banco Agro Mercantil", typos: 8 },
            { id: "cibest", name: "Cibest", typos: 10 },
            { id: "sufi", name: "SUFI", typos: 11 },
            { id: "wompi", name: "WOMPI", typos: 11 },
            { id: "zaswin", name: "Zaswin", typos: 10 },
          ].map(b => (
            <button
              key={b.id}
              onClick={() => search(b.id)}
              disabled={loading}
              className={`p-2 rounded border border-border bg-background hover:bg-accent transition text-left disabled:opacity-50 disabled:cursor-not-allowed`}
            >
              <div className="text-xs font-semibold">{b.name}</div>
              <div className="text-[10px] text-muted-foreground">{b.typos} typos a probar</div>
            </button>
          ))}
        </div>
        <div className="mt-3 text-[10px] text-muted-foreground">
          <strong>Fuentes REALES:</strong> DNS (resolucion de typos) · RDAP (datos de registro de dominios) · crt.sh (Certificate Transparency, certificados TLS emitidos) · urlscan.io (scans publicos, opcional con API key)
        </div>
      </Panel>

      {error && <div className="mb-4 p-3 rounded border border-red-500/40 bg-red-500/10 text-red-400 flex items-center gap-2"><AlertTriangle className="w-4 h-4 shrink-0" /> {error}</div>}

      {/* SUMMARY */}
      {summary && (
        <Panel title={`Resultados: ${summary.total} dominios typosquatting en ${Object.keys(summary.byBrand || {}).length} marcas`} className="md:col-span-2"
          action={<Button size="sm" variant="outline" onClick={generatePdf} disabled={results.length === 0}><Printer className="w-3 h-3 mr-1.5" /> PDF</Button>}
        >
          <div className="grid grid-cols-2 md:grid-cols-5 gap-2 mb-3">
            <div className="rounded p-2 border border-cyan-500/40 bg-cyan-500/5"><div className="text-lg font-bold font-mono text-cyan-400">{summary.total}</div><div className="text-[10px]">Total dominios</div></div>
            <div className="rounded p-2 border border-red-500/40 bg-red-500/5"><div className="text-lg font-bold font-mono text-red-400">{summary.bySeverity.high}</div><div className="text-[10px]">Alta (registrados)</div></div>
            <div className="rounded p-2 border border-yellow-500/40 bg-yellow-500/5"><div className="text-lg font-bold font-mono text-yellow-400">{summary.bySeverity.medium}</div><div className="text-[10px]">Media (resueltos)</div></div>
            <div className="rounded p-2 border border-green-500/40 bg-green-500/5"><div className="text-lg font-bold font-mono text-green-400">{summary.byCategory.registration || 0}</div><div className="text-[10px]">Con datos RDAP</div></div>
            <div className="rounded p-2 border border-blue-500/40 bg-blue-500/5"><div className="text-lg font-bold font-mono text-blue-400">{summary.byCategory.typosquatting || 0}</div><div className="text-[10px]">DNS resueltos</div></div>
          </div>
          {Object.keys(summary.byCategory || {}).length > 0 && (
            <div className="mb-3">
              <div className="text-[9px] text-muted-foreground uppercase tracking-wider mb-1.5">Por tipo (clic para filtrar):</div>
              <div className="flex gap-2 flex-wrap">
                <button
                  onClick={() => setActiveCategory("all")}
                  className={`px-2 py-1 rounded border text-xs transition ${activeCategory === "all" ? "border-cyan-500 bg-cyan-500/10" : "border-border bg-background hover:bg-accent"}`}
                >
                  Todas: <span className="font-bold">{summary.total}</span>
                </button>
                {Object.entries(summary.byCategory).map(([cat, count]) => (
                  <button
                    key={cat}
                    onClick={() => setActiveCategory(activeCategory === cat ? "all" : cat)}
                    className={`px-2 py-1 rounded border text-xs transition flex items-center gap-1 ${activeCategory === cat ? "border-cyan-500 bg-cyan-500/10" : "border-border bg-background hover:bg-accent"}`}
                  >
                    {CAT_ICONS[cat]}
                    {CAT_LABELS[cat] || cat}: <span className="font-bold">{count as number}</span>
                  </button>
                ))}
              </div>
            </div>
          )}
          {Object.keys(summary.byBrand || {}).length > 0 && (
            <div>
              <div className="text-[9px] text-muted-foreground uppercase tracking-wider mb-1.5">Por marca (clic para filtrar):</div>
              <div className="flex gap-2 flex-wrap">
                <button
                  onClick={() => setActiveBrand("all")}
                  className={`px-2 py-1 rounded border text-xs transition ${activeBrand === "all" ? "border-cyan-500 bg-cyan-500/10" : "border-border bg-background hover:bg-accent"}`}
                >
                  Todas: <span className="font-bold">{summary.total}</span>
                </button>
                {Object.entries(summary.byBrand).map(([brand, count]) => (
                  <button
                    key={brand}
                    onClick={() => setActiveBrand(activeBrand === brand ? "all" : brand)}
                    className={`px-2 py-1 rounded border text-xs transition ${activeBrand === brand ? "border-cyan-500 bg-cyan-500/10" : "border-border bg-background hover:bg-accent"}`}
                  >
                    {brand}: <span className="font-bold">{count as number}</span>
                  </button>
                ))}
              </div>
            </div>
          )}
        </Panel>
      )}

      {/* RESULTS — RICH CARDS */}
      {filteredResults.length > 0 && (
        <Panel title={`Hallazgos REALES (${filteredResults.length})`} className="md:col-span-2">
          <div className="text-[10px] text-muted-foreground mb-3">
            Cada hallazgo es un dominio REAL que contiene el nombre (o typo) de la marca, resuelto por DNS y con datos de registro reales via RDAP. No son resultados de Bing (que esta bloqueado server-side).
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-2 max-h-[600px] overflow-y-auto">
            {filteredResults.map((r, i) => (
              <div key={i} className={`p-3 rounded border ${r.severity === "high" ? "border-red-500/40 bg-red-500/5" : "border-yellow-500/40 bg-yellow-500/5"}`}>
                <div className="flex items-center justify-between mb-2">
                  <div className="flex items-center gap-1.5">
                    {CAT_ICONS[r.category]}
                    <span className="text-xs font-semibold">{r.brand}</span>
                    <Badge variant="outline" className="text-[9px] font-mono">{r.source}</Badge>
                  </div>
                  <Badge variant={sevColors[r.severity]} className="text-[9px]">{sevText[r.severity]}</Badge>
                </div>
                <div className="mb-1">
                  <a href={`https://${r.domain}`} target="_blank" rel="noreferrer" className="text-sm font-mono text-cyan-500 hover:underline inline-flex items-center gap-1">
                    {r.domain} <ExternalLink className="w-3 h-3" />
                  </a>
                </div>
                <div className="text-[11px] text-muted-foreground space-y-0.5">
                  {r.metadata?.ip && (
                    <div><span className="text-muted-foreground">IP:</span> <code className="text-cyan-500">{r.metadata.ip}</code></div>
                  )}
                  {r.metadata?.rdap?.registrationDate && (
                    <div className="flex items-center gap-1">
                      <Calendar className="w-2.5 h-2.5" />
                      <span className="text-muted-foreground">Registrado:</span> {r.metadata.rdap.registrationDate.slice(0, 10)}
                    </div>
                  )}
                  {r.metadata?.rdap?.expirationDate && (
                    <div className="flex items-center gap-1">
                      <Calendar className="w-2.5 h-2.5" />
                      <span className="text-muted-foreground">Expira:</span> {r.metadata.rdap.expirationDate.slice(0, 10)}
                    </div>
                  )}
                  {r.metadata?.rdap?.registrar && (
                    <div><span className="text-muted-foreground">Registrar:</span> {r.metadata.rdap.registrar}</div>
                  )}
                  {r.metadata?.rdap?.registrant && r.metadata.rdap.registrant !== "?" && (
                    <div><span className="text-muted-foreground">Registrant:</span> {r.metadata.rdap.registrant}</div>
                  )}
                  {r.metadata?.rdap?.nameservers && r.metadata.rdap.nameservers.length > 0 && (
                    <div><span className="text-muted-foreground">NS:</span> {r.metadata.rdap.nameservers.slice(0, 2).join(", ")}</div>
                  )}
                  {r.metadata?.rdap?.status && r.metadata.rdap.status.length > 0 && (
                    <div><span className="text-muted-foreground">Status:</span> <span className="text-amber-500">{r.metadata.rdap.status.join(", ")}</span></div>
                  )}
                  {r.metadata?.issuer && (
                    <div><span className="text-muted-foreground">Cert issuer:</span> {r.metadata.issuer}</div>
                  )}
                  {r.metadata?.commonName && (
                    <div><span className="text-muted-foreground">CN:</span> <code className="text-cyan-500">{r.metadata.commonName}</code></div>
                  )}
                </div>
              </div>
            ))}
          </div>
        </Panel>
      )}

      {searched && !loading && results.length === 0 && !error && (
        <Panel title="Sin hallazgos" className="md:col-span-2">
          <div className="flex flex-col items-center py-8 text-center gap-3">
            <ShieldCheck className="w-8 h-8 text-green-500" />
            <p className="text-sm text-muted-foreground">
              Ninguno de los typos conocidos de esta marca esta resuelto por DNS (ningun dominio typosquatting activo).
            </p>
            <p className="text-xs text-muted-foreground">
              Esto es BUENA señal — la marca no tiene typosquats activos registrados.
            </p>
          </div>
        </Panel>
      )}

      {!searched && !loading && (
        <Panel title="Marcas monitoreadas y fuentes de datos" className="md:col-span-2">
          <div className="flex flex-col items-center py-10 text-center gap-4">
            <ShieldCheck className="w-12 h-12 text-muted-foreground/50" />
            <h3 className="text-base font-semibold">Brand Protection — 9 marcas financieras</h3>
            <p className="text-xs text-muted-foreground max-w-2xl">
              Detecta typosquatting y phishing usando fuentes REALES de datos (no scraping de Bing que esta bloqueado server-side).
            </p>
            <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-5 gap-2 max-w-3xl w-full">
              {[
                { name: "Bancolombia", cat: "Bancos", typos: 15 },
                { name: "Nequi", cat: "Fintech", typos: 14 },
                { name: "Wenia", cat: "Fintech", typos: 9 },
                { name: "Banco Agricola", cat: "Bancos", typos: 8 },
                { name: "Banco Agro Mercantil", cat: "Bancos", typos: 8 },
                { name: "Cibest", cat: "Servicios Financieros", typos: 10 },
                { name: "SUFI", cat: "Servicios Financieros", typos: 11 },
                { name: "WOMPI", cat: "Pagos", typos: 11 },
                { name: "Zaswin", cat: "Servicios Financieros", typos: 10 },
              ].map((b, i) => (
                <div key={i} className="rounded border border-cyan-500/30 bg-cyan-500/5 p-2 text-left text-[11px]">
                  <div className="font-semibold text-cyan-500">{b.name}</div>
                  <div className="text-[9px] text-muted-foreground">{b.cat} · {b.typos} typos</div>
                </div>
              ))}
            </div>
            <div className="grid grid-cols-1 md:grid-cols-4 gap-2 max-w-3xl w-full mt-4 text-left">
              <div className="p-3 rounded border border-emerald-500/30 bg-emerald-500/5 text-[11px]">
                <div className="font-semibold text-emerald-500 mb-1 flex items-center gap-1"><Globe className="w-3 h-3" /> DNS</div>
                <div className="text-muted-foreground">Resuelve typos conocidos (banc0lombia.com, nekiapp.com, etc.) y devuelve IPs reales</div>
              </div>
              <div className="p-3 rounded border border-emerald-500/30 bg-emerald-500/5 text-[11px]">
                <div className="font-semibold text-emerald-500 mb-1 flex items-center gap-1"><Building2 className="w-3 h-3" /> RDAP</div>
                <div className="text-muted-foreground">Datos de registro: fecha, expiracion, registrante, registrador, nameservers</div>
              </div>
              <div className="p-3 rounded border border-emerald-500/30 bg-emerald-500/5 text-[11px]">
                <div className="font-semibold text-emerald-500 mb-1 flex items-center gap-1"><KeyRound className="w-3 h-3" /> crt.sh</div>
                <div className="text-muted-foreground">Certificate Transparency: certificados TLS emitidos con el nombre de la marca</div>
              </div>
              <div className="p-3 rounded border border-emerald-500/30 bg-emerald-500/5 text-[11px]">
                <div className="font-semibold text-emerald-500 mb-1 flex items-center gap-1"><ShieldAlert className="w-3 h-3" /> urlscan.io</div>
                <div className="text-muted-foreground">Scans publicos de URLs (opcional, requiere API key para mas resultados)</div>
              </div>
            </div>
            <p className="text-[10px] text-cyan-500 mt-2">Click en "Buscar todas" para analizar las 9 marcas a la vez, o en una marca especifica.</p>
          </div>
        </Panel>
      )}
    </ModuleShell>
  );
}
