"use client";

import * as React from "react";
import {
  ShieldCheck, Search, Loader2, Printer, AlertTriangle, ExternalLink, Copy,
  ShieldAlert, Globe, FileText, UserX, KeyRound,
} from "lucide-react";
import { jsPDF } from "jspdf";
import autoTable from "jspdf-autotable";

import { ModuleShell, Panel } from "@/components/module-shell";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  Table, TableBody, TableCell, TableHead, TableHeader, TableRow,
} from "@/components/ui/table";

interface BrandResult {
  brand: string;
  category: string;          // phishing | typosquatting | leak | impersonation
  source: string;
  type: string;
  title: string;
  url: string;
  snippet: string;
  severity: "high" | "medium" | "low" | "info";
  timestamp: string | null;
}

interface Brand {
  id: string;
  name: string;
  category: string;
  officialDomain: string;
}

const CAT_ICONS: Record<string, React.ReactNode> = {
  phishing: <ShieldAlert className="w-3 h-3" />,
  typosquatting: <Globe className="w-3 h-3" />,
  leak: <KeyRound className="w-3 h-3" />,
  impersonation: <UserX className="w-3 h-3" />,
};

const CAT_LABELS: Record<string, string> = {
  phishing: "Phishing",
  typosquatting: "Typosquatting",
  leak: "Credenciales filtradas",
  impersonation: "Impersonacion",
};

export function BrandProtectionView() {
  const [loading, setLoading] = React.useState(false);
  const [results, setResults] = React.useState<BrandResult[]>([]);
  const [brands, setBrands] = React.useState<Brand[]>([]);
  const [dorksByBrand, setDorksByBrand] = React.useState<Record<string, any>>({});
  const [manualLinks, setManualLinks] = React.useState<Record<string, any>>({});
  const [summary, setSummary] = React.useState<{
    total: number;
    byBrand: Record<string, number>;
    byCategory: Record<string, number>;
    bySeverity: { high: number; medium: number; low: number; info: number };
  } | null>(null);
  const [enginesUsed, setEnginesUsed] = React.useState<string[]>([]);
  const [error, setError] = React.useState<string | null>(null);
  const [searched, setSearched] = React.useState(false);
  const [activeBrand, setActiveBrand] = React.useState<string>("all");
  const [activeCategory, setActiveCategory] = React.useState<string>("all");

  const search = async (brandId: string = "all") => {
    setLoading(true);
    setError(null);
    setResults([]);
    setBrands([]);
    setDorksByBrand({});
    setManualLinks({});
    setSummary(null);
    setEnginesUsed([]);
    setSearched(true);
    setActiveBrand("all");
    setActiveCategory("all");
    try {
      const r = await fetch(`/api/brand-protection/search?brand=${encodeURIComponent(brandId)}`);
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      const j = await r.json();
      setResults(j.results || []);
      setBrands(j.brands || []);
      setDorksByBrand(j.dorksByBrand || {});
      setManualLinks(j.manualLinks || {});
      setSummary(j.summary || null);
      setEnginesUsed(j.enginesUsed || []);
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
    doc.text(`Marcas analizadas: ${Object.keys(summary?.byBrand || {}).length}`, pw - m, y + 22, { align: "right" });
    y += 48; doc.line(m, y, pw - m, y); y += 28;
    autoTable(doc, {
      startY: y, head: [["Brand", "Category", "Severity", "Source", "Title", "Snippet", "URL"]],
      body: results.map(r => [r.brand, r.category, sevText[r.severity], r.source, r.title.slice(0, 50), r.snippet.slice(0, 60), r.url.slice(0, 50)]),
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
    if (activeBrand !== "all" && r.brand !== activeBrand) return false;
    if (activeCategory !== "all" && r.category !== activeCategory) return false;
    return true;
  });

  return (
    <ModuleShell
      name="Brand Protection"
      description="Detecta phishing, typosquatting, leaks de credenciales e impersonacion de 9 marcas financieras pre-configuradas en Bing + DuckDuckGo (auto) y Google/Yandex/Edge (manual)."
      icon={ShieldCheck}
      category="OSINT"
    >
      {/* SEARCH PANEL */}
      <Panel title="Buscar phishing por marca" className="md:col-span-2"
        action={
          <Button size="sm" onClick={() => search("all")} disabled={loading}>
            {loading ? <><Loader2 className="w-3.5 h-3.5 mr-1.5 animate-spin" /> Buscando...</> : <><Search className="w-3.5 h-3.5 mr-1.5" /> Buscar todas</>}
          </Button>
        }
      >
        <div className="text-[10px] text-muted-foreground mb-3">
          9 marcas pre-configuradas: Bancolombia, Nequi, Wenia, Banco Agricola, Banco Agro Mercantil, Cibest, SUFI, WOMPI, Zaswin. Click en una marca para buscar solo esa, o "Buscar todas" para analizar las 9 a la vez.
        </div>
        <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-5 gap-1.5">
          {[
            { id: "bancolombia", name: "Bancolombia", color: "yellow" },
            { id: "nequi", name: "Nequi", color: "purple" },
            { id: "wenia", name: "Wenia", color: "blue" },
            { id: "banco-agricola", name: "Banco Agricola", color: "green" },
            { id: "banco-agro-mercantil", name: "Banco Agro Mercantil", color: "red" },
            { id: "cibest", name: "Cibest", color: "cyan" },
            { id: "sufi", name: "SUFI", color: "amber" },
            { id: "wompi", name: "WOMPI", color: "purple" },
            { id: "zaswin", name: "Zaswin", color: "slate" },
          ].map(b => (
            <button
              key={b.id}
              onClick={() => search(b.id)}
              disabled={loading}
              className={`p-2 rounded border border-border bg-background hover:bg-accent transition text-left disabled:opacity-50 disabled:cursor-not-allowed`}
            >
              <div className="text-xs font-semibold">{b.name}</div>
              <div className="text-[10px] text-muted-foreground">Buscar phishing</div>
            </button>
          ))}
        </div>
        <div className="mt-3 text-[10px] text-muted-foreground">
          Motores: <span className="text-emerald-400">Bing</span> + <span className="text-orange-400">DuckDuckGo</span> automaticos · <span className="text-blue-400">Google</span>, <span className="text-red-400">Yandex</span>, <span className="text-cyan-400">Edge</span> con botones al lado de cada dork.
        </div>
      </Panel>

      {error && <div className="mb-4 p-3 rounded border border-red-500/40 bg-red-500/10 text-red-400 flex items-center gap-2"><AlertTriangle className="w-4 h-4 shrink-0" /> {error}</div>}

      {/* SUMMARY */}
      {summary && (
        <Panel title={`Resultados: ${summary.total} hallazgos en ${Object.keys(summary.byBrand || {}).length} marcas`} className="md:col-span-2"
          action={<Button size="sm" variant="outline" onClick={generatePdf} disabled={results.length === 0}><Printer className="w-3 h-3 mr-1.5" /> PDF</Button>}
        >
          <div className="grid grid-cols-2 md:grid-cols-5 gap-2 mb-3">
            <div className="rounded p-2 border border-cyan-500/40 bg-cyan-500/5"><div className="text-lg font-bold font-mono text-cyan-400">{summary.total}</div><div className="text-[10px]">Total hallazgos</div></div>
            <div className="rounded p-2 border border-red-500/40 bg-red-500/5"><div className="text-lg font-bold font-mono text-red-400">{summary.bySeverity.high}</div><div className="text-[10px]">Alta (phishing/leak)</div></div>
            <div className="rounded p-2 border border-yellow-500/40 bg-yellow-500/5"><div className="text-lg font-bold font-mono text-yellow-400">{summary.bySeverity.medium}</div><div className="text-[10px]">Media</div></div>
            <div className="rounded p-2 border border-green-500/40 bg-green-500/5"><div className="text-lg font-bold font-mono text-green-400">{summary.bySeverity.low}</div><div className="text-[10px]">Baja</div></div>
            <div className="rounded p-2 border border-blue-500/40 bg-blue-500/5"><div className="text-lg font-bold font-mono text-blue-400">{summary.bySeverity.info}</div><div className="text-[10px]">Info</div></div>
          </div>
          {Object.keys(summary.byCategory || {}).length > 0 && (
            <div className="mb-3">
              <div className="text-[9px] text-muted-foreground uppercase tracking-wider mb-1.5">Por tipo de amenaza:</div>
              <div className="flex gap-2 flex-wrap">
                {Object.entries(summary.byCategory).map(([cat, count]) => (
                  <button
                    key={cat}
                    onClick={() => setActiveCategory(activeCategory === cat ? "all" : cat)}
                    className={`px-2 py-1 rounded border text-xs transition ${activeCategory === cat ? "border-cyan-500 bg-cyan-500/10" : "border-border bg-background hover:bg-accent"}`}
                  >
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

      {/* RESULTS TABLE */}
      {filteredResults.length > 0 && (
        <Panel title={`Resultados (${filteredResults.length})`} className="md:col-span-2">
          <div className="max-h-[600px] overflow-y-auto">
            <Table>
              <TableHeader><TableRow>
                <TableHead className="w-[12%]">Marca</TableHead>
                <TableHead className="w-[12%]">Categoria</TableHead>
                <TableHead className="w-[8%]">Sev</TableHead>
                <TableHead className="w-[10%]">Source</TableHead>
                <TableHead className="w-[28%]">Title</TableHead>
                <TableHead className="w-[30%]">Snippet</TableHead>
              </TableRow></TableHeader>
              <TableBody>
                {filteredResults.map((r, i) => (
                  <TableRow key={i}>
                    <TableCell className="text-[11px]"><Badge variant="outline" className="text-[9px] font-mono">{r.brand}</Badge></TableCell>
                    <TableCell className="text-[10px]">
                      <div className="flex items-center gap-1">
                        {CAT_ICONS[r.category]}
                        <span>{CAT_LABELS[r.category] || r.category}</span>
                      </div>
                    </TableCell>
                    <TableCell><Badge variant={sevColors[r.severity]} className="text-[9px] font-mono">{sevText[r.severity]}</Badge></TableCell>
                    <TableCell><Badge variant="outline" className="text-[9px] font-mono">{r.source}</Badge></TableCell>
                    <TableCell className="text-[11px]"><a href={r.url} target="_blank" rel="noreferrer" className="text-cyan-500 hover:underline inline-flex items-center gap-1">{r.title.slice(0, 60)} <ExternalLink className="w-2.5 h-2.5" /></a></TableCell>
                    <TableCell className="text-[11px] text-muted-foreground font-mono">{r.snippet.slice(0, 120)}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        </Panel>
      )}

      {/* DORKS BY BRAND */}
      {Object.keys(dorksByBrand).length > 0 && (
        <Panel title={`Dorks generados por marca (con botones G/Y/E/B/D)`} className="md:col-span-2">
          <div className="text-[10px] text-muted-foreground mb-3">
            Los primeros 8 dorks por marca (5 phishing + 2 typosquatting + 1 leak) se ejecutan automaticamente en <span className="text-emerald-400">Bing</span> + <span className="text-orange-400">DuckDuckGo</span>. El resto puedes ejecutarlos en <span className="text-blue-400">Google</span>, <span className="text-red-400">Yandex</span> o <span className="text-cyan-400">Edge</span> con los botones al lado de cada dork.
          </div>
          <div className="max-h-96 overflow-y-auto space-y-3">
            {Object.entries(dorksByBrand).map(([brandId, dorks]) => {
              const brand = brands.find(b => b.id === brandId);
              const brandName = brand?.name || brandId;
              return (
                <div key={brandId} className="border-l-2 border-cyan-500/40 pl-2">
                  <div className="flex items-center gap-1 mb-1">
                    <span className="text-[11px] font-semibold">{brandName}</span>
                    <Badge variant="outline" className="text-[9px] font-mono text-muted-foreground">{brand?.category || ""}</Badge>
                    {brand && <a href={`https://${brand.officialDomain}`} target="_blank" rel="noreferrer" className="text-[9px] text-cyan-500 ml-1">{brand.officialDomain}</a>}
                  </div>
                  {(["phishing", "typosquatting", "leak", "impersonation"] as const).map(cat => {
                    const catDorks = (dorks as any)[cat] as string[];
                    if (!catDorks || catDorks.length === 0) return null;
                    return (
                      <div key={cat} className="mb-1">
                        <div className="text-[10px] text-muted-foreground mb-0.5 ml-2">{CAT_LABELS[cat]} ({catDorks.length} dorks):</div>
                        {catDorks.map((d, i) => {
                          const links = manualLinks[d];
                          return (
                            <div key={i} className="text-[10px] font-mono text-muted-foreground flex items-center gap-1 ml-3 mb-0.5 flex-wrap">
                              <span className="text-purple-400">{i + 1}.</span>
                              {i < (cat === "phishing" ? 5 : cat === "typosquatting" ? 2 : cat === "leak" ? 1 : 0) && (
                                <Badge variant="outline" className="text-[8px] text-emerald-400 border-emerald-500/40">auto</Badge>
                              )}
                              <code className="flex-1 truncate text-[9px]">{d}</code>
                              {links && (
                                <div className="flex gap-0.5 shrink-0">
                                  <a href={links.google} target="_blank" rel="noreferrer" title="Google" className="bg-blue-500 hover:bg-blue-600 text-white px-1 rounded text-[8px] font-bold">G</a>
                                  <a href={links.yandex} target="_blank" rel="noreferrer" title="Yandex" className="bg-red-500 hover:bg-red-600 text-white px-1 rounded text-[8px] font-bold">Y</a>
                                  <a href={links.edge} target="_blank" rel="noreferrer" title="Edge" className="bg-cyan-500 hover:bg-cyan-600 text-white px-1 rounded text-[8px] font-bold">E</a>
                                  <a href={links.bing} target="_blank" rel="noreferrer" title="Bing" className="bg-emerald-500 hover:bg-emerald-600 text-white px-1 rounded text-[8px] font-bold">B</a>
                                  <a href={links.duckduckgo} target="_blank" rel="noreferrer" title="DuckDuckGo" className="bg-orange-500 hover:bg-orange-600 text-white px-1 rounded text-[8px] font-bold">D</a>
                                </div>
                              )}
                              <button onClick={() => navigator.clipboard.writeText(d)} className="text-muted-foreground hover:text-cyan-500 shrink-0"><Copy className="w-2.5 h-2.5" /></button>
                            </div>
                          );
                        })}
                      </div>
                    );
                  })}
                </div>
              );
            })}
          </div>
        </Panel>
      )}

      {searched && !loading && results.length === 0 && !error && (
        <Panel title="Sin hallazgos automaticos" className="md:col-span-2">
          <div className="flex flex-col items-center py-8 text-center gap-3">
            <AlertTriangle className="w-8 h-8 text-amber-500" />
            <p className="text-sm text-muted-foreground">
              No se detectaron amenazas automaticas (los motores Bing/DuckDuckGo desde el servidor pueden estar limitados).
            </p>
            <p className="text-xs text-muted-foreground">
              <strong>Importante:</strong> usa los botones <span className="bg-blue-500 text-white px-1 rounded text-[10px] font-bold">G</span> <span className="bg-red-500 text-white px-1 rounded text-[10px] font-bold">Y</span> <span className="bg-cyan-500 text-white px-1 rounded text-[10px] font-bold">E</span> al lado de cada dork abajo para ejecutarlos en tu navegador (donde Google, Yandex y Edge no estan bloqueados). Alli encontraras los resultados reales de phishing.
            </p>
          </div>
        </Panel>
      )}

      {!searched && !loading && (
        <Panel title="Marcas monitoreadas" className="md:col-span-2">
          <div className="flex flex-col items-center py-10 text-center gap-4">
            <ShieldCheck className="w-12 h-12 text-muted-foreground/50" />
            <h3 className="text-base font-semibold">Brand Protection — 9 marcas financieras</h3>
            <p className="text-xs text-muted-foreground max-w-2xl">
              Detecta phishing, typosquatting, leaks de credenciales e impersonacion en Bing + DuckDuckGo (automatico) y Google/Yandex/Edge (manual con botones).
            </p>
            <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-5 gap-2 max-w-2xl w-full">
              {[
                { name: "Bancolombia", cat: "Bancos" },
                { name: "Nequi", cat: "Fintech" },
                { name: "Wenia", cat: "Fintech" },
                { name: "Banco Agricola", cat: "Bancos" },
                { name: "Banco Agro Mercantil", cat: "Bancos" },
                { name: "Cibest", cat: "Servicios Financieros" },
                { name: "SUFI", cat: "Servicios Financieros" },
                { name: "WOMPI", cat: "Pagos" },
                { name: "Zaswin", cat: "Servicios Financieros" },
              ].map((b, i) => (
                <div key={i} className="rounded border border-cyan-500/30 bg-cyan-500/5 p-2 text-left text-[11px]">
                  <div className="font-semibold text-cyan-500">{b.name}</div>
                  <div className="text-[9px] text-muted-foreground">{b.cat}</div>
                </div>
              ))}
            </div>
            <p className="text-[10px] text-cyan-500 mt-2">Click en "Buscar todas" para analizar las 9 marcas a la vez, o en una marca especifica.</p>
          </div>
        </Panel>
      )}
    </ModuleShell>
  );
}
