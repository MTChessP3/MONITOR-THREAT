"use client";

import * as React from "react";
import {
  Skull, Search, Loader2, Printer, AlertTriangle, ExternalLink,
  Globe, ShieldAlert, Scale, Crosshair, Sparkles, Camera,
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

interface SearchResult {
  source: string;
  type: string;
  title: string;
  url: string;
  snippet: string;
  severity: "high" | "medium" | "low" | "info";
  timestamp: string | null;
  category?: string;
  displayLink?: string;
}

interface CategoryInfo {
  id: string;
  name: string;
  description: string;
  severity: "high" | "medium" | "low" | "info";
}

// Iconos por categoria (mapeo a lucide-react)
const CAT_ICONS: Record<string, React.ReactNode> = {
  "general": <Sparkles className="w-3 h-3" />,
  "crime": <ShieldAlert className="w-3 h-3" />,
  "criminal-organizations": <Skull className="w-3 h-3" />,
  "criminal-records": <Scale className="w-3 h-3" />,
  "cold-cases": <Crosshair className="w-3 h-3" />,
  "fraud": <AlertTriangle className="w-3 h-3" />,
  "money-laundering": <Scale className="w-3 h-3" />,
  "sanctions": <Globe className="w-3 h-3" />,
  "terrorism": <Skull className="w-3 h-3" />,
  "extremism": <AlertTriangle className="w-3 h-3" />,
  "narcotics": <Crosshair className="w-3 h-3" />,
  "missing-person": <Globe className="w-3 h-3" />,
  "murder": <Skull className="w-3 h-3" />,
  "sexual-abuse": <AlertTriangle className="w-3 h-3" />,
  "child-abuse": <ShieldAlert className="w-3 h-3" />,
  "cryptocurrency": <Sparkles className="w-3 h-3" />,
  "trade-index": <Scale className="w-3 h-3" />,
  "news": <Globe className="w-3 h-3" />,
  "politics": <Scale className="w-3 h-3" />,
  "religion": <Sparkles className="w-3 h-3" />,
  "history": <Globe className="w-3 h-3" />,
  "culture": <Sparkles className="w-3 h-3" />,
  "medical": <Crosshair className="w-3 h-3" />,
  "social-media": <Globe className="w-3 h-3" />,
  "satellite": <Camera className="w-3 h-3" />,
  "webcams": <Camera className="w-3 h-3" />,
};

export function DeepDarkWebView() {
  const [query, setQuery] = React.useState("");
  const [category, setCategory] = React.useState<string>("all");
  const [loading, setLoading] = React.useState(false);
  const [results, setResults] = React.useState<SearchResult[]>([]);
  const [summary, setSummary] = React.useState<{
    total: number;
    byCategory: Record<string, number>;
    bySeverity: { high: number; medium: number; low: number; info: number };
  } | null>(null);
  const [totalResultsGoogle, setTotalResultsGoogle] = React.useState<number>(0);
  const [errors, setErrors] = React.useState<string[]>([]);
  const [searched, setSearched] = React.useState(false);
  const [activeCategory, setActiveCategory] = React.useState<string>("all");
  const [categoriesList, setCategoriesList] = React.useState<CategoryInfo[]>([]);

  const search = async () => {
    if (!query.trim()) return;
    setLoading(true);
    setResults([]);
    setSummary(null);
    setTotalResultsGoogle(0);
    setErrors([]);
    setSearched(true);
    setActiveCategory("all");
    try {
      const r = await fetch(`/api/darkweb/search?q=${encodeURIComponent(query.trim())}&category=${encodeURIComponent(category)}`);
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      const j = await r.json();
      setResults(j.results || []);
      setSummary(j.summary || null);
      setTotalResultsGoogle(j.totalResultsGoogle || 0);
      setErrors(j.errors || []);
      setCategoriesList(j.availableCategories || []);
    } catch (e: any) {
      setErrors([String(e?.message || e)]);
    }
    setLoading(false);
  };

  const sevColors: Record<string, "destructive" | "default" | "secondary" | "outline"> = {
    high: "destructive", medium: "default", low: "secondary", info: "outline",
  };
  const sevText: Record<string, string> = { high: "ALTA", medium: "MEDIA", low: "BAJA", info: "INFO" };

  const filteredResults = activeCategory === "all"
    ? results
    : results.filter(r => r.category === activeCategory);

  const generatePdf = () => {
    if (filteredResults.length === 0) return;
    const doc = new jsPDF({ unit: "pt", format: "a4" });
    const pw = doc.internal.pageSize.getWidth();
    const ph = doc.internal.pageSize.getHeight();
    const m = 40;
    let y = m;
    doc.setFont("helvetica", "bold"); doc.setFontSize(22); doc.setTextColor(15, 23, 42);
    doc.text("Deep & Dark Web Report", m, y + 8);
    doc.setFont("helvetica", "normal"); doc.setFontSize(11); doc.setTextColor(220, 38, 38);
    doc.text("MONITOR-THREAT", m, y + 26);
    doc.setFontSize(10); doc.setTextColor(71, 85, 105);
    doc.text(`Target: ${query}`, pw - m, y + 8, { align: "right" });
    doc.text(`Categoria: ${category}`, pw - m, y + 22, { align: "right" });
    doc.text(`Total Google: ${totalResultsGoogle.toLocaleString()}`, pw - m, y + 36, { align: "right" });
    y += 48; doc.line(m, y, pw - m, y); y += 28;
    autoTable(doc, {
      startY: y, head: [["Categoria", "Source", "Severity", "Title", "Snippet", "URL"]],
      body: filteredResults.map(r => [r.category || "?", r.source, sevText[r.severity], r.title.slice(0, 50), r.snippet.slice(0, 60), r.url.slice(0, 50)]),
      theme: "grid", margin: { left: m, right: m },
      styles: { fontSize: 7, cellPadding: 3 },
      headStyles: { fillColor: [220, 38, 38], textColor: [255, 255, 255], fontSize: 7 },
    });
    for (let i = 1; i <= doc.getNumberOfPages(); i++) {
      doc.setPage(i); doc.setFontSize(8); doc.setTextColor(150, 150, 150);
      doc.text(`MONITOR-THREAT - Deep & Dark Web - Pagina ${i} de ${doc.getNumberOfPages()}`, pw / 2, ph - 20, { align: "center" });
    }
    doc.save(`darkweb-${Date.now()}.pdf`);
  };

  return (
    <ModuleShell
      name="Deep & Dark Web"
      description="Busca en Deep & Dark Web via Google Programmable Search Engines. 25 categorias: fraude, crimen, terrorismo, narcoticos, etc."
      icon={Skull}
      category="OSINT"
    >
      {/* SEARCH */}
      <Panel title="Buscar en Deep & Dark Web (via Google CSE)" className="md:col-span-2"
        action={
          <Button size="sm" onClick={search} disabled={loading || !query.trim()}>
            {loading ? <><Loader2 className="w-3.5 h-3.5 mr-1.5 animate-spin" /> Buscando en Google...</> : <><Search className="w-3.5 h-3.5 mr-1.5" /> Buscar</>}
          </Button>
        }
      >
        <div className="flex gap-2 mb-3">
          <select value={category} onChange={e => setCategory(e.target.value)} className="h-9 text-xs rounded border border-border bg-background px-2 min-w-[200px]">
            <option value="all">Todas las categorias (general + fraud + crime + narcotics + terrorism)</option>
            <option value="general">General OSINT</option>
            <option value="crime">Crimen</option>
            <option value="criminal-organizations">Organizaciones criminales</option>
            <option value="criminal-records">Records criminales</option>
            <option value="cold-cases">Casos frios</option>
            <option value="fraud">Fraude</option>
            <option value="money-laundering">Lavado de dinero</option>
            <option value="sanctions">Sanciones</option>
            <option value="terrorism">Terrorismo</option>
            <option value="extremism">Extremismo</option>
            <option value="narcotics">Narcoticos</option>
            <option value="missing-person">Personas desaparecidas</option>
            <option value="murder">Asesinatos</option>
            <option value="sexual-abuse">Abuso sexual</option>
            <option value="child-abuse">Abuso infantil</option>
            <option value="cryptocurrency">Criptomonedas</option>
            <option value="trade-index">Indice comercial</option>
            <option value="news">Noticias</option>
            <option value="politics">Politica</option>
            <option value="religion">Religion</option>
            <option value="history">Historia</option>
            <option value="culture">Cultura</option>
            <option value="medical">Medico</option>
            <option value="social-media">Redes sociales</option>
            <option value="satellite">Satelital</option>
            <option value="webcams">Webcams</option>
          </select>
          <Input type="text" placeholder="ej: bancolombia phishing, isil, drug marketplace, @username..." value={query} onChange={e => setQuery(e.target.value)} onKeyDown={e => e.key === "Enter" && search()} className="flex-1 font-mono text-sm" autoFocus />
        </div>
        <div className="text-[10px] text-muted-foreground">
          Usa Google Programmable Search Engines (CSE) pre-configurados para investigacion OSINT. Cada categoria es un motor distinto indexado por Google con sites relevantes.
        </div>
      </Panel>

      {errors.length > 0 && (
        <div className="mb-4 p-3 rounded border border-amber-500/40 bg-amber-500/10 text-amber-400 flex flex-col gap-1">
          <div className="flex items-center gap-2"><AlertTriangle className="w-4 h-4 shrink-0" /> Avisos:</div>
          {errors.map((e, i) => <div key={i} className="text-[10px] font-mono ml-6">{e}</div>)}
        </div>
      )}

      {/* SUMMARY */}
      {summary && (
        <Panel title={`Resultados: ${summary.total} obtenidos · ${totalResultsGoogle.toLocaleString()} indexados por Google`} className="md:col-span-2"
          action={<Button size="sm" variant="outline" onClick={generatePdf} disabled={filteredResults.length === 0}><Printer className="w-3 h-3 mr-1.5" /> PDF</Button>}
        >
          <div className="grid grid-cols-2 md:grid-cols-5 gap-2 mb-3">
            <div className="rounded p-2 border border-cyan-500/40 bg-cyan-500/5"><div className="text-lg font-bold font-mono text-cyan-400">{summary.total}</div><div className="text-[10px]">Resultados obtenidos</div></div>
            <div className="rounded p-2 border border-red-500/40 bg-red-500/5"><div className="text-lg font-bold font-mono text-red-400">{summary.bySeverity.high}</div><div className="text-[10px]">Alta</div></div>
            <div className="rounded p-2 border border-yellow-500/40 bg-yellow-500/5"><div className="text-lg font-bold font-mono text-yellow-400">{summary.bySeverity.medium}</div><div className="text-[10px]">Media</div></div>
            <div className="rounded p-2 border border-green-500/40 bg-green-500/5"><div className="text-lg font-bold font-mono text-green-400">{summary.bySeverity.low}</div><div className="text-[10px]">Baja</div></div>
            <div className="rounded p-2 border border-blue-500/40 bg-blue-500/5"><div className="text-lg font-bold font-mono text-blue-400">{summary.bySeverity.info}</div><div className="text-[10px]">Info</div></div>
          </div>
          {Object.keys(summary.byCategory).length > 0 && (
            <div>
              <div className="text-[9px] text-muted-foreground uppercase tracking-wider mb-1.5">Por categoria (clic para filtrar):</div>
              <div className="flex gap-2 flex-wrap">
                <button onClick={() => setActiveCategory("all")} className={`px-2 py-1 rounded border text-xs transition ${activeCategory === "all" ? "border-cyan-500 bg-cyan-500/10" : "border-border bg-background hover:bg-accent"}`}>
                  Todas: <span className="font-bold">{summary.total}</span>
                </button>
                {Object.entries(summary.byCategory).map(([cat, count]) => (
                  <button
                    key={cat}
                    onClick={() => setActiveCategory(activeCategory === cat ? "all" : cat)}
                    className={`px-2 py-1 rounded border text-xs transition flex items-center gap-1 ${activeCategory === cat ? "border-cyan-500 bg-cyan-500/10" : "border-border bg-background hover:bg-accent"}`}
                  >
                    {CAT_ICONS[cat]}
                    {categoriesList.find(c => c.id === cat)?.name || cat}: <span className="font-bold">{count as number}</span>
                  </button>
                ))}
              </div>
            </div>
          )}
        </Panel>
      )}

      {/* RESULTS */}
      {filteredResults.length > 0 && (
        <Panel title={`Resultados (${filteredResults.length})`} className="md:col-span-2">
          <div className="max-h-[600px] overflow-y-auto">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="w-[15%]">Categoria</TableHead>
                  <TableHead className="w-[8%]">Sev</TableHead>
                  <TableHead className="w-[15%]">Dominio</TableHead>
                  <TableHead className="w-[28%]">Title</TableHead>
                  <TableHead className="w-[34%]">Snippet</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {filteredResults.map((r, i) => (
                  <TableRow key={i}>
                    <TableCell className="text-[10px]">
                      <div className="flex items-center gap-1">
                        {CAT_ICONS[r.category || ""]}
                        <span className="truncate">{categoriesList.find(c => c.id === r.category)?.name || r.category || "?"}</span>
                      </div>
                    </TableCell>
                    <TableCell><Badge variant={sevColors[r.severity]} className="text-[9px] font-mono">{sevText[r.severity]}</Badge></TableCell>
                    <TableCell className="text-[10px] font-mono text-cyan-500 truncate" title={r.displayLink}>{r.displayLink || "?"}</TableCell>
                    <TableCell className="text-[11px]">
                      <a href={r.url} target="_blank" rel="noreferrer" className="text-cyan-500 hover:underline inline-flex items-center gap-1">
                        {r.title.slice(0, 60)} <ExternalLink className="w-2.5 h-2.5" />
                      </a>
                    </TableCell>
                    <TableCell className="text-[11px] text-muted-foreground font-mono">{r.snippet.slice(0, 150)}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        </Panel>
      )}

      {/* Empty state */}
      {searched && !loading && filteredResults.length === 0 && errors.length === 0 && (
        <Panel title="Sin resultados" className="md:col-span-2">
          <div className="flex flex-col items-center py-8 text-center gap-3">
            <AlertTriangle className="w-8 h-8 text-yellow-500" />
            <p className="text-sm text-muted-foreground">
              No se encontraron resultados para <strong>"{query}"</strong> en categoria <strong>{category}</strong>.
            </p>
            <p className="text-xs text-muted-foreground">
              Prueba con otra categoria o keywords mas generales. Google tiene indexados millones de sites relevantes para cada categoria.
            </p>
          </div>
        </Panel>
      )}

      {/* Initial state */}
      {!searched && !loading && (
        <Panel title="Que hace este modulo?" className="md:col-span-2">
          <div className="flex flex-col items-center py-10 text-center gap-4">
            <Skull className="w-12 h-12 text-muted-foreground/50" />
            <h3 className="text-base font-semibold">Deep & Dark Web — Google CSE</h3>
            <p className="text-xs text-muted-foreground max-w-2xl">
              Busca via <strong>Google Programmable Search Engines (CSE)</strong> pre-configurados para OSINT. 25 categorias de investigacion con motores especificos indexados por Google.
            </p>
            <div className="grid grid-cols-2 md:grid-cols-5 gap-2 max-w-3xl w-full text-left">
              {[
                { cat: "general", name: "General OSINT", color: "blue" },
                { cat: "fraud", name: "Fraude", color: "red" },
                { cat: "crime", name: "Crimen", color: "red" },
                { cat: "narcotics", name: "Narcoticos", color: "red" },
                { cat: "terrorism", name: "Terrorismo", color: "red" },
                { cat: "money-laundering", name: "Lavado", color: "yellow" },
                { cat: "sanctions", name: "Sanciones", color: "yellow" },
                { cat: "missing-person", name: "Desaparecidos", color: "yellow" },
                { cat: "murder", name: "Asesinatos", color: "red" },
                { cat: "cryptocurrency", name: "Cripto", color: "yellow" },
              ].map((c, i) => (
                <div key={i} className={`rounded border border-${c.color}-500/30 bg-${c.color}-500/5 p-2 text-[11px]`}>
                  <div className="flex items-center gap-1">
                    {CAT_ICONS[c.cat]}
                    <span className={`font-semibold text-${c.color}-500`}>{c.name}</span>
                  </div>
                </div>
              ))}
            </div>
            <div className="text-[10px] text-muted-foreground max-w-2xl mt-4">
              <strong>Como funciona:</strong> usamos la API JSON de Google Custom Search con motores pre-configurados para cada categoria. Google devuelve resultados REALES y veridicos, indexados desde sites seleccionados para investigacion.
            </div>
            <p className="text-[10px] text-cyan-500 mt-2">Prueba: categoria "fraud", query "bancolombia phishing" → resultados reales de Google indexados desde sites de fraude.</p>
          </div>
        </Panel>
      )}
    </ModuleShell>
  );
}
