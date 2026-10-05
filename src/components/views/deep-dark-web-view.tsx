"use client";

import * as React from "react";
import {
  Skull,
  Search,
  Loader2,
  Printer,
  AlertTriangle,
  ExternalLink,
  Terminal,
  Copy,
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
}

export function DeepDarkWebView() {
  const [query, setQuery] = React.useState("");
  const [queryType, setQueryType] = React.useState("keyword");
  const [loading, setLoading] = React.useState(false);
  const [results, setResults] = React.useState<SearchResult[]>([]);
  const [dorks, setDorks] = React.useState<string[]>([]);
  const [summary, setSummary] = React.useState<{ total: number; bySource: Record<string, number>; bySeverity: { high: number; medium: number; low: number; info: number } } | null>(null);
  const [error, setError] = React.useState<string | null>(null);
  const [searched, setSearched] = React.useState(false);

  const search = async () => {
    if (!query.trim()) return;
    setLoading(true);
    setError(null);
    setResults([]);
    setDorks([]);
    setSummary(null);
    setSearched(true);

    try {
      const r = await fetch(`/api/darkweb/search?q=${encodeURIComponent(query.trim())}&type=${queryType}`);
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      const j = await r.json();
      setResults(j.results || []);
      setDorks(j.dorks || []);
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
    const pw = doc.internal.pageSize.getWidth();
    const ph = doc.internal.pageSize.getHeight();
    const m = 40;
    const cw = pw - m * 2;
    let y = m;
    doc.setFont("helvetica", "bold"); doc.setFontSize(22); doc.setTextColor(15, 23, 42);
    doc.text("Deep & Dark Web Report", m, y + 8);
    doc.setFont("helvetica", "normal"); doc.setFontSize(11); doc.setTextColor(220, 38, 38);
    doc.text("MONITOR-THREAT", m, y + 26);
    doc.setFontSize(10); doc.setTextColor(71, 85, 105);
    doc.text(`Target: ${query}`, pw - m, y + 8, { align: "right" });
    doc.text(`Fecha: ${new Date().toLocaleString()}`, pw - m, y + 22, { align: "right" });
    y += 48; doc.line(m, y, pw - m, y); y += 28;

    autoTable(doc, {
      startY: y, head: [["Source", "Severity", "Type", "Title", "Snippet", "URL"]],
      body: results.map(r => [r.source, sevText[r.severity], r.type, r.title.slice(0, 50), r.snippet.slice(0, 60), r.url.slice(0, 50)]),
      theme: "grid", margin: { left: m, right: m },
      styles: { fontSize: 7, cellPadding: 3 },
      headStyles: { fillColor: [220, 38, 38], textColor: [255, 255, 255], fontSize: 7 },
    });
    for (let i = 1; i <= doc.getNumberOfPages(); i++) {
      doc.setPage(i); doc.setFontSize(8); doc.setTextColor(150, 150, 150);
      doc.text(`MONITOR-THREAT - Pagina ${i} de ${doc.getNumberOfPages()}`, pw / 2, ph - 20, { align: "center" });
    }
    doc.save(`darkweb-${Date.now()}.pdf`);
  };

  return (
    <ModuleShell
      name="Deep & Dark Web"
      description="Busca menciones del target en 9 fuentes: GitHub, Shodan, VirusTotal, AlienVault OTX, AbuseIPDB, URLscan, GitHub Gists + 80 dorks."
      icon={Skull}
      category="OSINT"
    >
      {/* Search */}
      <Panel title="Buscar en Dark Web y Deep Web" className="md:col-span-2"
        action={
          <Button size="sm" onClick={search} disabled={loading || !query.trim()}>
            {loading ? <><Loader2 className="w-3.5 h-3.5 mr-1.5 animate-spin" /> Buscando...</> : <><Search className="w-3.5 h-3.5 mr-1.5" /> Buscar</>}
          </Button>
        }
      >
        <div className="flex gap-2 mb-3">
          <select value={queryType} onChange={e => setQueryType(e.target.value)} className="h-9 text-xs rounded border border-border bg-background px-2">
            <option value="keyword">Keyword</option>
            <option value="domain">Dominio</option>
            <option value="email">Email</option>
            <option value="ip">IP</option>
            <option value="username">Username</option>
            <option value="phone">Telefono</option>
            <option value="org">Organizacion</option>
            <option value="apikey">API Key / Token</option>
          </select>
          <Input type="text" placeholder="ej: empresa.com | 8.8.8.8 | @username | email@empresa.com" value={query} onChange={e => setQuery(e.target.value)} onKeyDown={e => e.key === "Enter" && search()} className="flex-1 font-mono text-sm" autoFocus />
        </div>
        <div className="text-[10px] text-muted-foreground">
          9 fuentes: GitHub Code, GitHub Gists, GitHub User, Shodan, VirusTotal, AlienVault OTX, AbuseIPDB, URLscan, Leak-Lookup. 80+ dorks generados automaticamente.
        </div>
      </Panel>

      {error && (
        <div className="mb-4 p-3 rounded border border-red-500/40 bg-red-500/10 text-red-400 flex items-center gap-2">
          <AlertTriangle className="w-4 h-4 shrink-0" /> {error}
        </div>
      )}

      {/* Stats */}
      {summary && (
        <Panel title={`Resultados: ${summary.total} encontrados`} className="md:col-span-2"
          action={<Button size="sm" variant="outline" onClick={generatePdf} disabled={results.length === 0}><Printer className="w-3 h-3 mr-1.5" /> PDF</Button>}
        >
          <div className="grid grid-cols-2 md:grid-cols-5 gap-2 mb-3">
            <div className="rounded p-2 border border-cyan-500/40 bg-cyan-500/5"><div className="text-lg font-bold font-mono text-cyan-400">{summary.total}</div><div className="text-[10px]">Total</div></div>
            <div className="rounded p-2 border border-red-500/40 bg-red-500/5"><div className="text-lg font-bold font-mono text-red-400">{summary.bySeverity.high}</div><div className="text-[10px]">Alta</div></div>
            <div className="rounded p-2 border border-yellow-500/40 bg-yellow-500/5"><div className="text-lg font-bold font-mono text-yellow-400">{summary.bySeverity.medium}</div><div className="text-[10px]">Media</div></div>
            <div className="rounded p-2 border border-green-500/40 bg-green-500/5"><div className="text-lg font-bold font-mono text-green-400">{summary.bySeverity.low}</div><div className="text-[10px]">Baja</div></div>
            <div className="rounded p-2 border border-blue-500/40 bg-blue-500/5"><div className="text-lg font-bold font-mono text-blue-400">{summary.bySeverity.info}</div><div className="text-[10px]">Info</div></div>
          </div>
          {Object.keys(summary.bySource).length > 0 && (
            <div className="flex gap-1 flex-wrap mb-2">
              {Object.entries(summary.bySource).map(([s, c]) => (
                <Badge key={s} variant="outline" className="text-[9px] font-mono">{s}: {c}</Badge>
              ))}
            </div>
          )}
        </Panel>
      )}

      {/* Dorks */}
      {dorks.length > 0 && (
        <Panel title={`Dorks generados (${dorks.length})`} className="md:col-span-2">
          <div className="max-h-32 overflow-y-auto space-y-1">
            {dorks.map((d, i) => (
              <div key={i} className="text-[10px] font-mono text-muted-foreground flex items-center gap-1">
                <span className="text-blue-400">{i + 1}.</span>
                <code className="flex-1 truncate">{d}</code>
                <button onClick={() => navigator.clipboard.writeText(d)} className="text-muted-foreground hover:text-cyan-500 shrink-0"><Copy className="w-2.5 h-2.5" /></button>
              </div>
            ))}
          </div>
        </Panel>
      )}

      {/* Results */}
      {results.length > 0 && (
        <Panel title={`Resultados (${results.length})`} className="md:col-span-2">
          <div className="max-h-[500px] overflow-y-auto">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="w-[12%]">Source</TableHead>
                  <TableHead className="w-[8%]">Sev</TableHead>
                  <TableHead className="w-[12%]">Type</TableHead>
                  <TableHead className="w-[30%]">Title</TableHead>
                  <TableHead className="w-[38%]">Snippet</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {results.map((r, i) => (
                  <TableRow key={i}>
                    <TableCell><Badge variant="outline" className="text-[9px] font-mono">{r.source}</Badge></TableCell>
                    <TableCell><Badge variant={sevColors[r.severity]} className="text-[9px] font-mono">{sevText[r.severity]}</Badge></TableCell>
                    <TableCell className="text-[11px] text-muted-foreground">{r.type}</TableCell>
                    <TableCell className="text-[11px]">
                      <a href={r.url} target="_blank" rel="noreferrer" className="text-cyan-500 hover:underline inline-flex items-center gap-1">
                        {r.title.slice(0, 60)} <ExternalLink className="w-2.5 h-2.5" />
                      </a>
                    </TableCell>
                    <TableCell className="text-[11px] text-muted-foreground font-mono">{r.snippet.slice(0, 120)}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        </Panel>
      )}

      {/* Empty state after search */}
      {searched && !loading && results.length === 0 && !error && (
        <Panel title="Sin resultados" className="md:col-span-2">
          <div className="flex flex-col items-center py-8 text-center gap-3">
            <AlertTriangle className="w-8 h-8 text-yellow-500" />
            <p className="text-sm text-muted-foreground">
              No se encontraron resultados para <strong>"{query}"</strong> (tipo: {queryType}).
            </p>
            <p className="text-xs text-muted-foreground">
              Proba con otro tipo (ej: IP 8.8.8.8 o dominio google.com) o usa los dorks generados manualmente en Google.
            </p>
          </div>
        </Panel>
      )}

      {/* Initial state */}
      {!searched && !loading && (
        <Panel title="Que hace este modulo?" className="md:col-span-2">
          <div className="flex flex-col items-center py-10 text-center gap-4">
            <Skull className="w-12 h-12 text-muted-foreground/50" />
            <h3 className="text-base font-semibold">Deep & Dark Web Monitoring</h3>
            <p className="text-xs text-muted-foreground max-w-2xl">
              Escribe un target y selecciona el tipo. El sistema busca en 9 fuentes en paralelo.
            </p>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-3 max-w-2xl">
              <div className="rounded border border-red-500/30 bg-red-500/5 p-2 text-left text-[11px]">
                <div className="font-semibold text-red-500 mb-1">Leaked credentials</div>
                <div className="text-muted-foreground">GitHub .env files, gists, config files</div>
              </div>
              <div className="rounded border border-cyan-500/30 bg-cyan-500/5 p-2 text-left text-[11px]">
                <div className="font-semibold text-cyan-500 mb-1">IP / Domain reputation</div>
                <div className="text-muted-foreground">Shodan, VirusTotal, OTX, AbuseIPDB</div>
              </div>
              <div className="rounded border border-purple-500/30 bg-purple-500/5 p-2 text-left text-[11px]">
                <div className="font-semibold text-purple-500 mb-1">Dorks</div>
                <div className="text-muted-foreground">80+ Google dorks generados automaticamente</div>
              </div>
            </div>
            <p className="text-[10px] text-cyan-500 mt-2">Prueba: tipo IP, query 8.8.8.8 → 3 resultados reales (Shodan + VT + AbuseIPDB)</p>
          </div>
        </Panel>
      )}
    </ModuleShell>
  );
}
