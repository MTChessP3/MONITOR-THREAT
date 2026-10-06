"use client";

import * as React from "react";
import {
  MessageSquare,
  Search,
  Loader2,
  Printer,
  AlertTriangle,
  ExternalLink,
  Copy,
  ShieldAlert,
  Bot,
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

const DEFAULT_KEYWORDS = [
  "Bancolombia", "Nequi", "Wenia", "Banco Agricola", "Banco Agro Mercantil",
  "Cibest", "SUFI", "WOMPI", "Zaswin",
];

export function TelegramDiscordView() {
  const [query, setQuery] = React.useState("");
  const [loading, setLoading] = React.useState(false);
  const [results, setResults] = React.useState<SearchResult[]>([]);
  const [dorks, setDorks] = React.useState<string[]>([]);
  const [summary, setSummary] = React.useState<{ total: number; bySource: Record<string, number>; bySeverity: { high: number; medium: number; low: number; info: number } } | null>(null);
  const [error, setError] = React.useState<string | null>(null);
  const [searched, setSearched] = React.useState(false);
  const [hasTelegramBot, setHasTelegramBot] = React.useState(false);
  const [allKeywordResults, setAllKeywordResults] = React.useState<Record<string, SearchResult[]>>({});

  const search = async (q?: string) => {
    const target = (q ?? query).trim();
    if (!target) return;
    setQuery(target);
    setLoading(true);
    setError(null);
    setResults([]);
    setDorks([]);
    setSummary(null);
    setSearched(true);

    try {
      const r = await fetch(`/api/telegram-discord/search?q=${encodeURIComponent(target)}`);
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      const j = await r.json();
      setResults(j.results || []);
      setDorks(j.dorks || []);
      setSummary(j.summary || null);
      setHasTelegramBot(j.hasTelegramBot || false);
    } catch (e: any) {
      setError(String(e?.message || e));
    }
    setLoading(false);
  };

  // Search all keywords at once
  const searchAllKeywords = async () => {
    setLoading(true);
    setError(null);
    setSearched(true);
    setAllKeywordResults({});
    setResults([]);
    setSummary(null);

    const allResults: SearchResult[] = [];
    const byKeyword: Record<string, SearchResult[]> = {};

    for (const kw of DEFAULT_KEYWORDS) {
      try {
        const r = await fetch(`/api/telegram-discord/search?q=${encodeURIComponent(kw)}`);
        if (r.ok) {
          const j = await r.json();
          const kwResults = j.results || [];
          byKeyword[kw] = kwResults;
          // Tag each result with the keyword
          allResults.push(...kwResults.map(res => ({ ...res, title: `[${kw}] ${res.title}` })));
        }
      } catch {}
    }

    setAllKeywordResults(byKeyword);
    setResults(allResults);
    const bySource: Record<string, number> = {};
    const bySeverity = { high: 0, medium: 0, low: 0, info: 0 };
    for (const r of allResults) { bySource[r.source] = (bySource[r.source] || 0) + 1; bySeverity[r.severity]++; }
    setSummary({ total: allResults.length, bySource, bySeverity });
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
    let y = m;
    doc.setFont("helvetica", "bold"); doc.setFontSize(22); doc.setTextColor(15, 23, 42);
    doc.text("Telegram & Discord Monitor Report", m, y + 8);
    doc.setFont("helvetica", "normal"); doc.setFontSize(11); doc.setTextColor(220, 38, 38);
    doc.text("MONITOR-THREAT", m, y + 26);
    doc.setFontSize(10); doc.setTextColor(71, 85, 105);
    doc.text(`Fecha: ${new Date().toLocaleString()}`, pw - m, y + 8, { align: "right" });
    doc.text(`Resultados: ${results.length}`, pw - m, y + 22, { align: "right" });
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
      doc.text(`MONITOR-THREAT - Telegram & Discord Monitor - Pagina ${i} de ${doc.getNumberOfPages()}`, pw / 2, ph - 20, { align: "center" });
    }
    doc.save(`telegram-discord-${Date.now()}.pdf`);
  };

  return (
    <ModuleShell
      name="Telegram & Discord Monitor"
      description="Monitorea menciones de marcas financieras en Telegram, Discord y fuentes OSINT. Busca phishing, scam y exposicion de credenciales."
      icon={MessageSquare}
      category="OSINT"
    >
      {/* Search */}
      <Panel title="Buscar marca financiera" className="md:col-span-2"
        action={
          <div className="flex gap-2">
            <Button size="sm" variant="outline" onClick={searchAllKeywords} disabled={loading} className="text-purple-500 border-purple-500/40">
              {loading ? <Loader2 className="w-3 h-3 mr-1.5 animate-spin" /> : <ShieldAlert className="w-3 h-3 mr-1.5" />} Buscar todas ({DEFAULT_KEYWORDS.length})
            </Button>
            <Button size="sm" onClick={() => search()} disabled={loading || !query.trim()}>
              {loading ? <Loader2 className="w-3.5 h-3.5 mr-1.5 animate-spin" /> : <Search className="w-3.5 h-3.5 mr-1.5" />} Buscar
            </Button>
          </div>
        }
      >
        <div className="flex gap-2 mb-3">
          <Input type="text" placeholder="ej: Bancolombia, Nequi, WOMPI..." value={query} onChange={e => setQuery(e.target.value)} onKeyDown={e => e.key === "Enter" && search()} className="flex-1 font-mono text-sm" autoFocus />
        </div>
        <div className="flex gap-1 flex-wrap mb-2">
          {DEFAULT_KEYWORDS.map(kw => (
            <button key={kw} onClick={() => search(kw)} className="text-[10px] font-mono px-2 py-1 rounded border border-border bg-muted/20 hover:border-purple-500/40 hover:bg-purple-500/5 transition-all">
              {kw}
            </button>
          ))}
        </div>
        <div className="text-[10px] text-muted-foreground mt-2">
          Click en "Buscar todas" para escanear las {DEFAULT_KEYWORDS.length} marcas en paralelo, o click en una marca individual.
        </div>
        {hasTelegramBot && (
          <div className="mt-2 text-[10px] text-cyan-500 flex items-center gap-1">
            <Bot className="w-3 h-3" /> Bot de Telegram conectado — buscando en canales en tiempo real
          </div>
        )}
        {!hasTelegramBot && (
          <div className="mt-2 text-[10px] text-yellow-500">
            Sin bot de Telegram: usa dorks + GitHub + OTX + URLscan. Para monitoreo en tiempo real, configura TELEGRAM_BOT_TOKEN en Vercel.
          </div>
        )}
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
        <Panel title={`Dorks para Telegram y Discord (${dorks.length})`} className="md:col-span-2">
          <div className="max-h-32 overflow-y-auto space-y-1">
            {dorks.map((d, i) => (
              <div key={i} className="text-[10px] font-mono text-muted-foreground flex items-center gap-1">
                <span className="text-purple-400">{i + 1}.</span>
                <code className="flex-1 truncate">{d}</code>
                <button onClick={() => navigator.clipboard.writeText(d)} className="text-muted-foreground hover:text-cyan-500 shrink-0"><Copy className="w-2.5 h-2.5" /></button>
              </div>
            ))}
          </div>
        </Panel>
      )}

      {/* Per-keyword breakdown (when searching all) */}
      {Object.keys(allKeywordResults).length > 0 && (
        <Panel title="Resultados por marca" className="md:col-span-2">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-2">
            {Object.entries(allKeywordResults).map(([kw, res]) => (
              <div key={kw} className="rounded border border-border p-2">
                <div className="flex items-center justify-between mb-1">
                  <span className="font-mono text-xs font-bold">{kw}</span>
                  <Badge variant={res.length > 0 ? "default" : "secondary"} className="text-[9px]">{res.length} resultados</Badge>
                </div>
                {res.length > 0 && (
                  <div className="text-[10px] text-muted-foreground space-y-0.5">
                    {res.slice(0, 3).map((r, i) => (
                      <div key={i} className="truncate">
                        <Badge variant="outline" className="text-[8px] mr-1">{r.source}</Badge>
                        {r.title.slice(0, 40)}
                      </div>
                    ))}
                    {res.length > 3 && <div className="text-[9px] text-cyan-500">+{res.length - 3} mas...</div>}
                  </div>
                )}
              </div>
            ))}
          </div>
        </Panel>
      )}

      {/* Results table */}
      {results.length > 0 && (
        <Panel title={`Resultados (${results.length})`} className="md:col-span-2">
          <div className="max-h-[600px] overflow-y-auto">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="w-[12%]">Source</TableHead>
                  <TableHead className="w-[8%]">Sev</TableHead>
                  <TableHead className="w-[15%]">Type</TableHead>
                  <TableHead className="w-[30%]">Title</TableHead>
                  <TableHead className="w-[35%]">Snippet</TableHead>
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

      {/* Empty state */}
      {searched && !loading && results.length === 0 && !error && (
        <Panel title="Sin resultados" className="md:col-span-2">
          <div className="flex flex-col items-center py-8 text-center gap-3">
            <AlertTriangle className="w-8 h-8 text-yellow-500" />
            <p className="text-sm text-muted-foreground">No se encontraron resultados para "{query}".</p>
            <p className="text-xs text-muted-foreground">Proba con "Buscar todas" para escanear las {DEFAULT_KEYWORDS.length} marcas.</p>
          </div>
        </Panel>
      )}

      {/* Initial state */}
      {!searched && !loading && (
        <Panel title="Que hace este modulo?" className="md:col-span-2">
          <div className="flex flex-col items-center py-10 text-center gap-4">
            <MessageSquare className="w-12 h-12 text-muted-foreground/50" />
            <h3 className="text-base font-semibold">Telegram & Discord Monitor</h3>
            <p className="text-xs text-muted-foreground max-w-2xl">
              Busca menciones de marcas financieras en Telegram, Discord y fuentes OSINT.
            </p>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-3 max-w-2xl">
              <div className="rounded border border-red-500/30 bg-red-500/5 p-2 text-left text-[11px]">
                <div className="font-semibold text-red-500 mb-1">Phishing pages</div>
                <div className="text-muted-foreground">URLscan.io + VirusTotal: detecta paginas que imitan las marcas</div>
              </div>
              <div className="rounded border border-purple-500/30 bg-purple-500/5 p-2 text-left text-[11px]">
                <div className="font-semibold text-purple-500 mb-1">Telegram dorks</div>
                <div className="text-muted-foreground">site:t.me + site:discord.com dorks para canales publicos</div>
              </div>
              <div className="rounded border border-cyan-500/30 bg-cyan-500/5 p-2 text-left text-[11px]">
                <div className="font-semibold text-cyan-500 mb-1">Threat intel</div>
                <div className="text-muted-foreground">AlienVault OTX + GitHub: tools, IOCs, repos de phishing</div>
              </div>
            </div>
            <p className="text-[10px] text-cyan-500 mt-2">Prueba: click en "Buscar todas" para escanear 9 marcas de una vez</p>
          </div>
        </Panel>
      )}
    </ModuleShell>
  );
}
