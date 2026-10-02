"use client";

import * as React from "react";
import {
  Skull,
  Search,
  Loader2,
  Printer,
  Download,
  AlertTriangle,
  ExternalLink,
  ShieldAlert,
  Eye,
  Terminal,
  Activity,
  Trash2,
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

interface SearchResult {
  source: string;
  type: string;
  title: string;
  url: string;
  snippet: string;
  severity: "high" | "medium" | "low" | "info";
  timestamp: string | null;
}

interface DarkWebResponse {
  query: string;
  queryType: string;
  results: SearchResult[];
  summary: {
    total: number;
    bySource: Record<string, number>;
    bySeverity: { high: number; medium: number; low: number; info: number };
  };
  timestamp: string;
}

// ---------- Component ----------

export function DeepDarkWebView() {
  const [query, setQuery] = React.useState("");
  const [queryType, setQueryType] = React.useState<"email" | "domain" | "keyword" | "ip">("keyword");
  const [loading, setLoading] = React.useState(false);
  const [data, setData] = React.useState<DarkWebResponse | null>(null);
  const [error, setError] = React.useState<string | null>(null);
  const [step, setStep] = React.useState("");

  const search = async (q?: string, type?: string) => {
    const target = (q ?? query).trim();
    const t = type ?? queryType;
    if (!target) {
      alert("Escribi un target para buscar (email, dominio, keyword o IP).");
      return;
    }
    setQuery(target);
    setQueryType(t as any);
    setLoading(true);
    setError(null);
    setData(null);
    setStep("Buscando en dark web y deep web...");

    try {
      const r = await fetch(`/api/darkweb/search?q=${encodeURIComponent(target)}&type=${t}`);
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      const j: DarkWebResponse = await r.json();
      setData(j);
      setStep("");
    } catch (e: any) {
      setError(String(e?.message || e));
    }
    setLoading(false);
  };

  // ---- Stats ----
  const stats = data ? {
    total: data.summary.total,
    high: data.summary.bySeverity.high,
    medium: data.summary.bySeverity.medium,
    low: data.summary.bySeverity.low,
    intelx: data.summary.bySource["IntelligenceX"] || 0,
    ahmia: data.summary.bySource["Ahmia (.onion)"] || 0,
    leakcheck: data.summary.bySource["LeakCheck"] || 0,
    github: data.summary.bySource["GitHub"] || 0,
    pulsedive: data.summary.bySource["Pulsedive"] || 0,
    pastebin: data.summary.bySource["Pastebin"] || 0,
  } : null;

  // ---- PDF ----
  const generatePdf = async () => {
    if (!data) return;
    const doc = new jsPDF({ unit: "pt", format: "a4" });
    const pageWidth = doc.internal.pageSize.getWidth();
    const pageHeight = doc.internal.pageSize.getHeight();
    const margin = 40;
    const contentWidth = pageWidth - margin * 2;
    let y = margin;

    // Cover
    doc.setFont("helvetica", "bold"); doc.setFontSize(22); doc.setTextColor(15, 23, 42);
    doc.text("Deep & Dark Web Report", margin, y + 8);
    doc.setFont("helvetica", "normal"); doc.setFontSize(11); doc.setTextColor(220, 38, 38);
    doc.text("MONITOR-THREAT", margin, y + 26);
    doc.setTextColor(100, 116, 139);
    doc.text("OSINT & Surface Monitoring - Deep & Dark Web", margin + 105, y + 26);
    doc.setFontSize(10); doc.setTextColor(71, 85, 105);
    doc.text(`Fecha: ${new Date().toLocaleString()}`, pageWidth - margin, y + 8, { align: "right" });
    doc.text(`Target: ${data.query.slice(0, 60)}`, pageWidth - margin, y + 22, { align: "right" });
    y += 48; doc.setDrawColor(220, 220, 220); doc.setLineWidth(0.5);
    doc.line(margin, y, pageWidth - margin, y); y += 28;

    const sectionHeading = (label: string) => {
      if (y > pageHeight - margin - 120) { doc.addPage(); y = margin + 6; } else { y += 20; }
      doc.setFont("helvetica", "bold"); doc.setFontSize(13); doc.setTextColor(220, 38, 38);
      doc.text(label, margin, y); doc.setDrawColor(220, 38, 38); doc.setLineWidth(1);
      doc.line(margin, y + 4, pageWidth - margin, y + 4); y += 16;
      doc.setFont("helvetica", "normal"); doc.setFontSize(10); doc.setTextColor(51, 65, 85);
    };

    // Resumen
    sectionHeading("Resumen");
    autoTable(doc, {
      startY: y,
      head: [["Metrica", "Valor"]],
      body: [
        ["Target", data.query],
        ["Tipo", data.queryType],
        ["Total resultados", String(stats!.total)],
        ["Severidad alta", String(stats!.high)],
        ["Severidad media", String(stats!.medium)],
        ["Severidad baja", String(stats!.low)],
        ["IntelligenceX", String(stats!.intelx)],
        ["Ahmia (.onion)", String(stats!.ahmia)],
        ["LeakCheck", String(stats!.leakcheck)],
        ["GitHub leaks", String(stats!.github)],
        ["Pulsedive", String(stats!.pulsedive)],
        ["Pastebin", String(stats!.pastebin)],
      ],
      theme: "striped",
      margin: { left: margin, right: margin },
      styles: { fontSize: 9, cellPadding: 5, textColor: [30, 41, 59] },
      headStyles: { fillColor: [241, 245, 249], textColor: [71, 85, 105], fontSize: 9 },
      columnStyles: { 0: { cellWidth: contentWidth * 0.32, fontStyle: "bold", textColor: [100, 116, 139] } },
    });
    // @ts-ignore
    y = (doc as any).lastAutoTable.finalY + 18;

    // Detalle por resultado
    sectionHeading("Resultados de la Busqueda");
    const rows = data.results.map(r => [
      r.source,
      r.severity,
      r.type,
      r.title.slice(0, 60),
      r.snippet.slice(0, 80),
      r.url.slice(0, 70),
    ]);
    autoTable(doc, {
      startY: y,
      head: [["Source", "Severity", "Type", "Title", "Snippet", "URL"]],
      body: rows,
      theme: "grid",
      margin: { left: margin, right: margin },
      styles: { fontSize: 8, cellPadding: 4, textColor: [30, 41, 59], lineColor: [226, 232, 240], lineWidth: 0.3 },
      headStyles: { fillColor: [220, 38, 38], textColor: [255, 255, 255], fontSize: 8 },
      didParseCell: (data: any) => {
        if (data.section === "body" && data.column.index === 1) {
          const v = String(data.cell.raw || "");
          if (v === "high") data.cell.styles.textColor = [220, 38, 38];
          else if (v === "medium") data.cell.styles.textColor = [161, 98, 7];
          else data.cell.styles.textColor = [22, 163, 74];
        }
      },
    });

    // Footer
    const pageCount = doc.getNumberOfPages();
    for (let i = 1; i <= pageCount; i++) {
      doc.setPage(i);
      doc.setFont("helvetica", "normal"); doc.setFontSize(8); doc.setTextColor(150, 150, 150);
      doc.text(`MONITOR-THREAT - Deep & Dark Web Report - Pagina ${i} de ${pageCount}`, pageWidth / 2, pageHeight - 20, { align: "center" });
    }

    doc.save(`darkweb-report-${Date.now()}.pdf`);
  };

  const severityColors: Record<string, string> = {
    high: "destructive",
    medium: "default",
    low: "secondary",
    info: "outline",
  };
  const severityText: Record<string, string> = {
    high: "ALTA",
    medium: "MEDIA",
    low: "BAJA",
    info: "INFO",
  };

  return (
    <ModuleShell
      name="Deep & Dark Web"
      description="Busca menciones del target en la dark web (.onion), deep web (pastes, leaks) y GitHub. Usa IntelligenceX, Ahmia, LeakCheck, GitHub y Pulsedive."
      icon={Skull}
      category="OSINT"
    >
      {/* Search bar */}
      <Panel title="Buscar en Dark Web y Deep Web" className="md:col-span-2"
        action={
          <Button size="sm" onClick={() => search()} disabled={loading || !query.trim()}>
            {loading ? <><Loader2 className="w-3.5 h-3.5 mr-1.5 animate-spin" /> {step}</> : <><Search className="w-3.5 h-3.5 mr-1.5" /> Buscar</>}
          </Button>
        }
      >
        <div className="flex gap-2 mb-3">
          <select
            value={queryType}
            onChange={e => setQueryType(e.target.value as any)}
            className="h-9 text-xs rounded border border-border bg-background px-2"
          >
            <option value="keyword">Keyword</option>
            <option value="email">Email</option>
            <option value="domain">Dominio</option>
            <option value="ip">IP</option>
          </select>
          <Input
            type="text"
            placeholder="ej: target@empresa.com | empresa.com | keyword | 8.8.8.8"
            value={query}
            onChange={e => setQuery(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && search()}
            className="flex-1 font-mono text-sm"
            autoFocus
          />
        </div>
        <div className="text-[10px] text-muted-foreground">
          El sistema busca en IntelligenceX, Ahmia (.onion), LeakCheck, GitHub Code Search, Pulsedive y Pastebin en paralelo.
        </div>
      </Panel>

      {/* Error */}
      {error && (
        <div className="mb-4 p-3 rounded-md border border-red-500/40 bg-red-500/10 text-red-400 flex items-center gap-2">
          <AlertTriangle className="w-4 h-4 shrink-0" /><span className="text-sm">{error}</span>
        </div>
      )}

      {/* Stats */}
      {stats && (
        <Panel title="Resultados de la Busqueda" className="md:col-span-2"
          action={
            <div className="flex gap-2">
              <Button size="sm" variant="outline" onClick={generatePdf}>
                <Printer className="w-3 h-3 mr-1.5" /> PDF
              </Button>
            </div>
          }
        >
          <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-2 mb-4">
            <div className="rounded p-2 border border-cyan-500/40 bg-cyan-500/5 text-cyan-400">
              <div className="text-lg font-bold font-mono">{stats.total}</div>
              <div className="text-[10px]">Total resultados</div>
            </div>
            <div className="rounded p-2 border border-red-500/40 bg-red-500/5 text-red-400">
              <div className="text-lg font-bold font-mono">{stats.high}</div>
              <div className="text-[10px]">Severidad alta</div>
            </div>
            <div className="rounded p-2 border border-yellow-500/40 bg-yellow-500/5 text-yellow-400">
              <div className="text-lg font-bold font-mono">{stats.medium}</div>
              <div className="text-[10px]">Severidad media</div>
            </div>
            <div className="rounded p-2 border border-green-500/40 bg-green-500/5 text-green-400">
              <div className="text-lg font-bold font-mono">{stats.ahmia}</div>
              <div className="text-[10px]">Ahmia (.onion)</div>
            </div>
            <div className="rounded p-2 border border-purple-500/40 bg-purple-500/5 text-purple-400">
              <div className="text-lg font-bold font-mono">{stats.github}</div>
              <div className="text-[10px]">GitHub leaks</div>
            </div>
            <div className="rounded p-2 border border-orange-500/40 bg-orange-500/5 text-orange-400">
              <div className="text-lg font-bold font-mono">{stats.leakcheck + stats.intelx}</div>
              <div className="text-[10px]">Leaks/IntelX</div>
            </div>
          </div>
        </Panel>
      )}

      {/* Results table */}
      {data && data.results.length > 0 && (
        <Panel title={`Resultados detallados (${data.results.length})`} className="md:col-span-2">
          <div className="max-h-[500px] overflow-y-auto">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="w-[15%]">Source</TableHead>
                  <TableHead className="w-[10%]">Severity</TableHead>
                  <TableHead className="w-[15%]">Type</TableHead>
                  <TableHead className="w-[30%]">Title</TableHead>
                  <TableHead className="w-[30%]">Snippet</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {data.results.map((r, i) => (
                  <TableRow key={i}>
                    <TableCell className="font-mono text-[11px]">
                      <Badge variant="outline" className="text-[9px] font-mono">{r.source}</Badge>
                    </TableCell>
                    <TableCell>
                      <Badge variant={severityColors[r.severity] as any} className="text-[9px] font-mono">
                        {severityText[r.severity]}
                      </Badge>
                    </TableCell>
                    <TableCell className="text-[11px] text-muted-foreground">{r.type}</TableCell>
                    <TableCell className="text-[11px] font-medium">
                      <a href={r.url} target="_blank" rel="noreferrer" className="text-cyan-500 hover:underline inline-flex items-center gap-1">
                        {r.title.slice(0, 60)} <ExternalLink className="w-2.5 h-2.5 shrink-0" />
                      </a>
                    </TableCell>
                    <TableCell className="text-[11px] text-muted-foreground font-mono">{r.snippet.slice(0, 100)}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        </Panel>
      )}

      {/* Empty state */}
      {!data && !loading && (
        <Panel title="Que busca este modulo?" className="md:col-span-2">
          <div className="flex flex-col items-center justify-center py-10 text-center gap-4">
            <Skull className="w-12 h-12 text-muted-foreground/50" />
            <h3 className="text-base font-semibold">Deep & Dark Web Monitoring</h3>
            <p className="text-xs text-muted-foreground max-w-2xl text-center">
              Escribe un target (email, dominio, keyword o IP) arriba y hace click en Buscar.
              El sistema busca en paralelo en 6 fuentes:
            </p>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-3 max-w-2xl w-full">
              <div className="rounded border border-red-500/30 bg-red-500/5 p-2 text-left text-[11px]">
                <div className="font-semibold text-red-500 mb-1">🔴 Credenciales filtradas</div>
                <div className="text-muted-foreground">IntelligenceX + LeakCheck + GitHub</div>
              </div>
              <div className="rounded border border-yellow-500/30 bg-yellow-500/5 p-2 text-left text-[11px]">
                <div className="font-semibold text-yellow-500 mb-1">🟡 Dark web (.onion)</div>
                <div className="text-muted-foreground">Ahmia.fi + IntelligenceX darknet</div>
              </div>
              <div className="rounded border border-orange-500/30 bg-orange-500/5 p-2 text-left text-[11px]">
                <div className="font-semibold text-orange-500 mb-1">🟠 Deep web (pastes)</div>
                <div className="text-muted-foreground">Pastebin + Pulsedive + IntelX</div>
              </div>
            </div>
            <div className="text-[10px] text-yellow-500 mt-2">
              ⚠ Algunas fuentes requieren API keys (IntelligenceX, LeakCheck, Pulsedive). Sin keys, esas fuentes se marcan como salteadas.
            </div>
          </div>
        </Panel>
      )}
    </ModuleShell>
  );
}
