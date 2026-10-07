"use client";

import * as React from "react";
import {
  UserSearch, Search, Loader2, Printer, AlertTriangle, ExternalLink, Copy,
  Mail, Phone, User, AtSign, Upload, Image as ImageIcon, X,
  Users, Code, Globe, MapPin, FileText, Briefcase, Newspaper,
  MessageSquare, Shield, GraduationCap, Building, Radar, Skull, Eye,
  Scale, AtSign as AtSignIcon,
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
  category: string;
  source: string; type: string; title: string; url: string;
  snippet: string; severity: "high" | "medium" | "low" | "info"; timestamp: string | null;
}

interface Category {
  id: string; name: string; icon: string; severity: "high" | "medium" | "low" | "info"; dorksCount: number;
}

// Map icon string -> component
const ICON_MAP: Record<string, React.ComponentType<any>> = {
  Users, Code, Globe, Mail, MapPin, FileText, Briefcase, ImageIcon, Newspaper,
  Scale, MessageSquare, AlertTriangle, GraduationCap, Building, AtSign,
  Shield, Radar, Skull, Phone, Eye,
};

export function ExecutiveOsintView() {
  const [query, setQuery] = React.useState("");
  const [queryType, setQueryType] = React.useState<"name" | "email" | "phone" | "username">("name");
  const [loading, setLoading] = React.useState(false);
  const [results, setResults] = React.useState<SearchResult[]>([]);
  const [categories, setCategories] = React.useState<Category[]>([]);
  const [dorksByCategory, setDorksByCategory] = React.useState<Record<string, string[]>>({});
  const [dorksExecuted, setDorksExecuted] = React.useState(0);
  const [summary, setSummary] = React.useState<{
    total: number; byCategory: Record<string, number>; bySource: Record<string, number>;
    bySeverity: { high: number; medium: number; low: number; info: number };
    engines?: { bing: number };
    sherlock?: number;
    preciseMatch?: { wikipedia: number; ddg: number; wikidata?: number; opencorporates?: number };
  } | null>(null);
  const [sourcesUsed, setSourcesUsed] = React.useState<string[]>([]);
  const [enginesUsed, setEnginesUsed] = React.useState<string[]>([]);
  const [error, setError] = React.useState<string | null>(null);
  const [searched, setSearched] = React.useState(false);

  // Estado de la pestaña activa (categoria seleccionada)
  const [activeCategory, setActiveCategory] = React.useState<string>("all");

  // Estado de la busqueda por imagen
  const [imageFile, setImageFile] = React.useState<File | null>(null);
  const [imagePreview, setImagePreview] = React.useState<string | null>(null);
  const [imageResults, setImageResults] = React.useState<any>(null);
  const [imageLoading, setImageLoading] = React.useState(false);

  const search = async () => {
    if (!query.trim()) return;
    setLoading(true); setError(null); setResults([]); setCategories([]); setDorksByCategory({});
    setSummary(null); setSourcesUsed([]); setEnginesUsed([]); setSearched(true); setActiveCategory("all");
    try {
      const r = await fetch(`/api/executive-osint/search?q=${encodeURIComponent(query.trim())}&type=${queryType}`);
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      const j = await r.json();
      setResults(j.results || []);
      setCategories(j.categories || []);
      setDorksByCategory(j.dorksByCategory || {});
      setDorksExecuted(j.dorksExecuted || 0);
      setSummary(j.summary || null);
      setSourcesUsed(j.sourcesUsed || []);
      setEnginesUsed(j.enginesUsed || []);
    } catch (e: any) { setError(String(e?.message || e)); }
    setLoading(false);
  };

  const searchImage = async () => {
    if (!imageFile) return;
    setImageLoading(true);
    try {
      const formData = new FormData();
      formData.append("image", imageFile);
      const nameParam = query ? `?name=${encodeURIComponent(query.trim())}` : "";
      const r = await fetch(`/api/executive-osint/image-search${nameParam}`, { method: "POST", body: formData });
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      const j = await r.json();
      setImageResults(j);
    } catch (e: any) { setError(String(e?.message || e)); }
    setImageLoading(false);
  };

  const onImageChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    setImageFile(file);
    const reader = new FileReader();
    reader.onload = () => setImagePreview(reader.result as string);
    reader.readAsDataURL(file);
  };

  const clearImage = () => {
    setImageFile(null);
    setImagePreview(null);
    setImageResults(null);
  };

  const sevColors: Record<string, "destructive" | "default" | "secondary" | "outline"> = { high: "destructive", medium: "default", low: "secondary", info: "outline" };
  const sevText: Record<string, string> = { high: "ALTA", medium: "MEDIA", low: "BAJA", info: "INFO" };

  const generatePdf = () => {
    if (results.length === 0) return;
    const doc = new jsPDF({ unit: "pt", format: "a4" });
    const pw = doc.internal.pageSize.getWidth(), ph = doc.internal.pageSize.getHeight(), m = 40;
    let y = m;
    doc.setFont("helvetica", "bold"); doc.setFontSize(22); doc.setTextColor(15, 23, 42);
    doc.text("Executive OSINT Report", m, y + 8);
    doc.setFont("helvetica", "normal"); doc.setFontSize(11); doc.setTextColor(220, 38, 38);
    doc.text("MONITOR-THREAT", m, y + 26);
    doc.setFontSize(10); doc.setTextColor(71, 85, 105);
    doc.text(`Target: ${query} (${queryType})`, pw - m, y + 8, { align: "right" });
    doc.text(`Fecha: ${new Date().toLocaleString()}`, pw - m, y + 22, { align: "right" });
    y += 48; doc.line(m, y, pw - m, y); y += 28;
    autoTable(doc, {
      startY: y, head: [["Category", "Source", "Severity", "Type", "Title", "Snippet", "URL"]],
      body: results.map(r => [r.category, r.source, sevText[r.severity], r.type, r.title.slice(0, 50), r.snippet.slice(0, 60), r.url.slice(0, 50)]),
      theme: "grid", margin: { left: m, right: m }, styles: { fontSize: 7, cellPadding: 3 },
      headStyles: { fillColor: [220, 38, 38], textColor: [255, 255, 255], fontSize: 7 },
    });
    for (let i = 1; i <= doc.getNumberOfPages(); i++) {
      doc.setPage(i); doc.setFontSize(8); doc.setTextColor(150, 150, 150);
      doc.text(`MONITOR-THREAT - Executive OSINT - Pagina ${i} de ${doc.getNumberOfPages()}`, pw / 2, ph - 20, { align: "center" });
    }
    doc.save(`executive-osint-${Date.now()}.pdf`);
  };

  const typeIcons: Record<string, React.ReactNode> = {
    name: <User className="w-3 h-3" />, email: <Mail className="w-3 h-3" />,
    phone: <Phone className="w-3 h-3" />, username: <AtSign className="w-3 h-3" />,
  };

  // Filtrar resultados por categoria activa
  const filteredResults = activeCategory === "all" ? results : results.filter(r => r.category === activeCategory);

  return (
    <ModuleShell
      name="Executive OSINT"
      description="Investigacion por dorks en 20 categorias: social media, developer profiles, leaks, breaches, dark web, deepfake, image search y mas."
      icon={UserSearch}
      category="OSINT"
    >
      {/* SEARCH BAR */}
      <Panel title="Buscar ejecutivo / persona" className="md:col-span-2"
        action={<Button size="sm" onClick={search} disabled={loading || !query.trim()}>
          {loading ? <><Loader2 className="w-3.5 h-3.5 mr-1.5 animate-spin" /> Buscando...</> : <><Search className="w-3.5 h-3.5 mr-1.5" /> Buscar</>}
        </Button>}
      >
        <div className="flex gap-2 mb-3">
          <select value={queryType} onChange={e => setQueryType(e.target.value as any)} className="h-9 text-xs rounded border border-border bg-background px-2">
            <option value="name">Nombre</option>
            <option value="email">Email</option>
            <option value="phone">Telefono</option>
            <option value="username">Alias / @username</option>
          </select>
          <Input type="text" placeholder={queryType === "name" ? "ej: Juan Perez" : queryType === "email" ? "ej: juan@empresa.com" : queryType === "phone" ? "ej: +57 3001234567" : "ej: @jperez"} value={query} onChange={e => setQuery(e.target.value)} onKeyDown={e => e.key === "Enter" && search()} className="flex-1 font-mono text-sm" autoFocus />
        </div>
        <div className="text-[10px] text-muted-foreground">
          20 categorias de dorks ejecutadas en Bing + APIs: GitHub, Gravatar, HIBP, VirusTotal, Wikipedia (EN+ES), DuckDuckGo IA, Hunter, Wikidata, OpenCorporates, Sherlock (17 redes). {dorksExecuted > 0 && <span className="text-purple-400">| {dorksExecuted} dorks ejecutados</span>}
        </div>
        {(sourcesUsed.length > 0 || enginesUsed.length > 0) && (
          <div className="flex gap-1 flex-wrap mt-2">
            <span className="text-[9px] text-muted-foreground uppercase tracking-wider self-center mr-1">Fuentes activas:</span>
            {sourcesUsed.map(s => <Badge key={s} variant="outline" className="text-[9px] font-mono text-cyan-400 border-cyan-500/40">{s}</Badge>)}
            {enginesUsed.map(e => <Badge key={e} variant="outline" className="text-[9px] font-mono text-purple-400 border-purple-500/40">{e}</Badge>)}
          </div>
        )}
      </Panel>

      {/* IMAGE UPLOAD */}
      <Panel title="Busqueda por imagen (Deepfake / Face match)" className="md:col-span-2">
        <div className="flex gap-3 items-start">
          <div className="flex-1">
            <div className="text-[10px] text-muted-foreground mb-2">
              Sube una imagen del ejecutivo para generar enlaces a Google Images, Yandex (mejor para rostros), PimEyes, FaceCheck, TinEye y mas. Tambien genera dorks de deepfake usando el nombre.
            </div>
            <div className="flex gap-2 items-center">
              <label className="cursor-pointer">
                <input type="file" accept="image/*" onChange={onImageChange} className="hidden" />
                <span className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs rounded border border-border bg-background hover:bg-accent">
                  <Upload className="w-3 h-3" /> {imageFile ? "Cambiar imagen" : "Subir imagen"}
                </span>
              </label>
              {imageFile && (
                <>
                  <Button size="sm" onClick={searchImage} disabled={imageLoading || !imageFile}>
                    {imageLoading ? <><Loader2 className="w-3.5 h-3.5 mr-1.5 animate-spin" /> Buscando...</> : <><ImageIcon className="w-3.5 h-3.5 mr-1.5" /> Buscar imagen</>}
                  </Button>
                  <Button size="sm" variant="outline" onClick={clearImage}><X className="w-3.5 h-3.5" /></Button>
                </>
              )}
              <span className="text-[10px] text-muted-foreground">{imageFile?.name}</span>
            </div>
          </div>
          {imagePreview && (
            <div className="relative">
              <img src={imagePreview} alt="preview" className="w-32 h-32 object-cover rounded border border-border" />
              <button onClick={clearImage} className="absolute -top-2 -right-2 bg-red-500 text-white rounded-full w-5 h-5 flex items-center justify-center text-[10px]"><X className="w-3 h-3" /></button>
            </div>
          )}
        </div>

        {imageResults && (
          <div className="mt-4 border-t border-border pt-3">
            <div className="text-xs font-semibold mb-2 flex items-center gap-1.5"><ImageIcon className="w-3.5 h-3.5" /> Motores de busqueda visual</div>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
              {imageResults.searchEngines?.map((eng: any, i: number) => {
                const sevColor = eng.severity === "high" ? "border-red-500/40 bg-red-500/5" : eng.severity === "medium" ? "border-yellow-500/40 bg-yellow-500/5" : "border-blue-500/40 bg-blue-500/5";
                return (
                  <a key={i} href={eng.url} target="_blank" rel="noreferrer" className={`block p-2 rounded border ${sevColor} hover:bg-accent transition`}>
                    <div className="flex items-center justify-between mb-1">
                      <span className="text-xs font-semibold">{eng.source}</span>
                      <Badge variant={sevColors[eng.severity] || "outline"} className="text-[9px]">{sevText[eng.severity]}</Badge>
                    </div>
                    <div className="text-[10px] text-muted-foreground">{eng.snippet}</div>
                    <div className="text-[10px] text-cyan-500 mt-1">{eng.instructions}</div>
                  </a>
                );
              })}
            </div>
            {imageResults.deepfakeDorks?.length > 0 && (
              <div className="mt-3">
                <div className="text-xs font-semibold mb-2">Dorks de Deepfake para &quot;{query}&quot;:</div>
                <div className="space-y-1">
                  {imageResults.deepfakeDorks.map((d: string, i: number) => (
                    <div key={i} className="text-[10px] font-mono text-muted-foreground flex items-center gap-1">
                      <span className="text-red-400">{i + 1}.</span>
                      <code className="flex-1 truncate">{d}</code>
                      <button onClick={() => navigator.clipboard.writeText(d)} className="text-muted-foreground hover:text-cyan-500 shrink-0"><Copy className="w-2.5 h-2.5" /></button>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}
      </Panel>

      {error && <div className="mb-4 p-3 rounded border border-red-500/40 bg-red-500/10 text-red-400 flex items-center gap-2"><AlertTriangle className="w-4 h-4 shrink-0" /> {error}</div>}

      {/* SUMMARY */}
      {summary && (
        <Panel title={`Resultados: ${summary.total} encontrados en ${Object.keys(summary.byCategory || {}).length} categorias`} className="md:col-span-2"
          action={<Button size="sm" variant="outline" onClick={generatePdf} disabled={results.length === 0}><Printer className="w-3 h-3 mr-1.5" /> PDF</Button>}
        >
          <div className="grid grid-cols-2 md:grid-cols-5 gap-2 mb-3">
            <div className="rounded p-2 border border-cyan-500/40 bg-cyan-500/5"><div className="text-lg font-bold font-mono text-cyan-400">{summary.total}</div><div className="text-[10px]">Total</div></div>
            <div className="rounded p-2 border border-red-500/40 bg-red-500/5"><div className="text-lg font-bold font-mono text-red-400">{summary.bySeverity.high}</div><div className="text-[10px]">Alta</div></div>
            <div className="rounded p-2 border border-yellow-500/40 bg-yellow-500/5"><div className="text-lg font-bold font-mono text-yellow-400">{summary.bySeverity.medium}</div><div className="text-[10px]">Media</div></div>
            <div className="rounded p-2 border border-green-500/40 bg-green-500/5"><div className="text-lg font-bold font-mono text-green-400">{summary.bySeverity.low}</div><div className="text-[10px]">Baja</div></div>
            <div className="rounded p-2 border border-blue-500/40 bg-blue-500/5"><div className="text-lg font-bold font-mono text-blue-400">{summary.bySeverity.info}</div><div className="text-[10px]">Info</div></div>
          </div>
          {summary.engines && (
            <div className="flex gap-2 mb-2">
              {summary.engines.bing !== undefined && <div className="rounded p-2 border border-purple-500/40 bg-purple-500/5 flex-1"><div className="text-lg font-bold font-mono text-purple-400">{summary.engines.bing}</div><div className="text-[10px]">Bing</div></div>}
              {summary.preciseMatch && <div className="rounded p-2 border border-cyan-500/40 bg-cyan-500/5 flex-1"><div className="text-lg font-bold font-mono text-cyan-400">{summary.preciseMatch.wikipedia + summary.preciseMatch.ddg + (summary.preciseMatch.wikidata || 0) + (summary.preciseMatch.opencorporates || 0)}</div><div className="text-[10px]">Wikipedia+DDG+Wikidata+OpenCorp</div></div>}
              {summary.sherlock !== undefined && <div className="rounded p-2 border border-amber-500/40 bg-amber-500/5 flex-1"><div className="text-lg font-bold font-mono text-amber-400">{summary.sherlock}</div><div className="text-[10px]">Sherlock (17)</div></div>}
            </div>
          )}
        </Panel>
      )}

      {/* CATEGORY NAVIGATION */}
      {categories.length > 0 && (
        <Panel title="Categorias de investigacion" className="md:col-span-2">
          <div className="grid grid-cols-2 md:grid-cols-5 lg:grid-cols-10 gap-1.5">
            <button
              onClick={() => setActiveCategory("all")}
              className={`p-2 rounded border text-left transition ${activeCategory === "all" ? "border-cyan-500 bg-cyan-500/10" : "border-border bg-background hover:bg-accent"}`}
            >
              <div className="text-xs font-semibold">Todas</div>
              <div className="text-[10px] text-muted-foreground">{results.length} hits</div>
            </button>
            {categories.map(cat => {
              const Icon = ICON_MAP[cat.icon] || Globe;
              const count = summary?.byCategory?.[cat.id] || 0;
              return (
                <button
                  key={cat.id}
                  onClick={() => setActiveCategory(cat.id)}
                  className={`p-2 rounded border text-left transition ${activeCategory === cat.id ? "border-cyan-500 bg-cyan-500/10" : "border-border bg-background hover:bg-accent"}`}
                >
                  <div className="flex items-center gap-1 mb-0.5">
                    <Icon className="w-3 h-3 text-cyan-500" />
                    <span className="text-[10px] font-semibold truncate">{cat.name.split(" ")[0]}</span>
                  </div>
                  <div className="text-[10px] text-muted-foreground">{count} hits · {cat.dorksCount} dorks</div>
                </button>
              );
            })}
          </div>
        </Panel>
      )}

      {/* DORKS BY CATEGORY */}
      {Object.keys(dorksByCategory).length > 0 && (
        <Panel title={`Dorks generados — ${dorksExecuted} ejecutados en Bing`} className="md:col-span-2">
          <div className="text-[10px] text-muted-foreground mb-2">1 dork por categoria se ejecuta automaticamente en Bing. Copia los demas para usarlos manualmente en Google/Yandex:</div>
          <div className="max-h-72 overflow-y-auto space-y-3">
            {categories.map(cat => {
              const catDorks = dorksByCategory[cat.id] || [];
              if (catDorks.length === 0) return null;
              const Icon = ICON_MAP[cat.icon] || Globe;
              return (
                <div key={cat.id} className="border-l-2 border-cyan-500/40 pl-2">
                  <div className="flex items-center gap-1 mb-1">
                    <Icon className="w-3 h-3 text-cyan-500" />
                    <span className="text-[11px] font-semibold">{cat.name}</span>
                    <Badge variant={sevColors[cat.severity]} className="text-[9px] ml-1">{sevText[cat.severity]}</Badge>
                  </div>
                  {catDorks.map((d, i) => (
                    <div key={i} className="text-[10px] font-mono text-muted-foreground flex items-center gap-1 ml-3">
                      <span className="text-purple-400">{i + 1}.</span>
                      {i === 0 && <Badge variant="outline" className="text-[8px] text-purple-400 border-purple-500/40">auto</Badge>}
                      <code className="flex-1 truncate">{d}</code>
                      <button onClick={() => navigator.clipboard.writeText(d)} className="text-muted-foreground hover:text-cyan-500 shrink-0"><Copy className="w-2.5 h-2.5" /></button>
                    </div>
                  ))}
                </div>
              );
            })}
          </div>
        </Panel>
      )}

      {/* RESULTS */}
      {filteredResults.length > 0 && (
        <Panel title={`Resultados (${filteredResults.length}) ${activeCategory !== "all" ? `— ${categories.find(c => c.id === activeCategory)?.name || activeCategory}` : ""}`} className="md:col-span-2">
          <div className="max-h-[600px] overflow-y-auto">
            <Table>
              <TableHeader><TableRow>
                <TableHead className="w-[15%]">Categoria</TableHead>
                <TableHead className="w-[10%]">Source</TableHead>
                <TableHead className="w-[6%]">Sev</TableHead>
                <TableHead className="w-[10%]">Type</TableHead>
                <TableHead className="w-[27%]">Title</TableHead>
                <TableHead className="w-[32%]">Snippet</TableHead>
              </TableRow></TableHeader>
              <TableBody>
                {filteredResults.map((r, i) => {
                  const cat = categories.find(c => c.id === r.category);
                  const Icon = cat ? (ICON_MAP[cat.icon] || Globe) : Globe;
                  return (
                    <TableRow key={i}>
                      <TableCell className="text-[10px]">
                        <div className="flex items-center gap-1">
                          <Icon className="w-2.5 h-2.5 text-cyan-500 shrink-0" />
                          <span className="truncate">{cat?.name || r.category}</span>
                        </div>
                      </TableCell>
                      <TableCell><Badge variant="outline" className="text-[9px] font-mono">{r.source}</Badge></TableCell>
                      <TableCell><Badge variant={sevColors[r.severity]} className="text-[9px] font-mono">{sevText[r.severity]}</Badge></TableCell>
                      <TableCell className="text-[11px] text-muted-foreground">{r.type}</TableCell>
                      <TableCell className="text-[11px]"><a href={r.url} target="_blank" rel="noreferrer" className="text-cyan-500 hover:underline inline-flex items-center gap-1">{r.title.slice(0, 60)} <ExternalLink className="w-2.5 h-2.5" /></a></TableCell>
                      <TableCell className="text-[11px] text-muted-foreground font-mono">{r.snippet.slice(0, 120)}</TableCell>
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>
          </div>
        </Panel>
      )}

      {searched && !loading && results.length === 0 && !error && (
        <Panel title="Sin resultados" className="md:col-span-2">
          <div className="flex flex-col items-center py-8 text-center gap-3">
            <AlertTriangle className="w-8 h-8 text-yellow-500" />
            <p className="text-sm text-muted-foreground">No se encontraron resultados para &quot;{query}&quot; (tipo: {queryType}).</p>
            <p className="text-xs text-muted-foreground">Usa los dorks generados arriba para buscar manualmente en Google/Bing/Yandex.</p>
          </div>
        </Panel>
      )}

      {!searched && !loading && (
        <Panel title="Categorias de investigacion OSINT" className="md:col-span-2">
          <div className="flex flex-col items-center py-10 text-center gap-4">
            <UserSearch className="w-12 h-12 text-muted-foreground/50" />
            <h3 className="text-base font-semibold">Executive OSINT — 20 categorias</h3>
            <p className="text-xs text-muted-foreground max-w-2xl">Investigacion por dorks en 20 categorias para hallar informacion de ejecutivos en redes sociales, leaks, breaches, dark web y mas.</p>
            <div className="grid grid-cols-2 md:grid-cols-5 gap-2 max-w-3xl w-full text-left">
              {[
                { icon: Users, name: "Social Media", color: "blue" },
                { icon: Code, name: "Developer Profiles", color: "green" },
                { icon: Globe, name: "Web Presence", color: "blue" },
                { icon: Mail, name: "Emails & Usernames", color: "yellow" },
                { icon: MapPin, name: "Location & Contact", color: "yellow" },
                { icon: FileText, name: "PDF Publications", color: "blue" },
                { icon: Briefcase, name: "Work History", color: "blue" },
                { icon: ImageIcon, name: "Images", color: "blue" },
                { icon: Newspaper, name: "News & Articles", color: "blue" },
                { icon: Scale, name: "Public Records", color: "yellow" },
                { icon: MessageSquare, name: "Forums", color: "blue" },
                { icon: AlertTriangle, name: "Leaks & Pastes", color: "red" },
                { icon: GraduationCap, name: "Academic", color: "blue" },
                { icon: Building, name: "Company Registries", color: "yellow" },
                { icon: AtSignIcon, name: "Usernames x-ref", color: "yellow" },
                { icon: Shield, name: "Breach Databases", color: "red" },
                { icon: Radar, name: "IntelX / Shodan", color: "yellow" },
                { icon: Skull, name: "Dark Web", color: "red" },
                { icon: Phone, name: "Phone & Address", color: "yellow" },
                { icon: Eye, name: "Deepfake", color: "red" },
              ].map((c, i) => {
                const Icon = c.icon;
                return (
                  <div key={i} className={`rounded border border-${c.color}-500/30 bg-${c.color}-500/5 p-2 text-left text-[10px]`}>
                    <div className="flex items-center gap-1 mb-0.5">
                      <Icon className={`w-3 h-3 text-${c.color}-500`} />
                      <span className="font-semibold">{c.name}</span>
                    </div>
                  </div>
                );
              })}
            </div>
            <p className="text-[10px] text-cyan-500 mt-2">Sube una imagen del ejecutivo para buscar coincidencias visuales en Google, Yandex, PimEyes, TinEye y mas.</p>
          </div>
        </Panel>
      )}
    </ModuleShell>
  );
}
