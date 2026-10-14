"use client";

import * as React from "react";
import {
  Skull, Search, Loader2, Printer, AlertTriangle, ExternalLink, ChevronDown,
  Globe, ShieldAlert, Scale, Crosshair, Sparkles, Camera, Languages, Calendar, FileType,
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
  formattedUrl?: string;
  mime?: string;
}

interface CategoryInfo {
  id: string;
  name: string;
  description: string;
  severity: "high" | "medium" | "low" | "info";
}

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

const FILE_TYPES = ["pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "csv", "kml", "kmz"];

const LANGUAGES = [
  { code: "", name: "Cualquier idioma" },
  { code: "lang_ar", name: "Arabe" },
  { code: "lang_bg", name: "Bulgaro" },
  { code: "lang_ca", name: "Catalan" },
  { code: "lang_zh-CN", name: "Chino (Simplificado)" },
  { code: "lang_zh-TW", name: "Chino (Tradicional)" },
  { code: "lang_hr", name: "Croata" },
  { code: "lang_cs", name: "Checo" },
  { code: "lang_da", name: "Danes" },
  { code: "lang_nl", name: "Holandes" },
  { code: "lang_en", name: "Ingles" },
  { code: "lang_et", name: "Estonio" },
  { code: "lang_fi", name: "Finlandes" },
  { code: "lang_fr", name: "Frances" },
  { code: "lang_de", name: "Aleman" },
  { code: "lang_el", name: "Griego" },
  { code: "lang_he", name: "Hebreo" },
  { code: "lang_hu", name: "Hungaro" },
  { code: "lang_is", name: "Islandes" },
  { code: "lang_id", name: "Indonesio" },
  { code: "lang_it", name: "Italiano" },
  { code: "lang_ja", name: "Japones" },
  { code: "lang_ko", name: "Coreano" },
  { code: "lang_lv", name: "Leton" },
  { code: "lang_lt", name: "Lituano" },
  { code: "lang_no", name: "Noruego" },
  { code: "lang_pl", name: "Polaco" },
  { code: "lang_pt", name: "Portugues" },
  { code: "lang_ro", name: "Rumano" },
  { code: "lang_ru", name: "Ruso" },
  { code: "lang_sr", name: "Serbio" },
  { code: "lang_sk", name: "Eslovaco" },
  { code: "lang_sl", name: "Esloveno" },
  { code: "lang_es", name: "Espanol" },
  { code: "lang_sv", name: "Sueco" },
  { code: "lang_tr", name: "Turco" },
];

const COUNTRIES = [
  { code: "", name: "Cualquier pais" },
  { code: "co", name: "Colombia" },
  { code: "ar", name: "Argentina" },
  { code: "bo", name: "Bolivia" },
  { code: "br", name: "Brasil" },
  { code: "ca", name: "Canada" },
  { code: "cl", name: "Chile" },
  { code: "cr", name: "Costa Rica" },
  { code: "cu", name: "Cuba" },
  { code: "do", name: "Republica Dominicana" },
  { code: "ec", name: "Ecuador" },
  { code: "sv", name: "El Salvador" },
  { code: "es", name: "Espana" },
  { code: "us", name: "Estados Unidos" },
  { code: "fr", name: "Francia" },
  { code: "gt", name: "Guatemala" },
  { code: "hn", name: "Honduras" },
  { code: "it", name: "Italia" },
  { code: "mx", name: "Mexico" },
  { code: "ni", name: "Nicaragua" },
  { code: "pa", name: "Panama" },
  { code: "py", name: "Paraguay" },
  { code: "pe", name: "Peru" },
  { code: "pt", name: "Portugal" },
  { code: "pr", name: "Puerto Rico" },
  { code: "gb", name: "Reino Unido" },
  { code: "ru", name: "Rusia" },
  { code: "uy", name: "Uruguay" },
  { code: "ve", name: "Venezuela" },
  { code: "de", name: "Alemania" },
  { code: "cn", name: "China" },
  { code: "jp", name: "Japon" },
  { code: "kr", name: "Corea del Sur" },
  { code: "in", name: "India" },
];

const COMMON_TRANSLATE_LANGS = [
  { code: "", name: "No traducir" },
  { code: "es", name: "Espanol" },
  { code: "en", name: "Ingles" },
  { code: "fr", name: "Frances" },
  { code: "de", name: "Aleman" },
  { code: "pt", name: "Portugues" },
  { code: "it", name: "Italiano" },
  { code: "ru", name: "Ruso" },
  { code: "ar", name: "Arabe" },
  { code: "zh-CN", name: "Chino" },
  { code: "ja", name: "Japones" },
  { code: "ko", name: "Coreano" },
  { code: "nl", name: "Holandes" },
  { code: "tr", name: "Turco" },
];

export function DeepDarkWebView() {
  // Search basic
  const [query, setQuery] = React.useState("");
  const [category, setCategory] = React.useState<string>("all");

  // Advanced filters
  const [exactMatch, setExactMatch] = React.useState("");
  const [includeWords, setIncludeWords] = React.useState("");
  const [excludeWords, setExcludeWords] = React.useState("");
  const [domain, setDomain] = React.useState("");
  const [fileTypes, setFileTypes] = React.useState<string[]>([]);
  const [sortBy, setSortBy] = React.useState("relevance");
  const [timeRange, setTimeRange] = React.useState("all");
  const [customStartDate, setCustomStartDate] = React.useState("");
  const [customEndDate, setCustomEndDate] = React.useState("");
  const [language, setLanguage] = React.useState("");
  const [country, setCountry] = React.useState("");
  const [interfaceLanguage, setInterfaceLanguage] = React.useState("");
  const [translateFrom, setTranslateFrom] = React.useState("");
  const [translateTo, setTranslateTo] = React.useState("");

  // Results state
  const [loading, setLoading] = React.useState(false);
  const [results, setResults] = React.useState<SearchResult[]>([]);
  const [fullQuery, setFullQuery] = React.useState<string>("");
  const [translatedQuery, setTranslatedQuery] = React.useState<string | null>(null);
  const [summary, setSummary] = React.useState<{
    total: number;
    byCategory: Record<string, number>;
    bySeverity: { high: number; medium: number; low: number; info: number };
  } | null>(null);
  const [totalResultsGoogle, setTotalResultsGoogle] = React.useState<number>(0);
  const [nextPageStart, setNextPageStart] = React.useState<number | undefined>(undefined);
  const [currentPage, setCurrentPage] = React.useState(1);
  const [errors, setErrors] = React.useState<string[]>([]);
  const [searched, setSearched] = React.useState(false);
  const [activeCategory, setActiveCategory] = React.useState<string>("all");
  const [categoriesList, setCategoriesList] = React.useState<CategoryInfo[]>([]);
  const [showAdvanced, setShowAdvanced] = React.useState(false);

  const search = async (start: number = 1) => {
    if (!query.trim()) return;
    setLoading(true);
    setResults([]);
    setErrors([]);
    setActiveCategory("all");
    setCurrentPage(start);
    setSearched(true);

    const params = new URLSearchParams({
      q: query.trim(),
      category,
      start: String(start),
      num: "10",
    });
    if (exactMatch) params.set("exactMatch", exactMatch);
    if (includeWords) params.set("includeWords", includeWords);
    if (excludeWords) params.set("excludeWords", excludeWords);
    if (domain) params.set("domain", domain);
    if (fileTypes.length > 0) params.set("fileTypes", fileTypes.join(","));
    if (sortBy !== "relevance") params.set("sortBy", sortBy);
    if (timeRange !== "all") params.set("timeRange", timeRange);
    if (customStartDate) params.set("customStartDate", customStartDate);
    if (customEndDate) params.set("customEndDate", customEndDate);
    if (language) params.set("language", language);
    if (country) params.set("country", country);
    if (interfaceLanguage) params.set("interfaceLanguage", interfaceLanguage);
    if (translateFrom) params.set("translateFrom", translateFrom);
    if (translateTo) params.set("translateTo", translateTo);

    try {
      const r = await fetch(`/api/darkweb/search?${params.toString()}`);
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      const j = await r.json();
      setResults(j.results || []);
      setFullQuery(j.fullQuery || query);
      setTranslatedQuery(j.translatedQuery || null);
      setSummary(j.summary || null);
      setTotalResultsGoogle(j.totalResultsGoogle || 0);
      setNextPageStart(j.nextPageStart);
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

  const toggleFileType = (ft: string) => {
    setFileTypes(prev => prev.includes(ft) ? prev.filter(f => f !== ft) : [...prev, ft]);
  };

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
    doc.text(`Query: ${query}`, pw - m, y + 8, { align: "right" });
    doc.text(`Categoria: ${category}`, pw - m, y + 22, { align: "right" });
    doc.text(`Total Google: ${totalResultsGoogle.toLocaleString()}`, pw - m, y + 36, { align: "right" });
    y += 48; doc.line(m, y, pw - m, y); y += 28;
    autoTable(doc, {
      startY: y, head: [["Categoria", "Dominio", "Title", "Snippet", "URL"]],
      body: filteredResults.map(r => [
        categoriesList.find(c => c.id === r.category)?.name || r.category || "?",
        r.displayLink || "",
        r.title.slice(0, 60),
        r.snippet.slice(0, 80),
        r.url.slice(0, 60),
      ]),
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

  const hasAdvancedFilters = exactMatch || includeWords || excludeWords || domain ||
    fileTypes.length > 0 || sortBy !== "relevance" || timeRange !== "all" ||
    language || country || interfaceLanguage || translateFrom || translateTo;

  return (
    <ModuleShell
      name="Deep & Dark Web"
      description="Busca en Deep & Dark Web via Google Programmable Search Engines. 25 categorias: fraude, crimen, terrorismo, narcoticos, etc."
      icon={Skull}
      category="OSINT"
    >
      {/* SEARCH PANEL — estilo osintsear.ch con todos los filtros */}
      <Panel title="Buscar en Deep & Dark Web" className="md:col-span-2"
        action={
          <div className="flex gap-2 items-center">
            <Button size="sm" variant="outline" onClick={() => setShowAdvanced(!showAdvanced)}>
              {showAdvanced ? "Ocultar filtros" : "Mostrar filtros"}
              <ChevronDown className={`w-3 h-3 ml-1 transition ${showAdvanced ? "rotate-180" : ""}`} />
            </Button>
            <Button size="sm" onClick={() => search(1)} disabled={loading || !query.trim()}>
              {loading ? <><Loader2 className="w-3.5 h-3.5 mr-1.5 animate-spin" /> Buscando...</> : <><Search className="w-3.5 h-3.5 mr-1.5" /> Buscar</>}
            </Button>
          </div>
        }
      >
        {/* Query + categoria */}
        <div className="flex gap-2 mb-3">
          <select
            value={category}
            onChange={e => setCategory(e.target.value)}
            className="h-9 text-xs rounded border border-border bg-background px-2 min-w-[200px]"
          >
            <option value="all">Todas las categorias (general+fraud+crime+narcotics+terrorism)</option>
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
          <Input
            type="text"
            placeholder="Buscar... (ej: bancolombia phishing, isil, @username)"
            value={query}
            onChange={e => setQuery(e.target.value)}
            onKeyDown={e => e.key === "Enter" && search(1)}
            className="flex-1 font-mono text-sm"
            autoFocus
          />
        </div>

        {/* Advanced filters — collapsible */}
        {showAdvanced && (
          <div className="border-t border-border pt-3 space-y-3 bg-muted/20 -mx-4 -mb-4 px-4 pb-4 rounded-b">
            {/* Exact match */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-2">
              <div>
                <label className="text-[10px] text-muted-foreground uppercase tracking-wider mb-1 block">Frase exacta</label>
                <Input
                  type="text"
                  placeholder='Ej: "phishing scam"'
                  value={exactMatch}
                  onChange={e => setExactMatch(e.target.value)}
                  className="text-xs font-mono"
                />
              </div>
              <div>
                <label className="text-[10px] text-muted-foreground uppercase tracking-wider mb-1 block">Palabras a incluir (+)</label>
                <Input
                  type="text"
                  placeholder="ej: password, credential, leak"
                  value={includeWords}
                  onChange={e => setIncludeWords(e.target.value)}
                  className="text-xs font-mono"
                />
              </div>
              <div>
                <label className="text-[10px] text-muted-foreground uppercase tracking-wider mb-1 block">Palabras a excluir (-)</label>
                <Input
                  type="text"
                  placeholder="ej: site, login, signup"
                  value={excludeWords}
                  onChange={e => setExcludeWords(e.target.value)}
                  className="text-xs font-mono"
                />
              </div>
            </div>

            {/* Domain + Language + Country */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-2">
              <div>
                <label className="text-[10px] text-muted-foreground uppercase tracking-wider mb-1 block">Limitar a dominio</label>
                <Input
                  type="text"
                  placeholder="ej: example.com, reddit.com"
                  value={domain}
                  onChange={e => setDomain(e.target.value)}
                  className="text-xs font-mono"
                />
              </div>
              <div>
                <label className="text-[10px] text-muted-foreground uppercase tracking-wider mb-1 block">Idioma</label>
                <select value={language} onChange={e => setLanguage(e.target.value)} className="h-9 text-xs rounded border border-border bg-background px-2 w-full">
                  {LANGUAGES.map(l => <option key={l.code} value={l.code}>{l.name}</option>)}
                </select>
              </div>
              <div>
                <label className="text-[10px] text-muted-foreground uppercase tracking-wider mb-1 block">Pais</label>
                <select value={country} onChange={e => setCountry(e.target.value)} className="h-9 text-xs rounded border border-border bg-background px-2 w-full">
                  {COUNTRIES.map(c => <option key={c.code} value={c.code}>{c.name}</option>)}
                </select>
              </div>
            </div>

            {/* File types */}
            <div>
              <label className="text-[10px] text-muted-foreground uppercase tracking-wider mb-1 flex items-center gap-1">
                <FileType className="w-3 h-3" /> Tipos de archivo
              </label>
              <div className="flex flex-wrap gap-1">
                {FILE_TYPES.map(ft => (
                  <button
                    key={ft}
                    onClick={() => toggleFileType(ft)}
                    className={`px-2 py-0.5 rounded text-[10px] border transition ${
                      fileTypes.includes(ft)
                        ? "border-cyan-500 bg-cyan-500/10 text-cyan-400"
                        : "border-border bg-background text-muted-foreground hover:bg-accent"
                    }`}
                  >
                    {ft.toUpperCase()}
                  </button>
                ))}
              </div>
            </div>

            {/* Sort + Time range + Custom dates */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-2">
              <div>
                <label className="text-[10px] text-muted-foreground uppercase tracking-wider mb-1 block">Ordenar por</label>
                <select value={sortBy} onChange={e => setSortBy(e.target.value)} className="h-9 text-xs rounded border border-border bg-background px-2 w-full">
                  <option value="relevance">Relevancia</option>
                  <option value="date">Fecha</option>
                </select>
              </div>
              <div>
                <label className="text-[10px] text-muted-foreground uppercase tracking-wider mb-1 block flex items-center gap-1">
                  <Calendar className="w-3 h-3" /> Rango temporal
                </label>
                <select value={timeRange} onChange={e => setTimeRange(e.target.value)} className="h-9 text-xs rounded border border-border bg-background px-2 w-full">
                  <option value="all">Todo el tiempo</option>
                  <option value="hour">Ultima hora</option>
                  <option value="day">Ultimas 24 horas</option>
                  <option value="week">Ultima semana</option>
                  <option value="month">Ultimo mes</option>
                  <option value="year">Ultimo ano</option>
                  <option value="custom">Rango personalizado</option>
                </select>
              </div>
              {timeRange === "custom" && (
                <div className="flex gap-1">
                  <div className="flex-1">
                    <label className="text-[10px] text-muted-foreground uppercase tracking-wider mb-1 block">Inicio</label>
                    <Input type="date" value={customStartDate} onChange={e => setCustomStartDate(e.target.value)} className="text-xs" />
                  </div>
                  <div className="flex-1">
                    <label className="text-[10px] text-muted-foreground uppercase tracking-wider mb-1 block">Fin</label>
                    <Input type="date" value={customEndDate} onChange={e => setCustomEndDate(e.target.value)} className="text-xs" />
                  </div>
                </div>
              )}
            </div>

            {/* Translate */}
            <div className="grid grid-cols-2 gap-2">
              <div>
                <label className="text-[10px] text-muted-foreground uppercase tracking-wider mb-1 flex items-center gap-1">
                  <Languages className="w-3 h-3" /> Traducir query desde
                </label>
                <select value={translateFrom} onChange={e => setTranslateFrom(e.target.value)} className="h-9 text-xs rounded border border-border bg-background px-2 w-full">
                  {COMMON_TRANSLATE_LANGS.map(l => <option key={l.code} value={l.code}>{l.name}</option>)}
                </select>
              </div>
              <div>
                <label className="text-[10px] text-muted-foreground uppercase tracking-wider mb-1 block">a</label>
                <select value={translateTo} onChange={e => setTranslateTo(e.target.value)} className="h-9 text-xs rounded border border-border bg-background px-2 w-full">
                  {COMMON_TRANSLATE_LANGS.map(l => <option key={l.code} value={l.code}>{l.name}</option>)}
                </select>
              </div>
            </div>

            {/* Interface language */}
            <div>
              <label className="text-[10px] text-muted-foreground uppercase tracking-wider mb-1 block">Idioma de interfaz de Google</label>
              <select value={interfaceLanguage} onChange={e => setInterfaceLanguage(e.target.value)} className="h-9 text-xs rounded border border-border bg-background px-2">
                <option value="">Default</option>
                {LANGUAGES.filter(l => l.code).map(l => <option key={l.code} value={l.code.replace("lang_", "")}>{l.name}</option>)}
              </select>
            </div>

            {hasAdvancedFilters && (
              <div className="text-[10px] text-cyan-500 pt-2 border-t border-border">
                Filtros activos: {[exactMatch && `exact:"${exactMatch}"`, includeWords && `+${includeWords}`, excludeWords && `-${excludeWords}`, domain && `site:${domain}`, fileTypes.length > 0 && `filetype:${fileTypes.join(",")}`, sortBy !== "relevance" && `sort:${sortBy}`, timeRange !== "all" && `time:${timeRange}`, language && `lang:${language}`, country && `pais:${country}`, translateFrom && translateTo && `traducir:${translateFrom}->${translateTo}`].filter(Boolean).join(" | ")}
              </div>
            )}
          </div>
        )}
        {!showAdvanced && (
          <div className="text-[10px] text-muted-foreground">
            Usa Google Programmable Search Engines (CSE) pre-configurados para investigacion OSINT. 25 categorias. Click en "Mostrar filtros" para busqueda avanzada.
          </div>
        )}
      </Panel>

      {errors.length > 0 && (
        <div className="mb-4 p-3 rounded border border-amber-500/40 bg-amber-500/10 text-amber-400 flex flex-col gap-1">
          <div className="flex items-center gap-2"><AlertTriangle className="w-4 h-4 shrink-0" /> Avisos:</div>
          {errors.map((e, i) => <div key={i} className="text-[10px] font-mono ml-6">{e}</div>)}
        </div>
      )}

      {/* SUMMARY */}
      {summary && (
        <Panel
          title={`Resultados: ${summary.total} obtenidos · ${totalResultsGoogle.toLocaleString()} indexados por Google`}
          className="md:col-span-2"
          action={
            <div className="flex gap-2">
              {nextPageStart && (
                <Button size="sm" variant="outline" onClick={() => search(nextPageStart)} disabled={loading}>
                  Siguiente pagina
                </Button>
              )}
              <Button size="sm" variant="outline" onClick={generatePdf} disabled={filteredResults.length === 0}>
                <Printer className="w-3 h-3 mr-1.5" /> PDF
              </Button>
            </div>
          }
        >
          {/* Query final traducido y construido */}
          {(translatedQuery || (fullQuery && fullQuery !== query)) && (
            <div className="mb-3 p-2 rounded border border-cyan-500/40 bg-cyan-500/5 text-[10px] font-mono">
              {translatedQuery && <div><span className="text-muted-foreground">Query traducido:</span> <span className="text-cyan-400">{translatedQuery}</span></div>}
              {fullQuery !== query && <div className="mt-1"><span className="text-muted-foreground">Query final enviado a Google:</span> <span className="text-cyan-400">{fullQuery}</span></div>}
            </div>
          )}
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
                  <TableHead className="w-[15%]">Dominio</TableHead>
                  <TableHead className="w-[8%]">Tipo</TableHead>
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
                    <TableCell className="text-[10px] font-mono text-cyan-500 truncate" title={r.displayLink}>{r.displayLink || "?"}</TableCell>
                    <TableCell>{r.mime && <Badge variant="outline" className="text-[9px] font-mono">{r.mime}</Badge>}</TableCell>
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
              No se encontraron resultados para <strong>"{query}"</strong>.
            </p>
            <p className="text-xs text-muted-foreground">
              Prueba con otra categoria, keywords mas generales o quita filtros avanzados.
            </p>
          </div>
        </Panel>
      )}

      {/* Initial state */}
      {!searched && !loading && (
        <Panel title="Que hace este modulo?" className="md:col-span-2">
          <div className="flex flex-col items-center py-10 text-center gap-4">
            <Skull className="w-12 h-12 text-muted-foreground/50" />
            <h3 className="text-base font-semibold">Deep & Dark Web — Google Programmable Search Engines</h3>
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
              <strong>Filtros avanzados disponibles:</strong> frase exacta, palabras a incluir/excluir, dominio, tipos de archivo (PDF/DOC/XLS/...), orden (relevancia/fecha), rango temporal, idioma (36), pais (247), traduccion automatica de query (104 idiomas).
            </div>
            <p className="text-[10px] text-cyan-500 mt-2">Prueba: categoria "fraud", query "bancolombia phishing" → resultados reales de Google.</p>
          </div>
        </Panel>
      )}
    </ModuleShell>
  );
}
