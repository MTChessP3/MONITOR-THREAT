"use client";

import * as React from "react";
import {
  UserSearch, Search, Loader2, Printer, AlertTriangle, ExternalLink, Copy,
  Mail, Phone, User, AtSign, Upload, Image as ImageIcon, X, Plus,
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
    engines?: { bing: number; duckduckgo: number; google: number; yandex: number; edge: number };
    sherlock?: number;
    preciseMatch?: { wikipedia: number; ddg: number; wikidata?: number; opencorporates?: number };
  } | null>(null);
  const [sourcesUsed, setSourcesUsed] = React.useState<string[]>([]);
  const [enginesUsed, setEnginesUsed] = React.useState<string[]>([]);
  const [enginesAuto, setEnginesAuto] = React.useState<string[]>([]);
  const [enginesManual, setEnginesManual] = React.useState<string[]>([]);
  const [manualLinks, setManualLinks] = React.useState<Record<string, { google: string; yandex: string; edge: string; bing: string; duckduckgo: string }>>({});
  const [error, setError] = React.useState<string | null>(null);
  const [searched, setSearched] = React.useState(false);

  // Estado de la pestaña activa (categoria seleccionada)
  const [activeCategory, setActiveCategory] = React.useState<string>("all");

  // Estado de la busqueda por imagen
  const [imageFile, setImageFile] = React.useState<File | null>(null);
  const [imagePreview, setImagePreview] = React.useState<string | null>(null);
  const [imageResults, setImageResults] = React.useState<any>(null);
  const [imageLoading, setImageLoading] = React.useState(false);

  // Mis hallazgos manuales - URLs/links que el usuario encuentra al hacer
  // busquedas manuales en Google/Yandex/Edge y quiere integrar al informe
  const [manualFindings, setManualFindings] = React.useState<Array<{ url: string; title: string; notes: string; engine: string; category: string }>>([]);
  const [newFindingUrl, setNewFindingUrl] = React.useState("");
  const [newFindingTitle, setNewFindingTitle] = React.useState("");
  const [newFindingNotes, setNewFindingNotes] = React.useState("");
  const [newFindingEngine, setNewFindingEngine] = React.useState("Google");
  const [newFindingCategory, setNewFindingCategory] = React.useState("manual");

  const search = async () => {
    if (!query.trim()) return;
    setLoading(true); setError(null); setResults([]); setCategories([]); setDorksByCategory({});
    setSummary(null); setSourcesUsed([]); setEnginesUsed([]); setEnginesAuto([]); setEnginesManual([]);
    setManualLinks({}); setSearched(true); setActiveCategory("all");
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
      setEnginesAuto(j.enginesAuto || []);
      setEnginesManual(j.enginesManual || []);
      setManualLinks(j.manualLinks || {});
    } catch (e: any) { setError(String(e?.message || e)); }
    setLoading(false);
  };

  // Estado de detección facial (cliente)
  const [faceApiLoading, setFaceApiLoading] = React.useState(false);
  const [faceApiStatus, setFaceApiStatus] = React.useState<string>("");

  // Carga dinámica de face-api desde CDN (solo cuando se necesita)
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const _faceApiRef = React.useRef<any>(null);
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const loadFaceApi = async (): Promise<any> => {
    if (_faceApiRef.current) return _faceApiRef.current;
    setFaceApiStatus("Cargando libreria face-api...");
    // Load script dynamically
    await new Promise<void>((resolve, reject) => {
      if (document.querySelector('script[data-faceapi]')) return resolve();
      const s = document.createElement('script');
      s.src = 'https://cdn.jsdelivr.net/npm/@vladmandic/face-api@1.7.15/dist/face-api.min.js';
      s.dataset.faceapi = 'true';
      s.onload = () => resolve();
      s.onerror = () => reject(new Error('No se pudo cargar face-api desde CDN'));
      document.head.appendChild(s);
    });
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    _faceApiRef.current = (window as any).faceapi;
    setFaceApiStatus("Cargando modelos de deteccion facial...");
    await _faceApiRef.current.nets.ssdMobilenetv1.loadFromUri('/models');
    await _faceApiRef.current.nets.faceLandmark68Net.loadFromUri('/models');
    await _faceApiRef.current.nets.faceRecognitionNet.loadFromUri('/models');
    setFaceApiStatus("");
    return _faceApiRef.current;
  };

  // Detecta el rostro de la imagen y devuelve descriptor de 128 dim
  const detectFaceDescriptor = async (faceapi: any, imgEl: HTMLImageElement): Promise<Float32Array | null> => {
    try {
      const detections = await faceapi
        .detectAllFaces(imgEl, new faceapi.SsdMobilenetv1Options({ minConfidence: 0.2 }))
        .withFaceLandmarks()
        .withFaceDescriptors();
      if (!detections || detections.length === 0) return null;
      // Tomar el rostro mas grande
      let best = detections[0];
      for (const d of detections) {
        const area = d.detection.box.width * d.detection.box.height;
        if (area > best.detection.box.width * best.detection.box.height) best = d;
      }
      return best.descriptor as Float32Array;
    } catch { return null; }
  };

  const faceDistance = (a: Float32Array, b: Float32Array): number => {
    let sum = 0;
    const len = Math.min(a.length, b.length);
    for (let i = 0; i < len; i++) {
      const d = a[i] - b[i];
      sum += d * d;
    }
    return Math.sqrt(sum);
  };

  const searchImage = async () => {
    if (!imageFile) return;
    setImageLoading(true);
    setError(null);
    try {
      // PASO 1: Llamar al endpoint del servidor (sube a tmpfiles + Bing)
      const formData = new FormData();
      formData.append("image", imageFile);
      const nameParam = query ? `?name=${encodeURIComponent(query.trim())}` : "";
      setFaceApiStatus("Enviando imagen al servidor...");
      const r = await fetch(`/api/executive-osint/image-search${nameParam}`, { method: "POST", body: formData });
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      const j: any = await r.json();
      // Mostrar inmediatamente los motores de busqueda visual (con URLs ya cargadas)
      setImageResults(j);

      // PASO 2: Si hay candidatos de Bing, intentar matching facial en el cliente
      const candidates: any[] = j.bingCandidates || [];
      if (candidates.length === 0) {
        setImageLoading(false);
        setFaceApiStatus("");
        return;
      }

      setFaceApiLoading(true);
      setFaceApiStatus("Iniciando reconocimiento facial...");
      try {
        const faceapi = await loadFaceApi();

        // Detectar rostro en la imagen original subida
        setFaceApiStatus("Detectando rostro en tu imagen...");
        const origImg = new Image();
        origImg.src = imagePreview || "";
        await new Promise((res) => { origImg.onload = res; origImg.onerror = res; });
        const origDescriptor = await detectFaceDescriptor(faceapi, origImg);

        if (!origDescriptor) {
          setFaceApiStatus("No se detecto rostro en la imagen original. Mostrando candidatos de Bing sin filtro facial.");
          // Sin filtro facial: mostrar todos los candidatos como "color match"
          const matches = candidates.map((c: any) => ({
            url: c.url, imageUrl: c.imageUrl, thumbnailUrl: c.thumbnailUrl,
            title: c.title, source: "Bing Visual",
            width: c.width, height: c.height,
            distance: 0, similarity: 0,
            matchType: "color",
          }));
          setImageResults({ ...j, imageMatches: matches, matchCount: matches.length, faceDetected: false, faceMatchesCount: 0, colorMatchesCount: matches.length, candidatesCount: candidates.length });
          setImageLoading(false);
          setFaceApiLoading(false);
          setTimeout(() => setFaceApiStatus(""), 5000);
          return;
        }

        setFaceApiStatus(`Rostro detectado. Comparando con ${candidates.length} candidatos de Bing...`);
        // Para cada candidato, descargar la imagen via proxy images.weserv.nl (CORS-enabled)
        // y detectar el rostro
        const faceMatches: any[] = [];
        let processed = 0;
        const FACE_THRESHOLD = 0.62;

        // Procesa en lotes de 4 para no saturar
        for (let i = 0; i < candidates.length; i += 4) {
          const batch = candidates.slice(i, i + 4);
          const results = await Promise.all(batch.map(async (c: any): Promise<any | null> => {
            if (!c.imageUrl) return null;
            try {
              // images.weserv.nl is a free image proxy with proper CORS headers
              // Format: https://images.weserv.nl/?url=<original-url-without-protocol>
              const originalUrl = c.imageUrl.replace(/^https?:\/\//, '');
              const proxyUrl = `https://images.weserv.nl/?url=${encodeURIComponent(originalUrl)}`;
              const candImg = new Image();
              candImg.crossOrigin = "anonymous";
              candImg.src = proxyUrl;
              await new Promise((res, rej) => {
                candImg.onload = res;
                candImg.onerror = rej;
                setTimeout(rej, 10000);
              });
              const candDesc = await detectFaceDescriptor(faceapi, candImg);
              if (!candDesc) return null;
              const distance = faceDistance(origDescriptor, candDesc);
              const similarity = Math.max(0, Math.round(100 - (distance / FACE_THRESHOLD) * 100));
              if (distance <= FACE_THRESHOLD) {
                return {
                  url: c.url, imageUrl: c.imageUrl, thumbnailUrl: c.thumbnailUrl,
                  title: c.title, source: "Face Match (face-api)",
                  width: c.width, height: c.height,
                  distance, similarity, matchType: "face",
                };
              }
              return null;
            } catch { return null; }
          }));
          for (const m of results) if (m) faceMatches.push(m);
          processed += batch.length;
          setFaceApiStatus(`Comparando con ${candidates.length} candidatos... ${processed}/${candidates.length} (${faceMatches.length} coincidencias)`);
        }

        setFaceApiStatus(`Comparacion completa: ${faceMatches.length} coincidencias faciales reales de ${candidates.length} candidatos.`);
        setImageResults({
          ...j,
          imageMatches: faceMatches,
          matchCount: faceMatches.length,
          faceDetected: true,
          faceMatchesCount: faceMatches.length,
          colorMatchesCount: 0,
          candidatesCount: candidates.length,
          filteredOut: Math.max(0, candidates.length - faceMatches.length),
        });
      } catch (e: any) {
        console.error("Face recognition error:", e);
        setFaceApiStatus(`Reconocimiento facial no disponible (${String(e?.message || e)}). Mostrando candidatos sin filtro.`);
        // Mostrar candidatos sin filtro como fallback
        const matches = candidates.map((c: any) => ({
          url: c.url, imageUrl: c.imageUrl, thumbnailUrl: c.thumbnailUrl,
          title: c.title, source: "Bing Visual",
          width: c.width, height: c.height,
          distance: 0, similarity: 0,
          matchType: "color",
        }));
        setImageResults({ ...j, imageMatches: matches, matchCount: matches.length, faceDetected: false, faceMatchesCount: 0, colorMatchesCount: matches.length, candidatesCount: candidates.length });
      } finally {
        setFaceApiLoading(false);
        // Mantener el status 5s mas para que el usuario vea el resultado
        setTimeout(() => setFaceApiStatus(""), 5000);
      }
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

  // Anadir un hallazgo manual a la lista
  const addFinding = () => {
    if (!newFindingUrl.trim()) return;
    setManualFindings(prev => [...prev, {
      url: newFindingUrl.trim(),
      title: newFindingTitle.trim() || newFindingUrl.trim().slice(0, 80),
      notes: newFindingNotes.trim(),
      engine: newFindingEngine,
      category: newFindingCategory,
    }]);
    setNewFindingUrl(""); setNewFindingTitle(""); setNewFindingNotes("");
  };

  const removeFinding = (idx: number) => {
    setManualFindings(prev => prev.filter((_, i) => i !== idx));
  };

  // Convertir hallazgos manuales a SearchResult[] para incluir en informe
  const manualFindingsAsResults = (): SearchResult[] => manualFindings.map(f => ({
    category: f.category,
    source: `Manual (${f.engine})`,
    type: "manual finding",
    title: f.title,
    url: f.url,
    snippet: f.notes || `Hallazgo manual via ${f.engine}`,
    severity: "medium" as const,
    timestamp: null,
  }));

  const sevColors: Record<string, "destructive" | "default" | "secondary" | "outline"> = { high: "destructive", medium: "default", low: "secondary", info: "outline" };
  const sevText: Record<string, string> = { high: "ALTA", medium: "MEDIA", low: "BAJA", info: "INFO" };

  const generatePdf = () => {
    if (results.length === 0 && manualFindings.length === 0) return;
    const allResults = [...results, ...manualFindingsAsResults()];
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
      body: allResults.map(r => [r.category, r.source, sevText[r.severity], r.type, r.title.slice(0, 50), r.snippet.slice(0, 60), r.url.slice(0, 50)]),
      theme: "grid", margin: { left: m, right: m }, styles: { fontSize: 7, cellPadding: 3 },
      headStyles: { fillColor: [220, 38, 38], textColor: [255, 255, 255], fontSize: 7 },
    });
    for (let i = 1; i <= doc.getNumberOfPages(); i++) {
      doc.setPage(i); doc.setFontSize(8); doc.setTextColor(150, 150, 150);
      doc.text(`MONITOR-THREAT - Executive OSINT - Pagina ${i} de ${doc.getNumberOfPages()}`, pw / 2, ph - 20, { align: "center" });
    }
    doc.save(`executive-osint-${Date.now()}.pdf`);
  };

  // Genera un Informe HTML imprimible que se abre en nueva ventana con
  // estilos de impresion amigables y boton "Imprimir / Guardar como PDF"
  const generateHtmlReport = () => {
    if (results.length === 0 && manualFindings.length === 0) return;
    const sevColorsHtml: Record<string, string> = {
      high: "#dc2626", medium: "#eab308", low: "#16a34a", info: "#3b82f6",
    };
    const sevTextLocal: Record<string, string> = { high: "ALTA", medium: "MEDIA", low: "BAJA", info: "INFO" };
    const esc = (s: string) => (s || "").replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");

    // Group results by category
    const grouped: Record<string, SearchResult[]> = {};
    const allResultsForReport = [...results, ...manualFindingsAsResults()];
    for (const r of allResultsForReport) {
      if (!grouped[r.category]) grouped[r.category] = [];
      grouped[r.category].push(r);
    }

    const categoryRows = Object.entries(grouped).map(([catId, rs]) => {
      const cat = categories.find(c => c.id === catId);
      const catName = cat?.name || catId;
      const rowsHtml = rs.map(r => `
        <tr>
          <td><span class="src-badge">${esc(r.source)}</span></td>
          <td><span class="sev sev-${r.severity}">${sevTextLocal[r.severity]}</span></td>
          <td>${esc(r.type)}</td>
          <td><a href="${esc(r.url)}" target="_blank">${esc(r.title.slice(0, 80))}</a></td>
          <td class="snippet">${esc(r.snippet.slice(0, 150))}</td>
        </tr>
      `).join("");
      return `
        <section class="category-section">
          <h2>${esc(catName)} <span class="count">(${rs.length})</span></h2>
          <table>
            <thead>
              <tr>
                <th>Source</th><th>Severity</th><th>Type</th><th>Title</th><th>Snippet</th>
              </tr>
            </thead>
            <tbody>${rowsHtml}</tbody>
          </table>
        </section>
      `;
    }).join("");

    // Dorks HTML grouped by category with manual links
    const dorksHtml = categories.map(cat => {
      const catDorks = dorksByCategory[cat.id] || [];
      if (catDorks.length === 0) return "";
      const dorkRows = catDorks.map((d, i) => {
        const links = manualLinks[d];
        const linksHtml = links ? `
          <div class="engine-links">
            <a href="${esc(links.google)}" target="_blank" class="engine-link google">G</a>
            <a href="${esc(links.yandex)}" target="_blank" class="engine-link yandex">Y</a>
            <a href="${esc(links.edge)}" target="_blank" class="engine-link edge">E</a>
            <a href="${esc(links.bing)}" target="_blank" class="engine-link bing">B</a>
            <a href="${esc(links.duckduckgo)}" target="_blank" class="engine-link ddg">D</a>
          </div>
        ` : "";
        return `
          <div class="dork-row">
            <span class="dork-num">${i + 1}</span>
            <code class="dork-text">${esc(d)}</code>
            ${i === 0 ? '<span class="auto-badge">auto</span>' : ""}
            ${linksHtml}
          </div>
        `;
      }).join("");
      return `
        <details class="dorks-cat">
          <summary>${esc(cat.name)} (${catDorks.length} dorks)</summary>
          ${dorkRows}
        </details>
      `;
    }).join("");

    // Summary stats
    const summaryStats = summary ? `
      <div class="summary-stats">
        <div class="stat"><span class="num">${summary.total}</span><span class="lbl">Total</span></div>
        <div class="stat high"><span class="num">${summary.bySeverity.high}</span><span class="lbl">Alta</span></div>
        <div class="stat medium"><span class="num">${summary.bySeverity.medium}</span><span class="lbl">Media</span></div>
        <div class="stat low"><span class="num">${summary.bySeverity.low}</span><span class="lbl">Baja</span></div>
        <div class="stat info"><span class="num">${summary.bySeverity.info}</span><span class="lbl">Info</span></div>
      </div>
      ${summary.engines ? `
        <div class="engines-row">
          <div class="engine-stat"><span class="num">${summary.engines.bing}</span><span class="lbl">Bing</span></div>
          <div class="engine-stat"><span class="num">${summary.engines.duckduckgo}</span><span class="lbl">DuckDuckGo</span></div>
          <div class="engine-stat"><span class="num">${summary.engines.google}</span><span class="lbl">Google</span></div>
          <div class="engine-stat"><span class="num">${summary.engines.yandex}</span><span class="lbl">Yandex</span></div>
          <div class="engine-stat"><span class="num">${summary.engines.edge}</span><span class="lbl">Edge</span></div>
        </div>
      ` : ""}
    ` : "";

    const html = `<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8">
  <title>Executive OSINT Report - ${esc(query)}</title>
  <style>
    @page { size: A4; margin: 1.5cm; }
    * { box-sizing: border-box; }
    body { font-family: 'Helvetica Neue', Arial, sans-serif; color: #1a1a1a; margin: 0; padding: 20px; background: #fff; }
    .header { display: flex; justify-content: space-between; align-items: flex-end; border-bottom: 3px solid #dc2626; padding-bottom: 12px; margin-bottom: 20px; }
    .header h1 { font-size: 28px; margin: 0; color: #1e293b; }
    .header .brand { font-size: 14px; color: #dc2626; font-weight: bold; letter-spacing: 1px; }
    .header .meta { font-size: 11px; color: #475569; text-align: right; }
    .summary-stats { display: flex; gap: 10px; margin: 15px 0; }
    .stat { padding: 10px 15px; border: 1px solid #e2e8f0; border-radius: 4px; min-width: 80px; text-align: center; background: #f8fafc; }
    .stat .num { display: block; font-size: 22px; font-weight: bold; color: #1e293b; }
    .stat .lbl { display: block; font-size: 10px; color: #64748b; text-transform: uppercase; letter-spacing: 0.5px; }
    .stat.high { border-color: #dc2626; background: #fef2f2; }
    .stat.high .num { color: #dc2626; }
    .stat.medium { border-color: #eab308; background: #fefce8; }
    .stat.medium .num { color: #eab308; }
    .stat.low { border-color: #16a34a; background: #f0fdf4; }
    .stat.low .num { color: #16a34a; }
    .stat.info { border-color: #3b82f6; background: #eff6ff; }
    .stat.info .num { color: #3b82f6; }
    .engines-row { display: flex; gap: 8px; margin: 10px 0 20px 0; }
    .engine-stat { padding: 6px 12px; border: 1px dashed #cbd5e1; border-radius: 3px; font-size: 11px; text-align: center; }
    .engine-stat .num { font-weight: bold; color: #1e293b; }
    .engine-stat .lbl { color: #64748b; font-size: 9px; }
    .category-section { margin: 18px 0; page-break-inside: avoid; }
    .category-section h2 { font-size: 14px; color: #0f172a; border-left: 4px solid #dc2626; padding-left: 8px; margin: 0 0 8px 0; }
    .category-section h2 .count { font-size: 11px; color: #64748b; font-weight: normal; }
    table { width: 100%; border-collapse: collapse; font-size: 10px; }
    th { background: #1e293b; color: #fff; padding: 6px 8px; text-align: left; font-weight: 600; font-size: 9px; text-transform: uppercase; letter-spacing: 0.3px; }
    td { padding: 6px 8px; border: 1px solid #e2e8f0; vertical-align: top; }
    tr:nth-child(even) td { background: #f8fafc; }
    .src-badge { display: inline-block; padding: 2px 6px; border: 1px solid #cbd5e1; border-radius: 3px; font-size: 9px; font-family: monospace; background: #fff; }
    .sev { display: inline-block; padding: 2px 6px; border-radius: 3px; font-size: 9px; font-weight: bold; color: #fff; }
    .sev-high { background: #dc2626; }
    .sev-medium { background: #eab308; color: #1a1a1a; }
    .sev-low { background: #16a34a; }
    .sev-info { background: #3b82f6; }
    .snippet { font-family: monospace; font-size: 9px; color: #475569; max-width: 280px; word-break: break-word; }
    a { color: #2563eb; text-decoration: none; }
    a:hover { text-decoration: underline; }
    h2.dorks-title { font-size: 16px; margin-top: 30px; border-bottom: 2px solid #1e293b; padding-bottom: 5px; }
    .dorks-cat { margin: 10px 0; }
    .dorks-cat summary { cursor: pointer; font-weight: 600; padding: 6px; background: #f1f5f9; border-radius: 3px; }
    .dork-row { display: flex; align-items: center; gap: 8px; padding: 4px 8px; border-bottom: 1px dashed #e2e8f0; font-size: 10px; }
    .dork-num { color: #dc2626; font-weight: bold; min-width: 20px; }
    .dork-text { flex: 1; font-family: monospace; color: #475569; word-break: break-all; }
    .auto-badge { background: #8b5cf6; color: #fff; padding: 1px 5px; border-radius: 3px; font-size: 8px; }
    .engine-links { display: flex; gap: 3px; }
    .engine-link { display: inline-block; padding: 1px 6px; border-radius: 3px; font-size: 9px; font-weight: bold; color: #fff !important; }
    .engine-link.google { background: #4285f4; }
    .engine-link.yandex { background: #ff0000; }
    .engine-link.edge { background: #0078d7; }
    .engine-link.bing { background: #008373; }
    .engine-link.ddg { background: #de5833; }
    .footer { margin-top: 30px; padding-top: 10px; border-top: 1px solid #e2e8f0; text-align: center; font-size: 9px; color: #94a3b8; }
    .print-btn { position: fixed; top: 20px; right: 20px; padding: 10px 20px; background: #dc2626; color: #fff; border: none; border-radius: 4px; font-size: 14px; cursor: pointer; box-shadow: 0 2px 8px rgba(0,0,0,0.2); }
    .print-btn:hover { background: #b91c1c; }
    @media print {
      .print-btn { display: none; }
      body { padding: 0; }
      .category-section { page-break-inside: avoid; }
    }
  </style>
</head>
<body>
  <button class="print-btn" onclick="window.print()">🖨 Imprimir / Guardar como PDF</button>
  <div class="header">
    <div>
      <h1>Executive OSINT Report</h1>
      <div class="brand">MONITOR-THREAT</div>
    </div>
    <div class="meta">
      <div><strong>Target:</strong> ${esc(query)} (${queryType})</div>
      <div><strong>Fecha:</strong> ${new Date().toLocaleString()}</div>
      <div><strong>Dorks ejecutados:</strong> ${dorksExecuted} (Bing + DuckDuckGo automaticos; Google, Yandex, Edge con botones)</div>
    </div>
  </div>

  ${summaryStats}

  <h2 class="dorks-title">Resultados por categoria</h2>
  ${categoryRows}

  <h2 class="dorks-title">Dorks generados (${dorksExecuted} ejecutados automaticamente)</h2>
  <div style="font-size: 10px; color: #64748b; margin-bottom: 10px;">
    Los dorks marcados como "auto" se ejecutaron automaticamente en Bing + DuckDuckGo.
    Para ejecutar los demas en Google/Yandex/Edge, haz clic en los botones <span class="engine-link google">G</span> <span class="engine-link yandex">Y</span> <span class="engine-link edge">E</span> <span class="engine-link bing">B</span> <span class="engine-link ddg">D</span>.
  </div>
  ${dorksHtml}

  <div class="footer">
    MONITOR-THREAT · Executive OSINT · Generado ${new Date().toISOString()}
  </div>
</body>
</html>`;

    // Open in new window
    const w = window.open("", "_blank");
    if (w) {
      w.document.write(html);
      w.document.close();
    } else {
      // Fallback: download HTML file
      const blob = new Blob([html], { type: "text/html" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `executive-osint-${Date.now()}.html`;
      a.click();
      URL.revokeObjectURL(url);
    }
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
          20 categorias de dorks ejecutadas en <span className="text-emerald-400">Bing</span> + <span className="text-orange-400">DuckDuckGo</span> (auto) · <span className="text-blue-400">Google</span>, <span className="text-red-400">Yandex</span>, <span className="text-cyan-400">Edge</span> (con botones al lado de cada dork) · APIs: GitHub, Gravatar, HIBP, VirusTotal, Wikipedia (EN+ES), DuckDuckGo IA, Hunter, Wikidata, OpenCorporates, Sherlock (17 redes). {dorksExecuted > 0 && <span className="text-purple-400">| {dorksExecuted} dorks ejecutados</span>}
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
                    {imageLoading || faceApiLoading ? <><Loader2 className="w-3.5 h-3.5 mr-1.5 animate-spin" /> Analizando...</> : <><ImageIcon className="w-3.5 h-3.5 mr-1.5" /> Buscar imagen</>}
                  </Button>
                  <Button size="sm" variant="outline" onClick={() => { clearImage(); setFaceApiStatus(""); }}><X className="w-3.5 h-3.5" /></Button>
                </>
              )}
              <span className="text-[10px] text-muted-foreground">{imageFile?.name}</span>
            </div>
            {faceApiStatus && (
              <div className="mt-2 p-2 rounded border border-cyan-500/40 bg-cyan-500/5 text-[11px] text-cyan-300 flex items-center gap-2">
                <Loader2 className="w-3 h-3 animate-spin shrink-0" />
                <span>{faceApiStatus}</span>
              </div>
            )}
          </div>
          {imagePreview && (
            <div className="relative">
              <img src={imagePreview} alt="preview" className="w-32 h-32 object-cover rounded border border-border" />
              <button onClick={() => { clearImage(); setFaceApiStatus(""); }} className="absolute -top-2 -right-2 bg-red-500 text-white rounded-full w-5 h-5 flex items-center justify-center text-[10px]"><X className="w-3 h-3" /></button>
            </div>
          )}
        </div>

        {imageResults && (
          <div className="mt-4 border-t border-border pt-3">
            {/* URL publica subida + estado de la subida */}
            {imageResults.publicImageUrl && (
              <div className="mb-3 p-2 rounded border border-emerald-500/40 bg-emerald-500/5 text-[11px]">
                <div className="flex items-center gap-1.5 text-emerald-400 mb-1">
                  <ImageIcon className="w-3 h-3" /> Imagen subida a hosting publico
                </div>
                <code className="text-[10px] text-muted-foreground break-all">{imageResults.publicImageUrl}</code>
              </div>
            )}
            {imageResults.uploadError && !imageResults.publicImageUrl && (
              <div className="mb-3 p-2 rounded border border-amber-500/40 bg-amber-500/5 text-[11px] text-amber-300">
                Error subiendo a hosting publico: {imageResults.uploadError}. Los motores aparecen en modo subida manual.
              </div>
            )}

            {/* Candidatos de Bing — mostrar inmediatamente TODOS como preview mientras se hace face match */}
            {imageResults.bingCandidates?.length > 0 && !imageResults.imageMatches && (
              <div className="mb-3 p-2 rounded border border-blue-500/40 bg-blue-500/5">
                <div className="text-xs font-semibold mb-2 flex items-center gap-1.5 text-blue-400">
                  <ImageIcon className="w-3.5 h-3.5" /> Candidatos de Bing Visual Search ({imageResults.bingCandidates.length})
                </div>
                <div className="text-[10px] text-muted-foreground mb-2">
                  Bing encontro estos resultados. El reconocimiento facial esta comparando cada uno con tu imagen original. Si face-api no detecta rostro en alguno, se descarta automaticamente.
                </div>
                <div className="grid grid-cols-2 md:grid-cols-4 gap-2 max-h-72 overflow-y-auto">
                  {imageResults.bingCandidates.map((c: any, i: number) => (
                    <a key={i} href={c.url} target="_blank" rel="noreferrer" className="block p-1.5 rounded border border-border bg-muted/20 hover:bg-accent transition">
                      {c.thumbnailUrl && (
                        // eslint-disable-next-line @next/next/no-img-element
                        <img src={c.thumbnailUrl} alt={c.title} className="w-full h-20 object-cover rounded mb-1" />
                      )}
                      <div className="text-[10px] font-semibold truncate" title={c.title}>{c.title}</div>
                      <div className="text-[9px] text-cyan-500 truncate" title={c.imageUrl}>{c.imageUrl}</div>
                    </a>
                  ))}
                </div>
              </div>
            )}

            {/* Coincidencias reales: face match (prioridad) + color match (fallback) */}
            {imageResults.imageMatches?.length > 0 && (
              <div className="mb-3 p-2 rounded border border-emerald-500/40 bg-emerald-500/5">
                <div className="text-xs font-semibold mb-2 flex items-center gap-1.5 text-emerald-400">
                  <ImageIcon className="w-3.5 h-3.5" /> Coincidencias verificadas ({imageResults.imageMatches.length} de {imageResults.candidatesCount || imageResults.imageMatches.length} candidatos)
                  {imageResults.faceDetected && (
                    <Badge variant="destructive" className="text-[9px] ml-2">Rostro detectado</Badge>
                  )}
                </div>
                <div className="text-[10px] text-muted-foreground mb-2">
                  {imageResults.faceDetected
                    ? `Rostro detectado en la imagen original. Cada candidato fue escaneado con face-api.js (SSD MobileNet) y comparado por descriptor facial de 128 dim (distancia euclidiana). El badge de cada coincidencia indica el % de similitud facial. ${imageResults.faceMatchesCount || 0} coincidencias de rostro + ${imageResults.colorMatchesCount || 0} por paleta de color.`
                    : `No se detecto rostro en la imagen original (o face-api no pudo cargar). Mostrando candidatos sin filtro facial. ${imageResults.colorMatchesCount || 0} coincidencias.`
                  }
                  {(imageResults.filteredOut || 0) > 0 && <span className="text-amber-500 ml-2">{imageResults.filteredOut} candidatos descartados por no coincidir.</span>}
                </div>
                <div className="grid grid-cols-2 md:grid-cols-4 gap-2 max-h-72 overflow-y-auto">
                  {imageResults.imageMatches.map((m: any, i: number) => (
                    <a key={i} href={m.url} target="_blank" rel="noreferrer" className="block p-1.5 rounded border border-border bg-muted/20 hover:bg-accent transition">
                      {m.thumbnailUrl && (
                        // eslint-disable-next-line @next/next/no-img-element
                        <img src={m.thumbnailUrl} alt={m.title} className="w-full h-20 object-cover rounded mb-1" />
                      )}
                      <div className="flex items-center justify-between mb-0.5">
                        <Badge variant={m.similarity >= 90 ? "destructive" : m.similarity >= 70 ? "default" : "secondary"} className="text-[9px] font-mono">
                          {m.similarity}% {m.matchType === "face" ? "cara" : "color"}
                        </Badge>
                        <span className="text-[9px] text-muted-foreground">d={m.distance.toFixed(m.matchType === "face" ? 2 : 3)}</span>
                      </div>
                      <div className="text-[10px] font-semibold truncate" title={m.title}>{m.title}</div>
                      <div className="text-[9px] text-cyan-500 truncate" title={m.imageUrl}>{m.imageUrl}</div>
                    </a>
                  ))}
                </div>
              </div>
            )}

            <div className="text-xs font-semibold mb-2 flex items-center gap-1.5"><ImageIcon className="w-3.5 h-3.5" /> Motores de busqueda visual</div>
            <div className="text-[10px] text-muted-foreground mb-2">
              {imageResults.publicImageUrl
                ? "Imagen ya cargada — haz clic en cualquier motor para ejecutar la busqueda automaticamente:"
                : "Sube la imagen manualmente en cada motor:"}
            </div>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
              {imageResults.engines?.map((eng: any, i: number) => {
                const sevColor = eng.severity === "high" ? "border-red-500/40 bg-red-500/5" : eng.severity === "medium" ? "border-yellow-500/40 bg-yellow-500/5" : "border-blue-500/40 bg-blue-500/5";
                return (
                  <a key={i} href={eng.url} target="_blank" rel="noreferrer" className={`block p-2 rounded border ${sevColor} hover:bg-accent transition`}>
                    <div className="flex items-center justify-between mb-1">
                      <span className="text-xs font-semibold">{eng.source}</span>
                      <div className="flex gap-1 items-center">
                        {eng.autoOpen && imageResults.publicImageUrl && (
                          <Badge variant="outline" className="text-[8px] font-mono text-emerald-400 border-emerald-500/40">auto</Badge>
                        )}
                        <Badge variant={sevColors[eng.severity] || "outline"} className="text-[9px]">{sevText[eng.severity]}</Badge>
                      </div>
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

      {/* MIS HALLAZGOS MANUALES - Panel para agregar URLs encontradas en Google/Yandex/Edge */}
      <Panel title={`Mis hallazgos manuales (${manualFindings.length})`} className="md:col-span-2">
        <div className="text-[10px] text-muted-foreground mb-3">
          Cuando hagas busquedas manuales en Google/Yandex/Edge (clic en los botones <span className="bg-blue-500 text-white px-1 rounded">G</span> <span className="bg-red-500 text-white px-1 rounded">Y</span> <span className="bg-cyan-500 text-white px-1 rounded">E</span> al lado de cada dork) y encuentres URLs relevantes que no aparecen en los resultados automaticos, agregalas aqui para que se incluyan en el informe HTML/PDF.
        </div>
        <div className="grid grid-cols-1 md:grid-cols-12 gap-2 mb-2">
          <Input type="url" placeholder="URL encontrada (https://...)" value={newFindingUrl} onChange={e => setNewFindingUrl(e.target.value)} className="md:col-span-4 font-mono text-xs" />
          <Input type="text" placeholder="Titulo (opcional)" value={newFindingTitle} onChange={e => setNewFindingTitle(e.target.value)} className="md:col-span-3 text-xs" />
          <Input type="text" placeholder="Notas (opcional)" value={newFindingNotes} onChange={e => setNewFindingNotes(e.target.value)} className="md:col-span-3 text-xs" />
          <select value={newFindingEngine} onChange={e => setNewFindingEngine(e.target.value)} className="md:col-span-1 h-9 text-xs rounded border border-border bg-background px-1">
            <option>Google</option>
            <option>Yandex</option>
            <option>Edge</option>
            <option>Bing</option>
            <option>DuckDuckGo</option>
            <option>Manual</option>
          </select>
          <select value={newFindingCategory} onChange={e => setNewFindingCategory(e.target.value)} className="md:col-span-1 h-9 text-xs rounded border border-border bg-background px-1">
            {categories.length > 0 ? (
              <>
                {categories.map(c => <option key={c.id} value={c.id}>{c.name.split(" ")[0]}</option>)}
              </>
            ) : (
              <>
                <option value="manual">Manual</option>
                <option value="social-media">Social</option>
                <option value="leaks-pastes">Leaks</option>
                <option value="breaches">Breaches</option>
                <option value="darkweb">Dark Web</option>
              </>
            )}
          </select>
        </div>
        <div className="flex justify-end mb-3">
          <Button size="sm" onClick={addFinding} disabled={!newFindingUrl.trim()}>
            <Plus className="w-3.5 h-3.5 mr-1.5" /> Agregar hallazgo
          </Button>
        </div>
        {manualFindings.length > 0 && (
          <div className="border-t border-border pt-2 max-h-48 overflow-y-auto space-y-1">
            {manualFindings.map((f, i) => (
              <div key={i} className="text-[11px] flex items-center gap-2 p-1.5 rounded bg-muted/30 border border-border">
                <Badge variant="outline" className="text-[9px] font-mono shrink-0">{f.engine}</Badge>
                <Badge variant="outline" className="text-[9px] font-mono shrink-0 text-cyan-400">{f.category}</Badge>
                <div className="flex-1 min-w-0">
                  <a href={f.url} target="_blank" rel="noreferrer" className="text-cyan-500 hover:underline inline-flex items-center gap-1">
                    <span className="truncate">{f.title}</span>
                    <ExternalLink className="w-2.5 h-2.5 shrink-0" />
                  </a>
                  {f.notes && <div className="text-[10px] text-muted-foreground mt-0.5">{f.notes}</div>}
                </div>
                <button onClick={() => removeFinding(i)} className="text-muted-foreground hover:text-red-500 shrink-0"><X className="w-3 h-3" /></button>
              </div>
            ))}
          </div>
        )}
      </Panel>

      {/* SUMMARY */}
      {summary && (
        <Panel title={`Resultados: ${summary.total} encontrados en ${Object.keys(summary.byCategory || {}).length} categorias`} className="md:col-span-2"
          action={(
            <div className="flex gap-1.5">
              <Button size="sm" variant="outline" onClick={generateHtmlReport} disabled={results.length === 0 && manualFindings.length === 0}><FileText className="w-3 h-3 mr-1.5" /> Informe HTML</Button>
              <Button size="sm" variant="outline" onClick={generatePdf} disabled={results.length === 0 && manualFindings.length === 0}><Printer className="w-3 h-3 mr-1.5" /> PDF</Button>
            </div>
          )}
        >
          <div className="grid grid-cols-2 md:grid-cols-5 gap-2 mb-3">
            <div className="rounded p-2 border border-cyan-500/40 bg-cyan-500/5"><div className="text-lg font-bold font-mono text-cyan-400">{summary.total}</div><div className="text-[10px]">Total</div></div>
            <div className="rounded p-2 border border-red-500/40 bg-red-500/5"><div className="text-lg font-bold font-mono text-red-400">{summary.bySeverity.high}</div><div className="text-[10px]">Alta</div></div>
            <div className="rounded p-2 border border-yellow-500/40 bg-yellow-500/5"><div className="text-lg font-bold font-mono text-yellow-400">{summary.bySeverity.medium}</div><div className="text-[10px]">Media</div></div>
            <div className="rounded p-2 border border-green-500/40 bg-green-500/5"><div className="text-lg font-bold font-mono text-green-400">{summary.bySeverity.low}</div><div className="text-[10px]">Baja</div></div>
            <div className="rounded p-2 border border-blue-500/40 bg-blue-500/5"><div className="text-lg font-bold font-mono text-blue-400">{summary.bySeverity.info}</div><div className="text-[10px]">Info</div></div>
          </div>
          {summary.engines && (
            <>
              <div className="text-[9px] text-muted-foreground uppercase tracking-wider mb-1.5 mt-2">Motores de busqueda:</div>
              <div className="grid grid-cols-2 md:grid-cols-5 gap-2 mb-2">
                {summary.engines.bing !== undefined && <div className="rounded p-2 border border-emerald-500/40 bg-emerald-500/5"><div className="text-lg font-bold font-mono text-emerald-400">{summary.engines.bing}</div><div className="text-[10px]">Bing (auto)</div></div>}
                {summary.engines.duckduckgo !== undefined && <div className="rounded p-2 border border-orange-500/40 bg-orange-500/5"><div className="text-lg font-bold font-mono text-orange-400">{summary.engines.duckduckgo}</div><div className="text-[10px]">DuckDuckGo (auto)</div></div>}
                {summary.engines.google !== undefined && <div className="rounded p-2 border border-blue-500/40 bg-blue-500/5"><div className="text-lg font-bold font-mono text-blue-400">{summary.engines.google}</div><div className="text-[10px]">Google</div></div>}
                {summary.engines.yandex !== undefined && <div className="rounded p-2 border border-red-500/40 bg-red-500/5"><div className="text-lg font-bold font-mono text-red-400">{summary.engines.yandex}</div><div className="text-[10px]">Yandex</div></div>}
                {summary.engines.edge !== undefined && <div className="rounded p-2 border border-cyan-500/40 bg-cyan-500/5"><div className="text-lg font-bold font-mono text-cyan-400">{summary.engines.edge}</div><div className="text-[10px]">Edge</div></div>}
              </div>
            </>
          )}
          {summary.preciseMatch && (
            <div className="flex gap-2 mb-2 mt-2">
              <div className="rounded p-2 border border-cyan-500/40 bg-cyan-500/5 flex-1"><div className="text-lg font-bold font-mono text-cyan-400">{summary.preciseMatch.wikipedia + summary.preciseMatch.ddg + (summary.preciseMatch.wikidata || 0) + (summary.preciseMatch.opencorporates || 0)}</div><div className="text-[10px]">Wikipedia+DDG IA+Wikidata+OpenCorp</div></div>
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
        <Panel title={`Dorks generados — ${dorksExecuted} ejecutados en Bing + DuckDuckGo · Google/Yandex/Edge`} className="md:col-span-2">
          <div className="text-[10px] text-muted-foreground mb-2">
            1 dork por categoria se ejecuta automaticamente en <span className="text-emerald-400">Bing</span> + <span className="text-orange-400">DuckDuckGo</span>.
            Para ejecutar en <span className="text-blue-400">Google</span>, <span className="text-red-400">Yandex</span> o <span className="text-cyan-400">Edge</span>, haz clic en los botones <span className="bg-blue-500 text-white px-1 rounded">G</span> <span className="bg-red-500 text-white px-1 rounded">Y</span> <span className="bg-cyan-500 text-white px-1 rounded">E</span> <span className="bg-emerald-500 text-white px-1 rounded">B</span> <span className="bg-orange-500 text-white px-1 rounded">D</span> al lado de cada dork:
          </div>
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
                  {catDorks.map((d, i) => {
                    const links = manualLinks[d];
                    return (
                      <div key={i} className="text-[10px] font-mono text-muted-foreground flex items-center gap-1 ml-3 flex-wrap">
                        <span className="text-purple-400">{i + 1}.</span>
                        {i === 0 && <Badge variant="outline" className="text-[8px] text-purple-400 border-purple-500/40">auto</Badge>}
                        <code className="flex-1 truncate">{d}</code>
                        {links && (
                          <div className="flex gap-0.5 shrink-0">
                            <a href={links.google} target="_blank" rel="noreferrer" title="Ejecutar en Google" className="bg-blue-500 hover:bg-blue-600 text-white px-1 rounded text-[8px] font-bold">G</a>
                            <a href={links.yandex} target="_blank" rel="noreferrer" title="Ejecutar en Yandex" className="bg-red-500 hover:bg-red-600 text-white px-1 rounded text-[8px] font-bold">Y</a>
                            <a href={links.edge} target="_blank" rel="noreferrer" title="Ejecutar en Edge (Bing)" className="bg-cyan-500 hover:bg-cyan-600 text-white px-1 rounded text-[8px] font-bold">E</a>
                            <a href={links.bing} target="_blank" rel="noreferrer" title="Ejecutar en Bing" className="bg-emerald-500 hover:bg-emerald-600 text-white px-1 rounded text-[8px] font-bold">B</a>
                            <a href={links.duckduckgo} target="_blank" rel="noreferrer" title="Ejecutar en DuckDuckGo" className="bg-orange-500 hover:bg-orange-600 text-white px-1 rounded text-[8px] font-bold">D</a>
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
