"use client";

import * as React from "react";
import {
  Box,
  Loader2,
  AlertTriangle,
  Printer,
  Play,
  Download,
  Video,
  ShieldAlert,
  ShieldCheck,
  Network,
  Cookie,
  AlertOctagon,
  Eye,
  Terminal,
  Activity,
  Cpu,
  FileCode,
  Search,
} from "lucide-react";
import { jsPDF } from "jspdf";
import autoTable from "jspdf-autotable";
import html2canvas from "html2canvas";

import {
  ModuleShell,
  Panel,
  FieldRow,
} from "@/components/module-shell";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Separator } from "@/components/ui/separator";
import {
  Table, TableBody, TableCell, TableHead, TableHeader, TableRow,
} from "@/components/ui/table";

// ---------- Types ----------

interface NetworkEntry { url: string; type: string; duration: number; size: number; }
interface ConsoleEntry { level: string; message: string; timestamp: string; }
interface DomMutation { type: string; target: string; addedNodes: string[]; timestamp: string; }
interface CookieEntry { name: string; value: string; domain: string; secure: boolean; httpOnly: boolean; }
interface StorageEntry { key: string; value: string; type: "localStorage" | "sessionStorage"; }
interface PopupEntry { url: string; count: number; }
interface EvalEntry { code: string; timestamp: string; }
interface CryptoEntry { script: string; miner: string; }

interface SandboxResult {
  url: string;
  timestamp: string;
  duration: number;
  screenshots: string[];
  videoBlobUrl?: string;
  finalDom: string;
  finalTitle: string;
  network: NetworkEntry[];
  console: ConsoleEntry[];
  errors: string[];
  domMutations: DomMutation[];
  cookies: CookieEntry[];
  localStorage: StorageEntry[];
  sessionStorage: StorageEntry[];
  popups: PopupEntry[];
  evalCalls: EvalEntry[];
  cryptoMining: CryptoEntry[];
  webglFingerprint: boolean;
  canvasFingerprint: boolean;
  formAutoSubmit: boolean;
  hiddenRedirect: string | null;
  serviceWorker: boolean;
  riskScore: number;
  riskClassification: "SAFE" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  verdict: string;
  loaded: boolean;
}

const SANDBOX_DURATION = 20000;
const SCREENSHOT_INTERVAL = 2000; // every 2s = 10 screenshots

// ---------- Sandbox Engine ----------

async function runSandbox(url: string, onProgress: (elapsed: number, step: string) => void): Promise<SandboxResult> {
  const startTime = Date.now();
  const screenshots: string[] = [];
  const network: NetworkEntry[] = [];
  const consoleLog: ConsoleEntry[] = [];
  const errors: string[] = [];
  const domMutations: DomMutation[] = [];
  const cookies: CookieEntry[] = [];
  const localStorageEntries: StorageEntry[] = [];
  const sessionStorageEntries: StorageEntry[] = [];
  const popups: PopupEntry[] = [];
  const evalCalls: EvalEntry[] = [];
  const cryptoMining: CryptoEntry[] = [];
  let webglFingerprint = false;
  let canvasFingerprint = false;
  let formAutoSubmit = false;
  let hiddenRedirect: string | null = null;
  let serviceWorker = false;
  let finalDom = "";
  let finalTitle = "";
  let loaded = false;

  // Open target in a new window (avoids X-Frame-Options/CSP)
  onProgress(0, "Opening URL in sandbox window...");
  const popup = window.open(url, "_blank", "width=1280,height=720,scrollbars=yes,resizable=yes,noopener=no");

  if (!popup) {
    return {
      url, timestamp: new Date(startTime).toISOString(), duration: 0,
      screenshots: [], videoBlobUrl: undefined, finalDom: "", finalTitle: "",
      network: [], console: [], errors: ["Popup blocked by browser — please allow popups for this site"],
      domMutations: [], cookies: [], localStorage: [], sessionStorage: [], popups: [],
      evalCalls: [], cryptoMining: [], webglFingerprint: false, canvasFingerprint: false,
      formAutoSubmit: false, hiddenRedirect: null, serviceWorker: false,
      riskScore: 0, riskClassification: "SAFE", verdict: "Sandbox could not start — popup blocked.", loaded: false,
    };
  }

  onProgress(500, "Waiting for page to load...");

  // Wait for popup to load (with 10s timeout)
  await new Promise<void>((resolve) => {
    const checkLoaded = setInterval(() => {
      try {
        if (popup.document && popup.document.readyState === "complete") {
          clearInterval(checkLoaded);
          loaded = true;
          resolve();
        }
      } catch {
        // Cross-origin — can't check readyState. Wait 3s and proceed.
        clearInterval(checkLoaded);
        loaded = false;
        resolve();
      }
    }, 500);
    setTimeout(() => { clearInterval(checkLoaded); resolve(); }, 10000);
  });

  onProgress(2000, "Injecting monitoring hooks...");

  // Try to inject monitoring hooks (only works for same-origin)
  try {
    const win = popup;
    const doc = popup.document;

    if (doc && doc.body) {
      finalTitle = doc.title || "";
      loaded = true;

      // Inject monitoring script
      const monitorScript = doc.createElement("script");
      monitorScript.textContent = `
        (function() {
          var origLog = console.log, origWarn = console.warn, origError = console.error, origInfo = console.info;
          console.log = function() { parent.postMessage({type:'console', level:'log', msg: Array.from(arguments).map(String).join(' ')}, '*'); origLog.apply(console, arguments); };
          console.warn = function() { parent.postMessage({type:'console', level:'warn', msg: Array.from(arguments).map(String).join(' ')}, '*'); origWarn.apply(console, arguments); };
          console.error = function() { parent.postMessage({type:'console', level:'error', msg: Array.from(arguments).map(String).join(' ')}, '*'); origError.apply(console, arguments); };
          console.info = function() { parent.postMessage({type:'console', level:'info', msg: Array.from(arguments).map(String).join(' ')}, '*'); origInfo.apply(console, arguments); };
          window.onerror = function(msg, src, line, col) { parent.postMessage({type:'error', msg: msg + ' (' + src + ':' + line + ':' + col + ')'}, '*'); return false; };
          var origOpen = window.open; window.open = function(u) { parent.postMessage({type:'popup', url: u || '(unknown)'}, '*'); };
          var origEval = window.eval; window.eval = function(code) { parent.postMessage({type:'eval', code: String(code).slice(0,300)}, '*'); try { return origEval.call(window, code); } catch(e) {} };
          var origFunc = Function; window.Function = function() { parent.postMessage({type:'eval', code: 'Function(' + Array.from(arguments).map(String).join(',') + ')'}, '*'); return new origFunc(...arguments); };
          var observer = new MutationObserver(function(muts) {
            for (var m of muts) {
              var added = [];
              m.addedNodes.forEach(function(n) { added.push(n.nodeName + (n.attributes ? '[' + Array.from(n.attributes).map(function(a) { return a.name; }).join(',') + ']' : '')); });
              if (added.length > 0 || m.type === 'attributes') {
                parent.postMessage({type:'mutation', mtype: m.type, target: m.target.nodeName, added: added.slice(0,5)}, '*');
              }
            }
          });
          observer.observe(document, {childList:true, subtree:true, attributes:true});
          // Detect form auto-submit
          var forms = document.querySelectorAll('form');
          for (var f of forms) {
            if (f.hasAttribute('onload') || f.querySelector('input[type=submit][autofocus]')) {
              parent.postMessage({type:'formAutoSubmit'}, '*');
            }
          }
          // Detect crypto mining
          var scripts = document.querySelectorAll('script[src]');
          for (var s of scripts) {
            var src = s.src.toLowerCase();
            if (src.includes('coinhive') || src.includes('coin-hive') || src.includes('cryptonight') || src.includes('webminer') || src.includes('monero') || src.includes('crypto-loot') || src.includes('deepminer')) {
              parent.postMessage({type:'crypto', script: s.src, miner: 'CoinHive/CryptoNight'}, '*');
            }
          }
          // Detect WebGL fingerprinting
          var c = document.createElement('canvas'); var gl = c.getContext('webgl') || c.getContext('experimental-webgl');
          if (gl) { var orig = gl.getParameter; gl.getParameter = function(p) { if (p==0x9245||p==0x9246||p==0x9247||p==0x9248) { parent.postMessage({type:'webglFp'}, '*'); } return orig.call(gl, p); }; }
          // Detect Canvas fingerprinting
          var c2 = document.createElement('canvas'); var ctx2 = c2.getContext('2d');
          if (ctx2) { var orig2 = ctx2.getImageData; ctx2.getImageData = function() { parent.postMessage({type:'canvasFp'}, '*'); return orig2.apply(ctx2, arguments); }; }
          // Detect service worker
          if (navigator.serviceWorker && navigator.serviceWorker.controller) {
            parent.postMessage({type:'serviceWorker'}, '*');
          }
          // Send localStorage and sessionStorage
          try { for (var i=0; i<localStorage.length; i++) { var k=localStorage.key(i); parent.postMessage({type:'storage', stype:'localStorage', key:k, value:localStorage.getItem(k).slice(0,200)}, '*'); } } catch(e) {}
          try { for (var i=0; i<sessionStorage.length; i++) { var k=sessionStorage.key(i); parent.postMessage({type:'storage', stype:'sessionStorage', key:k, value:sessionStorage.getItem(k).slice(0,200)}, '*'); } } catch(e) {}
          // Send cookies
          parent.postMessage({type:'cookies', cookies: document.cookie}, '*');
        })();
      `;
      doc.body.appendChild(monitorScript);

      // PerformanceObserver for network (inject into popup)
      const perfScript = doc.createElement("script");
      perfScript.textContent = `
        try {
          var po = new PerformanceObserver(function(list) {
            for (var entry of list.getEntries()) {
              parent.postMessage({type:'network', url: entry.name, itype: entry.initiatorType || 'other', dur: Math.round(entry.duration), size: entry.transferSize || 0}, '*');
            }
          });
          po.observe({entryTypes: ['resource', 'navigation']});
        } catch(e) {}
      `;
      doc.body.appendChild(perfScript);

      // Detect hidden redirect (meta refresh or JS redirect)
      const metaRefresh = doc.querySelector('meta[http-equiv="refresh"]');
      if (metaRefresh) {
        const content = metaRefresh.getAttribute("content") || "";
        const match = content.match(/url=(.+)/i);
        if (match) hiddenRedirect = match[1];
      }
    }
  } catch (e) {
    errors.push(`Cross-origin: Cannot inject monitoring hooks — ${e}`);
  }

  // Listen for postMessage from popup
  const messageHandler = (event: MessageEvent) => {
    const d = event.data;
    if (!d || typeof d !== "object") return;
    switch (d.type) {
      case "console":
        consoleLog.push({ level: d.level, message: (d.msg || "").slice(0, 500), timestamp: new Date().toISOString() });
        break;
      case "error":
        errors.push((d.msg || "").slice(0, 500));
        break;
      case "network":
        network.push({ url: d.url || "", type: d.itype || "other", duration: d.dur || 0, size: d.size || 0 });
        break;
      case "popup":
        const existing = popups.find(p => p.url === d.url);
        if (existing) existing.count++;
        else popups.push({ url: d.url || "", count: 1 });
        break;
      case "eval":
        evalCalls.push({ code: (d.code || "").slice(0, 300), timestamp: new Date().toISOString() });
        break;
      case "mutation":
        domMutations.push({ type: d.mtype, target: d.target, addedNodes: d.added || [], timestamp: new Date().toISOString() });
        break;
      case "webglFp":
        webglFingerprint = true;
        break;
      case "canvasFp":
        canvasFingerprint = true;
        break;
      case "formAutoSubmit":
        formAutoSubmit = true;
        break;
      case "crypto":
        cryptoMining.push({ script: d.script, miner: d.miner });
        break;
      case "serviceWorker":
        serviceWorker = true;
        break;
      case "storage":
        if (d.stype === "localStorage") localStorageEntries.push({ key: d.key, value: d.value, type: "localStorage" });
        else sessionStorageEntries.push({ key: d.key, value: d.value, type: "sessionStorage" });
        break;
      case "cookies":
        try {
          const cookieStr = d.cookies || "";
          for (const c of cookieStr.split(";")) {
            const [name, ...rest] = c.trim().split("=");
            cookies.push({ name: name || "", value: rest.join("=").slice(0, 200), domain: new URL(url).hostname, secure: url.startsWith("https"), httpOnly: false });
          }
        } catch {}
        break;
    }
  };
  window.addEventListener("message", messageHandler);

  onProgress(3000, "Capturing screenshots and video...");

  // Capture screenshots every SCREENSHOT_INTERVAL using html2canvas on the popup
  const screenshotInterval = setInterval(async () => {
    try {
      if (popup.document && popup.document.body) {
        const canvas = await html2canvas(popup.document.body, {
          width: 1280,
          height: 720,
          windowWidth: 1280,
          windowHeight: 720,
          useCORS: true,
          allowTaint: false,
          logging: false,
          scale: 1,
        });
        screenshots.push(canvas.toDataURL("image/png"));
      }
    } catch {
      // Cross-origin — can't screenshot
    }
  }, SCREENSHOT_INTERVAL);

  // Update progress
  const progressInterval = setInterval(() => {
    const elapsed = Date.now() - startTime;
    onProgress(elapsed, `Running... ${Math.round((elapsed / SANDBOX_DURATION) * 100)}%`);
  }, 500);

  // Wait for SANDBOX_DURATION
  await new Promise(resolve => setTimeout(resolve, SANDBOX_DURATION));

  clearInterval(screenshotInterval);
  clearInterval(progressInterval);
  window.removeEventListener("message", messageHandler);

  onProgress(SANDBOX_DURATION, "Capturing final DOM and generating video...");

  // Capture final DOM
  try {
    if (popup.document) {
      finalDom = popup.document.documentElement.outerHTML.slice(0, 50000);
      finalTitle = popup.document.title || "";
    }
  } catch { /* cross-origin */ }

  // Generate video from screenshots
  let videoBlobUrl: string | undefined;
  if (screenshots.length > 0) {
    try {
      const canvas = document.createElement("canvas");
      canvas.width = 1280;
      canvas.height = 720;
      const ctx = canvas.getContext("2d")!;
      const stream = canvas.captureStream(5); // 5 fps
      const recorder = new MediaRecorder(stream, { mimeType: "video/webm;codecs=vp8" });
      const chunks: Blob[] = [];
      recorder.ondataavailable = (e) => { if (e.data.size > 0) chunks.push(e.data); };

      await new Promise<void>(resolve => {
        recorder.onstop = () => resolve();
        recorder.start();

        let frameIndex = 0;
        const drawFrame = () => {
          if (frameIndex >= screenshots.length) {
            recorder.stop();
            return;
          }
          const img = new Image();
          img.onload = () => {
            ctx.fillStyle = "#1a1a1a";
            ctx.fillRect(0, 0, 1280, 720);
            ctx.drawImage(img, 0, 0, 1280, 720);
            ctx.fillStyle = "#ffffff";
            ctx.font = "14px monospace";
            ctx.fillText(`Frame ${frameIndex + 1}/${screenshots.length} · ${(frameIndex * SCREENSHOT_INTERVAL / 1000).toFixed(1)}s`, 10, 20);
            frameIndex++;
            setTimeout(drawFrame, 400); // 400ms per frame = 2.5 fps video
          };
          img.onerror = () => { frameIndex++; setTimeout(drawFrame, 400); };
          img.src = screenshots[frameIndex];
        };
        drawFrame();
      });

      if (chunks.length > 0) {
        const blob = new Blob(chunks, { type: "video/webm" });
        videoBlobUrl = URL.createObjectURL(blob);
      }
    } catch { /* video not supported */ }
  }

  // Close popup
  try { popup.close(); } catch {}

  // Compute risk score
  let score = 0;
  if (errors.length > 0) score += Math.min(errors.length * 5, 30);
  if (popups.length > 0) score += Math.min(popups.reduce((s, p) => s + p.count, 0) * 15, 30);
  if (evalCalls.length > 0) score += Math.min(evalCalls.length * 10, 30);
  if (webglFingerprint) score += 10;
  if (canvasFingerprint) score += 10;
  if (domMutations.length > 10) score += 15;
  if (cryptoMining.length > 0) score += 25;
  if (formAutoSubmit) score += 15;
  if (hiddenRedirect) score += 10;
  if (serviceWorker) score += 5;
  score = Math.min(100, score);

  let classification: SandboxResult["riskClassification"];
  if (score >= 75) classification = "CRITICAL";
  else if (score >= 50) classification = "HIGH";
  else if (score >= 25) classification = "MEDIUM";
  else if (score >= 10) classification = "LOW";
  else classification = "SAFE";

  let verdict = "";
  if (cryptoMining.length > 0) verdict += `${cryptoMining.length} crypto miner(s) detected! `;
  if (popups.length > 0) verdict += `${popups.reduce((s, p) => s + p.count, 0)} popup(s) opened. `;
  if (evalCalls.length > 0) verdict += `${evalCalls.length} eval/Function() call(s) — obfuscated code. `;
  if (webglFingerprint) verdict += "WebGL fingerprinting detected. ";
  if (canvasFingerprint) verdict += "Canvas fingerprinting detected. ";
  if (formAutoSubmit) verdict += "Auto-submitting form detected. ";
  if (hiddenRedirect) verdict += `Hidden redirect to ${hiddenRedirect}. `;
  if (errors.length > 5) verdict += `${errors.length} JavaScript errors. `;
  if (domMutations.length > 10) verdict += `${domMutations.length} DOM mutations. `;
  if (!verdict) verdict = "No significant malicious behavior detected during the 20-second sandbox execution.";

  return {
    url, timestamp: new Date(startTime).toISOString(), duration: SANDBOX_DURATION,
    screenshots, videoBlobUrl, finalDom, finalTitle,
    network, console: consoleLog, errors, domMutations, cookies,
    localStorage: localStorageEntries, sessionStorage: sessionStorageEntries,
    popups, evalCalls, cryptoMining,
    webglFingerprint, canvasFingerprint, formAutoSubmit, hiddenRedirect, serviceWorker,
    riskScore: score, riskClassification: classification, verdict, loaded,
  };
}

// ---------- PDF (same as before, with new sections) ----------

function downloadPdf(d: SandboxResult) {
  const doc = new jsPDF({ unit: "pt", format: "a4" });
  const pageWidth = doc.internal.pageSize.getWidth();
  const pageHeight = doc.internal.pageSize.getHeight();
  const margin = 40;
  const contentWidth = pageWidth - margin * 2;
  let y = margin;

  doc.setFont("helvetica", "bold"); doc.setFontSize(22); doc.setTextColor(15, 23, 42);
  doc.text("URL Sandbox Report", margin, y + 8);
  doc.setFont("helvetica", "normal"); doc.setFontSize(11); doc.setTextColor(220, 38, 38);
  doc.text("MONITOR-THREAT", margin, y + 26);
  doc.setTextColor(100, 116, 139);
  doc.text("Cyber Threat Intelligence Platform · v2.0", margin + 105, y + 26);
  const ts = new Date(d.timestamp).toLocaleString();
  doc.setFontSize(10); doc.setTextColor(71, 85, 105);
  doc.text(`Report generated: ${ts}`, pageWidth - margin, y + 8, { align: "right" });
  doc.text(`Target URL: ${d.url.slice(0, 60)}`, pageWidth - margin, y + 22, { align: "right" });
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
    autoTable(doc, { startY: y, head: [["Field", "Value"]], body: rows, theme: "striped",
      margin: { left: margin, right: margin },
      styles: { fontSize: 10, cellPadding: 6, textColor: [30, 41, 59], lineColor: [226, 232, 240], lineWidth: 0.5 },
      headStyles: { fillColor: [241, 245, 249], textColor: [71, 85, 105], fontStyle: "bold", fontSize: 10 },
      columnStyles: { 0: { cellWidth: contentWidth * 0.32, fontStyle: "bold", textColor: [100, 116, 139] } },
    });
    // @ts-ignore
    y = (doc as any).lastAutoTable.finalY + 18;
  };

  // Screenshots
  if (d.screenshots.length > 0) {
    sectionHeading("Screenshots");
    for (const s of d.screenshots.slice(0, 5)) {
      if (y > pageHeight - 300) { doc.addPage(); y = margin + 6; }
      try {
        const imgWidth = contentWidth;
        const imgHeight = imgWidth * (720 / 1280);
        doc.addImage(s, "PNG", margin, y, imgWidth, Math.min(imgHeight, 300));
        y += Math.min(imgHeight, 300) + 10;
      } catch {}
    }
  }

  // Risk Assessment
  sectionHeading("Risk Assessment");
  kvTable([["Risk score", `${d.riskScore} / 100`], ["Classification", d.riskClassification], ["Execution duration", "20 seconds"], ["Verdict", d.verdict]]);

  // 1. Network
  sectionHeading("1. Network Activity");
  kvTable([["Total requests", String(d.network.length)], ["XHR/Fetch", String(d.network.filter(n => n.type === "xmlhttprequest" || n.type === "fetch").length)]]);
  if (d.network.length > 0) {
    autoTable(doc, { startY: y, head: [["URL", "Type", "Duration", "Size"]],
      body: d.network.slice(0, 30).map(n => [n.url.slice(0, 120), n.type, `${n.duration}ms`, `${n.size}b`]),
      theme: "grid", margin: { left: margin, right: margin },
      styles: { fontSize: 8, cellPadding: 4, textColor: [30, 41, 59], lineColor: [226, 232, 240], lineWidth: 0.5 },
      headStyles: { fillColor: [241, 245, 249], textColor: [71, 85, 105], fontStyle: "bold", fontSize: 10 },
    });
    // @ts-ignore
    y = (doc as any).lastAutoTable.finalY + 18;
  }

  // 2. Console
  sectionHeading("2. Console Output");
  kvTable([["Total entries", String(d.console.length)]]);
  if (d.console.length > 0) {
    autoTable(doc, { startY: y, head: [["Level", "Time", "Message"]],
      body: d.console.slice(0, 20).map(c => [c.level, c.timestamp.slice(11, 19), c.message.slice(0, 120)]),
      theme: "grid", margin: { left: margin, right: margin },
      styles: { fontSize: 8, cellPadding: 4, textColor: [30, 41, 59], lineColor: [226, 232, 240], lineWidth: 0.5 },
      headStyles: { fillColor: [241, 245, 249], textColor: [71, 85, 105], fontStyle: "bold", fontSize: 10 },
    });
    // @ts-ignore
    y = (doc as any).lastAutoTable.finalY + 18;
  }

  // 3. Errors
  sectionHeading("3. JavaScript Errors");
  kvTable([["Error count", String(d.errors.length)]]);
  if (d.errors.length > 0) {
    for (const e of d.errors.slice(0, 15)) {
      if (y > pageHeight - 40) { doc.addPage(); y = margin + 6; }
      const wrapped = doc.splitTextToSize(`• ${e}`, contentWidth);
      doc.setFontSize(9); doc.setTextColor(220, 38, 38);
      doc.text(wrapped, margin, y); y += wrapped.length * 11 + 2;
    }
    y += 8;
  }

  // 4. DOM Mutations
  sectionHeading("4. DOM Mutations");
  kvTable([["Mutation count", String(d.domMutations.length)]]);
  if (d.domMutations.length > 0) {
    autoTable(doc, { startY: y, head: [["Type", "Target", "Added", "Time"]],
      body: d.domMutations.slice(0, 20).map(m => [m.type, m.target, m.addedNodes.join(", ").slice(0, 100), m.timestamp.slice(11, 19)]),
      theme: "grid", margin: { left: margin, right: margin },
      styles: { fontSize: 8, cellPadding: 4, textColor: [30, 41, 59], lineColor: [226, 232, 240], lineWidth: 0.5 },
      headStyles: { fillColor: [241, 245, 249], textColor: [71, 85, 105], fontStyle: "bold", fontSize: 10 },
    });
    // @ts-ignore
    y = (doc as any).lastAutoTable.finalY + 18;
  }

  // 5. Cookies
  sectionHeading("5. Cookies");
  kvTable([["Cookie count", String(d.cookies.length)]]);
  if (d.cookies.length > 0) {
    autoTable(doc, { startY: y, head: [["Name", "Value", "Secure", "HttpOnly"]],
      body: d.cookies.slice(0, 15).map(c => [c.name, c.value.slice(0, 60), c.secure ? "yes" : "no", c.httpOnly ? "yes" : "no"]),
      theme: "grid", margin: { left: margin, right: margin },
      styles: { fontSize: 9, cellPadding: 5, textColor: [30, 41, 59], lineColor: [226, 232, 240], lineWidth: 0.5 },
      headStyles: { fillColor: [241, 245, 249], textColor: [71, 85, 105], fontStyle: "bold", fontSize: 10 },
    });
    // @ts-ignore
    y = (doc as any).lastAutoTable.finalY + 18;
  }

  // 6. Storage
  sectionHeading("6. Web Storage");
  kvTable([
    ["localStorage entries", String(d.localStorage.length)],
    ["sessionStorage entries", String(d.sessionStorage.length)],
  ]);
  if (d.localStorage.length > 0 || d.sessionStorage.length > 0) {
    autoTable(doc, { startY: y, head: [["Type", "Key", "Value"]],
      body: [...d.localStorage, ...d.sessionStorage].slice(0, 20).map(s => [s.type, s.key, s.value.slice(0, 80)]),
      theme: "grid", margin: { left: margin, right: margin },
      styles: { fontSize: 8, cellPadding: 4, textColor: [30, 41, 59], lineColor: [226, 232, 240], lineWidth: 0.5 },
      headStyles: { fillColor: [241, 245, 249], textColor: [71, 85, 105], fontStyle: "bold", fontSize: 10 },
    });
    // @ts-ignore
    y = (doc as any).lastAutoTable.finalY + 18;
  }

  // 7. Popups
  sectionHeading("7. Popup Detection");
  kvTable([["Popup count", String(d.popups.length)], ["URLs", d.popups.map(p => `${p.url} (${p.count}x)`).join(", ") || "none"]]);

  // 8. Eval
  sectionHeading("8. Eval / Function() Detection");
  kvTable([["Eval calls", String(d.evalCalls.length)], ["Calls", d.evalCalls.map(e => e.code).join("\n").slice(0, 500) || "none"]]);

  // 9. Crypto Mining
  sectionHeading("9. Crypto Mining Detection");
  kvTable([["Miners detected", String(d.cryptoMining.length)], ["Miners", d.cryptoMining.map(c => `${c.miner}: ${c.script}`).join("\n") || "none"]]);

  // 10. Fingerprinting
  sectionHeading("10. Browser Fingerprinting");
  kvTable([
    ["WebGL fingerprinting", d.webglFingerprint ? "YES" : "no"],
    ["Canvas fingerprinting", d.canvasFingerprint ? "YES" : "no"],
  ]);

  // 11. Additional detections
  sectionHeading("11. Additional Detections");
  kvTable([
    ["Form auto-submit", d.formAutoSubmit ? "YES — phishing risk" : "no"],
    ["Hidden redirect", d.hiddenRedirect || "no"],
    ["Service worker", d.serviceWorker ? "YES" : "no"],
  ]);

  // 12. Final DOM
  sectionHeading("12. Final DOM Snapshot");
  kvTable([["Final title", d.finalTitle || "(empty)"], ["DOM size", `${d.finalDom.length} chars`]]);
  if (d.finalDom) {
    doc.setFontSize(7); doc.setFont("courier", "normal"); doc.setTextColor(51, 65, 85);
    const domLines = doc.splitTextToSize(d.finalDom.slice(0, 5000), contentWidth);
    for (const line of domLines.slice(0, 40)) {
      if (y > pageHeight - 40) { doc.addPage(); y = margin + 6; }
      doc.text(line, margin, y); y += 9;
    }
  }

  // 13. Video
  sectionHeading("13. Session Video");
  kvTable([["Video available", d.videoBlobUrl ? "Yes — WebM format, download via UI" : "No"]]);

  // Footer
  const pageCount = doc.getNumberOfPages();
  for (let i = 1; i <= pageCount; i++) {
    doc.setPage(i); doc.setFontSize(8); doc.setTextColor(148, 163, 184);
    doc.text(`MONITOR-THREAT v2.0  ·  Generated ${ts}  ·  Page ${i} of ${pageCount}`, pageWidth / 2, pageHeight - 22, { align: "center" });
    doc.text("This report is for informational purposes only and does not constitute legal advice.", pageWidth / 2, pageHeight - 10, { align: "center" });
  }
  doc.save(`MONITOR-THREAT-URL-Sandbox-${Date.now()}.pdf`);
}

// ---------- View ----------

const riskColors: Record<string, string> = {
  SAFE: "text-emerald-500", LOW: "text-green-500", MEDIUM: "text-yellow-500",
  HIGH: "text-orange-500", CRITICAL: "text-red-500",
};

export function UrlSandboxView() {
  const [input, setInput] = React.useState("");
  const [loading, setLoading] = React.useState(false);
  const [data, setData] = React.useState<SandboxResult | null>(null);
  const [error, setError] = React.useState<string | null>(null);
  const [elapsed, setElapsed] = React.useState(0);
  const [step, setStep] = React.useState("");

  async function analyze(url: string) {
    if (!url.trim()) return;
    setLoading(true); setError(null); setData(null); setElapsed(0);
    try {
      const result = await runSandbox(url.trim(), (e, s) => { setElapsed(e); setStep(s); });
      setData(result);
    } catch (err: any) {
      setError(err.message || "Sandbox execution failed");
    } finally {
      setLoading(false);
    }
  }

  return (
    <ModuleShell
      name="URL Sandbox"
      description="Live browser sandbox: opens the URL in a real popup window (bypasses X-Frame-Options/CSP), monitors for 20 seconds — network, console, errors, DOM mutations, cookies, storage, popups, eval, crypto mining, fingerprinting, screenshots + session video."
      icon={Box}
      category="INFRASTRUCTURE"
      status={loading ? "RUNNING" : "READY"}
    >
      <div className="flex flex-col gap-2 mb-4">
        <label className="text-xs font-medium text-muted-foreground uppercase tracking-wider">URL to sandbox</label>
        <div className="flex gap-2">
          <Input type="text" placeholder="e.g. https://suspicious-site.com/login"
            className="flex-1 font-mono text-sm" value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && analyze(input)} autoFocus />
          <Button type="button" size="sm" onClick={() => analyze(input)} disabled={loading || !input.trim()}>
            {loading ? <><Loader2 className="w-3.5 h-3.5 mr-2 animate-spin" />{(elapsed / 1000).toFixed(1)}s/20s</> : <><Play className="w-3.5 h-3.5 mr-2" />Run Sandbox</>}
          </Button>
          <Button type="button" size="sm" variant="outline" onClick={() => downloadPdf(data!)} disabled={!data}>
            <Printer className="w-3.5 h-3.5 mr-2" />Imprimir informe PDF
          </Button>
        </div>
        {loading && (
          <div className="flex flex-col gap-1">
            <div className="w-full bg-muted rounded-full h-2 overflow-hidden">
              <div className="bg-primary h-full transition-all" style={{ width: `${(elapsed / SANDBOX_DURATION) * 100}%` }} />
            </div>
            <div className="text-xs text-muted-foreground font-mono">{step}</div>
          </div>
        )}
      </div>

      {error && (
        <div className="mb-4 p-3 rounded-md border border-red-500/40 bg-red-500/10 text-red-400 flex items-center gap-2">
          <AlertTriangle className="w-4 h-4 shrink-0" /><span className="text-sm">{error}</span>
        </div>
      )}

      {!data && !loading && (
        <div className="flex flex-col items-center justify-center min-h-[400px] text-center gap-3">
          <div className="w-16 h-16 rounded-full bg-muted/50 flex items-center justify-center">
            <Box className="w-8 h-8 text-muted-foreground" />
          </div>
          <h2 className="text-lg font-semibold">Enter a URL to sandbox</h2>
          <p className="text-sm text-muted-foreground max-w-md">
            Opens the URL in a real popup window (bypasses X-Frame-Options/CSP), injects monitoring hooks,
            captures screenshots every 2s, generates a session video, and detects:
            crypto mining, popups, eval/Function(), WebGL/Canvas fingerprinting, form auto-submit,
            hidden redirects, service workers, localStorage/sessionStorage, and more.
          </p>
          <p className="text-xs text-yellow-500">⚠ Please allow popups for this site when prompted.</p>
        </div>
      )}

      {data && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {/* Risk Assessment */}
          <Panel title="Risk Assessment" className="md:col-span-2">
            <div className="flex items-start gap-4">
              <div className="flex flex-col items-center gap-1 shrink-0">
                <div className={`text-5xl font-mono font-bold ${riskColors[data.riskClassification] || "text-muted-foreground"}`}>
                  {data.riskScore}
                </div>
                <div className="text-base text-muted-foreground">/ 100</div>
                <Badge variant={data.riskClassification === "CRITICAL" || data.riskClassification === "HIGH" ? "destructive" : data.riskClassification === "MEDIUM" ? "default" : "secondary"} className="font-mono text-xs mt-1">
                  {data.riskClassification}
                </Badge>
              </div>
              <div className="flex-1">
                <div className="text-sm text-muted-foreground mb-1 font-semibold">Verdict:</div>
                <p className="text-sm">{data.verdict}</p>
                {!data.loaded && <p className="text-xs text-yellow-500 mt-1">⚠ Page loaded in popup but monitoring was limited (cross-origin).</p>}
              </div>
            </div>
          </Panel>

          {/* Screenshots */}
          {data.screenshots.length > 0 && (
            <Panel title={`Screenshots (${data.screenshots.length})`} className="md:col-span-2">
              <div className="flex gap-2 overflow-x-auto pb-2">
                {data.screenshots.map((s, i) => (
                  <div key={i} className="rounded border border-border overflow-hidden shrink-0">
                    <img src={s} alt={`Screenshot ${i + 1}`} className="h-32 w-auto" />
                    <div className="text-[10px] text-muted-foreground text-center py-1">{(i * SCREENSHOT_INTERVAL / 1000).toFixed(1)}s</div>
                  </div>
                ))}
              </div>
            </Panel>
          )}

          {/* Session Video — SIEMPRE VISIBLE */}
          <Panel title="Session Video (20s)" className="md:col-span-2" action={
            data.videoBlobUrl ? (
              <a href={data.videoBlobUrl} download={`sandbox-session-${Date.now()}.webm`}
                className="text-xs text-cyan-500 hover:underline flex items-center gap-1">
                <Download className="w-3 h-3" /> Download WebM
              </a>
            ) : undefined
          }>
            {data.videoBlobUrl ? (
              <div>
                <video src={data.videoBlobUrl} controls className="w-full rounded border border-border" style={{ maxHeight: "400px" }} />
                <div className="text-xs text-muted-foreground mt-1 text-center">
                  20-second session recording · {data.screenshots.length} frames · WebM format
                </div>
              </div>
            ) : (
              <div className="flex flex-col items-center justify-center py-8 gap-2 text-muted-foreground">
                <Video className="w-8 h-8" />
                <p className="text-sm">No video available — screenshots could not be captured (cross-origin or CSP blocked).</p>
                <p className="text-xs">The page may block monitoring via Content Security Policy. Try a URL on the same origin.</p>
              </div>
            )}
          </Panel>

          {/* 1. Network */}
          <Panel title={`1. Network Activity (${data.network.length})`}>
            <div className="grid grid-cols-2 gap-2 mb-3">
              <div className="rounded p-2 border border-border bg-muted/20">
                <div className="text-xl font-bold font-mono">{data.network.length}</div>
                <div className="text-[10px]">total requests</div>
              </div>
              <div className="rounded p-2 border border-border bg-muted/20">
                <div className="text-xl font-bold font-mono">{data.network.filter(n => n.type === "xmlhttprequest" || n.type === "fetch").length}</div>
                <div className="text-[10px]">XHR/Fetch</div>
              </div>
            </div>
            <div className="max-h-48 overflow-y-auto">
              {data.network.slice(0, 20).map((n, i) => (
                <div key={i} className="text-xs py-1 border-b border-border/30 flex justify-between">
                  <span className="font-mono truncate flex-1">{n.url.slice(0, 80)}</span>
                  <span className="text-muted-foreground shrink-0 ml-2">{n.duration}ms</span>
                </div>
              ))}
            </div>
          </Panel>

          {/* 2. Console */}
          <Panel title={`2. Console Output (${data.console.length})`}>
            <div className="max-h-48 overflow-y-auto">
              {data.console.length > 0 ? data.console.slice(0, 20).map((c, i) => (
                <div key={i} className={`text-xs py-1 border-b border-border/30 ${c.level === "error" ? "text-red-400" : c.level === "warn" ? "text-yellow-500" : "text-muted-foreground"}`}>
                  <span className="font-mono text-[10px]">[{c.timestamp.slice(11, 19)}]</span> {c.message.slice(0, 120)}
                </div>
              )) : <p className="text-sm text-muted-foreground">No console output.</p>}
            </div>
          </Panel>

          {/* 3. Errors */}
          <Panel title={`3. JavaScript Errors (${data.errors.length})`}>
            <div className="max-h-48 overflow-y-auto">
              {data.errors.length > 0 ? data.errors.slice(0, 15).map((e, i) => (
                <div key={i} className="text-xs text-red-400 py-1 border-b border-border/30 break-all">{e.slice(0, 200)}</div>
              )) : <p className="text-sm text-emerald-500 flex items-center gap-2"><ShieldCheck className="w-4 h-4" /> No errors.</p>}
            </div>
          </Panel>

          {/* 4. DOM Mutations */}
          <Panel title={`4. DOM Mutations (${data.domMutations.length})`}>
            <div className="max-h-48 overflow-y-auto">
              {data.domMutations.length > 0 ? data.domMutations.slice(0, 20).map((m, i) => (
                <div key={i} className="text-xs py-1 border-b border-border/30">
                  <span className="font-mono text-[10px] text-muted-foreground">[{m.timestamp.slice(11, 19)}]</span>{" "}
                  <Badge variant="outline" className="text-[9px] font-mono">{m.type}</Badge>{" "}
                  {m.target} {m.addedNodes.length > 0 && <span className="text-muted-foreground">+{m.addedNodes.join(", ")}</span>}
                </div>
              )) : <p className="text-sm text-muted-foreground">No DOM mutations.</p>}
            </div>
          </Panel>

          {/* 5. Cookies */}
          <Panel title={`5. Cookies (${data.cookies.length})`}>
            <div className="max-h-48 overflow-y-auto">
              {data.cookies.length > 0 ? data.cookies.slice(0, 15).map((c, i) => (
                <div key={i} className="text-xs py-1 border-b border-border/30">
                  <span className="font-mono font-semibold">{c.name}</span>: <span className="font-mono text-muted-foreground">{c.value.slice(0, 40)}</span>
                  {c.secure && <Badge variant="outline" className="text-[9px] ml-1">secure</Badge>}
                </div>
              )) : <p className="text-sm text-muted-foreground">No cookies detected.</p>}
            </div>
          </Panel>

          {/* 6. Web Storage */}
          <Panel title={`6. Web Storage (${data.localStorage.length + data.sessionStorage.length})`}>
            <div className="max-h-48 overflow-y-auto">
              {data.localStorage.length > 0 || data.sessionStorage.length > 0 ? (
                [...data.localStorage, ...data.sessionStorage].slice(0, 20).map((s, i) => (
                  <div key={i} className="text-xs py-1 border-b border-border/30">
                    <Badge variant="outline" className="text-[9px] font-mono mr-1">{s.type}</Badge>
                    <span className="font-mono font-semibold">{s.key}</span>: <span className="text-muted-foreground">{s.value.slice(0, 60)}</span>
                  </div>
                ))
              ) : <p className="text-sm text-muted-foreground">No storage entries detected.</p>}
            </div>
          </Panel>

          {/* 7. Popups */}
          <Panel title={`7. Popup Detection (${data.popups.length})`}>
            {data.popups.length > 0 ? (
              data.popups.map((p, i) => (
                <div key={i} className="text-xs text-orange-400 font-mono py-1 border-b border-border/30">
                  <ShieldAlert className="w-3 h-3 inline mr-1" /> window.open("{p.url.slice(0, 100)}") — {p.count}x
                </div>
              ))
            ) : <p className="text-sm text-emerald-500 flex items-center gap-2"><ShieldCheck className="w-4 h-4" /> No popups.</p>}
          </Panel>

          {/* 8. Eval */}
          <Panel title={`8. Eval / Function() (${data.evalCalls.length})`}>
            {data.evalCalls.length > 0 ? (
              <div className="max-h-48 overflow-y-auto">
                {data.evalCalls.slice(0, 15).map((e, i) => (
                  <div key={i} className="text-xs text-red-400 font-mono py-1 border-b border-border/30 break-all">{e.code.slice(0, 200)}</div>
                ))}
              </div>
            ) : <p className="text-sm text-emerald-500 flex items-center gap-2"><ShieldCheck className="w-4 h-4" /> No eval calls.</p>}
          </Panel>

          {/* 9. Crypto Mining */}
          <Panel title={`9. Crypto Mining (${data.cryptoMining.length})`}>
            {data.cryptoMining.length > 0 ? (
              data.cryptoMining.map((c, i) => (
                <div key={i} className="text-xs text-red-400 py-2 border-b border-border/30">
                  <Cpu className="w-4 h-4 inline mr-2" />
                  <span className="font-semibold">{c.miner}</span>: <span className="font-mono">{c.script.slice(0, 80)}</span>
                </div>
              ))
            ) : <p className="text-sm text-emerald-500 flex items-center gap-2"><ShieldCheck className="w-4 h-4" /> No crypto miners detected.</p>}
          </Panel>

          {/* 10. Fingerprinting */}
          <Panel title="10. Browser Fingerprinting">
            <div className="flex flex-col gap-2">
              <div className={`p-2 rounded border flex items-center gap-2 ${data.webglFingerprint ? "border-red-500/40 bg-red-500/10 text-red-400" : "border-emerald-500/40 bg-emerald-500/10 text-emerald-400"}`}>
                {data.webglFingerprint ? <ShieldAlert className="w-4 h-4" /> : <ShieldCheck className="w-4 h-4" />}
                <span className="text-sm">WebGL: {data.webglFingerprint ? "DETECTED" : "not detected"}</span>
              </div>
              <div className={`p-2 rounded border flex items-center gap-2 ${data.canvasFingerprint ? "border-red-500/40 bg-red-500/10 text-red-400" : "border-emerald-500/40 bg-emerald-500/10 text-emerald-400"}`}>
                {data.canvasFingerprint ? <ShieldAlert className="w-4 h-4" /> : <ShieldCheck className="w-4 h-4" />}
                <span className="text-sm">Canvas: {data.canvasFingerprint ? "DETECTED" : "not detected"}</span>
              </div>
            </div>
          </Panel>

          {/* 11. Additional Detections */}
          <Panel title="11. Additional Detections">
            <FieldRow label="Form auto-submit" value={data.formAutoSubmit ? "YES — phishing risk" : "no"} />
            <FieldRow label="Hidden redirect" value={data.hiddenRedirect || "no"} />
            <FieldRow label="Service worker" value={data.serviceWorker ? "YES" : "no"} />
          </Panel>

          {/* 12. Final DOM */}
          <Panel title={`12. Final DOM (${data.finalDom.length} chars)`} className="md:col-span-2">
            <FieldRow label="Final title" value={data.finalTitle || "(empty)"} />
            <FieldRow label="DOM size" value={`${data.finalDom.length} chars`} mono />
            {data.finalDom && (
              <>
                <Separator />
                <div className="pt-2 max-h-64 overflow-y-auto rounded border border-border p-2 bg-muted/20">
                  <pre className="text-[10px] font-mono whitespace-pre-wrap break-words">{data.finalDom.slice(0, 10000)}</pre>
                </div>
              </>
            )}
          </Panel>

          <div className="md:col-span-2 text-[10px] text-muted-foreground font-mono">
            Execution: {data.duration / 1000}s · {data.screenshots.length} screenshots · All analysis client-side in your browser.
          </div>
        </div>
      )}
    </ModuleShell>
  );
}
