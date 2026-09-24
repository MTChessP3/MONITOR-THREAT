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

// NUEVOS: tracking de redirecciones, timeline, vínculos externos, comportamiento
interface RedirectEntry {
  from: string;
  to: string;
  timestamp: string;
  method: string; // "meta-refresh" | "js-location" | "window.location" | "window.open" | "http-redirect" | "href-change"
  crossDomain: boolean;
}

interface TimelineEvent {
  time: string; // elapsed seconds (e.g. "1.2s")
  timestamp: string; // ISO
  type: string; // "load" | "redirect" | "popup" | "error" | "eval" | "crypto" | "form-submit" | "mutation" | "console-error"
  description: string;
  severity: "info" | "warning" | "danger";
}

interface ExternalLink {
  href: string;
  text: string;
  domain: string;
  sameDomain: boolean;
}

type BehaviorType =
  | "NORMAL"
  | "REDIRECT_CHAIN"
  | "POPUP_SPAM"
  | "PHISHING_REDIRECT"
  | "CRYPTO_MINING"
  | "MIXED_THREAT";

interface SandboxResult {
  url: string;
  timestamp: string;
  duration: number;
  screenshots: string[];
  videoBlobUrl?: string;
  finalDom: string;
  finalTitle: string;
  finalUrl: string; // NUEVO: URL final después de redirects
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
  // NUEVOS:
  redirects: RedirectEntry[];
  timeline: TimelineEvent[];
  externalLinks: ExternalLink[];
  behavior: BehaviorType;
  summary: string; // resumen ejecutivo en lenguaje natural
  riskScore: number;
  riskClassification: "SAFE" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  verdict: string;
  loaded: boolean;
}

const SANDBOX_DURATION = 20000;
const SCREENSHOT_INTERVAL = 6000; // 3 screenshots: ~6s, ~12s, ~18s

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
  let finalUrl = url;
  let loaded = false;
  // NUEVOS:
  const redirects: RedirectEntry[] = [];
  const timeline: TimelineEvent[] = [];
  const externalLinks: ExternalLink[] = [];
  let lastPopupUrl = url;
  let behavior: BehaviorType = "NORMAL";

  // NUEVO: Usar el proxy en lugar de la URL directa.
  // El proxy descarga la página server-side, le inyecta el script de
  // monitoreo, y la sirve desde nuestro propio dominio (same-origin).
  // Esto elimina TODOS los errores de cross-origin.
  const proxyUrl = `/api/sandbox/proxy?url=${encodeURIComponent(url)}`;

  // Open target via proxy (same-origin → monitoring hooks work!)
  onProgress(0, "Opening URL via sandbox proxy...");
  const popup = window.open(proxyUrl, "_blank", "width=1280,height=720,scrollbars=yes,resizable=yes,noopener=no");

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

  onProgress(2000, "Monitoring hooks injected by proxy — waiting for page events...");

  // The proxy already injected the monitoring script server-side.
  // We just need to listen for postMessage events from the popup.
  // No need to manually inject anything — the proxy did it for us.

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
      case "sandboxReady":
        loaded = true;
        timeline.push({
          time: `${((Date.now() - startTime) / 1000).toFixed(1)}s`,
          timestamp: new Date().toISOString(),
          type: "ready",
          description: "Monitoring active — page loaded via proxy",
          severity: "info",
        });
        break;
      case "link":
        if (!externalLinks.some(l => l.href === d.href)) {
          externalLinks.push({ href: d.href, text: d.text || "", domain: d.domain || "", sameDomain: !!d.sameDomain });
        }
        break;
      case "finalDom":
        finalDom = d.html || "";
        finalTitle = d.title || "";
        break;
      case "hiddenRedirect":
        if (d.url) hiddenRedirect = d.url;
        timeline.push({
          time: `${((Date.now() - startTime) / 1000).toFixed(1)}s`,
          timestamp: new Date().toISOString(),
          type: "redirect",
          description: `HIDDEN REDIRECT via meta-refresh to: ${d.url}`,
          severity: "warning",
        });
        break;
      case "screenshot":
        if (d.dataUrl) {
          screenshots.push(d.dataUrl);
          onProgress(Date.now() - startTime, `Screenshot capturado a los ${(d.delay / 1000).toFixed(0)}s`);
          const img = new Image();
          img.onload = () => {
            latestScreenshotImg = img;
            if (videoCtx) {
              videoCtx.fillStyle = "#ffffff";
              videoCtx.fillRect(0, 0, 1280, 720);
              videoCtx.drawImage(img, 0, 0, 1280, 720);
            }
          };
          img.src = d.dataUrl;
        }
        break;
      case "domSnapshot":
        // The popup sent its rendered DOM HTML. We render it in a hidden
        // iframe (same-origin) and use html2canvas to capture it.
        if (d.html) {
          onProgress(Date.now() - startTime, `Renderizando screenshot desde DOM...`);
          finalTitle = d.title || finalTitle;
          finalDom = d.html.slice(0, 50000);
          // Create a hidden iframe to render the DOM
          const hiddenIframe = document.createElement("iframe");
          hiddenIframe.style.position = "fixed";
          hiddenIframe.style.top = "-9999px";
          hiddenIframe.style.left = "-9999px";
          hiddenIframe.style.width = "1280px";
          hiddenIframe.style.height = "720px";
          hiddenIframe.style.border = "none";
          hiddenIframe.onload = async () => {
            try {
              const iframeDoc = hiddenIframe.contentDocument;
              if (iframeDoc && iframeDoc.body) {
                // Wait 500ms for the iframe to render
                await new Promise(r => setTimeout(r, 500));
                const canvas = await html2canvas(iframeDoc.body, {
                  width: 1280, height: 720, windowWidth: 1280, windowHeight: 720,
                  useCORS: true, allowTaint: true, logging: false, scale: 1,
                  backgroundColor: "#ffffff",
                });
                const dataUrl = canvas.toDataURL("image/png");
                screenshots.push(dataUrl);
                // Update latest screenshot for video
                const img = new Image();
                img.onload = () => {
                  latestScreenshotImg = img;
                  if (videoCtx) {
                    videoCtx.fillStyle = "#ffffff";
                    videoCtx.fillRect(0, 0, 1280, 720);
                    videoCtx.drawImage(img, 0, 0, 1280, 720);
                  }
                };
                img.src = dataUrl;
                onProgress(Date.now() - startTime, `Screenshot renderizado correctamente`);
              }
            } catch (e) {
              // html2canvas failed on the iframe — try text fallback
              try {
                const iframeDoc = hiddenIframe.contentDocument;
                if (iframeDoc) {
                  const bodyText = iframeDoc.body ? iframeDoc.body.innerText.slice(0, 5000) : "";
                  const titleText = iframeDoc.title || "";
                  const fc = document.createElement("canvas");
                  fc.width = 1280; fc.height = 720;
                  const fctx = fc.getContext("2d")!;
                  fctx.fillStyle = "#ffffff"; fctx.fillRect(0, 0, 1280, 720);
                  fctx.fillStyle = "#333"; fctx.font = "bold 24px sans-serif";
                  fctx.fillText(titleText.slice(0, 80), 20, 40);
                  fctx.font = "14px monospace";
                  const lines = bodyText.split("\n").slice(0, 40);
                  for (let i = 0; i < lines.length; i++) {
                    fctx.fillText(lines[i].slice(0, 150), 20, 80 + i * 20);
                  }
                  const dataUrl = fc.toDataURL("image/png");
                  screenshots.push(dataUrl);
                  const img = new Image();
                  img.onload = () => {
                    latestScreenshotImg = img;
                    if (videoCtx) {
                      videoCtx.fillStyle = "#ffffff";
                      videoCtx.fillRect(0, 0, 1280, 720);
                      videoCtx.drawImage(img, 0, 0, 1280, 720);
                    }
                  };
                  img.src = dataUrl;
                  onProgress(Date.now() - startTime, `Screenshot (text fallback) renderizado`);
                }
              } catch (e2) {
                onProgress(Date.now() - startTime, `Screenshot falló: ${String(e2).slice(0, 100)}`);
              }
            } finally {
              // Remove the hidden iframe
              if (hiddenIframe.parentNode) hiddenIframe.parentNode.removeChild(hiddenIframe);
            }
          };
          // Set the iframe content via srcdoc
          hiddenIframe.srcdoc = d.html.slice(0, 200000);
          document.body.appendChild(hiddenIframe);
        }
        break;
      case "screenshotError":
        timeline.push({
          time: `${((Date.now() - startTime) / 1000).toFixed(1)}s`,
          timestamp: new Date().toISOString(),
          type: "screenshot-error",
          description: `Screenshot falló a los ${(d.delay / 1000).toFixed(0)}s: ${d.error || "unknown"}`,
          severity: "warning",
        });
        break;
    }
  };
  window.addEventListener("message", messageHandler);

  // NUEVO: Tracking de redirecciones del popup — monitorea location.href cada 500ms
  // IMPORTANTE: el popup carga desde /api/sandbox/proxy?url=<target>, por lo que
  // location.href siempre empieza siendo la URL del proxy. Debemos:
  // 1. Ignorar la URL inicial del proxy (es nuestro dominio, no un redirect)
  // 2. Solo detectar redirects REALES: cuando el proxy cambia la URL del target
  //    (porque la página hace window.location = "otro sitio" o meta refresh)
  // 3. Extraer la URL del target del parámetro ?url= del proxy
  const originalHost = (() => { try { return new URL(url).hostname; } catch { return ""; } })();
  let lastKnownTargetUrl = url; // la URL del TARGET, no la del proxy

  const extractTargetFromProxy = (proxyHref: string): string => {
    // Si la URL es /api/sandbox/proxy?url=..., extraer el parámetro url
    try {
      const u = new URL(proxyHref);
      if (u.pathname.includes("/api/sandbox/proxy")) {
        const target = u.searchParams.get("url");
        if (target) return target;
      }
      return proxyHref; // no es proxy, devolver tal cual
    } catch {
      return proxyHref;
    }
  };

  const redirectInterval = setInterval(() => {
    let proxyUrl: string | null = null;
    try {
      proxyUrl = popup.location?.href || null;
    } catch {
      // No podemos leer location.href — el proxy es same-origin, así que
      // si no podemos leerlo es porque el popup fue cerrado o navegó fuera
    }

    if (proxyUrl) {
      const currentTarget = extractTargetFromProxy(proxyUrl);
      if (currentTarget !== lastKnownTargetUrl) {
        // ¡Redirect REAL detectado! El target cambió de URL.
        let crossDomain = false;
        try {
          const oldHost = new URL(lastKnownTargetUrl).hostname;
          const newHost = new URL(currentTarget).hostname;
          crossDomain = oldHost !== newHost;
        } catch {}

        // Solo registrar si el nuevo target NO es nuestro proxy (evita falsos positivos)
        if (!currentTarget.includes("/api/sandbox/proxy")) {
          redirects.push({
            from: lastKnownTargetUrl,
            to: currentTarget,
            timestamp: new Date().toISOString(),
            method: "location-change",
            crossDomain,
          });

          timeline.push({
            time: `${((Date.now() - startTime) / 1000).toFixed(1)}s`,
            timestamp: new Date().toISOString(),
            type: "redirect",
            description: crossDomain
              ? `REDIRECCIÓN CROSS-DOMAIN: ${lastKnownTargetUrl.slice(0, 60)} → ${currentTarget.slice(0, 60)}`
              : `Redirección: ${lastKnownTargetUrl.slice(0, 60)} → ${currentTarget.slice(0, 60)}`,
            severity: crossDomain ? "danger" : "warning",
          });

          lastKnownTargetUrl = currentTarget;
          finalUrl = currentTarget;
        }
      }
    }
  }, 500);

  // Timeline: evento de carga inicial
  timeline.push({
    time: "0.0s",
    timestamp: new Date(startTime).toISOString(),
    type: "load",
    description: `Sandbox started — URL: ${url}`,
    severity: "info",
  });

  // NUEVO: Hook para detectar window.open con redirección cross-domain
  // Modificamos el handler de popups para añadir al timeline
  const originalPopupHandler = messageHandler;

  onProgress(3000, "Starting video recording — waiting for page to render...");

  // Screenshots are captured BY THE POPUP ITSELF (proxy injects html2canvas).
  // We draw them into this canvas for the video recording.

  // Canvas for video recording
  const videoCanvas = document.createElement("canvas");
  videoCanvas.width = 1280;
  videoCanvas.height = 720;
  const videoCtx = videoCanvas.getContext("2d")!;

  // Track the latest screenshot image so we can redraw it every frame
  let latestScreenshotImg: HTMLImageElement | null = null;
  let latestScreenshotTime = 0;

  // Draw the INITIAL frame before starting the recorder — this prevents
  // the first 6 seconds from being black.
  const drawInitialFrame = () => {
    videoCtx.fillStyle = "#1a1a2e";
    videoCtx.fillRect(0, 0, 1280, 720);
    // Title
    videoCtx.fillStyle = "#e94560";
    videoCtx.font = "bold 28px monospace";
    videoCtx.fillText("MONITOR-THREAT", 40, 60);
    videoCtx.fillStyle = "#ffffff";
    videoCtx.font = "16px monospace";
    videoCtx.fillText("URL Sandbox — Recording in progress", 40, 90);
    videoCtx.fillStyle = "#888";
    videoCtx.font = "14px monospace";
    videoCtx.fillText(`Target: ${url.slice(0, 100)}`, 40, 120);
    videoCtx.fillText(`Duration: 20 seconds`, 40, 145);
    videoCtx.fillText(`Waiting for first screenshot at 6s...`, 40, 170);
    // Progress bar background
    videoCtx.fillStyle = "#333";
    videoCtx.fillRect(40, 680, 1200, 8);
    videoCtx.fillStyle = "#e94560";
    videoCtx.fillRect(40, 680, 0, 8);
  };
  drawInitialFrame();

  // Start recording AFTER the initial frame is drawn
  const videoStream = videoCanvas.captureStream(10); // 10 fps — higher fps = smoother video
  const mediaRecorder = new MediaRecorder(videoStream, { mimeType: "video/webm;codecs=vp8" });
  const videoChunks: Blob[] = [];
  mediaRecorder.ondataavailable = (e) => { if (e.data.size > 0) videoChunks.push(e.data); };
  mediaRecorder.start();

  // Redraw the canvas EVERY 200ms — this ensures the video always has content.
  // Each redraw shows: latest screenshot (if available) + live stats overlay.
  const drawInterval = setInterval(() => {
    const elapsed = Date.now() - startTime;
    const elapsedSec = (elapsed / 1000).toFixed(1);
    const pct = elapsed / SANDBOX_DURATION;

    // If we have a screenshot, draw it as the background
    if (latestScreenshotImg) {
      videoCtx.fillStyle = "#ffffff";
      videoCtx.fillRect(0, 0, 1280, 720);
      videoCtx.drawImage(latestScreenshotImg, 0, 0, 1280, 720);
    } else {
      // No screenshot yet — draw the "waiting" frame
      drawInitialFrame();
    }

    // Always draw the stats overlay at the bottom
    videoCtx.fillStyle = "rgba(0,0,0,0.85)";
    videoCtx.fillRect(0, 680, 1280, 40);
    videoCtx.fillStyle = "#e94560";
    videoCtx.font = "bold 14px monospace";
    videoCtx.fillText(`⏱ ${elapsedSec}s / 20s`, 10, 702);
    videoCtx.fillStyle = "#00ff88";
    videoCtx.font = "12px monospace";
    videoCtx.fillText(
      `Net: ${network.length} | Console: ${consoleLog.length} | Errors: ${errors.length} | Popups: ${popups.length} | Eval: ${evalCalls.length} | Screenshots: ${screenshots.length}`,
      120, 702
    );
    // Progress bar
    videoCtx.fillStyle = "#333";
    videoCtx.fillRect(0, 716, 1280, 4);
    videoCtx.fillStyle = "#e94560";
    videoCtx.fillRect(0, 716, 1280 * pct, 4);

    onProgress(elapsed, `Sandbox running... ${Math.round(pct * 100)}% | Screenshots: ${screenshots.length}`);
  }, 200);

  // Wait for SANDBOX_DURATION
  await new Promise(resolve => setTimeout(resolve, SANDBOX_DURATION));

  clearInterval(drawInterval);
  clearInterval(redirectInterval);
  window.removeEventListener("message", messageHandler);

  // Draw one final frame
  if (latestScreenshotImg) {
    videoCtx.fillStyle = "#ffffff";
    videoCtx.fillRect(0, 0, 1280, 720);
    videoCtx.drawImage(latestScreenshotImg, 0, 0, 1280, 720);
  }
  videoCtx.fillStyle = "rgba(0,0,0,0.85)";
  videoCtx.fillRect(0, 680, 1280, 40);
  videoCtx.fillStyle = "#e94560";
  videoCtx.font = "bold 14px monospace";
  videoCtx.fillText(`⏱ 20.0s / 20s — COMPLETE`, 10, 702);
  videoCtx.fillStyle = "#00ff88";
  videoCtx.font = "12px monospace";
  videoCtx.fillText(`Final: Net: ${network.length} | Console: ${consoleLog.length} | Errors: ${errors.length} | Popups: ${popups.length} | Screenshots: ${screenshots.length}`, 120, 702);

  // Wait 500ms so the final frame is captured by the recorder
  await new Promise(r => setTimeout(r, 500));

  // Stop video recording
  await new Promise<void>(resolve => {
    mediaRecorder.onstop = () => resolve();
    mediaRecorder.stop();
  });

  onProgress(SANDBOX_DURATION, "Capturing final DOM and generating video...");

  // Generate video blob URL from recorded chunks
  let videoBlobUrl: string | undefined;
  if (videoChunks.length > 0) {
    const blob = new Blob(videoChunks, { type: "video/webm" });
    videoBlobUrl = URL.createObjectURL(blob);
  }

  // Capture final DOM
  try {
    if (popup.document) {
      finalDom = popup.document.documentElement.outerHTML.slice(0, 50000);
      finalTitle = popup.document.title || "";
    }
  } catch { /* cross-origin */ }

  // Close popup
  try { popup.close(); } catch {}

  // NUEVO: Extraer vínculos externos del DOM final
  try {
    if (finalDom) {
      const linkMatches = finalDom.matchAll(/<a[^>]+href=["'`]([^"'`]+)["'`][^>]*>([^<]*)<\/a>/gi);
      const baseUrl = finalUrl || url;
      let originHost = "";
      try { originHost = new URL(baseUrl).hostname; } catch {}
      for (const m of linkMatches) {
        const href = m[1];
        const text = m[2]?.trim() || "";
        if (!href || href.startsWith("#") || href.startsWith("javascript:") || href.startsWith("mailto:")) continue;
        try {
          const absUrl = new URL(href, baseUrl).href;
          const linkHost = new URL(absUrl).hostname;
          const sameDomain = linkHost === originHost;
          if (!externalLinks.some(l => l.href === absUrl)) {
            externalLinks.push({ href: absUrl, text: text.slice(0, 80), domain: linkHost, sameDomain });
          }
        } catch {}
      }
    }
  } catch {}

  // NUEVO: Determinar comportamiento (behavior)
  if (cryptoMining.length > 0) {
    behavior = "CRYPTO_MINING";
  } else if (redirects.some(r => r.crossDomain) && popups.length > 0) {
    behavior = "PHISHING_REDIRECT";
  } else if (redirects.length >= 2) {
    behavior = "REDIRECT_CHAIN";
  } else if (popups.length >= 3) {
    behavior = "POPUP_SPAM";
  } else if (cryptoMining.length > 0 && redirects.length > 0 && popups.length > 0) {
    behavior = "MIXED_THREAT";
  }

  // NUEVO: Añadir eventos al timeline desde los datos capturados
  for (const err of errors.slice(0, 10)) {
    timeline.push({
      time: "?",
      timestamp: new Date().toISOString(),
      type: "error",
      description: `JS Error: ${err.slice(0, 150)}`,
      severity: "warning",
    });
  }
  for (const p of popups.slice(0, 5)) {
    let crossDomain = false;
    try {
      const popHost = new URL(p.url).hostname;
      const urlHost = new URL(url).hostname;
      crossDomain = popHost !== urlHost;
    } catch {}
    timeline.push({
      time: "?",
      timestamp: new Date().toISOString(),
      type: "popup",
      description: crossDomain
        ? `NUEVA VENTANA cross-domain: window.open("${p.url.slice(0, 80)}") — ${p.count}x`
        : `Nueva ventana: window.open("${p.url.slice(0, 80)}") — ${p.count}x`,
      severity: crossDomain ? "danger" : "warning",
    });
  }
  for (const e of evalCalls.slice(0, 5)) {
    timeline.push({
      time: e.timestamp ? `${((new Date(e.timestamp).getTime() - startTime) / 1000).toFixed(1)}s` : "?",
      timestamp: e.timestamp,
      type: "eval",
      description: `EVAL/Function(): ${e.code.slice(0, 150)}`,
      severity: "warning",
    });
  }
  for (const c of cryptoMining) {
    timeline.push({
      time: "?",
      timestamp: new Date().toISOString(),
      type: "crypto",
      description: `CRYPTO MINING: ${c.miner} — ${c.script.slice(0, 100)}`,
      severity: "danger",
    });
  }
  if (formAutoSubmit) {
    timeline.push({
      time: "?",
      timestamp: new Date().toISOString(),
      type: "form-submit",
      description: "FORM AUTO-SUBMIT detected — form submits automatically on page load (phishing credential harvester)",
      severity: "danger",
    });
  }
  if (hiddenRedirect) {
    timeline.push({
      time: "?",
      timestamp: new Date().toISOString(),
      type: "redirect",
      description: `HIDDEN REDIRECT via meta-refresh to: ${hiddenRedirect}`,
      severity: "warning",
    });
  }

  // Ordenar timeline por timestamp
  timeline.sort((a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime());

  // NUEVO: Resumen ejecutivo en lenguaje natural
  let summary = "";
  if (redirects.length > 0) {
    const crossDomainRedirects = redirects.filter(r => r.crossDomain);
    if (crossDomainRedirects.length > 0) {
      summary += `La URL original (${url.slice(0, 50)}) redirigió a ${redirects.length} URL(s) diferente(s), incluyendo ${crossDomainRedirects.length} redirección(es) a OTRO dominio. `;
      summary += `URL final: ${finalUrl.slice(0, 80)}. `;
    } else {
      summary += `La URL redirigió ${redirects.length} veces dentro del mismo dominio. URL final: ${finalUrl.slice(0, 80)}. `;
    }
  } else {
    summary += `La URL no redirigió. `;
  }
  if (popups.length > 0) {
    const crossDomainPopups = popups.filter(p => {
      try { return new URL(p.url).hostname !== new URL(url).hostname; } catch { return false; }
    });
    if (crossDomainPopups.length > 0) {
      summary += `Se abrieron ${popups.reduce((s, p) => s + p.count, 0)} ventana(s) nueva(s), ${crossDomainPopups.length} hacia OTRO dominio. `;
    } else {
      summary += `Se abrieron ${popups.reduce((s, p) => s + p.count, 0)} ventana(s) nueva(s). `;
    }
  }
  if (externalLinks.filter(l => !l.sameDomain).length > 0) {
    summary += `Se detectaron ${externalLinks.filter(l => !l.sameDomain).length} vínculo(s) externo(s) a ${[...new Set(externalLinks.filter(l => !l.sameDomain).map(l => l.domain))].slice(0, 5).join(", ")}. `;
  }
  if (cryptoMining.length > 0) summary += `Se detectó crypto mining (${cryptoMining.map(c => c.miner).join(", ")}). `;
  if (evalCalls.length > 0) summary += `Se ejecutaron ${evalCalls.length} llamada(s) eval/Function() (código ofuscado). `;
  if (formAutoSubmit) summary += `Se detectó auto-submit de formulario (posible robo de credenciales). `;
  if (webglFingerprint || canvasFingerprint) summary += `Se detectó fingerprinting del browser. `;
  if (errors.length > 5) summary += `Se capturaron ${errors.length} errores de JavaScript. `;
  if (summary === `La URL no redirigió. ` && popups.length === 0 && externalLinks.filter(l => !l.sameDomain).length === 0) {
    summary = `La URL se cargó normalmente sin redirecciones, ventanas nuevas, ni vínculos sospechosos. Comportamiento: NORMAL.`;
  }

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
  // NUEVO: redirects cross-domain = riesgo alto
  if (redirects.some(r => r.crossDomain)) score += 30;
  else if (redirects.length > 0) score += 10;
  // NUEVO: vínculos externos sospechosos
  if (externalLinks.filter(l => !l.sameDomain).length > 5) score += 10;
  score = Math.min(100, score);

  let classification: SandboxResult["riskClassification"];
  if (score >= 75) classification = "CRITICAL";
  else if (score >= 50) classification = "HIGH";
  else if (score >= 25) classification = "MEDIUM";
  else if (score >= 10) classification = "LOW";
  else classification = "SAFE";

  let verdict = "";
  if (redirects.length > 0) verdict += `${redirects.length} redirección(es) detectada(s). `;
  if (redirects.some(r => r.crossDomain)) verdict += `Redirección cross-domain — phishing indicator. `;
  if (popups.length > 0) verdict += `${popups.reduce((s, p) => s + p.count, 0)} ventana(s) nueva(s). `;
  if (cryptoMining.length > 0) verdict += `${cryptoMining.length} crypto miner(s). `;
  if (evalCalls.length > 0) verdict += `${evalCalls.length} eval/Function() call(s). `;
  if (webglFingerprint) verdict += "WebGL fingerprinting. ";
  if (canvasFingerprint) verdict += "Canvas fingerprinting. ";
  if (formAutoSubmit) verdict += "Auto-submit de formulario. ";
  if (hiddenRedirect) verdict += `Redirect oculto a ${hiddenRedirect}. `;
  if (externalLinks.filter(l => !l.sameDomain).length > 0) verdict += `${externalLinks.filter(l => !l.sameDomain).length} vínculo(s) externo(s). `;
  if (!verdict) verdict = "No se detectó comportamiento malicioso durante la ejecución de 20 segundos.";

  return {
    url, timestamp: new Date(startTime).toISOString(), duration: SANDBOX_DURATION,
    screenshots, videoBlobUrl, finalDom, finalTitle, finalUrl,
    network, console: consoleLog, errors, domMutations, cookies,
    localStorage: localStorageEntries, sessionStorage: sessionStorageEntries,
    popups, evalCalls, cryptoMining,
    webglFingerprint, canvasFingerprint, formAutoSubmit, hiddenRedirect, serviceWorker,
    redirects, timeline, externalLinks, behavior, summary,
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

  // Screenshots — only first 3 (inicio, medio, final)
  if (d.screenshots.length > 0) {
    sectionHeading("Screenshots (inicio, medio, final)");
    for (const s of d.screenshots.slice(0, 3)) {
      if (y > pageHeight - 300) { doc.addPage(); y = margin + 6; }
      try {
        const imgWidth = contentWidth;
        const imgHeight = imgWidth * (720 / 1280);
        doc.addImage(s, "PNG", margin, y, imgWidth, Math.min(imgHeight, 250));
        y += Math.min(imgHeight, 250) + 10;
      } catch {}
    }
  }

  // Resumen Ejecutivo (PRIORITARIO — al inicio del informe)
  sectionHeading("Resumen Ejecutivo");
  kvTable([
    ["Comportamiento", d.behavior],
    ["URL original", d.url.slice(0, 200)],
    ["URL final", d.finalUrl !== d.url ? d.finalUrl.slice(0, 200) : "(sin cambios)"],
    ["Redirecciones", `${d.redirects.length} (${d.redirects.filter(r => r.crossDomain).length} cross-domain)`],
    ["Ventanas nuevas", String(d.popups.reduce((s, p) => s + p.count, 0))],
    ["Vínculos externos", String(d.externalLinks.filter(l => !l.sameDomain).length)],
    ["Crypto mining", d.cryptoMining.length > 0 ? `SÍ — ${d.cryptoMining.map(c => c.miner).join(", ")}` : "no"],
    ["Eval/Function()", `${d.evalCalls.length} llamada(s)`],
    ["Form auto-submit", d.formAutoSubmit ? "SÍ — robo de credenciales" : "no"],
    ["Fingerprinting", [d.webglFingerprint ? "WebGL" : "", d.canvasFingerprint ? "Canvas" : ""].filter(Boolean).join(", ") || "no"],
    ["Resumen", d.summary],
  ]);

  // Redirecciones (PRIORITARIO)
  if (d.redirects.length > 0) {
    sectionHeading("Redirecciones Detectadas");
    autoTable(doc, { startY: y, head: [["Tiempo", "URL Origen", "→", "URL Destino", "Cross-Domain"]],
      body: d.redirects.map(r => [r.timestamp.slice(11, 19), r.from.slice(0, 100), "→", r.to.slice(0, 100), r.crossDomain ? "SÍ" : "no"]),
      theme: "grid", margin: { left: margin, right: margin },
      styles: { fontSize: 8, cellPadding: 4, textColor: [30, 41, 59], lineColor: [226, 232, 240], lineWidth: 0.5 },
      headStyles: { fillColor: [241, 245, 249], textColor: [71, 85, 105], fontStyle: "bold", fontSize: 10 },
    });
    // @ts-ignore
    y = (doc as any).lastAutoTable.finalY + 18;
  }

  // Timeline de Eventos (PRIORITARIO)
  sectionHeading("Timeline de Eventos");
  autoTable(doc, { startY: y, head: [["Tiempo", "Tipo", "Severidad", "Descripción"]],
    body: d.timeline.slice(0, 30).map(e => [e.time, e.type, e.severity, e.description.slice(0, 150)]),
    theme: "grid", margin: { left: margin, right: margin },
    styles: { fontSize: 8, cellPadding: 4, textColor: [30, 41, 59], lineColor: [226, 232, 240], lineWidth: 0.5 },
    headStyles: { fillColor: [241, 245, 249], textColor: [71, 85, 105], fontStyle: "bold", fontSize: 10 },
    columnStyles: { 0: { cellWidth: 40 }, 1: { cellWidth: 70 }, 2: { cellWidth: 60 } },
  });
  // @ts-ignore
  y = (doc as any).lastAutoTable.finalY + 18;

  // Vínculos Externos (PRIORITARIO)
  if (d.externalLinks.filter(l => !l.sameDomain).length > 0) {
    sectionHeading("Vínculos Externos Detectados");
    autoTable(doc, { startY: y, head: [["Dominio", "Texto", "URL"]],
      body: d.externalLinks.filter(l => !l.sameDomain).slice(0, 20).map(l => [l.domain, l.text.slice(0, 60), l.href.slice(0, 120)]),
      theme: "grid", margin: { left: margin, right: margin },
      styles: { fontSize: 8, cellPadding: 4, textColor: [30, 41, 59], lineColor: [226, 232, 240], lineWidth: 0.5 },
      headStyles: { fillColor: [241, 245, 249], textColor: [71, 85, 105], fontStyle: "bold", fontSize: 10 },
      columnStyles: { 0: { cellWidth: 120 } },
    });
    // @ts-ignore
    y = (doc as any).lastAutoTable.finalY + 18;
  }

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

          {/* NUEVO: Resumen Ejecutivo */}
          <Panel title="Resumen Ejecutivo" className="md:col-span-2">
            <div className="flex items-start gap-4 mb-3">
              <div className="shrink-0">
                <Badge
                  variant={data.behavior === "NORMAL" ? "secondary" : data.behavior === "MIXED_THREAT" || data.behavior === "PHISHING_REDIRECT" ? "destructive" : "default"}
                  className="font-mono text-xs"
                >
                  {data.behavior}
                </Badge>
              </div>
              <div className="flex-1">
                <p className="text-sm">{data.summary}</p>
              </div>
            </div>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-2 mt-2">
              <div className={`rounded p-2 border ${data.redirects.length > 0 ? "border-orange-500/40 bg-orange-500/10 text-orange-400" : "border-border bg-muted/20"}`}>
                <div className="text-xl font-bold font-mono">{data.redirects.length}</div>
                <div className="text-[10px]">redirecciones</div>
              </div>
              <div className={`rounded p-2 border ${data.popups.length > 0 ? "border-red-500/40 bg-red-500/10 text-red-400" : "border-border bg-muted/20"}`}>
                <div className="text-xl font-bold font-mono">{data.popups.reduce((s, p) => s + p.count, 0)}</div>
                <div className="text-[10px]">ventanas nuevas</div>
              </div>
              <div className={`rounded p-2 border ${data.externalLinks.filter(l => !l.sameDomain).length > 0 ? "border-purple-500/40 bg-purple-500/10 text-purple-400" : "border-border bg-muted/20"}`}>
                <div className="text-xl font-bold font-mono">{data.externalLinks.filter(l => !l.sameDomain).length}</div>
                <div className="text-[10px]">vínculos externos</div>
              </div>
              <div className="rounded p-2 border border-border bg-muted/20">
                <div className="text-xl font-bold font-mono text-cyan-400 break-all">{data.finalUrl !== data.url ? "→ " + data.finalUrl.slice(0, 40) : "sin cambios"}</div>
                <div className="text-[10px]">URL final</div>
              </div>
            </div>
          </Panel>

          {/* NUEVO: Timeline */}
          <Panel title={`Timeline de Eventos (${data.timeline.length})`} className="md:col-span-2">
            <div className="max-h-64 overflow-y-auto">
              {data.timeline.length > 0 ? (
                data.timeline.map((e, i) => (
                  <div key={i} className={`text-xs py-2 border-b border-border/30 flex items-start gap-3 ${
                    e.severity === "danger" ? "text-red-400" : e.severity === "warning" ? "text-orange-400" : "text-muted-foreground"
                  }`}>
                    <span className="font-mono text-[10px] shrink-0 w-12">{e.time}</span>
                    <Badge variant={e.severity === "danger" ? "destructive" : e.severity === "warning" ? "default" : "outline"} className="text-[9px] font-mono shrink-0">
                      {e.type}
                    </Badge>
                    <span className="flex-1">{e.description}</span>
                  </div>
                ))
              ) : (
                <p className="text-sm text-muted-foreground">No se capturaron eventos.</p>
              )}
            </div>
          </Panel>

          {/* NUEVO: Redirecciones detectadas */}
          {data.redirects.length > 0 && (
            <Panel title={`Redirecciones Detectadas (${data.redirects.length})`} className="md:col-span-2">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead className="w-16">Tiempo</TableHead>
                    <TableHead>URL Origen</TableHead>
                    <TableHead className="w-8 text-center">→</TableHead>
                    <TableHead>URL Destino</TableHead>
                    <TableHead className="w-24">Cross-Domain</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {data.redirects.map((r, i) => (
                    <TableRow key={i} className={r.crossDomain ? "bg-red-500/5" : ""}>
                      <TableCell className="font-mono text-xs">{r.timestamp.slice(11, 19)}</TableCell>
                      <TableCell className="font-mono text-xs break-all">{r.from.slice(0, 100)}</TableCell>
                      <TableCell className="text-center text-muted-foreground">→</TableCell>
                      <TableCell className="font-mono text-xs break-all">{r.to.slice(0, 100)}</TableCell>
                      <TableCell>
                        {r.crossDomain ? (
                          <Badge variant="destructive" className="text-[9px] font-mono">SÍ — phishing risk</Badge>
                        ) : (
                          <Badge variant="secondary" className="text-[9px] font-mono">no</Badge>
                        )}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </Panel>
          )}

          {/* NUEVO: Vínculos Externos */}
          {data.externalLinks.length > 0 && (
            <Panel title={`Vínculos Detectados (${data.externalLinks.length})`} className="md:col-span-2">
              <div className="grid grid-cols-2 md:grid-cols-3 gap-2">
                {data.externalLinks.slice(0, 30).map((l, i) => (
                  <div key={i} className={`rounded p-2 border text-xs ${l.sameDomain ? "border-border bg-muted/20" : "border-purple-500/40 bg-purple-500/5"}`}>
                    <div className="flex items-center gap-1 mb-1">
                      {l.sameDomain ? (
                        <Badge variant="secondary" className="text-[9px] font-mono">interno</Badge>
                      ) : (
                        <Badge variant="outline" className="text-[9px] font-mono text-purple-400 border-purple-500/40">externo</Badge>
                      )}
                      <span className="font-mono text-[10px] text-muted-foreground truncate">{l.domain}</span>
                    </div>
                    <a href={l.href} target="_blank" rel="noreferrer" className="text-cyan-500 hover:underline break-all">
                      {l.text || l.href.slice(0, 60)}
                    </a>
                  </div>
                ))}
              </div>
            </Panel>
          )}

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
                  20-second session recording · {data.screenshots.length} frames captured · WebM format
                </div>
              </div>
            ) : (
              <div className="flex flex-col items-center justify-center py-8 gap-2 text-muted-foreground">
                <Video className="w-8 h-8" />
                <p className="text-sm">Video recording was not available in this session.</p>
                <p className="text-xs">This happens when the browser blocks screen capture. On your next run, allow screen sharing when prompted to get a real video of the sandbox session.</p>
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
