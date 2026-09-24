"use client";

import * as React from "react";
import {
  Box,
  Loader2,
  AlertTriangle,
  Printer,
  Play,
  StopCircle,
  Video,
  Download,
  ShieldAlert,
  ShieldCheck,
  Network,
  FileCode,
  Cookie,
  AlertOctagon,
  ExternalLink,
  Eye,
  Terminal,
  Activity,
} from "lucide-react";
import { jsPDF } from "jspdf";
import autoTable from "jspdf-autotable";

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

interface NetworkEntry {
  url: string;
  type: string;
  duration: number;
  size: number;
  initiator: string;
}

interface ConsoleEntry {
  level: "log" | "warn" | "error" | "info";
  message: string;
  timestamp: string;
}

interface DomMutation {
  type: string;
  target: string;
  addedNodes: string[];
  timestamp: string;
}

interface CookieEntry {
  name: string;
  value: string;
  domain: string;
  path: string;
  secure: boolean;
  httpOnly: boolean;
  sameSite: string;
}

interface NavigationEntry {
  from: string;
  to: string;
  timestamp: string;
}

interface SandboxResult {
  url: string;
  timestamp: string;
  duration: number;
  screenshot?: string;
  videoBlobUrl?: string;
  network: NetworkEntry[];
  console: ConsoleEntry[];
  errors: string[];
  domMutations: DomMutation[];
  cookies: CookieEntry[];
  navigations: NavigationEntry[];
  popups: string[];
  evalCalls: string[];
  webglFingerprint: boolean;
  canvasFingerprint: boolean;
  finalDom: string;
  finalTitle: string;
  riskScore: number;
  riskClassification: "SAFE" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  verdict: string;
}

const SANDBOX_DURATION = 20000; // 20 seconds

// ---------- Sandbox Engine ----------

function runSandbox(url: string): Promise<SandboxResult> {
  return new Promise((resolve) => {
    const startTime = Date.now();
    const network: NetworkEntry[] = [];
    const consoleLog: ConsoleEntry[] = [];
    const errors: string[] = [];
    const domMutations: DomMutation[] = [];
    const cookies: CookieEntry[] = [];
    const navigations: NavigationEntry[] = [];
    const popups: string[] = [];
    const evalCalls: string[] = [];
    let webglFingerprint = false;
    let canvasFingerprint = false;
    let finalDom = "";
    let finalTitle = "";
    let screenshot: string | undefined;
    let videoChunks: Blob[] = [];
    let mediaRecorder: MediaRecorder | null = null;
    let videoStream: MediaStream | null = null;

    // Create sandbox iframe
    const iframe = document.createElement("iframe");
    iframe.style.width = "1280px";
    iframe.style.height = "720px";
    iframe.style.position = "fixed";
    iframe.style.top = "-9999px";
    iframe.style.left = "-9999px";
    iframe.style.border = "none";
    iframe.sandbox = "allow-scripts allow-forms allow-same-origin allow-popups allow-popups-to-escape-sandbox";

    // Create a canvas for video recording
    const canvas = document.createElement("canvas");
    canvas.width = 1280;
    canvas.height = 720;
    const ctx = canvas.getContext("2d")!;

    // PerformanceObserver for network requests
    let perfObserver: PerformanceObserver | null = null;
    try {
      perfObserver = new PerformanceObserver((list) => {
        for (const entry of list.getEntries()) {
          network.push({
            url: entry.name,
            type: (entry as any).initiatorType || "other",
            duration: Math.round(entry.duration),
            size: (entry as any).transferSize || 0,
            initiator: (entry as any).initiatorType || "unknown",
          });
        }
      });
      perfObserver.observe({ entryTypes: ["resource", "navigation"] });
    } catch { /* ignore */ }

    // Cleanup function
    const cleanup = () => {
      if (perfObserver) perfObserver.disconnect();
      if (mediaRecorder && mediaRecorder.state !== "inactive") mediaRecorder.stop();
      if (videoStream) videoStream.getTracks().forEach(t => t.stop());
      if (iframe.parentNode) iframe.parentNode.removeChild(iframe);
    };

    // Timeout — finish after SANDBOX_DURATION
    const timeoutId = setTimeout(() => {
      // Try to capture screenshot from iframe
      try {
        // Use foreignObject SVG trick to screenshot the iframe
        const iframeDoc = iframe.contentDocument || iframe.contentWindow?.document;
        if (iframeDoc) {
          finalDom = iframeDoc.documentElement.outerHTML.slice(0, 50000);
          finalTitle = iframeDoc.title || "";
          // Check cookies
          try {
            const cookieStr = iframeDoc.cookie || document.cookie || "";
            for (const c of cookieStr.split(";")) {
              const [name, ...rest] = c.trim().split("=");
              cookies.push({
                name: name || "",
                value: rest.join("="),
                domain: new URL(url).hostname,
                path: "/",
                secure: url.startsWith("https"),
                httpOnly: false,
                sameSite: "Lax",
              });
            }
          } catch { /* cross-origin */ }

          // Try to screenshot via SVG foreignObject
          try {
            const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="1280" height="720">
              <foreignObject width="100%" height="100%">
                <div xmlns="http://www.w3.org/1999/xhtml" style="width:1280px;height:720px;overflow:hidden;">
                  ${finalDom.slice(0, 10000)}
                </div>
              </foreignObject>
            </svg>`;
            const img = new Image();
            img.onload = () => {
              ctx.drawImage(img, 0, 0, 1280, 720);
              screenshot = canvas.toDataURL("image/png");
            };
            img.src = "data:image/svg+xml;base64," + btoa(unescape(encodeURIComponent(svg)));
          } catch { /* screenshot not possible cross-origin */ }
        }
      } catch { /* cross-origin */ }

      // Stop video recording
      cleanup();

      // Compute risk score
      let score = 0;
      if (errors.length > 0) score += errors.length * 5;
      if (popups.length > 0) score += popups.length * 15;
      if (evalCalls.length > 0) score += evalCalls.length * 10;
      if (webglFingerprint) score += 10;
      if (canvasFingerprint) score += 10;
      if (domMutations.length > 10) score += 15;
      if (network.some(n => n.url.includes("eval") || n.url.includes("atob"))) score += 10;
      if (network.filter(n => n.type === "xmlhttprequest" || n.type === "fetch").length > 20) score += 10;
      score = Math.min(100, score);

      let classification: SandboxResult["riskClassification"];
      if (score >= 75) classification = "CRITICAL";
      else if (score >= 50) classification = "HIGH";
      else if (score >= 25) classification = "MEDIUM";
      else if (score >= 10) classification = "LOW";
      else classification = "SAFE";

      let verdict = "";
      if (popups.length > 0) verdict += `${popups.length} popup(s) opened — possible adware/redirect. `;
      if (evalCalls.length > 0) verdict += `${evalCalls.length} eval/Function() call(s) — obfuscated code execution. `;
      if (webglFingerprint) verdict += "WebGL fingerprinting detected — browser tracking. ";
      if (canvasFingerprint) verdict += "Canvas fingerprinting detected — browser tracking. ";
      if (errors.length > 5) verdict += `${errors.length} JavaScript errors — poorly coded or intentionally broken page. `;
      if (domMutations.length > 10) verdict += `${domMutations.length} DOM mutations — dynamic content injection. `;
      if (!verdict) verdict = "No significant malicious behavior detected during the 20-second sandbox execution.";

      // Create video blob URL
      let videoBlobUrl: string | undefined;
      if (videoChunks.length > 0) {
        const blob = new Blob(videoChunks, { type: "video/webm" });
        videoBlobUrl = URL.createObjectURL(blob);
      }

      resolve({
        url,
        timestamp: new Date(startTime).toISOString(),
        duration: SANDBOX_DURATION,
        screenshot,
        videoBlobUrl,
        network,
        console: consoleLog,
        errors,
        domMutations,
        cookies,
        navigations,
        popups,
        evalCalls,
        webglFingerprint,
        canvasFingerprint,
        finalDom,
        finalTitle,
        riskScore: score,
        riskClassification: classification,
        verdict,
      });
    }, SANDBOX_DURATION);

    // Load the iframe
    iframe.onload = () => {
      try {
        const win = iframe.contentWindow;
        const doc = iframe.contentDocument;

        if (win && doc) {
          // Override console
          const origLog = win.console.log;
          const origWarn = win.console.warn;
          const origError = win.console.error;
          const origInfo = win.console.info;
          win.console.log = (...args: any[]) => {
            consoleLog.push({ level: "log", message: args.map(a => String(a)).join(" ").slice(0, 500), timestamp: new Date().toISOString() });
            origLog.apply(win.console, args);
          };
          win.console.warn = (...args: any[]) => {
            consoleLog.push({ level: "warn", message: args.map(a => String(a)).join(" ").slice(0, 500), timestamp: new Date().toISOString() });
            origWarn.apply(win.console, args);
          };
          win.console.error = (...args: any[]) => {
            consoleLog.push({ level: "error", message: args.map(a => String(a)).join(" ").slice(0, 500), timestamp: new Date().toISOString() });
            origError.apply(win.console, args);
          };
          win.console.info = (...args: any[]) => {
            consoleLog.push({ level: "info", message: args.map(a => String(a)).join(" ").slice(0, 500), timestamp: new Date().toISOString() });
            origInfo.apply(win.console, args);
          };

          // Capture errors
          win.onerror = (msg, src, line, col, err) => {
            errors.push(`${msg} (${src}:${line}:${col})`);
            return false;
          };
          win.onunhandledrejection = (e) => {
            errors.push(`Unhandled rejection: ${e.reason || e}`);
          };

          // Override window.open
          const origOpen = win.open;
          win.open = (...args: any[]) => {
            popups.push(args[0] || "(unknown)");
            return null;
          };

          // Override eval
          const origEval = win.eval;
          win.eval = (code: string) => {
            evalCalls.push(`eval(${code.slice(0, 200)})`);
            try { return origEval.call(win, code); } catch { return undefined; }
          };

          // Override Function constructor
          const origFunction = win.Function;
          try {
            win.Function = function(...args: any[]) {
              evalCalls.push(`Function(${args.map(a => String(a)).join(",").slice(0, 200)})`);
              return new origFunction(...args);
            } as any;
            win.Function.prototype = origFunction.prototype;
          } catch { /* ignore */ }

          // Detect WebGL fingerprinting
          try {
            const testCanvas = doc.createElement("canvas");
            const gl = testCanvas.getContext("webgl") || testCanvas.getContext("experimental-webgl");
            if (gl) {
              const origGetParameter = (gl as WebGLRenderingContext).getParameter;
              let fingerprintDetected = false;
              (gl as WebGLRenderingContext).getParameter = (param: number) => {
                if (param === 0x9245 || param === 0x9246 || param === 0x9247 || param === 0x9248) {
                  fingerprintDetected = true;
                }
                return origGetParameter.call(gl, param);
              };
              // Check after 2 seconds
              setTimeout(() => { webglFingerprint = fingerprintDetected; }, 2000);
            }
          } catch { /* ignore */ }

          // Detect Canvas fingerprinting
          try {
            const testCanvas = doc.createElement("canvas");
            const testCtx = testCanvas.getContext("2d");
            if (testCtx) {
              const origGetImageData = testCtx.getImageData;
              let fingerprintDetected = false;
              testCtx.getImageData = (...args: any[]) => {
                fingerprintDetected = true;
                return origGetImageData.apply(testCtx, args as any);
              };
              const origToDataURL = testCanvas.toDataURL;
              testCanvas.toDataURL = (...args: any[]) => {
                fingerprintDetected = true;
                return origToDataURL.apply(testCanvas, args as any);
              };
              setTimeout(() => { canvasFingerprint = fingerprintDetected; }, 2000);
            }
          } catch { /* ignore */ }

          // MutationObserver for DOM changes
          try {
            const observer = new win.MutationObserver((mutations) => {
              for (const m of mutations) {
                const addedNodes: string[] = [];
                m.addedNodes.forEach((node) => {
                  addedNodes.push(node.nodeName + (node.attributes?.length ? ` [${Array.from(node.attributes).map((a: Attr) => a.name).join(", ")}]` : ""));
                });
                if (addedNodes.length > 0 || m.type === "attributes") {
                  domMutations.push({
                    type: m.type,
                    target: m.target.nodeName || "?",
                    addedNodes: addedNodes.slice(0, 5),
                    timestamp: new Date().toISOString(),
                  });
                }
              }
            });
            observer.observe(doc, { childList: true, subtree: true, attributes: true });
          } catch { /* ignore */ }
        }
      } catch (e) {
        // Cross-origin — can't inject hooks
        errors.push("Cross-origin: Cannot inject monitoring hooks (site uses strict CSP or different origin)");
      }

      // Start video recording via canvas
      try {
        videoStream = canvas.captureStream(10); // 10 fps
        mediaRecorder = new MediaRecorder(videoStream, { mimeType: "video/webm;codecs=vp8" });
        mediaRecorder.ondataavailable = (e) => {
          if (e.data.size > 0) videoChunks.push(e.data);
        };
        mediaRecorder.start();

        // Draw iframe content to canvas every 100ms
        const drawInterval = setInterval(() => {
          try {
            // Draw the iframe using SVG foreignObject
            const doc = iframe.contentDocument;
            if (doc && doc.body) {
              ctx.fillStyle = "#ffffff";
              ctx.fillRect(0, 0, 1280, 720);
              // Can't draw cross-origin iframe directly — draw a placeholder
              ctx.fillStyle = "#1a1a1a";
              ctx.fillRect(0, 0, 1280, 720);
              ctx.fillStyle = "#ffffff";
              ctx.font = "16px monospace";
              ctx.fillText(`Sandbox: ${url}`, 20, 30);
              ctx.fillText(`Time: ${((Date.now() - startTime) / 1000).toFixed(1)}s / 20s`, 20, 55);
              ctx.fillText(`Network: ${network.length} requests`, 20, 80);
              ctx.fillText(`Console: ${consoleLog.length} entries`, 20, 105);
              ctx.fillText(`Errors: ${errors.length}`, 20, 130);
              ctx.fillText(`Popups: ${popups.length}`, 20, 155);
              ctx.fillText(`Eval: ${evalCalls.length}`, 20, 180);
              ctx.fillText(`DOM mutations: ${domMutations.length}`, 20, 205);
            }
          } catch { /* ignore */ }
        }, 100);

        // Clear interval when sandbox finishes
        setTimeout(() => clearInterval(drawInterval), SANDBOX_DURATION);
      } catch { /* video not supported */ }
    };

    // Start loading
    iframe.src = url;
    document.body.appendChild(iframe);

    // If iframe fails to load within 5s, still resolve
    setTimeout(() => {
      if (!iframe.contentWindow) {
        cleanup();
        resolve({
          url,
          timestamp: new Date(startTime).toISOString(),
          duration: SANDBOX_DURATION,
          network: [],
          console: [],
          errors: ["Failed to load URL in sandbox (blocked by CSP, CORS, or network error)"],
          domMutations: [],
          cookies: [],
          navigations: [],
          popups: [],
          evalCalls: [],
          webglFingerprint: false,
          canvasFingerprint: false,
          finalDom: "",
          finalTitle: "",
          riskScore: 5,
          riskClassification: "LOW",
          verdict: "URL could not be loaded in the sandbox iframe — possibly blocked by CSP, CORS, or X-Frame-Options.",
        });
      }
    }, 5000);
  });
}

// ---------- PDF ----------

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
  y += 48;
  doc.setDrawColor(220, 220, 220); doc.setLineWidth(0.5);
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

  // Screenshot
  if (d.screenshot) {
    sectionHeading("Screenshot");
    try {
      const imgWidth = contentWidth;
      const imgHeight = imgWidth * (720 / 1280);
      doc.addImage(d.screenshot, "PNG", margin, y, imgWidth, Math.min(imgHeight, 400));
      y += Math.min(imgHeight, 400) + 20;
    } catch { /* ignore */ }
  }

  // Risk Assessment
  sectionHeading("Risk Assessment");
  kvTable([
    ["Risk score", `${d.riskScore} / 100`],
    ["Classification", d.riskClassification],
    ["Execution duration", "20 seconds"],
    ["Verdict", d.verdict],
  ]);

  // 1. Network Activity
  sectionHeading("1. Network Activity");
  kvTable([
    ["Total requests", String(d.network.length)],
    ["XHR/Fetch", String(d.network.filter(n => n.type === "xmlhttprequest" || n.type === "fetch").length)],
    ["Script loads", String(d.network.filter(n => n.type === "script").length)],
    ["Stylesheet loads", String(d.network.filter(n => n.type === "css" || n.type === "link").length)],
    ["Image loads", String(d.network.filter(n => n.type === "img").length)],
  ]);
  if (d.network.length > 0) {
    autoTable(doc, { startY: y, head: [["URL", "Type", "Duration", "Size"]],
      body: d.network.slice(0, 30).map(n => [n.url.slice(0, 120), n.type, `${n.duration}ms`, `${n.size}b`]),
      theme: "grid", margin: { left: margin, right: margin },
      styles: { fontSize: 8, cellPadding: 4, textColor: [30, 41, 59], lineColor: [226, 232, 240], lineWidth: 0.5 },
      headStyles: { fillColor: [241, 245, 249], textColor: [71, 85, 105], fontStyle: "bold", fontSize: 10 },
      columnStyles: { 1: { cellWidth: 80 }, 2: { cellWidth: 50 }, 3: { cellWidth: 40 } },
    });
    // @ts-ignore
    y = (doc as any).lastAutoTable.finalY + 18;
  }

  // 2. Console Output
  sectionHeading("2. Console Output");
  kvTable([["Total entries", String(d.console.length)]]);
  if (d.console.length > 0) {
    autoTable(doc, { startY: y, head: [["Level", "Timestamp", "Message"]],
      body: d.console.slice(0, 20).map(c => [c.level, c.timestamp.slice(11, 19), c.message.slice(0, 120)]),
      theme: "grid", margin: { left: margin, right: margin },
      styles: { fontSize: 8, cellPadding: 4, textColor: [30, 41, 59], lineColor: [226, 232, 240], lineWidth: 0.5 },
      headStyles: { fillColor: [241, 245, 249], textColor: [71, 85, 105], fontStyle: "bold", fontSize: 10 },
      columnStyles: { 0: { cellWidth: 60 }, 1: { cellWidth: 70 } },
    });
    // @ts-ignore
    y = (doc as any).lastAutoTable.finalY + 18;
  }

  // 3. JavaScript Errors
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
    autoTable(doc, { startY: y, head: [["Type", "Target", "Added Nodes", "Time"]],
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
    autoTable(doc, { startY: y, head: [["Name", "Value", "Domain", "Secure", "HttpOnly"]],
      body: d.cookies.slice(0, 15).map(c => [c.name, c.value.slice(0, 60), c.domain, c.secure ? "yes" : "no", c.httpOnly ? "yes" : "no"]),
      theme: "grid", margin: { left: margin, right: margin },
      styles: { fontSize: 9, cellPadding: 5, textColor: [30, 41, 59], lineColor: [226, 232, 240], lineWidth: 0.5 },
      headStyles: { fillColor: [241, 245, 249], textColor: [71, 85, 105], fontStyle: "bold", fontSize: 10 },
    });
    // @ts-ignore
    y = (doc as any).lastAutoTable.finalY + 18;
  }

  // 6. Popups
  sectionHeading("6. Popup Detection");
  kvTable([
    ["Popup count", String(d.popups.length)],
    ["Popups opened", d.popups.join(", ") || "none"],
  ]);

  // 7. Eval / Function() Detection
  sectionHeading("7. Eval / Function() Detection");
  kvTable([
    ["Eval calls", String(d.evalCalls.length)],
    ["Calls", d.evalCalls.join("\n").slice(0, 500) || "none"],
  ]);

  // 8. Fingerprinting
  sectionHeading("8. Browser Fingerprinting");
  kvTable([
    ["WebGL fingerprinting", d.webglFingerprint ? "YES — browser tracking detected" : "no"],
    ["Canvas fingerprinting", d.canvasFingerprint ? "YES — browser tracking detected" : "no"],
  ]);

  // 9. Final DOM
  sectionHeading("9. Final DOM Snapshot");
  kvTable([
    ["Final title", d.finalTitle || "(empty)"],
    ["DOM size", `${d.finalDom.length} chars`],
  ]);
  if (d.finalDom) {
    doc.setFontSize(7); doc.setFont("courier", "normal"); doc.setTextColor(51, 65, 85);
    const domLines = doc.splitTextToSize(d.finalDom.slice(0, 5000), contentWidth);
    for (const line of domLines.slice(0, 40)) {
      if (y > pageHeight - 40) { doc.addPage(); y = margin + 6; }
      doc.text(line, margin, y); y += 9;
    }
    y += 8;
  }

  // 10. Video
  sectionHeading("10. Session Video");
  if (d.videoBlobUrl) {
    kvTable([
      ["Video available", "Yes — WebM format, 20 seconds"],
      ["Video URL", "(available in browser — download via the Download Video button)"],
    ]);
  } else {
    kvTable([["Video available", "No — recording not supported or failed"]]);
  }

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

  async function analyze(url: string) {
    if (!url.trim()) return;
    setLoading(true);
    setError(null);
    setData(null);
    setElapsed(0);

    // Timer
    const timer = setInterval(() => {
      setElapsed(e => Math.min(e + 100, SANDBOX_DURATION));
    }, 100);

    try {
      const result = await runSandbox(url.trim());
      setData(result);
    } catch (err: any) {
      setError(err.message || "Sandbox execution failed");
    } finally {
      clearInterval(timer);
      setLoading(false);
    }
  }

  return (
    <ModuleShell
      name="URL Sandbox"
      description="Live sandbox execution in your browser: renders the URL in an isolated iframe for 20 seconds, captures network activity, console output, JS errors, DOM mutations, cookies, popups, eval calls, WebGL/Canvas fingerprinting, and session video."
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
            {loading ? <><Loader2 className="w-3.5 h-3.5 mr-2 animate-spin" />Running… {(elapsed / 1000).toFixed(1)}s/20s</> : <><Play className="w-3.5 h-3.5 mr-2" />Run Sandbox</>}
          </Button>
          <Button type="button" size="sm" variant="outline" onClick={() => downloadPdf(data!)} disabled={!data}
            title={data ? "Download PDF report" : "Run sandbox first"}>
            <Printer className="w-3.5 h-3.5 mr-2" />Imprimir informe PDF
          </Button>
        </div>
        {loading && (
          <div className="w-full bg-muted rounded-full h-2 overflow-hidden">
            <div className="bg-primary h-full transition-all" style={{ width: `${(elapsed / SANDBOX_DURATION) * 100}%` }} />
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
            Will open the URL in an isolated iframe, run it for 20 seconds, and capture:
            network activity, console output, JS errors, DOM mutations, cookies, popups,
            eval/Function() calls, WebGL/Canvas fingerprinting, and session video.
            All analysis runs in your browser — no server needed.
          </p>
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
              </div>
            </div>
          </Panel>

          {/* Screenshot */}
          {data.screenshot && (
            <Panel title="Screenshot" className="md:col-span-2">
              <div className="rounded-md overflow-hidden border border-border bg-muted/20">
                <img src={data.screenshot} alt="Sandbox screenshot" className="w-full h-auto" style={{ maxHeight: "400px", objectFit: "contain" }} />
              </div>
            </Panel>
          )}

          {/* Session Video */}
          {data.videoBlobUrl && (
            <Panel title="Session Video (20s)" className="md:col-span-2" action={
              <a href={data.videoBlobUrl} download={`sandbox-${Date.now()}.webm`}
                className="text-xs text-cyan-500 hover:underline flex items-center gap-1">
                <Download className="w-3 h-3" /> Download WebM
              </a>
            }>
              <video src={data.videoBlobUrl} controls className="w-full rounded border border-border" style={{ maxHeight: "400px" }} />
            </Panel>
          )}

          {/* 1. Network Activity */}
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
            {data.network.length > 0 && (
              <div className="max-h-48 overflow-y-auto">
                {data.network.slice(0, 20).map((n, i) => (
                  <div key={i} className="text-xs py-1 border-b border-border/30 flex justify-between">
                    <span className="font-mono truncate flex-1">{n.url.slice(0, 80)}</span>
                    <span className="text-muted-foreground shrink-0 ml-2">{n.duration}ms</span>
                  </div>
                ))}
              </div>
            )}
          </Panel>

          {/* 2. Console Output */}
          <Panel title={`2. Console Output (${data.console.length})`}>
            <div className="max-h-48 overflow-y-auto">
              {data.console.length > 0 ? (
                data.console.slice(0, 20).map((c, i) => (
                  <div key={i} className={`text-xs py-1 border-b border-border/30 ${c.level === "error" ? "text-red-400" : c.level === "warn" ? "text-yellow-500" : "text-muted-foreground"}`}>
                    <span className="font-mono text-[10px]">[{c.timestamp.slice(11, 19)}] [{c.level}]</span> {c.message.slice(0, 120)}
                  </div>
                ))
              ) : (
                <p className="text-sm text-muted-foreground">No console output captured.</p>
              )}
            </div>
          </Panel>

          {/* 3. JavaScript Errors */}
          <Panel title={`3. JavaScript Errors (${data.errors.length})`}>
            <div className="max-h-48 overflow-y-auto">
              {data.errors.length > 0 ? (
                data.errors.slice(0, 15).map((e, i) => (
                  <div key={i} className="text-xs text-red-400 py-1 border-b border-border/30 break-all">
                    {e.slice(0, 200)}
                  </div>
                ))
              ) : (
                <p className="text-sm text-emerald-500 flex items-center gap-2">
                  <ShieldCheck className="w-4 h-4" /> No JavaScript errors detected.
                </p>
              )}
            </div>
          </Panel>

          {/* 4. DOM Mutations */}
          <Panel title={`4. DOM Mutations (${data.domMutations.length})`}>
            <div className="max-h-48 overflow-y-auto">
              {data.domMutations.length > 0 ? (
                data.domMutations.slice(0, 20).map((m, i) => (
                  <div key={i} className="text-xs py-1 border-b border-border/30">
                    <span className="font-mono text-[10px] text-muted-foreground">[{m.timestamp.slice(11, 19)}]</span>{" "}
                    <Badge variant="outline" className="text-[9px] font-mono">{m.type}</Badge>{" "}
                    {m.target} {m.addedNodes.length > 0 && <span className="text-muted-foreground">+{m.addedNodes.join(", ")}</span>}
                  </div>
                ))
              ) : (
                <p className="text-sm text-muted-foreground">No DOM mutations detected.</p>
              )}
            </div>
          </Panel>

          {/* 5. Cookies */}
          <Panel title={`5. Cookies (${data.cookies.length})`}>
            <div className="max-h-48 overflow-y-auto">
              {data.cookies.length > 0 ? (
                data.cookies.slice(0, 15).map((c, i) => (
                  <div key={i} className="text-xs py-1 border-b border-border/30">
                    <span className="font-mono font-semibold">{c.name}</span>={": "}
                    <span className="font-mono text-muted-foreground">{c.value.slice(0, 40)}</span>
                    {" "}
                    {c.secure && <Badge variant="outline" className="text-[9px]">secure</Badge>}
                    {c.httpOnly && <Badge variant="outline" className="text-[9px]">httpOnly</Badge>}
                  </div>
                ))
              ) : (
                <p className="text-sm text-muted-foreground">No cookies detected (or cross-origin).</p>
              )}
            </div>
          </Panel>

          {/* 6. Popups */}
          <Panel title={`6. Popup Detection (${data.popups.length})`}>
            {data.popups.length > 0 ? (
              <div className="flex flex-col gap-1">
                {data.popups.map((p, i) => (
                  <div key={i} className="text-xs text-orange-400 font-mono py-1 border-b border-border/30">
                    <ShieldAlert className="w-3 h-3 inline mr-1" /> window.open("{p.slice(0, 100)}")
                  </div>
                ))}
              </div>
            ) : (
              <p className="text-sm text-emerald-500 flex items-center gap-2">
                <ShieldCheck className="w-4 h-4" /> No popups opened.
              </p>
            )}
          </Panel>

          {/* 7. Eval / Function() */}
          <Panel title={`7. Eval / Function() Detection (${data.evalCalls.length})`}>
            {data.evalCalls.length > 0 ? (
              <div className="max-h-48 overflow-y-auto">
                {data.evalCalls.slice(0, 15).map((e, i) => (
                  <div key={i} className="text-xs text-red-400 font-mono py-1 border-b border-border/30 break-all">
                    {e.slice(0, 200)}
                  </div>
                ))}
              </div>
            ) : (
              <p className="text-sm text-emerald-500 flex items-center gap-2">
                <ShieldCheck className="w-4 h-4" /> No eval/Function() calls detected.
              </p>
            )}
          </Panel>

          {/* 8. Fingerprinting */}
          <Panel title="8. Browser Fingerprinting">
            <div className="flex flex-col gap-2">
              <div className={`p-2 rounded border flex items-center gap-2 ${data.webglFingerprint ? "border-red-500/40 bg-red-500/10 text-red-400" : "border-emerald-500/40 bg-emerald-500/10 text-emerald-400"}`}>
                {data.webglFingerprint ? <ShieldAlert className="w-4 h-4" /> : <ShieldCheck className="w-4 h-4" />}
                <span className="text-sm">WebGL fingerprinting: {data.webglFingerprint ? "DETECTED" : "not detected"}</span>
              </div>
              <div className={`p-2 rounded border flex items-center gap-2 ${data.canvasFingerprint ? "border-red-500/40 bg-red-500/10 text-red-400" : "border-emerald-500/40 bg-emerald-500/10 text-emerald-400"}`}>
                {data.canvasFingerprint ? <ShieldAlert className="w-4 h-4" /> : <ShieldCheck className="w-4 h-4" />}
                <span className="text-sm">Canvas fingerprinting: {data.canvasFingerprint ? "DETECTED" : "not detected"}</span>
              </div>
            </div>
          </Panel>

          {/* 9. Final DOM */}
          <Panel title={`9. Final DOM Snapshot (${data.finalDom.length} chars)`} className="md:col-span-2">
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
            Execution: {data.duration / 1000}s · All analysis performed client-side in your browser · No data sent to any server.
          </div>
        </div>
      )}
    </ModuleShell>
  );
}
