// TakeDown Monitor — server-side HTTP check of a URL to detect if
// it's still active, suspended, blocked, deleted, or down.
//
// GET /api/takedown/monitor?url=<url>
//
// Classification based on HTTP status + final URL + title:
//   - "ACTIVA": HTTP 200 + content looks like a real page
//   - "SUSPENDIDA": HTTP 200 + title contains "suspended/blocked/account"
//       OR HTTP 301/302 + final URL contains "suspension/security"
//   - "BANEADA": HTTP 403 (hosting blocked the access)
//   - "BORRADA": HTTP 404 or 410 (files deleted)
//   - "SERVIDOR_CAIDO": HTTP 500, 502, 503 (server collapsed)
//   - "SERVIDOR_APAGADO": Network timeout (server powered off)
//   - "DOMINIO_ELIMINADO": DNS error / domain doesn't resolve
//   - "DOMINIO_CADUCO": SSL certificate error / domain expired
//   - "ERROR": Some other unexpected error

import { NextResponse } from "next/server";

interface MonitorResult {
  url: string;
  httpStatus: number | null;
  finalUrl: string | null;
  title: string | null;
  classification: string;
  classificationColor: "red" | "green" | "yellow" | "gray";
  classificationReason: string;
  error?: string;
  timestamp: string;
}

const SUSPENDED_KEYWORDS = [
  "suspended", "account suspended", "account has been suspended",
  "this account has been suspended", "site suspended", "blocked",
  "access denied", "site blocked", "page blocked",
  "this domain has been suspended", "forbidden",
];

const SECURITY_KEYWORDS = [
  "suspension", "security", "abuse", "phishing", "deceptive",
  "dangerous", "harmful", "blocked by", "reported",
];

export async function GET(request: Request) {
  const { searchParams } = new URL(request.url);
  const targetUrl = (searchParams.get("url") || "").trim();
  if (!targetUrl) {
    return NextResponse.json({ error: "missing_url" }, { status: 400 });
  }

  const result: MonitorResult = {
    url: targetUrl,
    httpStatus: null,
    finalUrl: null,
    title: null,
    classification: "ERROR",
    classificationColor: "gray",
    classificationReason: "",
    timestamp: new Date().toISOString(),
  };

  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 12000);
    const r = await fetch(targetUrl, {
      redirect: "follow",
      signal: controller.signal,
      headers: {
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        Accept: "text/html,application/xhtml+xml,*/*;q=0.8",
      },
    });
    clearTimeout(timeout);

    result.httpStatus = r.status;
    result.finalUrl = r.url || targetUrl;

    // Get the title from the HTML (only if HTML)
    const contentType = r.headers.get("content-type") || "";
    if (contentType.includes("text/html") || contentType.includes("application/xhtml")) {
      const html = await r.text();
      const titleMatch = html.match(/<title[^>]*>([^<]*)<\/title>/i);
      result.title = titleMatch ? titleMatch[1].trim().slice(0, 200) : null;
    }

    // Classify based on status code + title + final URL
    const titleLower = (result.title || "").toLowerCase();
    const finalUrlLower = (result.finalUrl || "").toLowerCase();

    if (r.status === 200) {
      // Check if title contains suspension keywords
      const isSuspended = SUSPENDED_KEYWORDS.some(kw => titleLower.includes(kw));
      if (isSuspended) {
        result.classification = "SUSPENDIDA";
        result.classificationColor = "green";
        result.classificationReason = `HTTP 200 + titulo contiene palabra de suspencion (hosting la bloqueo)`;
      } else {
        result.classification = "ACTIVA";
        result.classificationColor = "red";
        result.classificationReason = "HTTP 200 + contenido normal — el phishing sigue activo";
      }
    } else if (r.status === 301 || r.status === 302) {
      // Check if redirect goes to a security/suspension page
      const redirectToSecurity = SECURITY_KEYWORDS.some(kw => finalUrlLower.includes(kw));
      if (redirectToSecurity) {
        result.classification = "SUSPENDIDA";
        result.classificationColor = "green";
        result.classificationReason = `HTTP ${r.status} + redirige a URL con palabra de seguridad/suspension`;
      } else {
        result.classification = "ACTIVA";
        result.classificationColor = "red";
        result.classificationReason = `HTTP ${r.status} + redirige a otra URL (no de suspension)`;
      }
    } else if (r.status === 403) {
      result.classification = "BANEADA";
      result.classificationColor = "green";
      result.classificationReason = "HTTP 403 — el hosting bloqueo el acceso";
    } else if (r.status === 404 || r.status === 410) {
      result.classification = "BORRADA";
      result.classificationColor = "green";
      result.classificationReason = `HTTP ${r.status} — los archivos del fraude fueron borrados`;
    } else if (r.status === 500 || r.status === 502 || r.status === 503) {
      result.classification = "SERVIDOR_CAIDO";
      result.classificationColor = "yellow";
      result.classificationReason = `HTTP ${r.status} — el servidor del atacante colapso`;
    } else {
      result.classification = "ERROR";
      result.classificationColor = "gray";
      result.classificationReason = `HTTP ${r.status} — codigo inesperado`;
    }
  } catch (e: any) {
    const errStr = String(e?.message || e).toLowerCase();
    if (errStr.includes("abort") || errStr.includes("timeout")) {
      result.classification = "SERVIDOR_APAGADO";
      result.classificationColor = "yellow";
      result.classificationReason = "Timeout — el servidor fue apagado por completo";
    } else if (errStr.includes("enotfound") || errStr.includes("dns") || errStr.includes("getaddrinfo")) {
      result.classification = "DOMINIO_ELIMINADO";
      result.classificationColor = "green";
      result.classificationReason = "Error de DNS — el dominio fue eliminado";
    } else if (errStr.includes("certificate") || errStr.includes("ssl") || errStr.includes("tls")) {
      result.classification = "DOMINIO_CADUCO";
      result.classificationColor = "green";
      result.classificationReason = "Error de certificado SSL — el dominio caduco";
    } else {
      result.classification = "ERROR";
      result.classificationColor = "gray";
      result.classificationReason = `Error de red: ${errStr.slice(0, 100)}`;
    }
    result.error = String(e?.message || e);
  }

  return NextResponse.json(result, {
    headers: { "Cache-Control": "no-store" },
  });
}

export async function OPTIONS() {
  return new NextResponse(null, {
    status: 204,
    headers: {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET, OPTIONS",
      "Access-Control-Allow-Headers": "*",
    },
  });
}
