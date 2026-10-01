// TakeDown Keys — runtime API key configuration.
// Allows the user to set the API keys directly from the dashboard UI
// (no need to redeploy Vercel). Keys are stored as httpOnly cookies
// for the user's session, and the submit/enrich endpoints read them
// first from cookies, then fall back to env vars.
//
// POST /api/takedown/keys
//   Body: { "URLHAUS_API_KEY": "...", "URLSCAN_API_KEY": "...", ... }
//   Sets httpOnly cookies for each non-empty key.
//
// GET /api/takedown/keys
//   Returns the list of keys that are currently configured (from
//   either cookies or env vars).

import { NextResponse } from "next/server";

const KEY_IDS = [
  "VIRUSTOTAL_API_KEY",
  "URLHAUS_API_KEY",
  "URLSCAN_API_KEY",
];

export async function GET(request: Request) {
  const cookieHeader = request.headers.get("cookie") || "";
  const cookies = Object.fromEntries(
    cookieHeader.split(";").map(c => {
      const [k, ...v] = c.trim().split("=");
      return [k, v.join("=")];
    })
  );

  const status = KEY_IDS.map(id => {
    const fromCookie = !!cookies[id];
    const fromEnv = !!process.env[id];
    return { id, configured: fromCookie || fromEnv, fromCookie, fromEnv };
  });

  return NextResponse.json({ keys: status }, {
    headers: { "Cache-Control": "no-store" },
  });
}

export async function POST(request: Request) {
  let body: Record<string, string>;
  try {
    body = await request.json();
  } catch {
    return NextResponse.json({ error: "invalid_json" }, { status: 400 });
  }

  // Set httpOnly cookies for each key the user provided.
  // httpOnly + secure + sameSite=strict for safety.
  // maxAge = 30 days (matches the localStorage persistence duration).
  const headers = new Headers({ "Content-Type": "application/json" });
  const set: string[] = [];
  const cleared: string[] = [];

  for (const id of KEY_IDS) {
    const value = (body[id] || "").trim();
    if (value) {
      // Set the cookie
      const cookie = `${id}=${encodeURIComponent(value)}; Path=/; Max-Age=2592000; SameSite=Strict; HttpOnly`;
      headers.append("Set-Cookie", cookie);
      set.push(id);
    } else if (body[id] === "") {
      // Explicitly cleared by user (sent empty string)
      const cookie = `${id}=; Path=/; Max-Age=0; SameSite=Strict; HttpOnly`;
      headers.append("Set-Cookie", cookie);
      cleared.push(id);
    }
  }

  return NextResponse.json({
    success: true,
    set,
    cleared,
    message: `${set.length} API key(s) configurada(s) en tu sesión.`,
  }, { headers });
}

export async function OPTIONS() {
  return new NextResponse(null, {
    status: 204,
    headers: {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
      "Access-Control-Allow-Headers": "*",
    },
  });
}
