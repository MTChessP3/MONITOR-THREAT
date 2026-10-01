// TakeDown Store — server-side persistence via Vercel KV.
// Replaces localStorage. All URL state (submits, monitoring, etc.)
// is stored server-side so nothing lives on the user's machine.
//
// Requires Vercel KV to be set up on the project:
//   1. Vercel dashboard → Storage → Create Database → KV
//   2. Connect to the MTChessP3/MONITOR-THREAT project
//   3. Vercel auto-sets KV_REST_API_URL + KV_REST_API_TOKEN env vars
//
// GET /api/takedown/store — returns all stored entries
// POST /api/takedown/store — body: { entries: UrlEntry[] } — saves entries
//
// Falls back to returning empty list if KV not configured (so the
// user can still use the module in-memory only mode).

import { kv } from "@vercel/kv";
import { NextResponse } from "next/server";

const KEY = "monitor-threat:takedown:entries";

export async function GET() {
  // Check if KV is configured (env vars present)
  if (!process.env.KV_REST_API_URL || !process.env.KV_REST_API_TOKEN) {
    return NextResponse.json({ entries: [], kvConfigured: false });
  }
  try {
    const raw = await kv.get(KEY);
    const entries = raw ? JSON.parse(raw as string) : [];
    return NextResponse.json({ entries, kvConfigured: true });
  } catch (e: any) {
    return NextResponse.json({ entries: [], kvConfigured: false, error: String(e?.message || e) });
  }
}

export async function POST(request: Request) {
  if (!process.env.KV_REST_API_URL || !process.env.KV_REST_API_TOKEN) {
    return NextResponse.json({ saved: false, kvConfigured: false, message: "Vercel KV not configured. State will not persist across sessions. Set up KV in Vercel dashboard → Storage → Create KV database." });
  }
  try {
    const body = await request.json();
    const entries = body.entries || [];
    await kv.set(KEY, JSON.stringify(entries));
    return NextResponse.json({ saved: true, kvConfigured: true, count: entries.length });
  } catch (e: any) {
    return NextResponse.json({ saved: false, kvConfigured: true, error: String(e?.message || e) }, { status: 200 });
  }
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
