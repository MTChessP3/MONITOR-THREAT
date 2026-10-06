// TakeDown Store — server-side persistence via Upstash Redis.
// Replaces localStorage. All URL state (submits, monitoring, etc.)
// is stored server-side so nothing lives on the user's machine.
//
// Requires Upstash Redis to be set up on the Vercel project:
//   1. Vercel dashboard → Storage → Create Database → Upstash (Redis)
//   2. Connect to the MTChessP3/MONITOR-THREAT project
//   3. Vercel auto-sets UPSTASH_REDIS_REST_URL + UPSTASH_REDIS_REST_TOKEN
//
// GET /api/takedown/store — returns all stored entries
// POST /api/takedown/store — body: { entries: UrlEntry[] } — saves entries
//
// Falls back to returning empty list if Redis not configured (so the
// user can still use the module in-memory only mode).

import { Redis } from "@upstash/redis";
import { NextResponse } from "next/server";

const KEY = "monitor-threat:takedown:entries";

// Create the Redis client only if env vars are present
function getRedis(): Redis | null {
  const url = process.env.UPSTASH_REDIS_REST_URL;
  const token = process.env.UPSTASH_REDIS_REST_TOKEN;
  if (!url || !token) return null;
  return new Redis({ url, token });
}

export async function GET() {
  const redis = getRedis();
  if (!redis) {
    return NextResponse.json({ entries: [], redisConfigured: false });
  }
  try {
    const raw = await redis.get(KEY);
    const entries = raw ? JSON.parse(raw as string) : [];
    return NextResponse.json({ entries, redisConfigured: true });
  } catch (e: any) {
    return NextResponse.json({ entries: [], redisConfigured: false, error: String(e?.message || e) });
  }
}

export async function POST(request: Request) {
  const redis = getRedis();
  if (!redis) {
    return NextResponse.json({ saved: false, redisConfigured: false, message: "Upstash Redis not configured. Set up Redis in Vercel dashboard → Storage → Upstash." });
  }
  try {
    const body = await request.json();
    const entries = body.entries || [];
    await redis.set(KEY, JSON.stringify(entries));
    return NextResponse.json({ saved: true, redisConfigured: true, count: entries.length });
  } catch (e: any) {
    return NextResponse.json({ saved: false, redisConfigured: true, error: String(e?.message || e) }, { status: 200 });
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
