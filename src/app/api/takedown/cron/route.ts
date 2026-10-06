// TakeDown Cron — monthly auto-monitoring endpoint.
// Triggered by Vercel Cron (configured in vercel.json).
// Reads all stored URLs from Upstash Redis, runs the monitor check on
// each one, updates the monitoring state in Redis.
//
// CRON_PROTECTION_TOKEN env var (optional): if set, this endpoint
// requires a matching `x-cron-token` header. Prevents abuse.

import { Redis } from "@upstash/redis";
import { NextResponse } from "next/server";

const KEY = "monitor-threat:takedown:entries";

function getRedis(): Redis | null {
  const url = process.env.UPSTASH_REDIS_REST_URL;
  const token = process.env.UPSTASH_REDIS_REST_TOKEN;
  if (!url || !token) return null;
  return new Redis({ url, token });
}

export async function GET(request: Request) {
  // Auth check if CRON_PROTECTION_TOKEN is set
  const expectedToken = process.env.CRON_PROTECTION_TOKEN;
  if (expectedToken) {
    const got = request.headers.get("x-cron-token");
    if (got !== expectedToken) {
      return NextResponse.json({ error: "unauthorized" }, { status: 401 });
    }
  }

  const redis = getRedis();
  if (!redis) {
    return NextResponse.json({ ok: false, message: "Upstash Redis not configured. Set up Redis in Vercel dashboard → Storage → Upstash." });
  }

  try {
    const raw = await redis.get(KEY);
    const entries: any[] = raw ? JSON.parse(raw as string) : [];
    if (entries.length === 0) {
      return NextResponse.json({ ok: true, monitored: 0, message: "No URLs stored to monitor." });
    }

    let monitored = 0;
    const updatedEntries: any[] = [];
    for (const entry of entries) {
      try {
        const monitorRes = await fetch(`https://monitor-threat.vercel.app/api/takedown/monitor?url=${encodeURIComponent(entry.url)}`, {
          signal: AbortSignal.timeout(15000),
        });
        const monitorResult = await monitorRes.json();
        entry.monitoring = {
          ...monitorResult,
          lastChecked: new Date().toISOString(),
        };
        monitored++;
      } catch (e) {
        entry.monitoring = {
          url: entry.url,
          classification: "ERROR",
          classificationColor: "gray",
          classificationReason: `Cron monitor failed: ${String(e).slice(0, 100)}`,
          lastChecked: new Date().toISOString(),
        };
      }
      updatedEntries.push(entry);
    }

    await redis.set(KEY, JSON.stringify(updatedEntries));
    return NextResponse.json({ ok: true, monitored, total: entries.length });
  } catch (e: any) {
    return NextResponse.json({ ok: false, error: String(e?.message || e) }, { status: 200 });
  }
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
