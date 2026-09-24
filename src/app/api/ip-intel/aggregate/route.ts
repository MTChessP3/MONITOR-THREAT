// IP Intel — aggregate endpoint
// Calls geo + blacklists + ports + reputation in parallel and returns a single
// JSON envelope. The frontend uses this for one-shot rendering.

import { NextResponse } from "next/server";

export async function GET(request: Request) {
  const { searchParams } = new URL(request.url);
  const ip = (searchParams.get("ip") || "").trim();

  if (!ip) {
    return NextResponse.json(
      { error: "missing_params", hint: "Provide an 'ip' query parameter." },
      { status: 400 }
    );
  }

  const base = new URL(request.url).origin;
  const ipEnc = encodeURIComponent(ip);

  const [geo, blacklists, ports, reputation] = await Promise.all([
    fetch(`${base}/api/ip-intel/geo?ip=${ipEnc}`).then((r) =>
      r.ok ? r.json() : Promise.resolve({ error: "geo_failed" })
    ),
    fetch(`${base}/api/ip-intel/blacklists?ip=${ipEnc}`).then((r) =>
      r.ok ? r.json() : Promise.resolve({ error: "blacklists_failed" })
    ),
    fetch(`${base}/api/ip-intel/ports?ip=${ipEnc}`).then((r) =>
      r.ok ? r.json() : Promise.resolve({ error: "ports_failed" })
    ),
    fetch(`${base}/api/ip-intel/reputation?ip=${ipEnc}`).then((r) =>
      r.ok ? r.json() : Promise.resolve({ error: "reputation_failed" })
    ),
  ]);

  // Collect tags from all sources
  const tags: string[] = [];
  if (reputation && Array.isArray(reputation.tags)) tags.push(...reputation.tags);
  if (ports && Array.isArray(ports.tags)) tags.push(...ports.tags);

  return NextResponse.json({
    ip,
    geo,
    blacklists,
    ports,
    reputation,
    tags: [...new Set(tags)],
    timestamp: new Date().toISOString(),
  });
}
