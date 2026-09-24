// IP Intel — geolocation & ASN
// Uses ipwho.is (free, no API key, HTTPS) with ip-api.com as fallback.

import { NextResponse } from "next/server";
import { getCached, setCached, cacheKey } from "@/lib/cache";

interface GeoResult {
  ip: string;
  type?: string;
  continent?: string;
  continentCode?: string;
  country: string;
  countryCode: string;
  region?: string;
  regionCode?: string;
  city: string;
  latitude: number;
  longitude: number;
  postal?: string;
  callingCode?: string;
  asn?: number;
  organization?: string;
  isp?: string;
  domain?: string;
  timezone?: string;
  utcOffset?: string;
  flagEmoji?: string;
  reverse?: string;
  provider: string;
}

const FALLBACK_PROVIDERS = [
  {
    name: "ipwho.is",
    url: (ip: string) => `https://ipwho.is/${ip}`,
    transform: (d: any): GeoResult => ({
      ip: d.ip,
      type: d.type,
      continent: d.continent,
      continentCode: d.continent_code,
      country: d.country,
      countryCode: d.country_code,
      region: d.region,
      regionCode: d.region_code,
      city: d.city,
      latitude: d.latitude,
      longitude: d.longitude,
      postal: d.postal,
      callingCode: d.calling_code,
      asn: d.connection?.asn,
      organization: d.connection?.org,
      isp: d.connection?.isp,
      domain: d.connection?.domain,
      timezone: d.timezone?.id,
      utcOffset: d.timezone?.utc,
      flagEmoji: d.flag?.emoji,
      provider: "ipwho.is",
    }),
  },
  {
    name: "ip-api.com",
    url: (ip: string) =>
      `http://ip-api.com/json/${ip}?fields=status,message,country,countryCode,region,regionName,city,lat,lon,timezone,isp,org,as,asname,reverse,query`,
    transform: (d: any): GeoResult => ({
      ip: d.query,
      country: d.country,
      countryCode: d.countryCode,
      region: d.regionName,
      regionCode: d.region,
      city: d.city,
      latitude: d.lat,
      longitude: d.lon,
      timezone: d.timezone,
      asn: d.as ? parseInt(d.as.split(" ")[0].replace("AS", "")) : undefined,
      organization: d.org,
      isp: d.isp,
      reverse: d.reverse,
      provider: "ip-api.com",
    }),
  },
];

export async function GET(request: Request) {
  const { searchParams } = new URL(request.url);
  const ip = (searchParams.get("ip") || "").trim();

  if (!ip) {
    return NextResponse.json(
      { error: "missing_params", hint: "Provide an 'ip' query parameter." },
      { status: 400 }
    );
  }

  // Basic IPv4/IPv6 validation
  const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/;
  const ipv6Regex = /^([0-9a-fA-F:]+)$/;
  if (!ipv4Regex.test(ip) && !ipv6Regex.test(ip)) {
    return NextResponse.json(
      { error: "invalid_ip", hint: `Not a valid IP: ${ip}` },
      { status: 400 }
    );
  }

  // Cache check — saves a network roundtrip on repeat queries
  const cacheK = cacheKey("geo", ip);
  const cached = getCached<GeoResult>(cacheK);
  if (cached) return NextResponse.json({ ...cached, cached: true });

  for (const provider of FALLBACK_PROVIDERS) {
    try {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 4000);
      const res = await fetch(provider.url(ip), {
        signal: controller.signal,
        headers: { "User-Agent": "MONITOR-THREAT/2.0 (IP Intel)" },
      });
      clearTimeout(timeout);

      if (!res.ok) continue;
      const data = await res.json();

      if ("success" in data && data.success === false) continue;
      if ("status" in data && data.status === "fail") continue;

      const result: GeoResult = provider.transform(data);
      setCached(cacheK, result);
      return NextResponse.json(result);
    } catch (err) {
      continue;
    }
  }

  return NextResponse.json(
    {
      error: "all_providers_failed",
      hint: "Could not geolocate the IP from any provider.",
    },
    { status: 502 }
  );
}
