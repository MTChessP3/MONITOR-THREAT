// IP Intel — open ports & services via Shodan InternetDB (free, no API key)
// https://internetdb.shodan.io/

import { NextResponse } from "next/server";
import { getCached, setCached, cacheKey } from "@/lib/cache";

interface PortInfo {
  port: number;
  service?: string;
}

interface InternetDbResult {
  ip: string;
  cpes: string[];
  hostnames: string[];
  ports: number[];
  tags: string[];
  vulns: string[];
  provider: string;
}

// Map common port numbers to service names
const PORT_SERVICES: Record<number, string> = {
  21: "FTP",
  22: "SSH",
  23: "Telnet",
  25: "SMTP",
  53: "DNS",
  80: "HTTP",
  110: "POP3",
  143: "IMAP",
  443: "HTTPS",
  465: "SMTPS",
  587: "SMTP Submission",
  993: "IMAPS",
  995: "POP3S",
  1433: "MSSQL",
  1521: "Oracle",
  3306: "MySQL",
  3389: "RDP",
  5432: "PostgreSQL",
  5900: "VNC",
  6379: "Redis",
  8080: "HTTP Alt",
  8443: "HTTPS Alt",
  9001: "Tor ORPort",
  9030: "Tor DirPort",
  27017: "MongoDB",
};

export async function GET(request: Request) {
  const { searchParams } = new URL(request.url);
  const ip = (searchParams.get("ip") || "").trim();

  if (!ip) {
    return NextResponse.json(
      { error: "missing_params", hint: "Provide an 'ip' query parameter." },
      { status: 400 }
    );
  }

  const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/;
  const ipv6Regex = /^([0-9a-fA-F:]+)$/;
  if (!ipv4Regex.test(ip) && !ipv6Regex.test(ip)) {
    return NextResponse.json(
      { error: "invalid_ip", hint: `Not a valid IP: ${ip}` },
      { status: 400 }
    );
  }

  // Cache check
  const cacheK = cacheKey("ports", ip);
  const cached = getCached<InternetDbResult>(cacheK);
  if (cached) return NextResponse.json({ ...cached, cached: true });

  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 4000);
    const res = await fetch(`https://internetdb.shodan.io/${ip}`, {
      signal: controller.signal,
      headers: { "User-Agent": "MONITOR-THREAT/2.0" },
    });
    clearTimeout(timeout);

    if (!res.ok) {
      if (res.status === 404) {
        return NextResponse.json({
          ip,
          cpes: [],
          hostnames: [],
          ports: [],
          tags: [],
          vulns: [],
          provider: "shodan-internetdb",
          note: "No data — the IP has not been scanned by Shodan.",
        });
      }
      return NextResponse.json(
        { error: "shodan_failed", status: res.status },
        { status: 502 }
      );
    }

    const data = await res.json();
    const result: InternetDbResult = {
      ip,
      cpes: data.cpes || [],
      hostnames: data.hostnames || [],
      ports: data.ports || [],
      tags: data.tags || [],
      vulns: data.vulns || [],
      provider: "shodan-internetdb",
    };

    setCached(cacheK, result);
    return NextResponse.json(result);
  } catch (err: any) {
    return NextResponse.json(
      { error: "shodan_unreachable", hint: err.message },
      { status: 502 }
    );
  }
}

export { PORT_SERVICES };
