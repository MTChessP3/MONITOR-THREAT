"use client";

import * as React from "react";
import {
  MapPin,
  Globe,
  Search,
  Server,
  Link as LinkIcon,
  Box,
  ShieldOff,
  Network,
  Loader2,
  AlertTriangle,
  ExternalLink,
  ShieldAlert,
} from "lucide-react";

import {
  ModuleShell,
  Panel,
  FieldRow,
  SearchBar,
  EmptyModuleState,
} from "@/components/module-shell";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Separator } from "@/components/ui/separator";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";

import {
  DOMAIN_INTEL_RESULT,
  URL_SCANNER_RESULT,
  TAKEDOWN_REQUESTS,
} from "@/lib/mock-data";

const PORT_SERVICES: Record<number, string> = {
  21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
  80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS",
  465: "SMTPS", 587: "SMTP Submission", 993: "IMAPS", 995: "POP3S",
  1433: "MSSQL", 1521: "Oracle", 3306: "MySQL", 3389: "RDP",
  5432: "PostgreSQL", 5900: "VNC", 6379: "Redis",
  8080: "HTTP Alt", 8443: "HTTPS Alt",
  9001: "Tor ORPort", 9030: "Tor DirPort", 27017: "MongoDB",
};

// ---- Types for the real IP Intel API response ----
interface GeoResult {
  ip: string;
  country: string;
  countryCode: string;
  region?: string;
  city: string;
  latitude: number;
  longitude: number;
  asn?: number;
  organization?: string;
  isp?: string;
  domain?: string;
  timezone?: string;
  reverse?: string;
  flagEmoji?: string;
  provider: string;
  error?: string;
}

interface BlacklistEntry {
  rid: string;
  zone: string;
  url?: string;
  result: string;
  category: "black" | "brown" | "yellow" | "white" | "neutral" | "not_listed" | "failed";
  reason?: string;
}

interface BlacklistResult {
  ip: string;
  summary: {
    total: number;
    blacklisted: number;
    brownlisted: number;
    yellowlisted: number;
    whitelisted: number;
    neutrallisted: number;
    notListed: number;
    failed: number;
  };
  entries: BlacklistEntry[];
  embedded_url: string;
  error?: string;
}

interface PortsResult {
  ip: string;
  ports: number[];
  hostnames: string[];
  tags: string[];
  vulns: string[];
  cpes: string[];
  error?: string;
}

interface ReputationResult {
  ip: string;
  score: number;
  classification: "BENIGN" | "SUSPICIOUS" | "MALICIOUS";
  signals: Array<{ source: string; weight: number; detail: string }>;
  tags: string[];
  threatIntel: Array<{ source: string; verdict: string; details?: string }>;
  abuseipdb?: {
    score: number;
    totalReports: number;
    abuseConfidenceScore: number;
  } | null;
  error?: string;
}

interface AggregateResult {
  ip: string;
  geo: GeoResult;
  blacklists: BlacklistResult;
  ports: PortsResult;
  reputation: ReputationResult;
  tags: string[];
  timestamp: string;
}

const CATEGORY_BADGE: Record<BlacklistEntry["category"], { label: string; cls: string }> = {
  black: { label: "BLACKLISTED", cls: "bg-red-500 text-white" },
  brown: { label: "BROWNLISTED", cls: "bg-orange-600 text-white" },
  yellow: { label: "YELLOWLISTED", cls: "bg-yellow-500 text-black" },
  white: { label: "WHITELISTED", cls: "bg-emerald-500 text-white" },
  neutral: { label: "NEUTRAL", cls: "bg-cyan-500 text-white" },
  not_listed: { label: "NOT LISTED", cls: "bg-muted text-muted-foreground" },
  failed: { label: "FAILED", cls: "bg-zinc-700 text-zinc-400" },
};

// ---------- IP Intel (real APIs) ----------
export function IpIntelView() {
  const [input, setInput] = React.useState("8.8.8.8");
  const [loading, setLoading] = React.useState(false);
  const [data, setData] = React.useState<AggregateResult | null>(null);
  const [error, setError] = React.useState<string | null>(null);
  const abortRef = React.useRef<AbortController | null>(null);

  async function analyze(ip: string) {
    if (!ip.trim()) return;
    abortRef.current?.abort();
    const ac = new AbortController();
    abortRef.current = ac;

    setLoading(true);
    setError(null);
    try {
      const res = await fetch(
        `/api/ip-intel/aggregate?ip=${encodeURIComponent(ip.trim())}`,
        { signal: ac.signal }
      );
      const json = await res.json();
      if (!res.ok) {
        setError(json?.error || `HTTP ${res.status}`);
        setData(null);
      } else {
        setData(json);
      }
    } catch (err: any) {
      if (err.name !== "AbortError") {
        setError(err.message || "Fetch failed");
        setData(null);
      }
    } finally {
      if (ac === abortRef.current) setLoading(false);
    }
  }

  React.useEffect(() => {
    analyze("8.8.8.8");
    return () => abortRef.current?.abort();
  }, []);

  return (
    <ModuleShell
      name="IP Intel"
      description="Geolocation, ASN, open ports, reputation and threat intel for an IP address. Powered by ipwho.is, multirbl.valli.org, Shodan InternetDB and AbuseIPDB."
      icon={MapPin}
      category="INFRASTRUCTURE"
      status={loading ? "QUERYING" : "READY"}
    >
      <div className="flex flex-col gap-2 mb-4">
        <label className="text-xs font-medium text-muted-foreground uppercase tracking-wider">
          IP address (IPv4 / IPv6)
        </label>
        <div className="flex gap-2">
          <Input
            type="text"
            placeholder="e.g. 8.8.8.8, 185.220.101.34, 2001:4860:4860::8888"
            className="flex-1 font-mono text-sm"
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && analyze(input)}
          />
          <Button
            type="button"
            size="sm"
            onClick={() => analyze(input)}
            disabled={loading}
          >
            {loading ? (
              <>
                <Loader2 className="w-3.5 h-3.5 mr-2 animate-spin" />
                Analyzing…
              </>
            ) : (
              <>
                <Search className="w-3.5 h-3.5 mr-2" />
                Analyze
              </>
            )}
          </Button>
        </div>
      </div>

      {error && (
        <div className="mb-4 p-3 rounded-md border border-red-500/40 bg-red-500/10 text-red-400 flex items-center gap-2">
          <AlertTriangle className="w-4 h-4 shrink-0" />
          <span className="text-sm">{error}</span>
        </div>
      )}

      {data && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {/* Geolocation & ASN */}
          <Panel
            title="Geolocation & ASN"
            action={
              data.geo?.latitude && data.geo?.longitude ? (
                <a
                  href={`https://www.openstreetmap.org/?mlat=${data.geo.latitude}&mlon=${data.geo.longitude}#map=12/${data.geo.latitude}/${data.geo.longitude}`}
                  target="_blank"
                  rel="noreferrer"
                  className="text-xs text-cyan-500 hover:underline flex items-center gap-1"
                >
                  OpenStreetMap <ExternalLink className="w-3 h-3" />
                </a>
              ) : undefined
            }
          >
            {data.geo?.error ? (
              <p className="text-sm text-muted-foreground">{data.geo.error}</p>
            ) : data.geo ? (
              <>
                <FieldRow label="IP" value={data.geo.ip} mono />
                <FieldRow
                  label="Country"
                  value={`${data.geo.flagEmoji || "🌐"} ${data.geo.country} (${data.geo.countryCode})`}
                />
                {data.geo.region && (
                  <FieldRow label="Region" value={data.geo.region} />
                )}
                <FieldRow label="City" value={data.geo.city} />
                <FieldRow
                  label="Coordinates"
                  value={`${data.geo.latitude}, ${data.geo.longitude}`}
                  mono
                />
                {data.geo.asn && (
                  <FieldRow label="ASN" value={`AS${data.geo.asn}`} mono />
                )}
                {data.geo.organization && (
                  <FieldRow label="Organization" value={data.geo.organization} />
                )}
                {data.geo.isp && <FieldRow label="ISP" value={data.geo.isp} />}
                {data.geo.domain && (
                  <FieldRow label="Domain" value={data.geo.domain} mono />
                )}
                {data.geo.timezone && (
                  <FieldRow label="Timezone" value={data.geo.timezone} mono />
                )}
                {data.geo.reverse && (
                  <FieldRow label="rDNS" value={data.geo.reverse} mono />
                )}
                <div className="mt-2 pt-2 text-[10px] text-muted-foreground border-t border-border/40">
                  Source: {data.geo.provider}
                </div>
              </>
            ) : (
              <p className="text-sm text-muted-foreground">No data.</p>
            )}
          </Panel>

          {/* OpenStreetMap embed */}
          <Panel title="OpenStreetMap View">
            {data.geo?.latitude && data.geo?.longitude ? (
              <div className="flex flex-col gap-2">
                <div className="rounded-md overflow-hidden border border-border">
                  <iframe
                    title="OpenStreetMap"
                    className="w-full h-[260px]"
                    loading="lazy"
                    src={`https://www.openstreetmap.org/export/embed.html?bbox=${
                      data.geo.longitude - 0.15
                    }%2C${data.geo.latitude - 0.1}%2C${
                      data.geo.longitude + 0.15
                    }%2C${data.geo.latitude + 0.1}&layer=mapnik&marker=${data.geo.latitude}%2C${data.geo.longitude}`}
                  />
                </div>
                <Button variant="outline" size="sm" asChild>
                  <a
                    href={`https://www.openstreetmap.org/?mlat=${data.geo.latitude}&mlon=${data.geo.longitude}#map=12/${data.geo.latitude}/${data.geo.longitude}`}
                    target="_blank"
                    rel="noreferrer"
                  >
                    <ExternalLink className="w-3 h-3 mr-1" />
                    Open in OpenStreetMap
                  </a>
                </Button>
              </div>
            ) : (
              <p className="text-sm text-muted-foreground">
                No coordinates available.
              </p>
            )}
          </Panel>

          {/* Open Ports */}
          <Panel title="Open Ports & Services">
            {data.ports?.error ? (
              <p className="text-sm text-muted-foreground">{data.ports.error}</p>
            ) : data.ports ? (
              <>
                <div className="flex flex-wrap gap-1.5 mb-3">
                  {data.ports.ports.length > 0 ? (
                    data.ports.ports.map((p) => (
                      <Badge
                        key={p}
                        variant="outline"
                        className="font-mono text-xs"
                        title={PORT_SERVICES[p] || ""}
                      >
                        :{p}{" "}
                        {PORT_SERVICES[p] && (
                          <span className="text-muted-foreground ml-1">
                            {PORT_SERVICES[p]}
                          </span>
                        )}
                      </Badge>
                    ))
                  ) : (
                    <span className="text-sm text-muted-foreground">
                      No open ports recorded by Shodan.
                    </span>
                  )}
                </div>
                {data.ports.hostnames.length > 0 && (
                  <>
                    <Separator />
                    <div className="pt-2">
                      <span className="text-xs text-muted-foreground">Hostnames:</span>
                      <div className="flex flex-wrap gap-1 mt-1">
                        {data.ports.hostnames.map((h) => (
                          <Badge key={h} variant="secondary" className="font-mono text-[10px]">
                            {h}
                          </Badge>
                        ))}
                      </div>
                    </div>
                  </>
                )}
                {data.ports.vulns.length > 0 && (
                  <div className="mt-2 pt-2 border-t border-border/40">
                    <span className="text-xs text-red-500">Known CVEs:</span>
                    <div className="flex flex-wrap gap-1 mt-1">
                      {data.ports.vulns.slice(0, 12).map((v) => (
                        <Badge
                          key={v}
                          variant="destructive"
                          className="font-mono text-[10px]"
                        >
                          {v}
                        </Badge>
                      ))}
                    </div>
                  </div>
                )}
                <div className="mt-2 pt-2 text-[10px] text-muted-foreground border-t border-border/40">
                  Source: Shodan InternetDB · {data.ports.ports.length} ports ·{" "}
                  {data.ports.hostnames.length} hostnames
                </div>
              </>
            ) : (
              <p className="text-sm text-muted-foreground">No data.</p>
            )}
          </Panel>

          {/* Reputation */}
          <Panel title="Reputation">
            {data.reputation?.error ? (
              <p className="text-sm text-muted-foreground">{data.reputation.error}</p>
            ) : data.reputation ? (
              <>
                <div className="flex items-center gap-3 mb-3">
                  <div
                    className={`text-3xl font-mono font-bold ${
                      data.reputation.classification === "MALICIOUS"
                        ? "text-red-500"
                        : data.reputation.classification === "SUSPICIOUS"
                        ? "text-yellow-500"
                        : "text-emerald-500"
                    }`}
                  >
                    {data.reputation.score}
                    <span className="text-base text-muted-foreground">/100</span>
                  </div>
                  <div>
                    <Badge
                      variant={
                        data.reputation.classification === "MALICIOUS"
                          ? "destructive"
                          : data.reputation.classification === "SUSPICIOUS"
                          ? "default"
                          : "secondary"
                      }
                      className="font-mono text-xs"
                    >
                      {data.reputation.classification}
                    </Badge>
                    <div className="text-[10px] text-muted-foreground mt-1">
                      {data.reputation.signals.length} signal(s)
                    </div>
                  </div>
                </div>
                <Separator />
                <div className="pt-2 flex flex-col gap-1.5 max-h-44 overflow-y-auto">
                  {data.reputation.signals.length > 0 ? (
                    data.reputation.signals.map((s, i) => (
                      <div
                        key={i}
                        className="flex items-start gap-2 text-xs"
                      >
                        <ShieldAlert
                          className={`w-3 h-3 shrink-0 mt-0.5 ${
                            s.weight > 20
                              ? "text-red-500"
                              : s.weight > 5
                              ? "text-yellow-500"
                              : "text-muted-foreground"
                          }`}
                        />
                        <div className="flex-1">
                          <span className="font-mono text-[10px] text-cyan-500">
                            [{s.source}]
                          </span>{" "}
                          <span>{s.detail}</span>
                          <Badge variant="outline" className="ml-1 font-mono text-[9px]">
                            +{s.weight}
                          </Badge>
                        </div>
                      </div>
                    ))
                  ) : (
                    <span className="text-sm text-muted-foreground">
                      No negative signals detected.
                    </span>
                  )}
                </div>
              </>
            ) : (
              <p className="text-sm text-muted-foreground">No data.</p>
            )}
          </Panel>

          {/* Threat Intel */}
          <Panel title="Threat Intel Sources">
            {data.reputation && Array.isArray(data.reputation.threatIntel) ? (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Source</TableHead>
                    <TableHead>Verdict</TableHead>
                    <TableHead>Details</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {data.reputation.threatIntel.map((t, i) => (
                    <TableRow key={i}>
                      <TableCell className="font-mono text-xs">{t.source}</TableCell>
                      <TableCell>
                        <Badge
                          variant={
                            t.verdict === "malicious" || t.verdict === "blacklisted"
                              ? "destructive"
                              : t.verdict === "suspicious" || t.verdict === "tagged"
                              ? "default"
                              : "secondary"
                          }
                          className="font-mono text-[10px]"
                        >
                          {t.verdict}
                        </Badge>
                      </TableCell>
                      <TableCell className="text-xs text-muted-foreground">
                        {t.details || "-"}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            ) : (
              <p className="text-sm text-muted-foreground">No data.</p>
            )}
          </Panel>

          {/* Blacklists summary */}
          <Panel
            title="DNSBL / Blacklist Summary"
            className="md:col-span-2"
            action={
              data.blacklists?.embedded_url ? (
                <a
                  href={data.blacklists.embedded_url}
                  target="_blank"
                  rel="noreferrer"
                  className="text-xs text-cyan-500 hover:underline flex items-center gap-1"
                >
                  multirbl.valli.org <ExternalLink className="w-3 h-3" />
                </a>
              ) : undefined
            }
          >
            {data.blacklists?.error ? (
              <p className="text-sm text-muted-foreground">{data.blacklists.error}</p>
            ) : data.blacklists ? (
              <>
                <div className="grid grid-cols-2 md:grid-cols-4 gap-2 mb-3">
                  {[
                    { label: "Blacklisted", n: data.blacklists.summary.blacklisted, cls: "bg-red-500/15 text-red-400" },
                    { label: "Brownlisted", n: data.blacklists.summary.brownlisted, cls: "bg-orange-500/15 text-orange-400" },
                    { label: "Yellowlisted", n: data.blacklists.summary.yellowlisted, cls: "bg-yellow-500/15 text-yellow-400" },
                    { label: "Whitelisted", n: data.blacklists.summary.whitelisted, cls: "bg-emerald-500/15 text-emerald-400" },
                  ].map((b) => (
                    <div
                      key={b.label}
                      className={`rounded-md p-2 border border-border ${b.cls}`}
                    >
                      <div className="text-xl font-bold font-mono">{b.n}</div>
                      <div className="text-xs">{b.label}</div>
                    </div>
                  ))}
                </div>
                <div className="text-xs text-muted-foreground mb-2">
                  Total zones checked: {data.blacklists.summary.total} · Not listed:{" "}
                  {data.blacklists.summary.notListed} · Failed:{" "}
                  {data.blacklists.summary.failed}
                </div>
                <Separator />
                <div className="mt-2 max-h-72 overflow-y-auto">
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <TableHead className="w-32">Status</TableHead>
                        <TableHead>Zone</TableHead>
                        <TableHead>Reason</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {data.blacklists.entries
                        .filter((e, i) => e.category !== "not_listed" || i < 5)
                        .slice(0, 50)
                        .map((e) => {
                          const badge = CATEGORY_BADGE[e.category];
                          return (
                            <TableRow key={e.rid}>
                              <TableCell>
                                <span
                                  className={`inline-block px-1.5 py-0.5 rounded text-[10px] font-mono ${badge.cls}`}
                                >
                                  {badge.label}
                                </span>
                              </TableCell>
                              <TableCell className="font-mono text-xs">
                                {e.url ? (
                                  <a
                                    href={e.url}
                                    target="_blank"
                                    rel="noreferrer"
                                    className="text-cyan-500 hover:underline"
                                  >
                                    {e.zone}
                                  </a>
                                ) : (
                                  e.zone
                                )}
                              </TableCell>
                              <TableCell className="text-xs text-muted-foreground">
                                {e.reason || e.result}
                              </TableCell>
                            </TableRow>
                          );
                        })}
                    </TableBody>
                  </Table>
                </div>
                <div className="mt-2 pt-2 text-[10px] text-muted-foreground border-t border-border/40">
                  Source: multirbl.valli.org + direct DNSBL (15 zones)
                </div>
              </>
            ) : (
              <p className="text-sm text-muted-foreground">No data.</p>
            )}
          </Panel>

          {/* Tags */}
          {data.tags && data.tags.length > 0 && (
            <Panel title="Tags" className="md:col-span-2">
              <div className="flex flex-wrap gap-1.5">
                {data.tags.map((t) => (
                  <Badge key={t} variant="secondary" className="font-mono">
                    #{t}
                  </Badge>
                ))}
              </div>
            </Panel>
          )}

          <div className="md:col-span-2 text-[10px] text-muted-foreground font-mono">
            Query timestamp: {data.timestamp} · Powered by ipwho.is, multirbl.valli.org,
            Shodan InternetDB, AbuseIPDB (optional).
          </div>
        </div>
      )}
    </ModuleShell>
  );
}

// ---------- Domain Intel (mock) ----------
export function DomainIntelView() {
  const r = DOMAIN_INTEL_RESULT;
  return (
    <ModuleShell
      name="Domain Intel"
      description="WHOIS, DNS, subdomains, SSL certificates and historical records."
      icon={Globe}
      category="INFRASTRUCTURE"
    >
      <SearchBar label="Domain" placeholder="example.com" />
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mt-4">
        <Panel title="WHOIS">
          <FieldRow label="Domain" value={r.domain} mono />
          <FieldRow label="Registered" value={r.registered} mono />
          <FieldRow label="Registrar" value={r.registrar} />
          <FieldRow label="Registrant country" value={r.registrantCountry} mono />
          <FieldRow label="Nameservers" value={r.nameservers.join(", ")} mono />
        </Panel>
        <Panel title="DNS Records">
          <FieldRow label="A" value={r.dns.A.join(", ")} mono />
          <FieldRow label="MX" value={r.dns.MX.join(", ")} mono />
          <FieldRow label="NS" value={r.dns.NS.join(", ")} mono />
          <FieldRow label="TXT" value={r.dns.TXT[0]} mono />
        </Panel>
        <Panel title="SSL Certificate">
          <FieldRow label="Issuer" value={r.ssl.issuer} />
          <FieldRow label="Valid from" value={r.ssl.validFrom} mono />
          <FieldRow label="Valid to" value={r.ssl.validTo} mono />
          <FieldRow label="Serial" value={r.ssl.serial} mono />
        </Panel>
        <Panel title="Subdomains">
          <div className="flex flex-col gap-1">
            {r.subdomains.map((s) => (
              <span key={s} className="font-mono text-xs px-2 py-1 rounded bg-muted/40">
                {s}
              </span>
            ))}
          </div>
        </Panel>
      </div>
      <Panel title="History" className="mt-4">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Date</TableHead>
              <TableHead>Event</TableHead>
              <TableHead>From</TableHead>
              <TableHead>To</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {r.history.map((h) => (
              <TableRow key={h.date + h.event}>
                <TableCell className="font-mono">{h.date}</TableCell>
                <TableCell>{h.event}</TableCell>
                <TableCell className="font-mono text-xs">{h.from}</TableCell>
                <TableCell className="font-mono text-xs">{h.to}</TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </Panel>
    </ModuleShell>
  );
}

// ---------- Domain Forensics (placeholder) ----------
export function DomainForensicsView() {
  return (
    <ModuleShell
      name="Domain Forensics"
      description="Deep forensic analysis of domains: infrastructure, hosting and pivots."
      icon={Search}
      category="INFRASTRUCTURE"
    >
      <SearchBar label="Domain" placeholder="example.com" />
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mt-4">
        <Panel title="Passive DNS">
          <EmptyModuleState
            icon={Search}
            name="No data yet"
            description="Enter a domain to pivot through passive DNS history."
          />
        </Panel>
        <Panel title="Infrastructure graph">
          <EmptyModuleState
            icon={Network}
            name="Graph view"
            description="Render hosting, ASN and certificate relationships as a graph."
          />
        </Panel>
        <Panel title="Pivot recommendations">
          <EmptyModuleState
            icon={Search}
            name="Pivots"
            description="Suggested pivots based on shared infrastructure will appear here."
          />
        </Panel>
      </div>
    </ModuleShell>
  );
}

// ---------- DNS Dump (mock) ----------
export function DnsDumpView() {
  const records = [
    { type: "A", name: "@", value: "185.220.101.34", ttl: 3600 },
    { type: "AAAA", name: "@", value: "2001:db8::1", ttl: 3600 },
    { type: "MX", name: "@", value: "10 mail.example.com", ttl: 3600 },
    { type: "NS", name: "@", value: "ns1.example.com", ttl: 86400 },
    { type: "TXT", name: "@", value: "v=spf1 include:_spf.example.com ~all", ttl: 3600 },
    { type: "SOA", name: "@", value: "ns1.example.com admin.example.com", ttl: 3600 },
    { type: "CNAME", name: "www", value: "example.com", ttl: 3600 },
    { type: "SRV", name: "_sip._tcp", value: "10 5060 sip.example.com", ttl: 3600 },
    { type: "CAA", name: "@", value: "0 issue letsencrypt.org", ttl: 3600 },
    { type: "PTR", name: "1.0.0.0", value: "host.example.com", ttl: 3600 },
  ];
  return (
    <ModuleShell
      name="DNS Dump"
      description="Full dump of DNS records for a domain across all record types."
      icon={Server}
      category="INFRASTRUCTURE"
    >
      <SearchBar label="Domain" placeholder="example.com" />
      <Panel title="Records" className="mt-4">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead className="w-20">Type</TableHead>
              <TableHead className="w-32">Name</TableHead>
              <TableHead>Value</TableHead>
              <TableHead className="w-24">TTL</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {records.map((r, i) => (
              <TableRow key={i}>
                <TableCell>
                  <Badge variant="outline" className="font-mono">
                    {r.type}
                  </Badge>
                </TableCell>
                <TableCell className="font-mono text-sm">{r.name}</TableCell>
                <TableCell className="font-mono text-sm">{r.value}</TableCell>
                <TableCell className="font-mono text-sm">{r.ttl}</TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </Panel>
    </ModuleShell>
  );
}

// ---------- URL Scanner (mock) ----------
export function UrlScannerView() {
  const r = URL_SCANNER_RESULT;
  return (
    <ModuleShell
      name="URL Scanner"
      description="Static and dynamic analysis of suspicious URLs."
      icon={LinkIcon}
      category="INFRASTRUCTURE"
    >
      <SearchBar label="URL" placeholder="https://example.com/path" />
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mt-4">
        <Panel title="HTTP Response">
          <FieldRow label="Final URL" value={r.finalUrl} mono />
          <FieldRow label="Status" value={r.httpStatus} mono />
          <FieldRow label="Redirects" value={r.redirects} mono />
          <FieldRow label="Response time" value={`${r.responseTime}ms`} mono />
          <FieldRow
            label="SSL"
            value={
              r.ssl.valid
                ? `Valid · ${r.ssl.issuer}`
                : "Invalid"
            }
          />
        </Panel>
        <Panel title="Technologies">
          <div className="flex flex-wrap gap-1.5">
            {r.technologies.map((t) => (
              <Badge key={t} variant="secondary" className="font-mono">
                {t}
              </Badge>
            ))}
          </div>
        </Panel>
        <Panel title="Verdicts">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Source</TableHead>
                <TableHead>Verdict</TableHead>
                <TableHead>Details</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {r.verdicts.map((v) => (
                <TableRow key={v.source}>
                  <TableCell>{v.source}</TableCell>
                  <TableCell>
                    <Badge
                      variant={v.verdict === "malicious" ? "destructive" : "secondary"}
                      className="font-mono text-[10px]"
                    >
                      {v.verdict}
                    </Badge>
                  </TableCell>
                  <TableCell className="text-xs">
                    {"positives" in v
                      ? `${v.positives}/${v.total}`
                      : "score" in v
                      ? `score: ${v.score}`
                      : "listed: " + (v.listed ? "yes" : "no")}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </Panel>
        <Panel title="Extracted Content">
          <FieldRow label="Emails" value={r.extracted.emails.length} mono />
          <FieldRow label="Phones" value={r.extracted.phones.length} mono />
          <FieldRow label="IPs" value={r.extracted.ips.length} mono />
          <FieldRow label="Forms" value={r.extracted.forms} mono />
          <FieldRow label="Iframes" value={r.extracted.iframes} mono />
          <FieldRow label="Scripts" value={r.extracted.scripts} mono />
        </Panel>
      </div>
    </ModuleShell>
  );
}

// ---------- URL Sandbox (placeholder) ----------
export function UrlSandboxView() {
  return (
    <ModuleShell
      name="URL Sandbox"
      description="Isolated sandbox execution: network behavior, file system activity and process tree."
      icon={Box}
      category="INFRASTRUCTURE"
    >
      <SearchBar label="URL or file" placeholder="https://example.com/sample.exe" />
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mt-4">
        <Panel title="Network Activity">
          <EmptyModuleState
            icon={Network}
            name="No samples"
            description="Submit a URL or upload a file to see DNS queries, HTTP requests and C2 traffic."
          />
        </Panel>
        <Panel title="Filesystem Activity">
          <EmptyModuleState
            icon={Box}
            name="No samples"
            description="See file creation, modification, deletion and persistence changes."
          />
        </Panel>
        <Panel title="Process Tree">
          <EmptyModuleState
            icon={Box}
            name="No samples"
            description="Process spawn tree with arguments, exit codes and child processes."
          />
        </Panel>
        <Panel title="Behavioral Summary">
          <EmptyModuleState
            icon={Box}
            name="No samples"
            description="MITRE ATT&CK mapping and behavioral verdict after execution."
          />
        </Panel>
      </div>
    </ModuleShell>
  );
}

// ---------- TakeDown URL (mock) ----------
export function TakedownUrlView() {
  return (
    <ModuleShell
      name="TakeDown URL"
      description="Manage takedown requests for malicious content across providers."
      icon={ShieldOff}
      category="INFRASTRUCTURE"
    >
      <div className="flex items-center justify-between">
        <SearchBar label="Filter" placeholder="Search requests..." />
        <Button size="sm">+ New request</Button>
      </div>
      <Panel title="Recent Requests" className="mt-4">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>ID</TableHead>
              <TableHead>URL</TableHead>
              <TableHead>Target</TableHead>
              <TableHead>Provider</TableHead>
              <TableHead>Status</TableHead>
              <TableHead>Priority</TableHead>
              <TableHead>Submitted</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {TAKEDOWN_REQUESTS.map((t) => (
              <TableRow key={t.id}>
                <TableCell className="font-mono text-xs">{t.id}</TableCell>
                <TableCell className="font-mono text-xs">{t.url}</TableCell>
                <TableCell className="text-sm">{t.target}</TableCell>
                <TableCell className="text-sm">{t.provider}</TableCell>
                <TableCell>
                  <Badge
                    variant={
                      t.status === "approved"
                        ? "default"
                        : t.status === "rejected"
                        ? "destructive"
                        : "secondary"
                    }
                    className="font-mono text-[10px]"
                  >
                    {t.status}
                  </Badge>
                </TableCell>
                <TableCell>
                  <Badge
                    variant={t.priority === "critical" ? "destructive" : "outline"}
                    className="font-mono text-[10px]"
                  >
                    {t.priority}
                  </Badge>
                </TableCell>
                <TableCell className="font-mono text-xs">
                  {t.submittedAt.slice(0, 10)}
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </Panel>
      <Separator />
      <div className="flex gap-2 mt-2">
        <Button variant="outline" size="sm">
          Export CSV
        </Button>
        <Button variant="outline" size="sm">
          Sync with provider
        </Button>
      </div>
    </ModuleShell>
  );
}
