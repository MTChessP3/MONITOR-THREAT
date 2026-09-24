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
  IP_INTEL_RESULT,
  DOMAIN_INTEL_RESULT,
  URL_SCANNER_RESULT,
  TAKEDOWN_REQUESTS,
} from "@/lib/mock-data";

// ---------- IP Intel ----------
export function IpIntelView() {
  const r = IP_INTEL_RESULT;
  return (
    <ModuleShell
      name="IP Intel"
      description="Geolocation, ASN, open ports, reputation and threat intel for an IP address."
      icon={MapPin}
      category="INFRASTRUCTURE"
    >
      <SearchBar
        label="IP address"
        placeholder="e.g. 185.220.101.34"
        buttonText="Analyze"
      />
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mt-4">
        <Panel title="Geolocation & ASN">
          <FieldRow label="IP" value={r.ip} mono />
          <FieldRow label="ASN" value={r.asn} mono />
          <FieldRow label="ISP" value={r.isp} />
          <FieldRow label="Organization" value={r.organization} />
          <FieldRow label="Country" value={`${r.country} (${r.countryCode})`} />
          <FieldRow label="Region" value={r.region} />
          <FieldRow label="City" value={r.city} />
          <FieldRow
            label="Coordinates"
            value={`${r.latitude}, ${r.longitude}`}
            mono
          />
        </Panel>
        <Panel title="Open Ports">
          <div className="flex flex-wrap gap-1.5">
            {r.openPorts.map((p) => (
              <Badge key={p} variant="outline" className="font-mono">
                :{p}
              </Badge>
            ))}
          </div>
        </Panel>
        <Panel title="Reputation">
          <FieldRow label="Score" value={`${r.reputation.score}/100`} mono />
          <FieldRow
            label="Classification"
            value={
              <Badge variant="secondary" className="font-mono">
                {r.reputation.classification}
              </Badge>
            }
          />
          <FieldRow label="Votes" value={r.reputation.votes} mono />
          <FieldRow label="Last report" value={r.reputation.lastReport} mono />
        </Panel>
        <Panel title="Threat Intel">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Source</TableHead>
                <TableHead>Pulses</TableHead>
                <TableHead>Verdict</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {r.threatIntel.map((t) => (
                <TableRow key={t.source}>
                  <TableCell>{t.source}</TableCell>
                  <TableCell className="font-mono">
                    {("pulses" in t && t.pulses) ||
                      ("confidence" in t && t.confidence + "%") ||
                      "-"}
                  </TableCell>
                  <TableCell>
                    <Badge variant="outline" className="font-mono text-[10px]">
                      {t.verdict}
                    </Badge>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </Panel>
      </div>
      <Panel title="Tags" className="mt-4">
        <div className="flex flex-wrap gap-1.5">
          {r.tags.map((t) => (
            <Badge key={t} variant="secondary" className="font-mono">
              #{t}
            </Badge>
          ))}
        </div>
      </Panel>
    </ModuleShell>
  );
}

// ---------- Domain Intel ----------
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

// ---------- Domain Forensics ----------
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

// ---------- DNS Dump ----------
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

// ---------- URL Scanner ----------
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

// ---------- URL Sandbox ----------
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

// ---------- TakeDown URL ----------
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
