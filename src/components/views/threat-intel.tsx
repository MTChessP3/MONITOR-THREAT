"use client";

import * as React from "react";
import { Radio, Database, Library, Sparkles, Brain } from "lucide-react";

import {
  ModuleShell,
  Panel,
  FieldRow,
  SearchBar,
  EmptyModuleState,
} from "@/components/module-shell";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { THREAT_FEEDS } from "@/lib/mock-data";

// ---------- Threat Feeds ----------
export function ThreatFeedsView() {
  return (
    <ModuleShell
      name="Threat Feeds"
      description="Ingest feeds from CISA, AlienVault, Abuse.ch, MISP and STIX/TAXII sources."
      icon={Radio}
      category="THREAT INTEL"
    >
      <div className="flex items-center justify-between">
        <SearchBar label="Filter" placeholder="Search feeds..." />
        <Button size="sm">+ Add feed</Button>
      </div>
      <Panel title="Active Feeds" className="mt-4">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Name</TableHead>
              <TableHead>Source</TableHead>
              <TableHead>Last sync</TableHead>
              <TableHead>Entries</TableHead>
              <TableHead>Status</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {THREAT_FEEDS.map((f) => (
              <TableRow key={f.name}>
                <TableCell className="font-mono text-sm">{f.name}</TableCell>
                <TableCell className="font-mono text-xs">{f.source}</TableCell>
                <TableCell className="font-mono text-xs">
                  {f.lastSync.replace("T", " ").replace("Z", "")}
                </TableCell>
                <TableCell className="font-mono">{f.entries.toLocaleString()}</TableCell>
                <TableCell>
                  <Badge variant="outline" className="font-mono text-[10px] text-emerald-500 border-emerald-500/40">
                    {f.status}
                  </Badge>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </Panel>
    </ModuleShell>
  );
}

// ---------- IOC Manager ----------
export function IocManagerView() {
  const iocs = [
    { id: "IOC-001", type: "IP", value: "185.220.101.34", tags: ["tor-exit", "scanner"], ttp: "T1595", status: "SUSPICIOUS" },
    { id: "IOC-002", type: "DOMAIN", value: "evil.com", tags: ["phishing", "c2"], ttp: "T1566", status: "MALICIOUS" },
    { id: "IOC-003", type: "HASH", value: "44d88612fea8a8f36de82e1278abb02f", tags: ["sample"], ttp: "-", status: "BENIGN" },
    { id: "IOC-004", type: "CVE", value: "CVE-2024-3400", tags: ["rce", "palo-alto"], ttp: "T1190", status: "MALICIOUS" },
    { id: "IOC-005", type: "URL", value: "https://phishing-bank.com/login", tags: ["phishing", "banking"], ttp: "T1566", status: "MALICIOUS" },
  ];
  return (
    <ModuleShell
      name="IOC Manager"
      description="CRUD for indicators, enrichment, tagging and MITRE ATT&CK TTPs."
      icon={Database}
      category="THREAT INTEL"
    >
      <div className="flex items-center justify-between">
        <SearchBar label="Search" placeholder="Filter IOCs..." />
        <Button size="sm">+ New IOC</Button>
      </div>
      <Panel title="Indicator Inventory" className="mt-4">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>ID</TableHead>
              <TableHead className="w-20">Type</TableHead>
              <TableHead>Value</TableHead>
              <TableHead>Tags</TableHead>
              <TableHead>TTP</TableHead>
              <TableHead>Status</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {iocs.map((ioc) => (
              <TableRow key={ioc.id}>
                <TableCell className="font-mono text-xs">{ioc.id}</TableCell>
                <TableCell>
                  <Badge variant="outline" className="font-mono text-[10px]">
                    {ioc.type}
                  </Badge>
                </TableCell>
                <TableCell className="font-mono text-sm">{ioc.value}</TableCell>
                <TableCell>
                  <div className="flex gap-1 flex-wrap">
                    {ioc.tags.map((t) => (
                      <Badge key={t} variant="secondary" className="font-mono text-[10px]">
                        #{t}
                      </Badge>
                    ))}
                  </div>
                </TableCell>
                <TableCell className="font-mono text-xs">{ioc.ttp}</TableCell>
                <TableCell>
                  <Badge
                    variant={ioc.status === "MALICIOUS" ? "destructive" : "secondary"}
                    className="font-mono text-[10px]"
                  >
                    {ioc.status}
                  </Badge>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </Panel>
    </ModuleShell>
  );
}

// ---------- Intelligence Sources ----------
export function IntelligenceSourcesView() {
  const sources = [
    { name: "VirusTotal", type: "CTI", plan: "commercial", quota: "4/minute", active: true },
    { name: "Shodan", type: "OSINT", plan: "commercial", quota: "100/minute", active: true },
    { name: "AlienVault OTX", type: "OSINT", plan: "free", quota: "unlimited", active: true },
    { name: "AbuseIPDB", type: "OSINT", plan: "free", quota: "1000/day", active: true },
    { name: "MalwareBazaar", type: "OSINT", plan: "free", quota: "unlimited", active: true },
    { name: "HIBP", type: "OSINT", plan: "free", quota: "1/second", active: false },
    { name: "Censys", type: "OSINT", plan: "commercial", quota: "100/day", active: true },
    { name: "Internal HUMINT", type: "HUMINT", plan: "internal", quota: "n/a", active: true },
  ];
  return (
    <ModuleShell
      name="Intelligence Sources"
      description="Manage intelligence sources: OSINT, CTI, HUMINT and commercial feeds."
      icon={Library}
      category="THREAT INTEL"
    >
      <div className="flex items-center justify-between">
        <SearchBar label="Search" placeholder="Filter sources..." />
        <Button size="sm">+ Add source</Button>
      </div>
      <Panel title="Configured Sources" className="mt-4">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Name</TableHead>
              <TableHead>Type</TableHead>
              <TableHead>Plan</TableHead>
              <TableHead>Quota</TableHead>
              <TableHead>Active</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {sources.map((s) => (
              <TableRow key={s.name}>
                <TableCell className="font-mono text-sm">{s.name}</TableCell>
                <TableCell>
                  <Badge variant="outline" className="font-mono text-[10px]">
                    {s.type}
                  </Badge>
                </TableCell>
                <TableCell className="text-xs">{s.plan}</TableCell>
                <TableCell className="font-mono text-xs">{s.quota}</TableCell>
                <TableCell>
                  <Badge
                    variant="outline"
                    className={`font-mono text-[10px] ${
                      s.active
                        ? "text-emerald-500 border-emerald-500/40"
                        : "text-muted-foreground"
                    }`}
                  >
                    {s.active ? "active" : "inactive"}
                  </Badge>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </Panel>
    </ModuleShell>
  );
}

// ---------- AI Analyst ----------
export function AiAnalystView() {
  return (
    <ModuleShell
      name="AI Analyst"
      description="Correlation, summaries, predictions and assisted threat hunting."
      icon={Sparkles}
      category="THREAT INTEL"
    >
      <SearchBar label="Ask the analyst" placeholder="e.g. Correlate IOCs from last 7 days" />
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mt-4">
        <Panel title="Recent insights">
          <EmptyModuleState
            icon={Brain}
            name="No insights yet"
            description="Ask a question or run auto-correlation to surface hidden relationships."
          />
        </Panel>
        <Panel title="Suggested hunts">
          <EmptyModuleState
            icon={Brain}
            name="No suggestions"
            description="The analyst will propose hunting queries based on observed activity."
          />
        </Panel>
        <Panel title="Predictions">
          <EmptyModuleState
            icon={Brain}
            name="No predictions"
            description="Forecasting of attack likelihood based on current trends."
          />
        </Panel>
        <Panel title="Investigation log">
          <EmptyModuleState
            icon={Brain}
            name="No investigations"
            description="A log of analyst-driven investigations and their outcomes."
          />
        </Panel>
      </div>
    </ModuleShell>
  );
}
