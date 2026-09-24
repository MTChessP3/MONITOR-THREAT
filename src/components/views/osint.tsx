"use client";

import * as React from "react";
import {
  Skull,
  MessageSquare,
  UserSearch,
  ShieldCheck,
  Smartphone,
} from "lucide-react";

import {
  ModuleShell,
  Panel,
  FieldRow,
  SearchBar,
  EmptyModuleState,
} from "@/components/module-shell";
import { Badge } from "@/components/ui/badge";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { TELEGRAM_RESULT } from "@/lib/mock-data";

// ---------- Deep & Dark Web ----------
export function DeepDarkWebView() {
  const mentions = [
    { source: "EmpireMarket (onion)", type: "marketplace", count: 14, lastSeen: "2026-09-23" },
    { source: "BreachForums", type: "forum", count: 3, lastSeen: "2026-09-22" },
    { source: "Pastebin", type: "paste", count: 27, lastSeen: "2026-09-23" },
    { source: "Telegram channel @leaks", type: "telegram", count: 8, lastSeen: "2026-09-21" },
    { source: "Discord server 'dark'", type: "discord", count: 2, lastSeen: "2026-09-19" },
  ];
  return (
    <ModuleShell
      name="Deep & Dark Web"
      description="Monitor marketplaces, forums, paste sites and Telegram/Discord channels on the dark web."
      icon={Skull}
      category="OSINT"
    >
      <SearchBar label="Search term" placeholder="e.g. leaked email, brand, IOCs" />
      <Panel title="Recent Mentions" className="mt-4">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Source</TableHead>
              <TableHead>Type</TableHead>
              <TableHead>Mentions</TableHead>
              <TableHead>Last seen</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {mentions.map((m) => (
              <TableRow key={m.source}>
                <TableCell className="font-mono text-sm">{m.source}</TableCell>
                <TableCell>
                  <Badge variant="outline" className="font-mono text-[10px]">
                    {m.type}
                  </Badge>
                </TableCell>
                <TableCell className="font-mono">{m.count}</TableCell>
                <TableCell className="font-mono text-xs">{m.lastSeen}</TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </Panel>
    </ModuleShell>
  );
}

// ---------- Telegram & Discord Monitor ----------
export function TelegramDiscordView() {
  const r = TELEGRAM_RESULT;
  return (
    <ModuleShell
      name="Telegram & Discord Monitor"
      description="Resolve users, channels and groups; track membership changes and historical activity."
      icon={MessageSquare}
      category="OSINT"
    >
      <SearchBar label="@username or invite" placeholder="@threatintel_feed" />
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mt-4">
        <Panel title="Profile">
          <FieldRow label="Type" value={r.type} />
          <FieldRow label="Username" value={r.username} mono />
          <FieldRow label="ID" value={r.id} mono />
          <FieldRow label="Title" value={r.title} />
          <FieldRow label="Members" value={r.members.toLocaleString()} mono />
          <FieldRow
            label="Verified"
            value={
              <Badge variant="secondary" className="font-mono">
                {r.verified ? "yes" : "no"}
              </Badge>
            }
          />
        </Panel>
        <Panel title="Description">
          <p className="text-sm">{r.description}</p>
        </Panel>
        <Panel title="History" className="md:col-span-2">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Date</TableHead>
                <TableHead>Action</TableHead>
                <TableHead>From</TableHead>
                <TableHead>To</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {r.history.map((h, i) => (
                <TableRow key={i}>
                  <TableCell className="font-mono">{h.date}</TableCell>
                  <TableCell>{h.action}</TableCell>
                  <TableCell className="font-mono text-xs">
                    {"from" in h ? String(h.from) : "-"}
                  </TableCell>
                  <TableCell className="font-mono text-xs">
                    {"to" in h ? String(h.to) : "-"}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </Panel>
      </div>
    </ModuleShell>
  );
}

// ---------- Executive OSINT ----------
export function ExecutiveOsintView() {
  return (
    <ModuleShell
      name="Executive OSINT"
      description="Profiling of executives and VIPs; digital exposure and public footprint."
      icon={UserSearch}
      category="OSINT"
    >
      <SearchBar label="Full name or email" placeholder="John Doe / john@company.com" />
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mt-4">
        <Panel title="Public Footprint">
          <EmptyModuleState
            icon={UserSearch}
            name="No profile yet"
            description="Enter a name to enumerate LinkedIn, X, GitHub and corporate mentions."
          />
        </Panel>
        <Panel title="Data Breaches">
          <EmptyModuleState
            icon={UserSearch}
            name="No hits"
            description="Check HIBP, DeHashed and IntelX for credential leaks tied to the subject."
          />
        </Panel>
        <Panel title="Affiliations">
          <EmptyModuleState
            icon={UserSearch}
            name="No data"
            description="Discover companies, boards and partnerships publicly linked to the subject."
          />
        </Panel>
        <Panel title="Risk Assessment">
          <EmptyModuleState
            icon={UserSearch}
            name="No risk score"
            description="Combine exposure, breach history and behavior into a risk profile."
          />
        </Panel>
      </div>
    </ModuleShell>
  );
}

// ---------- Brand Protection ----------
export function BrandProtectionView() {
  return (
    <ModuleShell
      name="Brand Protection"
      description="Detect typosquatting, phishing, fake apps and impersonation across the surface web."
      icon={ShieldCheck}
      category="OSINT"
    >
      <SearchBar label="Brand or trademark" placeholder="Acme Corp" />
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mt-4">
        <Panel title="Typosquatting Domains">
          <EmptyModuleState
            icon={ShieldCheck}
            name="No alerts"
            description="Registered lookalike domains will be flagged here with registrant info."
          />
        </Panel>
        <Panel title="Phishing Sites">
          <EmptyModuleState
            icon={ShieldCheck}
            name="No alerts"
            description="Active phishing campaigns targeting your brand will appear here."
          />
        </Panel>
        <Panel title="Fake Apps">
          <EmptyModuleState
            icon={Smartphone}
            name="No alerts"
            description="Suspicious apps in stores and marketplaces will appear here."
          />
        </Panel>
        <Panel title="Social Impersonation">
          <EmptyModuleState
            icon={ShieldCheck}
            name="No alerts"
            description="Fake social profiles impersonating executives or brand accounts."
          />
        </Panel>
      </div>
    </ModuleShell>
  );
}

// ---------- Fake App Scanner ----------
export function FakeAppScannerView() {
  return (
    <ModuleShell
      name="Fake App Scanner"
      description="Search for fake apps in official stores and third-party marketplaces."
      icon={Smartphone}
      category="OSINT"
    >
      <SearchBar label="App name or developer" placeholder="WhatsApp" />
      <Panel title="Results" className="mt-4">
        <EmptyModuleState
          icon={Smartphone}
          name="No fake apps found"
          description="Lookalike apps with similar names, icons or developer names will appear here."
        />
      </Panel>
    </ModuleShell>
  );
}
