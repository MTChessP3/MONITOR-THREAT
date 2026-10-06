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

// ---------- Deep & Dark Web (re-export from dedicated file) ----------
export { DeepDarkWebView } from "@/components/views/deep-dark-web-view";

// ---------- Telegram & Discord Monitor (re-export from dedicated file) ----------
export { TelegramDiscordView } from "@/components/views/telegram-discord-view";

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
