"use client";

import * as React from "react";
import { Search, RefreshCw } from "lucide-react";

import { Sidebar } from "@/components/sidebar";
import { useAppStore } from "@/lib/store";
import { getModule } from "@/lib/modules";
import { DashboardView } from "@/components/views/dashboard";
import {
  IpIntelView,
  DomainIntelView,
  DomainForensicsView,
  DnsDumpView,
  UrlScannerView,
  UrlSandboxView,
  TakedownUrlView,
} from "@/components/views/infrastructure";
import {
  DeepDarkWebView,
  TelegramDiscordView,
  ExecutiveOsintView,
  BrandProtectionView,
  FakeAppScannerView,
} from "@/components/views/osint";
import {
  HashLookupView,
  CveDatabaseView,
  MobileSecurityView,
} from "@/components/views/technical";
import {
  ThreatFeedsView,
  IocManagerView,
  IntelligenceSourcesView,
  AiAnalystView,
} from "@/components/views/threat-intel";
import { ReportsView, ExportDataView } from "@/components/views/reporting";

import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";

function ModuleRouter() {
  const active = useAppStore((s) => s.activeModule);
  switch (active) {
    case "dashboard":
      return <DashboardView />;
    case "ip_intel":
      return <IpIntelView />;
    case "domain_intel":
      return <DomainIntelView />;
    case "domain_forensics":
      return <DomainForensicsView />;
    case "dns_dump":
      return <DnsDumpView />;
    case "url_scanner":
      return <UrlScannerView />;
    case "url_sandbox":
      return <UrlSandboxView />;
    case "takedown_url":
      return <TakedownUrlView />;
    case "deep_dark_web":
      return <DeepDarkWebView />;
    case "telegram_discord":
      return <TelegramDiscordView />;
    case "executive_osint":
      return <ExecutiveOsintView />;
    case "brand_protection":
      return <BrandProtectionView />;
    case "fake_app_scanner":
      return <FakeAppScannerView />;
    case "hash_lookup":
      return <HashLookupView />;
    case "cve_database":
      return <CveDatabaseView />;
    case "mobile_security":
      return <MobileSecurityView />;
    case "threat_feeds":
      return <ThreatFeedsView />;
    case "ioc_manager":
      return <IocManagerView />;
    case "intelligence_sources":
      return <IntelligenceSourcesView />;
    case "ai_analyst":
      return <AiAnalystView />;
    case "reports":
      return <ReportsView />;
    case "export_data":
      return <ExportDataView />;
    default:
      return <DashboardView />;
  }
}

export default function Home() {
  const searchQuery = useAppStore((s) => s.searchQuery);
  const setSearchQuery = useAppStore((s) => s.setSearchQuery);

  return (
    <div className="flex min-h-screen bg-background text-foreground">
      <Sidebar />
      <div className="flex-1 flex flex-col min-w-0">
        {/* Top bar */}
        <header className="h-14 border-b border-border flex items-center gap-3 px-4">
          <div className="relative flex-1 max-w-xl">
            <Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-muted-foreground" />
            <Input
              type="text"
              placeholder="Search IOCs, IPs, domains, hashes, CVEs..."
              className="pl-9 font-mono text-sm"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
            />
          </div>
          <Button variant="outline" size="sm">
            <RefreshCw className="w-3.5 h-3.5 mr-2" />
            Refresh
          </Button>
        </header>

        {/* Main content */}
        <main className="flex-1 overflow-y-auto p-6">
          <ModuleRouter />
        </main>

        {/* Footer */}
        <footer className="h-8 border-t border-border flex items-center justify-between px-4 text-xs text-muted-foreground">
          <span>MONITOR-THREAT v2.0.0 · Cyber Threat Intelligence Platform</span>
          <span>
            Connected: <span className="text-emerald-500">●</span> Live ·{" "}
            {new Date().getUTCFullYear()} MTChessP3
          </span>
        </footer>
      </div>
    </div>
  );
}
