"use client";

import * as React from "react";
import { FileText, Download, FileJson, FileCode } from "lucide-react";

import {
  ModuleShell,
  Panel,
  SearchBar,
  EmptyModuleState,
  FieldRow,
} from "@/components/module-shell";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Separator } from "@/components/ui/separator";

// ---------- Reports ----------
export function ReportsView() {
  const templates = [
    { name: "Executive summary", format: "PDF", lastRun: "2026-09-22" },
    { name: "Technical incident", format: "PDF", lastRun: "2026-09-20" },
    { name: "Monthly threat brief", format: "HTML", lastRun: "2026-09-01" },
    { name: "STIX bundle export", format: "STIX", lastRun: "2026-09-15" },
  ];
  return (
    <ModuleShell
      name="Reports"
      description="Generate executive and technical reports in PDF, HTML and STIX."
      icon={FileText}
      category="REPORTING"
    >
      <div className="flex items-center justify-between">
        <SearchBar label="Search reports" placeholder="Filter reports..." />
        <Button size="sm">+ Generate report</Button>
      </div>
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mt-4">
        {templates.map((t) => (
          <Panel key={t.name} title={t.name}>
            <FieldRow label="Format" value={t.format} mono />
            <FieldRow label="Last run" value={t.lastRun} mono />
            <Separator />
            <div className="flex gap-2 mt-2">
              <Button variant="outline" size="sm">
                <FileText className="w-3 h-3 mr-1" />
                Run
              </Button>
              <Button variant="outline" size="sm">
                Preview
              </Button>
            </div>
          </Panel>
        ))}
      </div>
    </ModuleShell>
  );
}

// ---------- Export Data ----------
export function ExportDataView() {
  const formats = [
    { id: "csv", name: "CSV", desc: "Comma-separated values for spreadsheets" },
    { id: "json", name: "JSON", desc: "Structured JSON for programmatic import" },
    { id: "stix", name: "STIX 2.1", desc: "STIX bundle for CTI platforms" },
    { id: "openioc", name: "OpenIOC", desc: "Mandiant OpenIOC 1.1 XML" },
    { id: "misp", name: "MISP", desc: "MISP core format JSON" },
  ];
  return (
    <ModuleShell
      name="Export Data"
      description="Export IOCs as CSV, JSON, STIX, OpenIOC and MISP."
      icon={Download}
      category="REPORTING"
    >
      <SearchBar label="Filter" placeholder="e.g. tag:phishing severity:critical" />
      <Panel title="Available formats" className="mt-4">
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          {formats.map((f) => {
            const Icon = f.id === "csv" ? FileText : f.id === "json" ? FileJson : FileCode;
            return (
              <div
                key={f.id}
                className="flex items-start gap-3 p-3 rounded-md border border-border hover:bg-muted/30 transition-colors"
              >
                <Icon className="w-5 h-5 text-muted-foreground shrink-0 mt-0.5" />
                <div className="flex-1">
                  <div className="flex items-center justify-between">
                    <span className="font-mono text-sm">{f.name}</span>
                    <Button variant="outline" size="sm">
                      <Download className="w-3 h-3 mr-1" />
                      Export
                    </Button>
                  </div>
                  <p className="text-xs text-muted-foreground mt-0.5">{f.desc}</p>
                </div>
              </div>
            );
          })}
        </div>
      </Panel>
      <Panel title="Current selection" className="mt-4">
        <EmptyModuleState
          icon={Download}
          name="Nothing selected"
          description="Use the filter above to scope your export, or click Export on any format to export all."
        />
      </Panel>
    </ModuleShell>
  );
}
