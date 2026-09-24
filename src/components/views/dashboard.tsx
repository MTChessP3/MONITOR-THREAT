"use client";

import * as React from "react";
import {
  RefreshCw,
  Database as DatabaseIcon,
  AlertOctagon,
  ShieldAlert,
  Activity,
  Filter,
  RotateCcw,
} from "lucide-react";
import { PieChart, Pie, Cell, ResponsiveContainer, BarChart, Bar, XAxis, YAxis, Tooltip as RTooltip, CartesianGrid } from "recharts";

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
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
  MOCK_IOCS,
  MOCK_TIMELINE,
  SEVERITY_COLORS,
  type Severity,
} from "@/lib/mock-data";
import { useAppStore } from "@/lib/store";
import type { ModuleId } from "@/lib/modules";

const severityTextClass: Record<Severity, string> = {
  CRITICAL: "text-red-500",
  HIGH: "text-orange-500",
  MEDIUM: "text-yellow-500",
  LOW: "text-emerald-500",
  INFO: "text-cyan-500",
};

const STATS = [
  { id: "total", label: "Total IOCs", value: "5", icon: DatabaseIcon, accent: "text-cyan-500" },
  { id: "critical", label: "Critical Threats", value: "2", icon: AlertOctagon, accent: "text-red-500" },
  { id: "malicious", label: "Malicious", value: "3", icon: ShieldAlert, accent: "text-orange-500" },
  { id: "events", label: "Live Events", value: "21", icon: Activity, accent: "text-emerald-500" },
];

const QUICK_ACTIONS: { label: string; module: ModuleId }[] = [
  { label: "IP Recon", module: "ip_intel" },
  { label: "Domain Scan", module: "domain_intel" },
  { label: "URL Analysis", module: "url_scanner" },
  { label: "Hash Lookup", module: "hash_lookup" },
  { label: "CVE Search", module: "cve_database" },
  { label: "AI Analysis", module: "ai_analyst" },
  { label: "Dark Web", module: "deep_dark_web" },
  { label: "Mobile Scan", module: "mobile_security" },
];

const severityData = [
  { name: "Critical", value: 2, color: SEVERITY_COLORS.CRITICAL },
  { name: "High", value: 1, color: SEVERITY_COLORS.HIGH },
  { name: "Medium", value: 1, color: SEVERITY_COLORS.MEDIUM },
  { name: "Low", value: 1, color: SEVERITY_COLORS.LOW },
];

const typeData = [
  { name: "IP", count: 1 },
  { name: "Domain", count: 1 },
  { name: "Hash", count: 1 },
  { name: "CVE", count: 1 },
  { name: "URL", count: 1 },
];

export function DashboardView() {
  const setActiveModule = useAppStore((s) => s.setActiveModule);

  return (
    <div className="flex flex-col gap-6">
      {/* Header */}
      <div className="flex items-center justify-between pb-4 border-b border-border">
        <div>
          <h1 className="text-2xl font-bold tracking-tight">MONITOR-THREAT-v2</h1>
          <p className="text-sm text-muted-foreground">
            Cyber Threat Intelligence · Command Dashboard
          </p>
        </div>
        <Button variant="outline" size="sm">
          <RefreshCw className="w-3.5 h-3.5 mr-2" />
          Refresh
        </Button>
      </div>

      {/* Live Stats */}
      <div>
        <h2 className="text-xs font-semibold uppercase tracking-wider text-muted-foreground mb-2">
          Live Stats
        </h2>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
          {STATS.map((stat) => {
            const Icon = stat.icon;
            return (
              <Card key={stat.id}>
                <CardContent className="p-4 flex items-center gap-3">
                  <div className={`p-2 rounded-md bg-muted/40 ${stat.accent}`}>
                    <Icon className="w-5 h-5" />
                  </div>
                  <div className="flex flex-col">
                    <span className="text-2xl font-bold leading-tight">
                      {stat.value}
                    </span>
                    <span className="text-xs text-muted-foreground">
                      {stat.label}
                    </span>
                  </div>
                </CardContent>
              </Card>
            );
          })}
        </div>
      </div>

      {/* Command Dashboard */}
      <div>
        <div className="flex items-center justify-between mb-3">
          <h2 className="text-base font-semibold">Command Dashboard</h2>
          <Button variant="outline" size="sm">
            <RefreshCw className="w-3.5 h-3.5 mr-2" />
            Refresh All
          </Button>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {/* Live Threat Timeline */}
          <Card className="md:col-span-2 lg:col-span-2">
            <CardHeader className="py-3 px-4 flex flex-row items-center justify-between">
              <CardTitle className="text-sm font-medium flex items-center gap-2">
                Live Threat Timeline
                <Badge variant="outline" className="text-[10px] font-mono">
                  <span className="text-emerald-500 animate-pulse">●</span> LIVE
                </Badge>
              </CardTitle>
              <Button variant="ghost" size="sm" className="h-7">
                <Filter className="w-3 h-3 mr-1" />
                Filter
              </Button>
            </CardHeader>
            <Separator />
            <CardContent className="p-0">
              <div className="max-h-[400px] overflow-y-auto divide-y divide-border/40">
                {MOCK_TIMELINE.map((e) => (
                  <div
                    key={e.id}
                    className="px-4 py-2 flex items-start gap-3 hover:bg-muted/30 cursor-pointer transition-colors"
                  >
                    <span className="font-mono text-xs text-muted-foreground shrink-0 w-32">
                      {e.timestamp}
                    </span>
                    <span className="text-sm flex-1">{e.message}</span>
                    <span
                      className={`text-[10px] font-mono font-semibold ${
                        severityTextClass[e.severity]
                      } shrink-0`}
                    >
                      {e.severity}
                    </span>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>

          {/* Right column: charts */}
          <div className="flex flex-col gap-4">
            <Card>
              <CardHeader className="py-3 px-4">
                <CardTitle className="text-sm font-medium">
                  Severity Distribution
                </CardTitle>
              </CardHeader>
              <Separator />
              <CardContent className="p-4 h-44">
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie
                      data={severityData}
                      dataKey="value"
                      nameKey="name"
                      innerRadius={28}
                      outerRadius={56}
                      paddingAngle={2}
                    >
                      {severityData.map((d) => (
                        <Cell key={d.name} fill={d.color} />
                      ))}
                    </Pie>
                    <RTooltip />
                  </PieChart>
                </ResponsiveContainer>
              </CardContent>
            </Card>

            <Card>
              <CardHeader className="py-3 px-4 flex flex-row items-center justify-between">
                <CardTitle className="text-sm font-medium">
                  Type Distribution
                </CardTitle>
                <Button variant="ghost" size="sm" className="h-7">
                  <RotateCcw className="w-3 h-3 mr-1" />
                  Reset
                </Button>
              </CardHeader>
              <Separator />
              <CardContent className="p-4 h-44">
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={typeData}>
                    <CartesianGrid strokeDasharray="3 3" stroke="#2a2a2a" />
                    <XAxis dataKey="name" tick={{ fontSize: 11 }} stroke="#777" />
                    <YAxis tick={{ fontSize: 11 }} stroke="#777" />
                    <RTooltip />
                    <Bar dataKey="count" fill="#0891b2" radius={[4, 4, 0, 0]} />
                  </BarChart>
                </ResponsiveContainer>
              </CardContent>
            </Card>
          </div>
        </div>
      </div>

      {/* Recent IOCs */}
      <Card>
        <CardHeader className="py-3 px-4 flex flex-row items-center justify-between">
          <CardTitle className="text-sm font-medium">Recent IOCs</CardTitle>
          <Button variant="ghost" size="sm" onClick={() => setActiveModule("ioc_manager")}>
            View All
          </Button>
        </CardHeader>
        <Separator />
        <CardContent className="p-0">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead className="w-20">Type</TableHead>
                <TableHead>Value</TableHead>
                <TableHead className="w-24">Severity</TableHead>
                <TableHead className="w-32">Status</TableHead>
                <TableHead className="w-16 text-right">Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {MOCK_IOCS.map((ioc) => (
                <TableRow
                  key={ioc.id}
                  className="cursor-pointer hover:bg-muted/30"
                  onClick={() => setActiveModule("ioc_manager")}
                >
                  <TableCell>
                    <Badge variant="outline" className="font-mono text-[10px]">
                      {ioc.type}
                    </Badge>
                  </TableCell>
                  <TableCell className="font-mono text-sm">{ioc.value}</TableCell>
                  <TableCell>
                    <span
                      className={`text-[10px] font-mono font-semibold ${
                        severityTextClass[ioc.severity]
                      }`}
                    >
                      {ioc.severity}
                    </span>
                  </TableCell>
                  <TableCell>
                    <Badge
                      variant={ioc.status === "MALICIOUS" ? "destructive" : "secondary"}
                      className="text-[10px] font-mono"
                    >
                      {ioc.status}
                    </Badge>
                  </TableCell>
                  <TableCell className="text-right">
                    <Button variant="ghost" size="sm" className="h-7">
                      ···
                    </Button>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </CardContent>
      </Card>

      {/* Quick Actions */}
      <div>
        <h2 className="text-xs font-semibold uppercase tracking-wider text-muted-foreground mb-2">
          Quick Actions
        </h2>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
          {QUICK_ACTIONS.map((qa) => (
            <Button
              key={qa.module}
              variant="outline"
              onClick={() => setActiveModule(qa.module)}
            >
              {qa.label}
            </Button>
          ))}
        </div>
      </div>
    </div>
  );
}
