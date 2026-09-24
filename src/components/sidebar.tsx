"use client";

import * as React from "react";
import {
  LayoutDashboard,
  Network,
  MapPin,
  Globe,
  Search,
  Server,
  Link as LinkIcon,
  Box,
  ShieldOff,
  Eye,
  Skull,
  MessageSquare,
  UserSearch,
  ShieldCheck,
  Smartphone,
  FlaskConical,
  Fingerprint,
  Bug,
  Zap,
  Radio,
  Database,
  Library,
  Sparkles,
  BarChart3,
  FileText,
  Download,
  ChevronDown,
  ChevronRight,
  type LucideIcon,
} from "lucide-react";

import { CATEGORIES, type ModuleCategory, type ModuleId } from "@/lib/modules";
import { useAppStore } from "@/lib/store";
import { cn } from "@/lib/utils";

const ICONS: Record<string, LucideIcon> = {
  LayoutDashboard,
  Network,
  MapPin,
  Globe,
  Search,
  Server,
  Link: LinkIcon,
  Box,
  ShieldOff,
  Eye,
  Skull,
  MessageSquare,
  UserSearch,
  ShieldCheck,
  Smartphone,
  FlaskConical,
  Fingerprint,
  Bug,
  Zap,
  Radio,
  Database,
  Library,
  Sparkles,
  BarChart3,
  FileText,
  Download,
};

interface SidebarState {
  collapsed: Set<ModuleCategory>;
  toggle: (id: ModuleCategory) => void;
}

function useSidebar() {
  const [collapsed, setCollapsed] = React.useState<Set<ModuleCategory>>(
    new Set()
  );
  const toggle = React.useCallback((id: ModuleCategory) => {
    setCollapsed((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }, []);
  return { collapsed, toggle } as SidebarState;
}

export function Sidebar() {
  const { collapsed, toggle } = useSidebar();
  const activeModule = useAppStore((s) => s.activeModule);
  const setActiveModule = useAppStore((s) => s.setActiveModule);

  return (
    <aside className="h-screen w-64 shrink-0 border-r border-border bg-sidebar overflow-y-auto flex flex-col">
      {/* Brand */}
      <div className="px-4 py-4 border-b border-sidebar-border flex items-center gap-2">
        <div className="w-8 h-8 rounded-md bg-primary text-primary-foreground flex items-center justify-center font-bold text-sm">
          M-T
        </div>
        <div className="flex flex-col">
          <span className="text-sm font-bold tracking-tight">MONITOR-THREAT</span>
          <span className="text-xs text-muted-foreground">v2 · CTI Platform</span>
        </div>
      </div>

      {/* Navigation */}
      <nav className="flex-1 overflow-y-auto px-2 py-2">
        {CATEGORIES.map((cat) => {
          const CatIcon = ICONS[cat.icon] ?? LayoutDashboard;
          const isDashboard = cat.id === "dashboard";
          const isCollapsed = !isDashboard && collapsed.has(cat.id);

          return (
            <div key={cat.id} className="mb-1">
              {/* Category header */}
              {isDashboard ? (
                <button
                  type="button"
                  onClick={() =>
                    setActiveModule(cat.modules[0].id as ModuleId)
                  }
                  className={cn(
                    "w-full flex items-center gap-2 px-2 py-2 rounded-md text-sm font-medium transition-colors",
                    activeModule === cat.modules[0].id
                      ? "bg-sidebar-primary text-sidebar-primary-foreground"
                      : "hover:bg-sidebar-accent text-sidebar-foreground"
                  )}
                >
                  <CatIcon className="w-4 h-4" />
                  <span>{cat.modules[0].name}</span>
                </button>
              ) : (
                <button
                  type="button"
                  onClick={() => toggle(cat.id)}
                  className="w-full flex items-center gap-1 px-2 py-2 rounded-md text-xs font-semibold uppercase tracking-wider text-muted-foreground hover:text-foreground transition-colors"
                >
                  <CatIcon className="w-4 h-4 shrink-0" />
                  <span className="flex-1 text-left normal-case tracking-normal">
                    {cat.label}
                  </span>
                  {isCollapsed ? (
                    <ChevronRight className="w-3.5 h-3.5" />
                  ) : (
                    <ChevronDown className="w-3.5 h-3.5" />
                  )}
                </button>
              )}

              {/* Module list */}
              {!isDashboard && !isCollapsed && (
                <ul className="mt-0.5 ml-4 mr-0 space-y-0.5 border-l border-sidebar-border pl-2">
                  {cat.modules.map((m) => {
                    const Icon = ICONS[m.icon] ?? LayoutDashboard;
                    const isActive = activeModule === m.id;
                    return (
                      <li key={m.id}>
                        <button
                          type="button"
                          onClick={() => setActiveModule(m.id)}
                          title={m.description}
                          className={cn(
                            "w-full flex items-center gap-2 px-2 py-1.5 rounded-md text-sm transition-colors",
                            isActive
                              ? "bg-sidebar-primary text-sidebar-primary-foreground"
                              : "hover:bg-sidebar-accent text-sidebar-foreground/90"
                          )}
                        >
                          <Icon className="w-3.5 h-3.5 shrink-0" />
                          <span className="truncate">{m.name}</span>
                        </button>
                      </li>
                    );
                  })}
                </ul>
              )}
            </div>
          );
        })}
      </nav>

      {/* Footer */}
      <div className="px-3 py-3 border-t border-sidebar-border text-xs text-muted-foreground">
        <div className="flex items-center justify-between">
          <span>Connected: <span className="text-emerald-500">●</span> Live</span>
          <span>v2.0.0</span>
        </div>
      </div>
    </aside>
  );
}
