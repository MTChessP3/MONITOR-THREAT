"use client";

import * as React from "react";
import { type LucideIcon, Activity } from "lucide-react";

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Separator } from "@/components/ui/separator";

export interface ModuleShellProps {
  name: string;
  description: string;
  icon: LucideIcon;
  category: string;
  status?: string;
  children: React.ReactNode;
}

export function ModuleShell({
  name,
  description,
  icon: Icon,
  category,
  status = "READY",
  children,
}: ModuleShellProps) {
  return (
    <div className="flex flex-col gap-4">
      {/* Header */}
      <div className="flex flex-col gap-2 pb-4 border-b border-border">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-md bg-primary/10 text-primary flex items-center justify-center">
            <Icon className="w-5 h-5" />
          </div>
          <div className="flex-1">
            <div className="flex items-center gap-2">
              <h1 className="text-xl font-semibold tracking-tight">{name}</h1>
              <Badge variant="secondary" className="text-[10px] font-mono">
                {category}
              </Badge>
              <Badge
                variant="outline"
                className="text-[10px] font-mono text-emerald-500 border-emerald-500/40"
              >
                <Activity className="w-2.5 h-2.5 mr-1" /> {status}
              </Badge>
            </div>
            <p className="text-sm text-muted-foreground mt-0.5">{description}</p>
          </div>
        </div>
      </div>
      {/* Body */}
      {children}
    </div>
  );
}

interface PanelProps {
  title: string;
  children: React.ReactNode;
  action?: React.ReactNode;
  className?: string;
}

export function Panel({ title, children, action, className }: PanelProps) {
  return (
    <Card className={className}>
      <CardHeader className="py-3 px-4 flex flex-row items-center justify-between">
        <CardTitle className="text-sm font-medium">{title}</CardTitle>
        {action}
      </CardHeader>
      <Separator />
      <CardContent className="p-4 text-sm">{children}</CardContent>
    </Card>
  );
}

interface FieldRowProps {
  label: string;
  value: React.ReactNode;
  mono?: boolean;
}

export function FieldRow({ label, value, mono }: FieldRowProps) {
  return (
    <div className="flex justify-between items-start py-1.5 border-b border-border/40 last:border-0">
      <span className="text-muted-foreground text-xs">{label}</span>
      <span
        className={`text-foreground text-sm text-right ${
          mono ? "font-mono" : ""
        }`}
      >
        {value}
      </span>
    </div>
  );
}

interface SearchBarProps {
  label: string;
  placeholder: string;
  buttonText?: string;
}

export function SearchBar({
  label,
  placeholder,
  buttonText = "Analyze",
}: SearchBarProps) {
  return (
    <div className="flex flex-col gap-2">
      <label className="text-xs font-medium text-muted-foreground uppercase tracking-wider">
        {label}
      </label>
      <div className="flex gap-2">
        <Input
          type="text"
          placeholder={placeholder}
          className="flex-1 font-mono text-sm"
          defaultValue=""
        />
        <Button type="button" size="sm">
          {buttonText}
        </Button>
      </div>
    </div>
  );
}

export function EmptyModuleState({
  icon: Icon,
  name,
  description,
}: {
  icon: LucideIcon;
  name: string;
  description: string;
}) {
  return (
    <div className="flex flex-col items-center justify-center min-h-[400px] text-center gap-3">
      <div className="w-16 h-16 rounded-full bg-muted/50 flex items-center justify-center">
        <Icon className="w-8 h-8 text-muted-foreground" />
      </div>
      <h2 className="text-lg font-semibold">{name}</h2>
      <p className="text-sm text-muted-foreground max-w-md">{description}</p>
      <p className="text-xs text-muted-foreground/70 mt-2">
        Connect an API key in Settings to enable live data for this module.
      </p>
    </div>
  );
}
