"use client";

import * as React from "react";
import { Fingerprint, Bug, Smartphone } from "lucide-react";

import {
  ModuleShell,
  Panel,
  FieldRow,
  SearchBar,
  EmptyModuleState,
} from "@/components/module-shell";
import { Badge } from "@/components/ui/badge";
import { Separator } from "@/components/ui/separator";
import { HASH_LOOKUP_RESULT, CVE_RESULT } from "@/lib/mock-data";

// ---------- Hash Lookup ----------
export function HashLookupView() {
  const r = HASH_LOOKUP_RESULT;
  return (
    <ModuleShell
      name="Hash Lookup"
      description="Identify hash algorithm and look up against VirusTotal, MalwareBazaar and HIBP."
      icon={Fingerprint}
      category="TECHNICAL"
    >
      <SearchBar label="Hash" placeholder="44d88612fea8a8f36de82e1278abb02f" />
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mt-4">
        <Panel title="Hash Info">
          <FieldRow label="Hash" value={r.hash} mono />
          <FieldRow label="Algorithm" value={r.algorithm} />
          <FieldRow label="Length" value={r.length} mono />
          <FieldRow label="File type" value={r.fileType} />
          <FieldRow label="File size" value={r.fileSize} mono />
          <FieldRow label="First seen" value={r.firstSeen} mono />
        </Panel>
        <Panel title="Detections">
          <FieldRow
            label="VirusTotal"
            value={`${r.detections.virusTotal.malicious}/${r.detections.virusTotal.total}`}
            mono
          />
          <FieldRow
            label="MalwareBazaar"
            value={r.detections.malwareBazaar.found ? "found" : "not found"}
          />
          <FieldRow
            label="HIBP"
            value={`${r.detections.hibp.breaches} breaches`}
            mono
          />
        </Panel>
      </div>
      <Separator />
      <Panel title="Cracking Notes" className="mt-2">
        <p className="text-sm text-muted-foreground">
          MD5 hashes are considered cryptographically broken. Use hashcat with
          mode 0 for raw MD5 or mode 1000 for NTLM if applicable.
        </p>
      </Panel>
    </ModuleShell>
  );
}

// ---------- CVE Database ----------
export function CveDatabaseView() {
  const r = CVE_RESULT;
  return (
    <ModuleShell
      name="CVE Database"
      description="Search vulnerabilities with exploits, PoCs and patches."
      icon={Bug}
      category="TECHNICAL"
    >
      <SearchBar label="CVE ID" placeholder="CVE-2024-3400" />
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mt-4">
        <Panel title="Vulnerability">
          <FieldRow label="CVE" value={r.cve} mono />
          <FieldRow label="Published" value={r.published} mono />
          <FieldRow label="Updated" value={r.updated} mono />
          <FieldRow
            label="CVSS"
            value={
              <Badge variant="destructive" className="font-mono">
                {r.cvss}
              </Badge>
            }
          />
          <FieldRow label="Vector" value={r.cvssVector} mono />
          <FieldRow label="CWE" value={r.cwe} mono />
        </Panel>
        <Panel title="Affected Product">
          <FieldRow label="Vendor" value={r.vendor} />
          <FieldRow label="Product" value={r.product} />
        </Panel>
        <Panel title="Description" className="md:col-span-2">
          <p className="text-sm">{r.description}</p>
        </Panel>
        <Panel title="Exploits">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Type</TableHead>
                <TableHead>URL</TableHead>
                <TableHead>Reliability</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {r.exploits.map((e) => (
                <TableRow key={e.url}>
                  <TableCell>
                    <Badge variant="outline" className="font-mono text-[10px]">
                      {e.type}
                    </Badge>
                  </TableCell>
                  <TableCell className="font-mono text-xs">{e.url}</TableCell>
                  <TableCell className="text-xs">{e.reliability}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </Panel>
        <Panel title="Patches">
          <div className="flex flex-col gap-1">
            {r.patches.map((p) => (
              <span key={p} className="font-mono text-xs px-2 py-1 rounded bg-muted/40">
                {p}
              </span>
            ))}
          </div>
        </Panel>
      </div>
    </ModuleShell>
  );
}

// ---------- Mobile Security ----------
export function MobileSecurityView() {
  return (
    <ModuleShell
      name="Mobile Security"
      description="Analyze APK/IPA: permissions, certificates, code and network calls."
      icon={Smartphone}
      category="TECHNICAL"
    >
      <SearchBar label="APK/IPA hash or upload" placeholder="SHA256 or upload file" />
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mt-4">
        <Panel title="Permissions">
          <EmptyModuleState
            icon={Smartphone}
            name="No sample"
            description="Requested Android/iOS permissions will be listed here."
          />
        </Panel>
        <Panel title="Certificate">
          <EmptyModuleState
            icon={Smartphone}
            name="No sample"
            description="Signing certificate details: issuer, validity, fingerprint."
          />
        </Panel>
        <Panel title="Network Calls">
          <EmptyModuleState
            icon={Smartphone}
            name="No sample"
            description="Outbound HTTP/HTTPS calls with URLs, methods and headers."
          />
        </Panel>
      </div>
    </ModuleShell>
  );
}

// re-import for the table
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
