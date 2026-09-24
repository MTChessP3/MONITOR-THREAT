// Module catalog for MONITOR-THREAT
// Each module has a unique id, a category, a name, an icon, and a description.

export type ModuleCategory =
  | "infrastructure"
  | "osint"
  | "technical"
  | "threat_intel"
  | "reporting";

export type ModuleId =
  | "dashboard"
  | "ip_intel"
  | "domain_intel"
  | "domain_forensics"
  | "dns_dump"
  | "url_scanner"
  | "url_sandbox"
  | "takedown_url"
  | "deep_dark_web"
  | "telegram_discord"
  | "executive_osint"
  | "brand_protection"
  | "fake_app_scanner"
  | "hash_lookup"
  | "cve_database"
  | "mobile_security"
  | "threat_feeds"
  | "ioc_manager"
  | "intelligence_sources"
  | "ai_analyst"
  | "reports"
  | "export_data";

export interface ModuleDef {
  id: ModuleId;
  name: string;
  description: string;
  category: ModuleCategory | "dashboard";
  icon: string; // lucide icon name
}

export interface CategoryDef {
  id: ModuleCategory | "dashboard";
  label: string;
  icon: string;
  modules: ModuleDef[];
}

export const CATEGORIES: CategoryDef[] = [
  {
    id: "dashboard",
    label: "Dashboard",
    icon: "LayoutDashboard",
    modules: [
      {
        id: "dashboard",
        name: "Command Dashboard",
        description:
          "Operational overview with live stats, threat timeline, IOC summary and quick actions.",
        category: "dashboard",
        icon: "LayoutDashboard",
      },
    ],
  },
  {
    id: "infrastructure",
    label: "🌐 Infrastructure & Network",
    icon: "Network",
    modules: [
      {
        id: "ip_intel",
        name: "IP Intel",
        description:
          "Geolocalization, ASN, open ports, reputation and threat intel for an IP.",
        category: "infrastructure",
        icon: "MapPin",
      },
      {
        id: "domain_intel",
        name: "Domain Intel",
        description:
          "WHOIS, DNS, subdomains, SSL certificates and historical records for a domain.",
        category: "infrastructure",
        icon: "Globe",
      },
      {
        id: "domain_forensics",
        name: "Domain Forensics",
        description: "Deep forensic analysis of domains: infrastructure, hosting and pivots.",
        category: "infrastructure",
        icon: "Search",
      },
      {
        id: "dns_dump",
        name: "DNS Dump",
        description: "Full dump of DNS records for a domain across all record types.",
        category: "infrastructure",
        icon: "Server",
      },
      {
        id: "url_scanner",
        name: "URL Scanner",
        description: "Static and dynamic analysis of suspicious URLs.",
        category: "infrastructure",
        icon: "Link",
      },
      {
        id: "url_sandbox",
        name: "URL Sandbox",
        description:
          "Isolated sandbox execution: network behavior, file system activity and process tree.",
        category: "infrastructure",
        icon: "Box",
      },
      {
        id: "takedown_url",
        name: "TakeDown URL",
        description: "Manage takedown requests for malicious content across providers.",
        category: "infrastructure",
        icon: "ShieldOff",
      },
    ],
  },
  {
    id: "osint",
    label: "🕵️ OSINT & Surface Monitoring",
    icon: "Eye",
    modules: [
      {
        id: "deep_dark_web",
        name: "Deep & Dark Web",
        description:
          "Monitor marketplaces, forums, paste sites and Telegram/Discord channels on the dark web.",
        category: "osint",
        icon: "Skull",
      },
      {
        id: "telegram_discord",
        name: "Telegram & Discord Monitor",
        description:
          "Resolve users, channels and groups; track membership changes and historical activity.",
        category: "osint",
        icon: "MessageSquare",
      },
      {
        id: "executive_osint",
        name: "Executive OSINT",
        description: "Profiling of executives and VIPs; digital exposure and public footprint.",
        category: "osint",
        icon: "UserSearch",
      },
      {
        id: "brand_protection",
        name: "Brand Protection",
        description:
          "Detect typosquatting, phishing, fake apps and impersonation across the surface web.",
        category: "osint",
        icon: "ShieldCheck",
      },
      {
        id: "fake_app_scanner",
        name: "Fake App Scanner",
        description: "Search for fake apps in official stores and third-party marketplaces.",
        category: "osint",
        icon: "Smartphone",
      },
    ],
  },
  {
    id: "technical",
    label: "🔬 Technical Analysis & Vulnerabilities",
    icon: "FlaskConical",
    modules: [
      {
        id: "hash_lookup",
        name: "Hash Lookup",
        description: "Identify hash algorithm and look up against VirusTotal, MalwareBazaar and HIBP.",
        category: "technical",
        icon: "Fingerprint",
      },
      {
        id: "cve_database",
        name: "CVE Database",
        description: "Search vulnerabilities with exploits, PoCs and patches.",
        category: "technical",
        icon: "Bug",
      },
      {
        id: "mobile_security",
        name: "Mobile Security",
        description: "Analyze APK/IPA: permissions, certificates, code and network calls.",
        category: "technical",
        icon: "Smartphone",
      },
    ],
  },
  {
    id: "threat_intel",
    label: "⚡ Threat Intelligence & AI",
    icon: "Zap",
    modules: [
      {
        id: "threat_feeds",
        name: "Threat Feeds",
        description: "Ingest feeds from CISA, AlienVault, Abuse.ch, MISP and STIX/TAXII sources.",
        category: "threat_intel",
        icon: "Radio",
      },
      {
        id: "ioc_manager",
        name: "IOC Manager",
        description:
          "CRUD for indicators, enrichment, tagging and MITRE ATT&CK TTPs.",
        category: "threat_intel",
        icon: "Database",
      },
      {
        id: "intelligence_sources",
        name: "Intelligence Sources",
        description: "Manage intelligence sources: OSINT, CTI, HUMINT and commercial feeds.",
        category: "threat_intel",
        icon: "Library",
      },
      {
        id: "ai_analyst",
        name: "AI Analyst",
        description: "Correlation, summaries, predictions and assisted threat hunting.",
        category: "threat_intel",
        icon: "Sparkles",
      },
    ],
  },
  {
    id: "reporting",
    label: "📊 Reporting & Exports",
    icon: "BarChart3",
    modules: [
      {
        id: "reports",
        name: "Reports",
        description: "Generate executive and technical reports in PDF, HTML and STIX.",
        category: "reporting",
        icon: "FileText",
      },
      {
        id: "export_data",
        name: "Export Data",
        description: "Export IOCs as CSV, JSON, STIX, OpenIOC and MISP.",
        category: "reporting",
        icon: "Download",
      },
    ],
  },
];

export const ALL_MODULES: ModuleDef[] = CATEGORIES.flatMap((c) => c.modules);

export const getModule = (id: ModuleId): ModuleDef | undefined =>
  ALL_MODULES.find((m) => m.id === id);
