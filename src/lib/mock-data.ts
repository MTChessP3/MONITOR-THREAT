// Mock data for the dashboard and module views.
// All data is synthetic and stable — used to demonstrate UI behavior.

export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
export type IOCStatus = "MALICIOUS" | "SUSPICIOUS" | "BENIGN" | "UNKNOWN";
export type IOCType = "IP" | "DOMAIN" | "HASH" | "CVE" | "URL" | "EMAIL" | "PHONE";

export interface IOC {
  id: string;
  type: IOCType;
  value: string;
  severity: Severity;
  status: IOCStatus;
  source: string;
  first_seen: string;
  last_seen: string;
  tags: string[];
  ttp?: string[]; // MITRE ATT&CK IDs
}

export const MOCK_IOCS: IOC[] = [
  {
    id: "ioc-1",
    type: "IP",
    value: "185.220.101.34",
    severity: "MEDIUM",
    status: "SUSPICIOUS",
    source: "AlienVault OTX",
    first_seen: "2026-09-18T08:14:00Z",
    last_seen: "2026-09-23T22:01:00Z",
    tags: ["tor-exit", "scanner"],
    ttp: ["T1595"],
  },
  {
    id: "ioc-2",
    type: "DOMAIN",
    value: "evil.com",
    severity: "HIGH",
    status: "MALICIOUS",
    source: "CISA KEV",
    first_seen: "2026-09-10T11:00:00Z",
    last_seen: "2026-09-23T18:00:00Z",
    tags: ["phishing", "c2"],
    ttp: ["T1566", "T1071"],
  },
  {
    id: "ioc-3",
    type: "HASH",
    value: "44d88612fea8a8f36de82e1278abb02f",
    severity: "LOW",
    status: "BENIGN",
    source: "VirusTotal",
    first_seen: "2026-09-01T00:00:00Z",
    last_seen: "2026-09-23T00:00:00Z",
    tags: ["sample"],
  },
  {
    id: "ioc-4",
    type: "CVE",
    value: "CVE-2024-3400",
    severity: "CRITICAL",
    status: "MALICIOUS",
    source: "NVD",
    first_seen: "2026-04-15T00:00:00Z",
    last_seen: "2026-09-23T12:00:00Z",
    tags: ["rce", "palo-alto"],
    ttp: ["T1190"],
  },
  {
    id: "ioc-5",
    type: "URL",
    value: "https://phishing-bank.com/login",
    severity: "CRITICAL",
    status: "MALICIOUS",
    source: "PhishTank",
    first_seen: "2026-09-20T09:00:00Z",
    last_seen: "2026-09-23T20:00:00Z",
    tags: ["phishing", "banking"],
    ttp: ["T1566"],
  },
];

export interface TimelineEvent {
  id: string;
  timestamp: string;
  message: string;
  severity: Severity;
}

export const MOCK_TIMELINE: TimelineEvent[] = [
  { id: "t1", timestamp: "12:46:59 AM", message: "New IOC detected by automated systems", severity: "INFO" },
  { id: "t2", timestamp: "11:59:54 PM", message: "Phishing campaign targeting finance sector", severity: "HIGH" },
  { id: "t3", timestamp: "11:57:54 PM", message: "Botnet C2 communication detected", severity: "CRITICAL" },
  { id: "t4", timestamp: "11:57:54 PM", message: "Dark web marketplace activity spike", severity: "HIGH" },
  { id: "t5", timestamp: "11:56:54 PM", message: "IOC added to watchlist", severity: "MEDIUM" },
  { id: "t6", timestamp: "11:56:54 PM", message: "Critical CVE published to NVD", severity: "CRITICAL" },
  { id: "t7", timestamp: "11:54:54 PM", message: "Domain resolution change detected", severity: "LOW" },
  { id: "t8", timestamp: "11:49:54 PM", message: "Data breach notification received", severity: "CRITICAL" },
  { id: "t9", timestamp: "12:44:54 AM", message: "Dark web marketplace activity spike", severity: "HIGH" },
  { id: "t10", timestamp: "12:41:54 AM", message: "SSL certificate expiration warning", severity: "LOW" },
  { id: "t11", timestamp: "12:32:54 AM", message: "Phishing campaign targeting finance sector", severity: "HIGH" },
  { id: "t12", timestamp: "12:30:54 AM", message: "Domain resolution change detected", severity: "LOW" },
  { id: "t13", timestamp: "12:29:54 AM", message: "SSL certificate expiration warning", severity: "LOW" },
  { id: "t14", timestamp: "12:25:54 AM", message: "SSL certificate expiration warning", severity: "LOW" },
  { id: "t15", timestamp: "12:24:54 AM", message: "Threat feed update received (CISA)", severity: "INFO" },
];

export const SEVERITY_COLORS: Record<Severity, string> = {
  CRITICAL: "#dc2626",
  HIGH: "#ea580c",
  MEDIUM: "#ca8a04",
  LOW: "#16a34a",
  INFO: "#0891b2",
};

// ----- IP Intel mock -----
export const IP_INTEL_RESULT = {
  ip: "185.220.101.34",
  asn: "AS200651",
  isp: "F3 Netze e.V.",
  organization: "Tor Exit Relay",
  country: "Germany",
  countryCode: "DE",
  region: "Hesse",
  city: "Frankfurt am Main",
  latitude: 50.1109,
  longitude: 8.6821,
  openPorts: [22, 80, 443, 9001, 9030],
  reputation: {
    score: 32,
    classification: "SUSPICIOUS",
    votes: 18,
    lastReport: "2026-09-23",
  },
  threatIntel: [
    { source: "AlienVault OTX", pulses: 14, verdict: "suspicious" },
    { source: "AbuseIPDB", confidence: 78, verdict: "abuse" },
    { source: "GreyNoise", tags: ["scanner", "tor"], classification: "benign" },
  ],
  tags: ["tor-exit", "port-scanner", "ssh-brute-force"],
};

// ----- Domain Intel mock -----
export const DOMAIN_INTEL_RESULT = {
  domain: "evil.com",
  registered: "2018-04-12",
  registrar: "NameCheap, Inc.",
  registrantCountry: "RU",
  nameservers: ["ns1.evil.com", "ns2.evil.com"],
  dns: {
    A: ["185.220.101.34"],
    MX: ["mail.evil.com"],
    TXT: ["v=spf1 include:_spf.evil.com ~all"],
    NS: ["ns1.evil.com", "ns2.evil.com"],
  },
  ssl: {
    issuer: "Let's Encrypt",
    validFrom: "2026-08-12",
    validTo: "2026-11-10",
    serial: "03:8c:aa:11:9b:21:7f:5d",
  },
  subdomains: ["www.evil.com", "mail.evil.com", "c2.evil.com", "login.evil.com", "admin.evil.com"],
  history: [
    { date: "2026-09-20", event: "A record changed", from: "1.2.3.4", to: "185.220.101.34" },
    { date: "2026-09-15", event: "SSL certificate renewed", from: "-", to: "Let's Encrypt" },
    { date: "2026-09-01", event: "MX record changed", from: "-", to: "mail.evil.com" },
  ],
};

// ----- URL Scanner mock -----
export const URL_SCANNER_RESULT = {
  url: "https://phishing-bank.com/login",
  finalUrl: "https://phishing-bank.com/login",
  redirects: 0,
  httpStatus: 200,
  responseTime: 487,
  ssl: { valid: true, issuer: "Let's Encrypt", expires: "2026-11-12" },
  technologies: ["Nginx", "PHP/7.4", "jQuery"],
  verdicts: [
    { source: "VirusTotal", verdict: "malicious", positives: 42, total: 92 },
    { source: "Google Safe Browsing", verdict: "malicious", reason: "Social engineering" },
    { source: "URLScan.io", verdict: "malicious", score: 92 },
    { source: "PhishTank", verdict: "phishing", listed: true },
  ],
  extracted: {
    emails: [],
    phones: [],
    ips: ["185.220.101.34"],
    forms: 1,
    iframes: 0,
    scripts: 4,
  },
};

// ----- Hash Lookup mock -----
export const HASH_LOOKUP_RESULT = {
  hash: "44d88612fea8a8f36de82e1278abb02f",
  algorithm: "MD5",
  length: 32,
  detections: {
    virusTotal: { malicious: 0, total: 72, permalink: "https://virustotal.com/..." },
    malwareBazaar: { found: false, signature: null },
    hibp: { found: false, breaches: 0 },
  },
  fileType: "PE32 executable",
  fileSize: "245 KB",
  firstSeen: "2026-09-01",
};

// ----- CVE mock -----
export const CVE_RESULT = {
  cve: "CVE-2024-3400",
  published: "2026-04-15",
  updated: "2026-09-20",
  cvss: 10.0,
  cvssVector: "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
  cwe: "CWE-78",
  vendor: "Palo Alto Networks",
  product: "PAN-OS GlobalProtect Gateway",
  description:
    "OS command injection in GlobalProtect gateway allows unauthenticated attacker to execute arbitrary code as root.",
  references: [
    "https://nvd.nist.gov/vuln/detail/CVE-2024-3400",
    "https://security.paloaltonetworks.com/CVE-2024-3400",
  ],
  exploits: [
    { type: "PoC", url: "https://github.com/example/cve-2024-3400", reliability: "high" },
    { type: "Metasploit", url: "https://github.com/rapid7/...", reliability: "verified" },
  ],
  patches: ["PAN-OS 11.1.2-h3", "PAN-OS 10.2.9-h1"],
  mitre: ["T1190"],
};

// ----- Telegram/Discord mock -----
export const TELEGRAM_RESULT = {
  type: "channel",
  username: "@threatintel_feed",
  id: "t.me/threatintel_feed",
  title: "Threat Intel Daily",
  members: 4521,
  verified: true,
  description: "Daily curated threat intelligence feed.",
  photo: "",
  history: [
    { date: "2026-09-23", action: "members_count_change", from: 4500, to: 4521 },
    { date: "2026-09-22", action: "title_change", from: "Threat Intel", to: "Threat Intel Daily" },
    { date: "2026-09-20", action: "pinned_message" },
  ],
};

// ----- Threat Feeds mock -----
export const THREAT_FEEDS = [
  { name: "CISA KEV", source: "cisa.gov", lastSync: "2026-09-23T22:00:00Z", entries: 1243, status: "active" },
  { name: "AlienVault OTX", source: "otx.alienvault.com", lastSync: "2026-09-23T21:55:00Z", entries: 8742, status: "active" },
  { name: "Abuse.ch URLhaus", source: "urlhaus.abuse.ch", lastSync: "2026-09-23T21:50:00Z", entries: 5234, status: "active" },
  { name: "Abuse.ch MalwareBazaar", source: "bazaar.abuse.ch", lastSync: "2026-09-23T21:45:00Z", entries: 2389, status: "active" },
  { name: "MISP Feed - Circl", source: "circl.lu", lastSync: "2026-09-23T20:00:00Z", entries: 1284, status: "active" },
  { name: "STIX/TAXII - MITRE", source: "cti.mitre.org", lastSync: "2026-09-23T18:00:00Z", entries: 645, status: "active" },
  { name: "PhishTank", source: "phishtank.com", lastSync: "2026-09-23T22:00:00Z", entries: 31200, status: "active" },
];

// ----- Takedown mock -----
export const TAKEDOWN_REQUESTS = [
  {
    id: "TD-2026-001",
    url: "https://phishing-bank.com/login",
    target: "Impersonation of Bank XYZ",
    provider: "Cloudflare",
    status: "submitted",
    submittedAt: "2026-09-20T14:30:00Z",
    evidence: ["screenshot.png", "url_scan_report.pdf"],
    priority: "critical",
  },
  {
    id: "TD-2026-002",
    url: "https://fake-store.shop/product/12345",
    target: "Counterfeit merchandise",
    provider: "Google Safe Browsing",
    status: "approved",
    submittedAt: "2026-09-18T09:00:00Z",
    evidence: ["brand_report.pdf"],
    priority: "high",
  },
  {
    id: "TD-2026-003",
    url: "https://malware-download.xyz/installer.exe",
    target: "Malware distribution",
    provider: "Hosting Provider",
    status: "pending_evidence",
    submittedAt: "2026-09-22T16:00:00Z",
    evidence: [],
    priority: "high",
  },
  {
    id: "TD-2026-004",
    url: "https://impersonation-social.fake/profile/john.doe",
    target: "Impersonation of executive",
    provider: "Social Platform",
    status: "rejected",
    submittedAt: "2026-09-15T10:30:00Z",
    evidence: ["impersonation_report.pdf"],
    priority: "medium",
  },
];
