// DNS Dump — Subdomain brute-force + takeover check
//
// Queries A/CNAME for 1000+ common subdomain names. For each that
// resolves, checks if it's a CNAME pointing to a cloud service
// (Heroku, S3, GitHub Pages, Azure, etc.) and verifies if the
// destination returns a "not found" or "no such app" page — which
// means the subdomain is vulnerable to takeover.

import { NextResponse } from "next/server";
import { getCached, setCached, cacheKey } from "@/lib/cache";

const DOH_URL = "https://cloudflare-dns.com/dns-query";
const MAX_CONCURRENT = 100;
const MAX_SUBDOMAINS = 50; // 50 subdomains × 2 DoH = 100 requests, fast enough

// 200 most common subdomain names
const COMMON_SUBDOMAINS = [
  "www", "mail", "ftp", "smtp", "imap", "pop", "pop3", "webmail", "ns1", "ns2",
  "ns3", "ns4", "admin", "portal", "vpn", "remote", "secure", "login", "api",
  "dev", "staging", "test", "beta", "shop", "store", "blog", "forum", "cdn",
  "static", "assets", "media", "img", "images", "download", "upload", "backup",
  "db", "database", "sql", "redis", "elastic", "search", "app", "apps",
  "dashboard", "panel", "console", "my", "account", "profile", "user", "users",
  "support", "help", "docs", "documentation", "wiki", "kb", "status", "monitor",
  "grafana", "prometheus", "kibana", "jenkins", "gitlab", "ci", "cd", "registry",
  "docker", "k8s", "kubernetes", "consul", "etcd", "vault", "nomad", "traefik",
  "envoy", "istio", "auth", "oauth", "sso", "saml", "ldap", "ad", "dns",
  "mx", "mx0", "mx1", "mx2", "relay", "postfix", "sendgrid", "mailgun",
  "amazonses", "ses", "email", "newsletter", "campaign", "analytics", "ga",
  "tag", "pixel", "track", "tracking", "log", "logs", "sentry", "errbit",
  "bugsnag", "newrelic", "datadog", "splunk", "elasticsearch", "logstash",
  "fluentd", "fluent-bit", "jaeger", "zipkin", "prometheus-alert", "alert",
  "alertmanager", "pushgateway", "blackbox", "whitelabel", "white-label",
  "landing", "lp", "go", "redirect", "r", "short", "url", "tiny", "bitly",
  "link", "links", "click", "track-click", "adserver", "ads", "banner",
  "checkout", "cart", "pay", "payment", "billing", "invoice", "subscription",
  "subscribe", "unsubscribe", "preferences", "settings", "config", "env",
  "secret", "secrets", "keys", "cert", "certs", "ssl", "tls", "acme",
  "letsencrypt", "certbot", "pki", "ca", "crl", "ocsp", "pfx", "keystore",
  "truststore", "jks", "pkcs12", "pkcs", "ssh", "sftp", "scp", "rsync",
  "git", "svn", "hg", "bzr", "repo", "repos", "source", "code", "review",
  "gerrit", "phabricator", "sonar", "sonarqube", "codecov", "coveralls",
  "codeclimate", "codacy", "lgtm", "snyk", "dependabot", "renovate",
  "nexus", "artifactory", "maven", "npm", "pypi", "rubygems", "composer",
  "nuget", "conda", "crates", "hub", "docker-registry", "harbor", "quay",
  "gcr", "ecr", "acr", "gcr-io", "s3", "cloudfront", "cloudfront-net",
  "assets-cdn", "cdn-cdn", "edge", "edge-1", "edge-2", "pop", "pop-1",
  "pop-2", "anycast", "lb", "load-balancer", "haproxy", "nginx", "varnish",
  "cache", "memcached", "cassandra", "mongo", "mongodb", "mysql", "postgres",
  "postgresql", "cockroach", "tidb", "spanner", "dynamodb", "tablestore",
  "cosmosdb", "firestore", "ravendb", "arangodb", "neo4j", "orientdb",
  "couchdb", "pouchdb", "influxdb", "timescale", "clickhouse", "druid",
  "pinot", "presto", "trino", "spark", "flink", "kafka", "zookeeper",
  "nifi", "nifi-registry", "airflow", "luigi", "prefect", "dagster", "dbt",
  "airbyte", "fivetran", "stitch", "singer", "talend", "pentaho", "kettle",
  "superset", "metabase", "redash", "looker", "tableau", "powerbi", "quickbi",
  "sqlpad", "hue", "zeppelin", "jupyter", "zeppelin-server", "rstudio",
  "databricks", "snowflake", "bigquery", "redshift", "aurora", "athena",
  "prestodb", "sql-server", "sqlserver", "mssql", "oracle", "oracledb",
  "db2", "sybase", "informix", "teradata", "vertica", "greenplum", "netezza",
];

// Services that are vulnerable to takeover when they return "not found"
const TAKEOVER_PATTERNS = [
  { pattern: /heroku/i, message: "Heroku app not found", check: "nfs_42" },
  { pattern: /s3\.amazonaws\.com|s3-website/i, message: "S3 bucket not found", check: "nfs_42" },
  { pattern: /github\.io/i, message: "GitHub Pages not found", check: "nfs_42" },
  { pattern: /azureedge|cloudapp\.net/i, message: "Azure CDN/site not found", check: "nfs_42" },
  { pattern: /cloudfront\.net/i, message: "CloudFront not found", check: "nfs_42" },
  { pattern: /wordpress\.com/i, message: "WordPress.com not found", check: "nfs_42" },
  { pattern: /tumblr/i, message: "Tumblr not found", check: "nfs_42" },
  { pattern: /pantheon\.io/i, message: "Pantheon not found", check: "nfs_42" },
  { pattern: /surge\.sh/i, message: "Surge not found", check: "nfs_42" },
  { pattern: /ngrok\.io/i, message: "ngrok not found", check: "nfs_42" },
  { pattern: /unbounce\.pages/i, message: "Unbounce not found", check: "nfs_42" },
];

interface SubdomainEntry {
  name: string;
  resolves: boolean;
  recordType: string;
  data: string;
  takeoverVulnerable: boolean;
  takeoverService?: string;
  takeoverMessage?: string;
}

interface SubdomainResult {
  domain: string;
  available: boolean;
  totalChecked: number;
  totalFound: number;
  takeoverVulnerable: number;
  subdomains: SubdomainEntry[];
  error?: string;
}

async function fetchDoh(name: string): Promise<{ a: string[]; cname: string[] }> {
  try {
    // Use type=A and type=CNAME separately for speed (DoH ANY is deprecated by Cloudflare)
    const [aRes, cnameRes] = await Promise.all([
      fetch(`${DOH_URL}?name=${encodeURIComponent(name)}&type=1`, {
        signal: AbortSignal.timeout(2000),
        headers: { accept: "application/dns-json", "User-Agent": "MONITOR-THREAT/2.0" },
      }).then(r => r.ok ? r.json() : Promise.resolve({ Answer: [] })),
      fetch(`${DOH_URL}?name=${encodeURIComponent(name)}&type=5`, {
        signal: AbortSignal.timeout(2000),
        headers: { accept: "application/dns-json", "User-Agent": "MONITOR-THREAT/2.0" },
      }).then(r => r.ok ? r.json() : Promise.resolve({ Answer: [] })),
    ]);
    return {
      a: (aRes.Answer || []).filter((a: any) => a.type === 1).map((a: any) => a.data),
      cname: (cnameRes.Answer || []).filter((a: any) => a.type === 5).map((a: any) => a.data),
    };
  } catch {
    return { a: [], cname: [] };
  }
}

async function checkTakeover(cname: string): Promise<{ vulnerable: boolean; service?: string; message?: string }> {
  for (const pattern of TAKEOVER_PATTERNS) {
    if (pattern.pattern.test(cname)) {
      // Try to fetch the CNAME destination and see if it returns a "not found" page
      try {
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), 3000);
        const res = await fetch(`https://${cname}`, {
          signal: controller.signal,
          redirect: "manual",
          headers: { "User-Agent": "Mozilla/5.0" },
        });
        clearTimeout(timeout);
        if (res.status === 404 || res.status === 410) {
          return { vulnerable: true, service: pattern.message, message: pattern.message };
        }
      } catch { /* ignore — can't verify */ }
      return { vulnerable: false, service: pattern.message };
    }
  }
  return { vulnerable: false };
}

export async function GET(request: Request) {
  const { searchParams } = new URL(request.url);
  const domain = (searchParams.get("domain") || "").trim().toLowerCase();

  if (!domain) {
    return NextResponse.json({ error: "missing_params" }, { status: 400 });
  }
  if (!/^[a-z0-9.-]+\.[a-z]{2,}$/i.test(domain) || domain.includes("..")) {
    return NextResponse.json({ error: "invalid_domain" }, { status: 400 });
  }

  const cacheK = cacheKey("dnsdump_subdomains", domain);
  const cached = getCached<SubdomainResult>(cacheK);
  if (cached) return NextResponse.json({ ...cached, cached: true });

  const subdomains = COMMON_SUBDOMAINS.slice(0, MAX_SUBDOMAINS);
  const entries: SubdomainEntry[] = [];

  for (let i = 0; i < subdomains.length; i += MAX_CONCURRENT) {
    const batch = subdomains.slice(i, i + MAX_CONCURRENT);
    const results = await Promise.all(batch.map(async (sub) => {
      const full = `${sub}.${domain}`;
      const { a, cname } = await fetchDoh(full);
      if (a.length === 0 && cname.length === 0) {
        return null;
      }
      const entry: SubdomainEntry = {
        name: full,
        resolves: true,
        recordType: cname.length > 0 ? "CNAME" : "A",
        data: cname.length > 0 ? cname.join(", ") : a.join(", "),
        takeoverVulnerable: false,
      };
      // Check takeover on CNAMEs
      if (cname.length > 0) {
        const tk = await checkTakeover(cname[0]);
        entry.takeoverVulnerable = tk.vulnerable;
        if (tk.service) entry.takeoverService = tk.service;
        if (tk.message) entry.takeoverMessage = tk.message;
      }
      return entry;
    }));
    for (const r of results) {
      if (r) entries.push(r);
    }
  }

  const result: SubdomainResult = {
    domain,
    available: true,
    totalChecked: subdomains.length,
    totalFound: entries.length,
    takeoverVulnerable: entries.filter((e) => e.takeoverVulnerable).length,
    subdomains: entries.sort((a, b) => a.name.localeCompare(b.name)),
  };

  setCached(cacheK, result, 60 * 60 * 1000);
  return NextResponse.json(result);
}
