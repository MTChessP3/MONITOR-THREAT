# MONITOR-THREAT

Cyber Threat Intelligence platform built with Next.js 16, TypeScript, Tailwind CSS 4 and shadcn/ui.

## Modules

### 🌐 Infrastructure & Network
| Module | Function |
|---|---|
| IP Intel | Geolocation, ASN, open ports, reputation and threat intel |
| Domain Intel | WHOIS, DNS, subdomains, SSL certificates and history |
| Domain Forensics | Deep forensic analysis of domains |
| DNS Dump | Full dump of DNS records for a domain |
| URL Scanner | Static and dynamic analysis of suspicious URLs |
| URL Sandbox | Isolated sandbox execution: behavior, network and files |
| TakeDown URL | Manage takedown requests for malicious content |

### 🕵️ OSINT & Surface Monitoring
| Module | Function |
|---|---|
| Deep & Dark Web | Monitor marketplaces, forums, paste sites, Telegram/Discord |
| Telegram & Discord Monitor | Resolve users/channels/groups; track membership history |
| Executive OSINT | Profiling of executives/VIPs; digital exposure |
| Brand Protection | Detect typosquatting, phishing, fake apps and impersonation |
| Fake App Scanner | Search for fake apps in official and third-party stores |

### 🔬 Technical Analysis & Vulnerabilities
| Module | Function |
|---|---|
| Hash Lookup | Identify algorithm and lookup against VT, MalwareBazaar and HIBP |
| CVE Database | Vulnerability database with exploits, PoCs and patches |
| Mobile Security | Analyze APK/IPA: permissions, certs, code and network |

### ⚡ Threat Intelligence & AI
| Module | Function |
|---|---|
| Threat Feeds | Ingest feeds from CISA, AlienVault, Abuse.ch, MISP and STIX/TAXII |
| IOC Manager | CRUD for indicators, enrichment, tagging and MITRE ATT&CK TTPs |
| Intelligence Sources | Manage sources: OSINT, CTI, HUMINT and commercial feeds |
| AI Analyst | Correlation, summaries, predictions and assisted hunting |

### 📊 Reporting & Exports
| Module | Function |
|---|---|
| Reports | Generate executive and technical reports (PDF, HTML, STIX) |
| Export Data | Export IOCs as CSV, JSON, STIX, OpenIOC and MISP |

## Tech Stack

- **Framework**: Next.js 16 (App Router)
- **Language**: TypeScript 5
- **Styling**: Tailwind CSS 4 with shadcn/ui (New York style)
- **State**: Zustand for client state
- **Charts**: Recharts
- **Icons**: Lucide React
- **Theme**: next-themes (dark by default)

## Getting Started

```bash
# Install dependencies
bun install

# Run dev server
bun run dev

# Build for production
bun run build

# Run linter
bun run lint
```

The app runs on port 3000 by default.

## Project Structure

```
src/
├── app/                    # Next.js App Router
│   ├── layout.tsx          # Root layout with theme provider
│   ├── page.tsx            # Main page with sidebar + module router
│   └── globals.css         # Tailwind + dark theme tokens
├── components/
│   ├── sidebar.tsx         # Sidebar with 20 modules in 5 categories
│   ├── theme-provider.tsx  # next-themes wrapper
│   ├── module-shell.tsx    # Reusable module layout primitives
│   └── views/              # One file per category
│       ├── dashboard.tsx
│       ├── infrastructure.tsx
│       ├── osint.tsx
│       ├── technical.tsx
│       ├── threat-intel.tsx
│       └── reporting.tsx
└── lib/
    ├── modules.ts          # Module catalog definition
    ├── mock-data.ts        # Synthetic data for all modules
    └── store.ts            # Zustand store for active module
```

## Author

MTChessP3 · 2026
