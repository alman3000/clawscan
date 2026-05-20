# clawscan

OSINT and vulnerability scanning infrastructure for [OpenFang](https://www.openfang.sh/) agents. Five specialized Docker containers expose security tooling that OpenFang agents orchestrate via `docker exec`.

## Containers

| Container | Tools | Purpose |
|---|---|---|
| `clawscan-osint` | theHarvester, amass, subfinder, dnsx, recon-ng, sherlock, assetfinder, waybackurls, gau, hakrawler | Domain/email/subdomain OSINT |
| `clawscan-vulnscan` | nuclei, nikto, sqlmap, wapiti, whatweb, wafw00f, dalfox, XSStrike, commix, **testssl** | Web vulnerability scanning + TLS audit |
| `clawscan-portscan` | nmap, masscan, naabu, rustscan, netcat, **hydra**, **enum4linux-ng**, **onesixtyone**, **snmpwalk** | Port/network scanning + SMB/SNMP enum |
| `clawscan-webscan` | gobuster, ffuf, feroxbuster, katana, httpx, **kiterunner** + SecLists | Directory brute-force, web crawling, API discovery |
| `clawscan-cmsscan` | wpscan, joomscan, droopescan, cmsmap, typo3scan, magescan | CMS scanning (WordPress, Joomla, Drupal, TYPO3, Magento) |

All containers share a `/results` volume. Results are scoped per target and timestamp by `scan.sh`.

## Setup

```bash
cp .env.example .env
# fill in API keys (all optional but improve coverage)
docker compose up -d
```

## Running a Scan

Use `scan.sh` to start a scan — it creates a scoped results directory, verifies containers, and runs Phases 1–2 automatically. The OpenFang agent drives Phases 3–5 based on the findings.

```bash
# Active scan (default) — OSINT + port scan, then agent continues
bash scripts/scan.sh example.com

# Passive scan — OSINT only, no direct host contact
bash scripts/scan.sh example.com passive
```

Results land in `./results/<target>/<timestamp>/`. Each run is isolated — no files overwrite between targets or runs.

## Updating Tool Databases

Run weekly to keep nuclei templates, WPScan DB, SecLists, and testssl.sh current:

```bash
bash scripts/update.sh
```

## Generating a Report

After a scan, aggregate all tool output into a single ranked Markdown report:

```bash
python3 scripts/report.py ./results/example.com/20240101_120000 example.com
# writes ./results/example.com/20240101_120000/report.md
```

Parses: nuclei JSONL, wpscan JSON, nmap XML, ffuf JSON, testssl JSON. Findings sorted Critical → High → Medium → Low → Info.

## OpenFang Hand

The pentest hand in `hands/pentest.hand/` wires this into OpenFang:

```bash
openfang hand activate pentest
openfang hand run pentest --target example.com --mode active
```

| File | Purpose |
|---|---|
| `HAND.toml` | Hand manifest — inputs, containers, phases, limits |
| `prompt.md` | Agent system prompt — full methodology with escalation logic |
| `SKILL.md` | Domain knowledge — port→attack surface map, CVE reference, default creds |

## Manual docker exec Examples

```bash
# OSINT — subdomain enumeration
docker exec clawscan-osint subfinder -d target.com -o /results/target.com/run/subdomains.txt

# Port scan — fast full-port then deep
docker exec clawscan-portscan nmap -p- --min-rate 5000 -T4 target.com
docker exec clawscan-portscan nmap -p 22,80,443 -sV -sC -oA /results/target.com/run/deep target.com

# TLS audit
docker exec clawscan-vulnscan testssl --jsonfile /results/target.com/run/testssl.json https://target.com

# Vuln scan — nuclei
docker exec clawscan-vulnscan nuclei -u https://target.com -t /root/nuclei-templates -o /results/target.com/run/nuclei.txt

# SMB enum
docker exec clawscan-portscan enum4linux-ng -A target.com -oJ /results/target.com/run/enum4linux.json

# SNMP community string brute
docker exec clawscan-portscan onesixtyone \
  -c /opt/seclists/Discovery/SNMP/common-snmp-community-strings.txt target.com

# API discovery
docker exec clawscan-webscan kr scan https://target.com \
  -w /opt/seclists/Discovery/Web-Content/api/objects.txt

# WordPress scan
docker exec clawscan-cmsscan wpscan --url https://target.com \
  --api-token $WPSCAN_API_TOKEN --enumerate p,t,u,vp,vt \
  --output /results/target.com/run/wpscan.json --format json

# Credential brute-force (hydra)
docker exec clawscan-portscan hydra -l admin \
  -P /opt/seclists/Passwords/Common-Credentials/10k-most-common.txt \
  target.com ssh
```

## Directory Structure

```
clawscan/
├── docker-compose.yml
├── .env.example
├── results/                        # scan output — <target>/<timestamp>/
├── wordlists/                      # drop custom wordlists here
├── scripts/
│   ├── scan.sh                     # scoped scan runner (Phases 1–2)
│   ├── report.py                   # report aggregator
│   └── update.sh                   # update nuclei/wpscan/seclists/testssl
├── hands/
│   └── pentest.hand/
│       ├── HAND.toml               # OpenFang hand manifest
│       ├── prompt.md               # agent system prompt
│       └── SKILL.md                # pentesting knowledge base
└── containers/
    ├── osint/Dockerfile
    ├── vulnscan/Dockerfile + entrypoint.sh
    ├── portscan/Dockerfile
    ├── webscan/Dockerfile
    └── cmsscan/Dockerfile + entrypoint.sh
```

## API Keys (.env)

| Variable | Service | Used by |
|---|---|---|
| `SHODAN_API_KEY` | [shodan.io](https://shodan.io) | osint |
| `HUNTER_API_KEY` | [hunter.io](https://hunter.io) | osint |
| `INTELX_API_KEY` | [intelx.io](https://intelx.io) | osint |
| `VIRUSTOTAL_API_KEY` | [virustotal.com](https://virustotal.com) | osint |
| `CENSYS_API_ID` / `CENSYS_API_SECRET` | [censys.io](https://censys.io) | osint |
| `WPSCAN_API_TOKEN` | [wpscan.com](https://wpscan.com) (free tier) | cmsscan |

## Notes

- `clawscan-portscan` requires `NET_ADMIN` and `NET_RAW` caps for SYN/UDP scans.
- Nuclei templates are pulled on first container start and persisted in the `nuclei-templates` named volume.
- Each service has CPU and memory limits in `docker-compose.yml` to prevent runaway scans.
- Only use against targets you own or have explicit written permission to test.
