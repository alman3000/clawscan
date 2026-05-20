#!/usr/bin/env python3
"""
Aggregate raw tool output from a clawscan results directory into a
single ranked Markdown report.

Usage: python3 scripts/report.py <results_dir> <target>
"""
import json
import os
import sys
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path

SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unknown": 5}


def sev(s: str) -> str:
    return s.lower() if s else "unknown"


def badge(s: str) -> str:
    icons = {"critical": "CRITICAL", "high": "HIGH", "medium": "MEDIUM",
             "low": "LOW", "info": "INFO", "unknown": "?"}
    return icons.get(sev(s), "?")


# ── Parsers ──────────────────────────────────────────────────────────────────

def parse_nuclei(path: Path) -> list[dict]:
    findings = []
    if not path.exists():
        return findings
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue
            findings.append({
                "severity": sev(item.get("info", {}).get("severity", "info")),
                "title": item.get("info", {}).get("name", "Nuclei finding"),
                "host": item.get("host", ""),
                "tool": f"nuclei ({item.get('template-id', '')})",
                "evidence": item.get("matched-at", item.get("host", "")),
                "description": item.get("info", {}).get("description", ""),
                "remediation": item.get("info", {}).get("remediation", ""),
            })
    return findings


def parse_wpscan(path: Path) -> list[dict]:
    findings = []
    if not path.exists():
        return findings
    try:
        data = json.loads(path.read_text())
    except (json.JSONDecodeError, OSError):
        return findings

    target = data.get("start_url", "")

    for plugin_name, plugin in data.get("plugins", {}).items():
        for vuln in plugin.get("vulnerabilities", []):
            cvss = vuln.get("cvss", {})
            score = float(cvss.get("score", 0)) if cvss else 0
            severity = "critical" if score >= 9 else "high" if score >= 7 else "medium" if score >= 4 else "low"
            findings.append({
                "severity": severity,
                "title": f"WordPress plugin '{plugin_name}': {vuln.get('title', 'Vulnerability')}",
                "host": target,
                "tool": "wpscan",
                "evidence": f"Plugin version: {plugin.get('version', {}).get('number', 'unknown')} | CVE: {', '.join(vuln.get('references', {}).get('cve', []))}",
                "description": vuln.get("title", ""),
                "remediation": f"Update plugin '{plugin_name}' to latest version.",
            })

    for user in data.get("users", {}).keys():
        findings.append({
            "severity": "medium",
            "title": f"WordPress user enumerated: {user}",
            "host": target,
            "tool": "wpscan",
            "evidence": f"Username: {user}",
            "description": "Valid WordPress username discovered via user enumeration.",
            "remediation": "Disable user enumeration (e.g. stop ?author= redirect). Use strong unique passwords.",
        })

    if data.get("xmlrpc", {}).get("found"):
        findings.append({
            "severity": "low",
            "title": "WordPress XML-RPC enabled",
            "host": target,
            "tool": "wpscan",
            "evidence": data.get("xmlrpc", {}).get("url", ""),
            "description": "XML-RPC can be abused for brute-force amplification and SSRF.",
            "remediation": "Disable XML-RPC unless required.",
        })

    return findings


def parse_nmap_xml(path: Path) -> list[dict]:
    findings = []
    xml_file = path.with_suffix(".xml") if path.suffix != ".xml" else path
    if not xml_file.exists():
        return findings
    try:
        tree = ET.parse(xml_file)
    except ET.ParseError:
        return findings

    for host in tree.findall("host"):
        addr_el = host.find("address[@addrtype='ipv4']")
        if addr_el is None:
            addr_el = host.find("address")
        addr = addr_el.attrib.get("addr", "") if addr_el is not None else ""

        for port_el in host.findall(".//port"):
            state = port_el.find("state")
            if state is None or state.attrib.get("state") != "open":
                continue
            portid = port_el.attrib.get("portid", "")
            service_el = port_el.find("service")
            service = service_el.attrib.get("name", "") if service_el is not None else ""
            product = service_el.attrib.get("product", "") if service_el is not None else ""
            version = service_el.attrib.get("version", "") if service_el is not None else ""

            for script in port_el.findall("script"):
                script_id = script.attrib.get("id", "")
                output = script.attrib.get("output", "")
                if "VULNERABLE" in output.upper():
                    findings.append({
                        "severity": "high",
                        "title": f"Nmap NSE: {script_id} — VULNERABLE on {addr}:{portid}",
                        "host": f"{addr}:{portid}",
                        "tool": f"nmap ({script_id})",
                        "evidence": output[:500],
                        "description": f"Service: {product} {version}",
                        "remediation": "Apply vendor patch for identified vulnerability.",
                    })

            # Version exposure
            if product or version:
                findings.append({
                    "severity": "info",
                    "title": f"Service version: {service} {product} {version} on {addr}:{portid}",
                    "host": f"{addr}:{portid}",
                    "tool": "nmap",
                    "evidence": f"{product} {version}",
                    "description": "Software version exposed — check against CVE databases.",
                    "remediation": "Suppress version banners where possible. Keep software updated.",
                })
    return findings


def parse_ffuf(path: Path) -> list[dict]:
    findings = []
    if not path.exists():
        return findings
    try:
        data = json.loads(path.read_text())
    except (json.JSONDecodeError, OSError):
        return findings

    for result in data.get("results", []):
        status = result.get("status", 0)
        url = result.get("url", "")
        if status in (200, 201):
            findings.append({
                "severity": "info",
                "title": f"Discovered endpoint: {url}",
                "host": url,
                "tool": "ffuf",
                "evidence": f"HTTP {status} — {result.get('length', 0)} bytes",
                "description": "Accessible endpoint found during directory enumeration.",
                "remediation": "Review whether this endpoint should be publicly accessible.",
            })
        elif status in (401, 403):
            findings.append({
                "severity": "low",
                "title": f"Restricted endpoint (HTTP {status}): {url}",
                "host": url,
                "tool": "ffuf",
                "evidence": f"HTTP {status} — {result.get('length', 0)} bytes",
                "description": "Endpoint exists but access is restricted. May be bypassable.",
                "remediation": "Verify access controls are enforced server-side.",
            })
    return findings


def parse_testssl(path: Path) -> list[dict]:
    findings = []
    if not path.exists():
        return findings
    try:
        data = json.loads(path.read_text())
    except (json.JSONDecodeError, OSError):
        return findings

    severity_map = {
        "CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium",
        "LOW": "low", "INFO": "info", "OK": None, "NOT applicable": None,
    }

    for entry in data if isinstance(data, list) else data.get("scanResult", [{}]):
        for finding in entry if isinstance(entry, list) else []:
            raw_sev = finding.get("severity", "")
            mapped = severity_map.get(raw_sev)
            if mapped is None:
                continue
            findings.append({
                "severity": mapped,
                "title": f"TLS: {finding.get('id', '')} — {finding.get('finding', '')}",
                "host": finding.get("ip", ""),
                "tool": "testssl",
                "evidence": finding.get("finding", ""),
                "description": finding.get("id", ""),
                "remediation": "Disable vulnerable protocol/cipher and apply patches.",
            })
    return findings


# ── Render ───────────────────────────────────────────────────────────────────

def render_report(findings: list[dict], target: str, results_dir: Path) -> str:
    findings.sort(key=lambda f: SEVERITY_RANK.get(sev(f.get("severity", "")), 5))

    counts = {s: 0 for s in SEVERITY_RANK}
    for f in findings:
        counts[sev(f.get("severity", "unknown"))] += 1

    lines = [
        f"# clawscan Report — {target}",
        f"",
        f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  ",
        f"Results directory: `{results_dir}`",
        f"",
        f"## Summary",
        f"",
        f"| Severity | Count |",
        f"|----------|-------|",
    ]
    for s in ["critical", "high", "medium", "low", "info"]:
        lines.append(f"| {s.capitalize()} | {counts.get(s, 0)} |")
    lines.append("")

    lines.append("## Findings")
    lines.append("")

    for f in findings:
        s = sev(f.get("severity", "unknown"))
        lines.append(f"### [{badge(s)}] {f.get('title', 'Finding')}")
        lines.append("")
        lines.append(f"**Host:** `{f.get('host', '')}`  ")
        lines.append(f"**Tool:** {f.get('tool', '')}  ")
        lines.append(f"**Severity:** {s.capitalize()}")
        lines.append("")
        if f.get("description"):
            lines.append(f"**Description:** {f['description']}")
            lines.append("")
        if f.get("evidence"):
            lines.append("**Evidence:**")
            lines.append("```")
            lines.append(f['evidence'])
            lines.append("```")
        if f.get("remediation"):
            lines.append(f"**Remediation:** {f['remediation']}")
        lines.append("")
        lines.append("---")
        lines.append("")

    return "\n".join(lines)


# ── Entry point ──────────────────────────────────────────────────────────────

def main():
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <results_dir> <target>")
        sys.exit(1)

    results_dir = Path(sys.argv[1])
    target = sys.argv[2]

    if not results_dir.exists():
        print(f"[!] Results directory not found: {results_dir}")
        sys.exit(1)

    print(f"[*] Aggregating results from {results_dir}")

    all_findings: list[dict] = []

    parsers = [
        (parse_nuclei,   results_dir / "nuclei.txt"),
        (parse_nuclei,   results_dir / "nuclei-cves.txt"),
        (parse_wpscan,   results_dir / "wpscan.json"),
        (parse_nmap_xml, results_dir / "portscan-deep"),
        (parse_ffuf,     results_dir / "ffuf.json"),
        (parse_testssl,  results_dir / "testssl.json"),
    ]

    for parser, path in parsers:
        found = parser(path)
        print(f"    {path.name}: {len(found)} finding(s)")
        all_findings.extend(found)

    print(f"[*] Total findings: {len(all_findings)}")

    report = render_report(all_findings, target, results_dir)

    report_path = results_dir / "report.md"
    report_path.write_text(report, encoding="utf-8")
    print(f"[*] Report written: {report_path}")


if __name__ == "__main__":
    main()
