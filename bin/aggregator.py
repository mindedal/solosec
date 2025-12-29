import argparse
import json
import os
from typing import Any, Dict, List, Optional, Union

JsonValue = Union[Dict[str, Any], List[Any]]


def load_json(report_dir: str, filename: str, default: JsonValue) -> JsonValue:
    """Load a JSON report from report_dir.

    Returns `default` if the file doesn't exist or can't be parsed.
    """
    filepath = os.path.join(report_dir, filename)
    if not os.path.exists(filepath):
        return default
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        print(f"Warning: Could not parse {filename}: {e}")
        return default


def parse_trivy(report_dir: str) -> List[Dict[str, Any]]:
    data = load_json(report_dir, "trivy.json", default={})
    findings: List[Dict[str, Any]] = []
    if isinstance(data, dict) and "Results" in data:
        for res in data.get("Results", []) or []:
            if not isinstance(res, dict):
                continue
            target = res.get("Target", "Unknown")
            for vuln in res.get("Vulnerabilities", []) or []:
                if not isinstance(vuln, dict):
                    continue
                pkg = vuln.get("PkgName") or "Unknown package"
                ver = vuln.get("InstalledVersion") or "Unknown version"
                title = (
                    vuln.get("Title") or vuln.get("VulnerabilityID") or "Vulnerability"
                )
                findings.append(
                    {
                        "tool": "Trivy",
                        "severity": (vuln.get("Severity") or "UNKNOWN"),
                        "file": target,
                        "description": f"{pkg} {ver} - {title}",
                        "fix": vuln.get("FixedVersion") or "No fix available",
                    }
                )
    return findings


def parse_semgrep(report_dir: str) -> List[Dict[str, Any]]:
    data = load_json(report_dir, "semgrep.json", default={})
    findings: List[Dict[str, Any]] = []
    if isinstance(data, dict) and "results" in data:
        for res in data.get("results", []) or []:
            if not isinstance(res, dict):
                continue
            extra = res.get("extra") or {}
            start = res.get("start") or {}
            findings.append(
                {
                    "tool": "Semgrep",
                    "severity": (extra.get("severity") or "UNKNOWN"),
                    "file": res.get("path") or "Unknown",
                    "line": start.get("line"),
                    "description": extra.get("message") or "Semgrep finding",
                    "rule_id": res.get("check_id") or res.get("check_id") or "Unknown",
                }
            )
    return findings


def parse_gitleaks(report_dir: str) -> List[Dict[str, Any]]:
    data = load_json(report_dir, "gitleaks.json", default=[])
    findings: List[Dict[str, Any]] = []
    if isinstance(data, list):
        for leak in data:
            if not isinstance(leak, dict):
                continue
            rule_id = leak.get("RuleID") or "Unknown"
            findings.append(
                {
                    "tool": "Gitleaks",
                    "severity": "CRITICAL",
                    "file": leak.get("File") or "Unknown",
                    "line": leak.get("StartLine"),
                    "description": f"Secret detected: {rule_id}",
                    "snippet": "REDACTED",
                }
            )
    return findings


def parse_zap(report_dir: str) -> List[Dict[str, Any]]:
    data = load_json(report_dir, "zap.json", default={})
    findings: List[Dict[str, Any]] = []
    if not isinstance(data, dict):
        return findings

    sites = data.get("site")
    if not isinstance(sites, list):
        return findings

    risk_map = {"3": "HIGH", "2": "MEDIUM", "1": "LOW", "0": "INFO"}
    for site in sites:
        if not isinstance(site, dict):
            continue
        for alert in site.get("alerts", []) or []:
            if not isinstance(alert, dict):
                continue
            riskcode = alert.get("riskcode")
            severity = risk_map.get(str(riskcode), "UNKNOWN")
            instances = alert.get("instances")
            target_url = "URL Target"
            if isinstance(instances, list) and instances:
                first = instances[0]
                if isinstance(first, dict):
                    target_url = first.get("uri") or target_url
            findings.append(
                {
                    "tool": "ZAP",
                    "severity": severity,
                    "file": target_url,
                    "description": alert.get("alert") or "ZAP alert",
                    "solution": alert.get("solution"),
                }
            )
    return findings


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="audit_agent.py",
        description="Aggregate security scanner reports (Trivy, Semgrep, Gitleaks, ZAP) into a single JSON file.",
    )
    parser.add_argument(
        "report_dir",
        help="Directory containing tool JSON outputs (e.g. trivy.json, semgrep.json)",
    )
    parser.add_argument("output_file", help="Path to write the aggregated JSON report")
    return parser.parse_args(argv)


def _severity_key(item: Dict[str, Any]) -> int:
    severity_rank = {
        "CRITICAL": 0,
        "HIGH": 1,
        "MEDIUM": 2,
        "LOW": 3,
        "INFO": 4,
        "UNKNOWN": 5,
    }
    sev = item.get("severity", "UNKNOWN")
    try:
        sev_str = str(sev).upper()
    except Exception:
        sev_str = "UNKNOWN"
    return severity_rank.get(sev_str, 5)


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)
    report_dir = args.report_dir
    output_file = args.output_file

    print(f"--- Aggregating Reports from {report_dir} ---")

    all_findings: List[Dict[str, Any]] = []
    all_findings.extend(parse_trivy(report_dir))
    all_findings.extend(parse_semgrep(report_dir))
    all_findings.extend(parse_gitleaks(report_dir))
    all_findings.extend(parse_zap(report_dir))

    all_findings.sort(key=_severity_key)

    report = {
        "summary": {
            "total_issues": len(all_findings),
            "tools_run": ["Trivy", "Semgrep", "Gitleaks", "ZAP"],
        },
        "findings": all_findings,
    }

    output_dir = os.path.dirname(os.path.abspath(output_file))
    if output_dir and not os.path.exists(output_dir):
        os.makedirs(output_dir, exist_ok=True)

    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)

    print(f"Generated {output_file} with {len(all_findings)} issues.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
