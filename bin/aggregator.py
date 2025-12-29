import argparse
import json
import os
from typing import Any, Dict, List, Optional, Union

JsonValue = Union[Dict[str, Any], List[Any]]


def _normalize_severity(sev: Any) -> str:
    """Normalize severities across tools to a common set."""
    try:
        s = str(sev).strip().upper()
    except (TypeError, AttributeError):
        return "UNKNOWN"

    # Common aliases / variants
    if s in {"CRIT"}:
        return "CRITICAL"
    # Semgrep-style severities
    if s in {"ERROR"}:
        return "HIGH"
    if s in {"WARN", "WARNING"}:
        return "MEDIUM"
    if s in {"INFORMATION", "INFORMATIONAL"}:
        return "INFO"
    if s in {""}:
        return "UNKNOWN"

    return s


def _category_for_tool(tool: str) -> str:
    """Human-friendly grouping for summary breakdown."""
    t = (tool or "").strip().lower()
    if t == "gitleaks":
        return "Secrets"
    if t == "semgrep":
        return "Code"
    if t == "trivy":
        return "Deps"
    if t == "zap":
        return "ZAP"
    return tool or "Other"


def _compute_human_summary(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Compute counts used by the terminal summary."""
    severities = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNKNOWN"]
    counts: Dict[str, int] = {s: 0 for s in severities}
    breakdown: Dict[str, Dict[str, int]] = {s: {} for s in severities}

    for f in findings:
        sev = _normalize_severity(f.get("severity", "UNKNOWN"))
        if sev not in counts:
            sev = "UNKNOWN"
        counts[sev] += 1

        category = _category_for_tool(str(f.get("tool", "Other")))
        breakdown_for_sev = breakdown[sev]
        breakdown_for_sev[category] = breakdown_for_sev.get(category, 0) + 1

    return {
        "counts": counts,
        "breakdown": breakdown,
        "total": len(findings),
    }


def _format_breakdown(items: Dict[str, int], order: Optional[List[str]] = None) -> str:
    if not items:
        return ""
    keys = order or sorted(items.keys())
    parts = [f"{k}: {items[k]}" for k in keys if items.get(k)]
    return ", ".join(parts)


def print_human_summary(
    *,
    findings: List[Dict[str, Any]],
    output_file: str,
    fail_on_critical: bool = True,
) -> bool:
    """Print a human summary. Returns True if scan should be considered failed."""
    summary = _compute_human_summary(findings)
    counts: Dict[str, int] = summary["counts"]
    breakdown: Dict[str, Dict[str, int]] = summary["breakdown"]

    critical = counts.get("CRITICAL", 0)
    high = counts.get("HIGH", 0)
    medium = counts.get("MEDIUM", 0)

    failed = bool(critical) if fail_on_critical else False

    # Prefer rich if available; fall back to plain text.
    try:
        from rich.console import Console  # type: ignore
        from rich.table import Table  # type: ignore
        from rich.text import Text  # type: ignore

        console = Console()
        console.print("" + ("-" * 50))
        console.print(Text("SCAN COMPLETE", style="bold cyan"))
        console.print("" + ("-" * 50))

        table = Table(show_header=True, header_style="bold")
        table.add_column("Severity", justify="left")
        table.add_column("Count", justify="right")
        table.add_column("Breakdown", justify="left")

        def add_row(label: str, sev: str, color: str, show_breakdown: bool = False) -> None:
            bd = ""
            if show_breakdown:
                bd = _format_breakdown(
                    breakdown.get(sev, {}),
                    order=["Secrets", "Code", "Deps", "ZAP"],
                )
            table.add_row(f"[{color}]{label}[/{color}]", str(counts.get(sev, 0)), bd)

        add_row("Critical", "CRITICAL", "red", show_breakdown=True)
        add_row("High", "HIGH", "bright_red", show_breakdown=True)
        add_row("Medium", "MEDIUM", "yellow")

        console.print(table)
        console.print("" + ("-" * 50))
        if failed:
            console.print(f"[red]FAIL:[/red] Critical issues found. See {output_file}")
        else:
            console.print(f"[green]PASS:[/green] No critical issues found. See {output_file}")
    except Exception:
        # ANSI color codes for plain text fallback
        RED = "\033[91m"
        YELLOW = "\033[93m"
        GREEN = "\033[92m"
        CYAN = "\033[96m"
        RESET = "\033[0m"
        
        line = "-" * 50
        print(line)
        print(f"{CYAN}SCAN COMPLETE{RESET}")
        print(line)
        crit_bd = _format_breakdown(breakdown.get("CRITICAL", {}), ["Secrets", "Code", "Deps", "ZAP"])
        high_bd = _format_breakdown(breakdown.get("HIGH", {}), ["Secrets", "Code", "Deps", "ZAP"])
        print(f"{RED}Critical:{RESET} {critical}" + (f"   ({crit_bd})" if crit_bd else ""))
        print(f"{RED}High:{RESET}     {high}" + (f"   ({high_bd})" if high_bd else ""))
        print(f"{YELLOW}Medium:{RESET}   {medium}")
        print(line)
        if failed:
            print(f"{RED}FAIL:{RESET} Critical issues found. See {output_file}")
        else:
            print(f"{GREEN}PASS:{RESET} No critical issues found. See {output_file}")

    return failed


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
    except (json.JSONDecodeError, OSError, IOError) as e:
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
                    "rule_id": res.get("check_id") or "Unknown",
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
    sev_str = _normalize_severity(item.get("severity", "UNKNOWN"))
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

    # Normalize severities so the JSON is consistent too.
    for f in all_findings:
        f["severity"] = _normalize_severity(f.get("severity", "UNKNOWN"))

    all_findings.sort(key=_severity_key)

    tools_run: List[str] = []
    if os.path.exists(os.path.join(report_dir, "trivy.json")):
        tools_run.append("Trivy")
    if os.path.exists(os.path.join(report_dir, "semgrep.json")):
        tools_run.append("Semgrep")
    if os.path.exists(os.path.join(report_dir, "gitleaks.json")):
        tools_run.append("Gitleaks")
    if os.path.exists(os.path.join(report_dir, "zap.json")):
        tools_run.append("ZAP")

    report = {
        "summary": {
            "total_issues": len(all_findings),
            "tools_run": tools_run,
        },
        "findings": all_findings,
    }

    output_dir = os.path.dirname(os.path.abspath(output_file))
    if output_dir and not os.path.exists(output_dir):
        os.makedirs(output_dir, exist_ok=True)

    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)

    print(f"Generated {output_file} with {len(all_findings)} issues.")

    failed = print_human_summary(findings=all_findings, output_file=output_file)
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
