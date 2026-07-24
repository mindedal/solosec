from __future__ import annotations

import argparse
import json
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Final, cast

from ._json import load_json
from ._models import (
    REPORT_FILES,
    AggregateCliOptions,
    AggregateReportDict,
    Finding,
    FindingDict,
    Severity,
)
from ._parsers import parse_gitleaks, parse_semgrep, parse_trivy, parse_zap, severity_rank
from ._summary import print_human_summary

ReportParser = Callable[[object | None], list[Finding]]

TOOL_PARSERS: Final[dict[str, ReportParser]] = {
    "Trivy": parse_trivy,
    "Semgrep": parse_semgrep,
    "Gitleaks": parse_gitleaks,
    "ZAP": parse_zap,
}


def finding_to_dict(finding: Finding) -> FindingDict:
    entry: FindingDict = {
        "tool": finding.tool,
        "severity": finding.severity,
        "file": finding.file,
        "description": finding.description,
    }
    if finding.line is not None:
        entry["line"] = finding.line
    if finding.fix is not None:
        entry["fix"] = finding.fix
    if finding.rule_id is not None:
        entry["rule_id"] = finding.rule_id
    if finding.snippet is not None:
        entry["snippet"] = finding.snippet
    if finding.solution is not None:
        entry["solution"] = finding.solution
    return entry


def _load_reports(report_dir: Path) -> dict[str, object | None]:
    return {tool_name: load_json(report_dir / filename) for tool_name, filename in REPORT_FILES}


def detect_tools_run(reports: Mapping[str, object | None]) -> list[str]:
    return [tool_name for tool_name, _ in REPORT_FILES if reports.get(tool_name) is not None]


def build_report(report_dir: str | Path) -> tuple[list[Finding], AggregateReportDict]:
    reports = _load_reports(Path(report_dir))
    findings = [
        finding
        for tool_name, _ in REPORT_FILES
        for finding in TOOL_PARSERS[tool_name](reports[tool_name])
    ]
    findings.sort(key=lambda finding: severity_rank(finding.severity))
    report: AggregateReportDict = {
        "summary": {
            "total_issues": len(findings),
            "tools_run": detect_tools_run(reports),
        },
        "findings": [finding_to_dict(finding) for finding in findings],
    }
    return findings, report


def write_report(output_file: str | Path, report: AggregateReportDict) -> None:
    output_path = Path(output_file)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")


def generate_report(
    *,
    report_dir: str | Path,
    output_file: str | Path,
    fail_on_severities: Sequence[Severity] | None = None,
) -> bool:
    findings, report = build_report(report_dir)
    write_report(output_file, report)
    print(f"Generated {output_file} with {len(findings)} issues.")
    return print_human_summary(
        findings=findings,
        output_file=output_file,
        fail_on_severities=fail_on_severities,
    )


def _parse_args(argv: list[str] | None = None) -> AggregateCliOptions:
    parser = argparse.ArgumentParser(
        prog="warden-aggregate",
        description=(
            "Aggregate security scanner reports (Trivy, Semgrep, Gitleaks, ZAP) "
            "into a single JSON file."
        ),
    )
    parser.add_argument(
        "report_dir",
        help="Directory containing tool JSON outputs (for example: trivy.json, semgrep.json)",
    )
    parser.add_argument("output_file", help="Path to write the aggregated JSON report")
    namespace = parser.parse_args(argv)
    return AggregateCliOptions(
        report_dir=Path(cast(str, namespace.report_dir)).resolve(),
        output_file=Path(cast(str, namespace.output_file)).resolve(),
    )


def main(argv: list[str] | None = None) -> int:
    options = _parse_args(argv)
    print(f"--- Aggregating Reports from {options.report_dir} ---")
    failed = generate_report(report_dir=options.report_dir, output_file=options.output_file)
    return 1 if failed else 0
