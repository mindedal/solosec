from __future__ import annotations

from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Final

from rich.console import Console
from rich.table import Table
from rich.text import Text

from ._models import DEFAULT_FAIL_ON_SEVERITIES, Finding, HumanSummary, Severity
from ._parsers import normalize_severity

TOOL_CATEGORIES: Final[dict[str, str]] = {
    "gitleaks": "Secrets",
    "semgrep": "Code",
    "trivy": "Deps",
    "zap": "ZAP",
}
CATEGORY_ORDER: Final[list[str]] = ["Secrets", "Code", "Deps", "ZAP"]
SUMMARY_ROWS: Final[tuple[tuple[str, Severity, str, bool], ...]] = (
    ("Critical", "CRITICAL", "red", True),
    ("High", "HIGH", "bright_red", True),
    ("Medium", "MEDIUM", "yellow", False),
)


def _category_for_tool(tool: str) -> str:
    normalized = tool.strip().lower()
    return TOOL_CATEGORIES.get(normalized, tool or "Other")


def compute_human_summary(findings: Sequence[Finding]) -> HumanSummary:
    summary = HumanSummary(total=len(findings))
    for finding in findings:
        severity = normalize_severity(finding.severity)
        summary.counts[severity] += 1
        category = _category_for_tool(finding.tool)
        severity_breakdown = summary.breakdown[severity]
        severity_breakdown[category] = severity_breakdown.get(category, 0) + 1
    return summary


def _format_breakdown(items: Mapping[str, int], order: Sequence[str] | None = None) -> str:
    if not items:
        return ""
    keys = list(order) if order is not None else sorted(items)
    return ", ".join(f"{key}: {items[key]}" for key in keys if items.get(key))


def _status_summary(failed: bool) -> tuple[str, str, str]:
    if failed:
        return "red", "FAIL", "High/Critical issues found."
    return "green", "PASS", "No High/Critical issues found."


def print_human_summary(
    *,
    findings: Sequence[Finding],
    output_file: str | Path,
    fail_on_severities: Sequence[Severity] | None = None,
) -> bool:
    summary = compute_human_summary(findings)
    counts = summary.counts
    breakdown = summary.breakdown
    failure_thresholds = tuple(fail_on_severities or DEFAULT_FAIL_ON_SEVERITIES)
    failed = any(counts[severity] > 0 for severity in failure_thresholds)
    output_path = str(output_file)

    console = Console()
    console.print("-" * 50)
    console.print(Text("SCAN COMPLETE", style="bold cyan"))
    console.print("-" * 50)

    table = Table(show_header=True, header_style="bold")
    table.add_column("Severity", justify="left")
    table.add_column("Count", justify="right")
    table.add_column("Breakdown", justify="left")

    for label, severity, color, show_breakdown in SUMMARY_ROWS:
        breakdown_text = ""
        if show_breakdown:
            breakdown_text = _format_breakdown(breakdown[severity], order=CATEGORY_ORDER)
        table.add_row(
            f"[{color}]{label}[/{color}]",
            str(counts[severity]),
            breakdown_text,
        )

    console.print(table)
    console.print("-" * 50)
    status_style, status_label, summary_line = _status_summary(failed)
    status_message = (
        f"[{status_style}]{status_label}:[/{status_style}] {summary_line} See {output_path}"
    )
    console.print(status_message)
    return failed
