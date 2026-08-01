from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Final, Literal, TypedDict

Severity = Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNKNOWN"]

SEVERITIES: Final[tuple[Severity, ...]] = (
    "CRITICAL",
    "HIGH",
    "MEDIUM",
    "LOW",
    "INFO",
    "UNKNOWN",
)
DEFAULT_FAIL_ON_SEVERITIES: Final[tuple[Severity, ...]] = ("CRITICAL", "HIGH")

ZAP_HTML_REPORT: Final[str] = "zap.html"


class BaseFindingDict(TypedDict):
    tool: str
    severity: Severity
    file: str
    description: str


class FindingDict(BaseFindingDict, total=False):
    line: int
    fix: str
    rule_id: str
    snippet: str
    solution: str


class ReportSummaryDict(TypedDict):
    total_issues: int
    tools_run: list[str]


class AggregateReportDict(TypedDict):
    summary: ReportSummaryDict
    findings: list[FindingDict]


SummaryCounts = dict[Severity, int]
SummaryBreakdown = dict[Severity, dict[str, int]]


@dataclass(slots=True, frozen=True)
class Finding:
    tool: str
    severity: Severity
    file: str
    description: str
    line: int | None = None
    fix: str | None = None
    rule_id: str | None = None
    snippet: str | None = None
    solution: str | None = None


@dataclass(slots=True, frozen=True)
class ToolSelection:
    """The scanner keys left enabled after `.warden.yaml` has been applied."""

    enabled: frozenset[str]

    def is_enabled(self, key: str) -> bool:
        return key in self.enabled


@dataclass(slots=True, frozen=True)
class ResolvedConfig:
    url: str
    exclude_dirs: list[str]
    tools: ToolSelection


@dataclass(slots=True, frozen=True)
class CliOptions:
    project_root: Path
    cli_url: str
    config_path: Path | None = None


@dataclass(slots=True, frozen=True)
class AggregateCliOptions:
    report_dir: Path
    output_file: Path


@dataclass(slots=True, frozen=True)
class ToolRunResult:
    name: str
    returncode: int | None
    report_path: Path
    accepted_returncodes: frozenset[int]
    warning: str | None = None


@dataclass(slots=True, frozen=True)
class CommandResult:
    returncode: int | None
    warning: str | None = None


@dataclass(slots=True, frozen=True)
class Verdict:
    """The build's pass/fail decision, and the tallies it was reached from."""

    triggered_by: tuple[Severity, ...]
    counts: SummaryCounts
    breakdown: SummaryBreakdown

    @property
    def failed(self) -> bool:
        return bool(self.triggered_by)
