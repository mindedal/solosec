from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Final

from ._models import Finding
from ._parsers import parse_gitleaks, parse_semgrep, parse_trivy, parse_zap

ReportParser = Callable[[object | None], list[Finding]]


@dataclass(slots=True, frozen=True)
class Scanner:
    """One scanner Warden knows about."""

    label: str
    report_file: str
    category: str
    parser: ReportParser
    accepted_returncodes: frozenset[int]

    @property
    def key(self) -> str:
        """The `.warden.yaml` key, derived from the label so the two cannot drift apart."""
        return self.label.lower()


TRIVY: Final[Scanner] = Scanner(
    label="Trivy",
    report_file="trivy.json",
    category="Deps",
    parser=parse_trivy,
    accepted_returncodes=frozenset({0}),
)
SEMGREP: Final[Scanner] = Scanner(
    label="Semgrep",
    report_file="semgrep.json",
    category="Code",
    parser=parse_semgrep,
    accepted_returncodes=frozenset({0, 1}),
)
GITLEAKS: Final[Scanner] = Scanner(
    label="Gitleaks",
    report_file="gitleaks.json",
    category="Secrets",
    parser=parse_gitleaks,
    accepted_returncodes=frozenset({0}),
)
ZAP: Final[Scanner] = Scanner(
    label="ZAP",
    report_file="zap.json",
    category="ZAP",
    parser=parse_zap,
    accepted_returncodes=frozenset({0}),
)

# Order matters: it is the stage order, the order findings are collected in, and the
# order `tools_run` is reported in.
SCANNERS: Final[tuple[Scanner, ...]] = (TRIVY, SEMGREP, GITLEAKS, ZAP)
