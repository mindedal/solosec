from __future__ import annotations

import json
from pathlib import Path

import pytest

from fakes import RecordingRunner
from warden import tooling
from warden._models import Finding
from warden._parsers import parse_zap
from warden._scanners import CATEGORY_ORDER, SCANNERS, ZAP, Scanner
from warden._summary import judge
from warden.config import resolve_config

FIXTURE_DIR = Path(__file__).parent / "fixtures"


def test_registry_holds_the_documented_scanners_in_report_order() -> None:
    assert [scanner.label for scanner in SCANNERS] == ["Trivy", "Semgrep", "Gitleaks", "ZAP"]
    assert [scanner.key for scanner in SCANNERS] == ["trivy", "semgrep", "gitleaks", "zap"]


def test_a_label_that_would_not_survive_lowercasing_is_rejected() -> None:
    """`key` is derived from `label`, which only holds for a single lowercase-able word."""
    with pytest.raises(ValueError, match="single alphanumeric word"):
        Scanner(
            label="OWASP ZAP",
            report_file="owasp.json",
            category="ZAP",
            summary_order=9,
            parser=parse_zap,
            build_command=ZAP.build_command,
            accepted_returncodes=frozenset({0}),
        )


def test_the_summary_category_order_is_derived_from_the_registry() -> None:
    """Display order is deliberately not stage order, so it is carried by `summary_order`."""
    assert CATEGORY_ORDER == ("Secrets", "Code", "Deps", "ZAP")
    assert set(CATEGORY_ORDER) == {scanner.category for scanner in SCANNERS}


def test_summary_categories_are_read_from_the_registry() -> None:
    findings = [
        Finding(tool=scanner.label, severity="HIGH", file="f", description="d")
        for scanner in SCANNERS
    ]

    verdict = judge(findings)

    assert verdict.breakdown["HIGH"] == {scanner.category: 1 for scanner in SCANNERS}


def test_each_parser_tags_its_findings_with_its_scanner_label() -> None:
    for scanner in SCANNERS:
        raw_report: object = json.loads(
            (FIXTURE_DIR / scanner.report_file).read_text(encoding="utf-8")
        )

        findings = scanner.parser(raw_report)

        assert {finding.tool for finding in findings} == {scanner.label}


def test_every_scanner_runs_through_the_same_interface(tmp_path: Path) -> None:
    """No scanner is special-cased at dispatch: ZAP included, each record carries its own argv."""
    runner = RecordingRunner()

    for scanner in SCANNERS:
        request = tooling.scan_request(
            scanner, project_root=tmp_path, report_dir=tmp_path, url="http://example.test"
        )
        result = tooling.run_scanner(scanner, request, runner)
        assert result.name == scanner.label
        assert result.report_path == tmp_path.resolve() / scanner.report_file
        assert result.accepted_returncodes == scanner.accepted_returncodes


def test_prepare_report_dir_clears_every_registered_report(tmp_path: Path) -> None:
    report_dir = tmp_path / ".security_reports"
    report_dir.mkdir()
    for scanner in SCANNERS:
        (report_dir / scanner.report_file).write_text("{}", encoding="utf-8")

    tooling.prepare_report_dir(tmp_path)

    assert not [scanner for scanner in SCANNERS if (report_dir / scanner.report_file).exists()]


def test_every_scanner_is_enabled_by_default(tmp_path: Path) -> None:
    resolved = resolve_config(project_root=tmp_path, cli_url="")

    assert all(scanner.key in resolved.enabled_tools for scanner in SCANNERS)


def test_every_scanner_can_be_disabled_by_its_key(tmp_path: Path) -> None:
    overrides = "\n".join(f"  {scanner.key}: false" for scanner in SCANNERS)
    (tmp_path / ".warden.yaml").write_text(f"tools:\n{overrides}\n", encoding="utf-8")

    resolved = resolve_config(project_root=tmp_path, cli_url="")

    assert not [scanner for scanner in SCANNERS if scanner.key in resolved.enabled_tools]
