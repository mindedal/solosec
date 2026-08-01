from __future__ import annotations

import json
from pathlib import Path

from fakes import RecordingRunner
from warden import tooling
from warden._models import Finding
from warden._scanners import SCANNERS, ZAP
from warden._summary import CATEGORY_ORDER, judge
from warden.config import resolve_config

FIXTURE_DIR = Path(__file__).parent / "fixtures"


def test_registry_holds_the_documented_scanners_in_report_order() -> None:
    assert [scanner.label for scanner in SCANNERS] == ["Trivy", "Semgrep", "Gitleaks", "ZAP"]
    assert [scanner.key for scanner in SCANNERS] == ["trivy", "semgrep", "gitleaks", "zap"]


def test_every_scanner_category_can_be_ordered_in_the_summary() -> None:
    assert {scanner.category for scanner in SCANNERS} <= set(CATEGORY_ORDER)


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


def test_every_static_scanner_has_a_runner(tmp_path: Path) -> None:
    runner = RecordingRunner()

    for scanner in SCANNERS:
        if scanner is ZAP:
            continue
        result = tooling.run_static_scanner(scanner, tmp_path, tmp_path, [], runner)
        assert result.name == scanner.label
        assert result.report_path == tmp_path / scanner.report_file
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

    assert all(resolved.tools.is_enabled(scanner.key) for scanner in SCANNERS)


def test_every_scanner_can_be_disabled_by_its_key(tmp_path: Path) -> None:
    overrides = "\n".join(f"  {scanner.key}: false" for scanner in SCANNERS)
    (tmp_path / ".warden.yaml").write_text(f"tools:\n{overrides}\n", encoding="utf-8")

    resolved = resolve_config(project_root=tmp_path, cli_url="")

    assert not [scanner for scanner in SCANNERS if resolved.tools.is_enabled(scanner.key)]
