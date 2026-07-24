from __future__ import annotations

import shutil
from pathlib import Path

from warden._parsers import normalize_severity, parse_zap
from warden._summary import compute_human_summary
from warden.aggregate import build_report

FIXTURE_DIR = Path(__file__).parent / "fixtures"


def _copy_fixture(name: str, destination: Path) -> None:
    shutil.copyfile(FIXTURE_DIR / name, destination / name)


def test_normalize_severity_maps_tool_specific_values() -> None:
    assert normalize_severity("crit") == "CRITICAL"
    assert normalize_severity("warning") == "MEDIUM"
    assert normalize_severity(None) == "UNKNOWN"


def test_build_report_reads_all_supported_tools(tmp_path: Path) -> None:
    _copy_fixture("trivy.json", tmp_path)
    _copy_fixture("semgrep.json", tmp_path)
    _copy_fixture("gitleaks.json", tmp_path)
    _copy_fixture("zap.json", tmp_path)

    findings, report = build_report(tmp_path)

    assert len(findings) == 4
    assert report["summary"]["tools_run"] == ["Trivy", "Semgrep", "Gitleaks", "ZAP"]
    assert findings[0].severity == "CRITICAL"
    assert report["findings"][0]["tool"] == "Gitleaks"


def test_parse_zap_reports_unknown_file_without_an_instance_uri() -> None:
    findings = parse_zap({"site": [{"alerts": [{"riskcode": "3", "alert": "No instances"}]}]})

    assert len(findings) == 1
    assert findings[0].file == "Unknown"


def test_compute_human_summary_groups_breakdown_by_category(tmp_path: Path) -> None:
    _copy_fixture("trivy.json", tmp_path)
    _copy_fixture("gitleaks.json", tmp_path)

    findings, _ = build_report(tmp_path)
    summary = compute_human_summary(findings)

    assert summary.counts["CRITICAL"] == 1
    assert summary.counts["HIGH"] == 1
    assert summary.breakdown["CRITICAL"] == {"Secrets": 1}
    assert summary.breakdown["HIGH"] == {"Deps": 1}
