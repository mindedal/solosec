from __future__ import annotations

import json
import shutil
from pathlib import Path

from pytest import MonkeyPatch

from warden import cli
from warden._models import ToolRunResult

FIXTURE_DIR = Path(__file__).parent / "fixtures"


def _successful_result(name: str, report_path: Path) -> ToolRunResult:
    report_path.write_text("{}", encoding="utf-8")
    return ToolRunResult(
        name=name,
        returncode=0,
        report_path=report_path,
        accepted_returncodes=frozenset({0, 1}),
    )


def _fake_run_trivy(
    project_root: str | Path, report_dir: str | Path, exclude_dirs: list[str]
) -> ToolRunResult:
    del project_root, exclude_dirs
    return _successful_result("Trivy", Path(report_dir) / "trivy.json")


def _fake_run_semgrep(
    project_root: str | Path,
    report_dir: str | Path,
    exclude_dirs: list[str],
) -> ToolRunResult:
    del project_root, exclude_dirs
    return _successful_result("Semgrep", Path(report_dir) / "semgrep.json")


def _fake_run_gitleaks(
    project_root: str | Path,
    report_dir: str | Path,
    exclude_dirs: list[str],
) -> ToolRunResult:
    del project_root, exclude_dirs
    return _successful_result("Gitleaks", Path(report_dir) / "gitleaks.json")


def test_cli_uses_cli_url_for_zap(monkeypatch: MonkeyPatch, tmp_path: Path) -> None:
    (tmp_path / ".warden.yaml").write_text(
        'target_url: "http://from-config"\n',
        encoding="utf-8",
    )

    captured: dict[str, str] = {}

    monkeypatch.setattr(cli.tooling, "run_trivy", _fake_run_trivy)
    monkeypatch.setattr(cli.tooling, "run_semgrep", _fake_run_semgrep)
    monkeypatch.setattr(cli.tooling, "run_gitleaks", _fake_run_gitleaks)

    def fake_run_zap(report_dir: str | Path, url: str) -> ToolRunResult:
        captured["url"] = url
        return _successful_result("ZAP", Path(report_dir) / "zap.json")

    monkeypatch.setattr(cli.tooling, "run_zap", fake_run_zap)

    exit_code = cli.main(["--project-root", str(tmp_path), "--url", "http://from-cli"])

    assert exit_code == 0
    assert captured["url"] == "http://from-cli"
    report = json.loads((tmp_path / "security_audit.json").read_text(encoding="utf-8"))
    assert report["summary"]["tools_run"] == ["Trivy", "Semgrep", "Gitleaks", "ZAP"]


def test_cli_rewrites_localhost_target_for_zap(
    monkeypatch: MonkeyPatch,
    tmp_path: Path,
) -> None:
    captured: dict[str, str] = {}

    monkeypatch.setattr(cli.tooling, "run_trivy", _fake_run_trivy)
    monkeypatch.setattr(cli.tooling, "run_semgrep", _fake_run_semgrep)
    monkeypatch.setattr(cli.tooling, "run_gitleaks", _fake_run_gitleaks)

    def fake_run_zap(report_dir: str | Path, url: str) -> ToolRunResult:
        captured["url"] = url
        return _successful_result("ZAP", Path(report_dir) / "zap.json")

    monkeypatch.setattr(cli.tooling, "run_zap", fake_run_zap)

    exit_code = cli.main(["--project-root", str(tmp_path), "--url", "http://localhost:3000"])

    assert exit_code == 0
    assert captured["url"] == "http://host.docker.internal:3000"


def test_cli_skips_disabled_tools(monkeypatch: MonkeyPatch, tmp_path: Path) -> None:
    (tmp_path / ".warden.yaml").write_text(
        """
        tools:
          trivy: false
          semgrep: false
          gitleaks: false
          zap: false
        """,
        encoding="utf-8",
    )

    def fail_if_called(*args: object, **kwargs: object) -> ToolRunResult:
        raise AssertionError("tool runner should not be called")

    monkeypatch.setattr(cli.tooling, "run_trivy", fail_if_called)
    monkeypatch.setattr(cli.tooling, "run_semgrep", fail_if_called)
    monkeypatch.setattr(cli.tooling, "run_gitleaks", fail_if_called)
    monkeypatch.setattr(cli.tooling, "run_zap", fail_if_called)

    exit_code = cli.main(["--project-root", str(tmp_path)])

    assert exit_code == 0
    report = json.loads((tmp_path / "security_audit.json").read_text(encoding="utf-8"))
    assert report["summary"]["total_issues"] == 0
    assert report["findings"] == []


def test_cli_discards_reports_from_a_previous_run(monkeypatch: MonkeyPatch, tmp_path: Path) -> None:
    (tmp_path / ".warden.yaml").write_text(
        """
        tools:
          trivy: false
          semgrep: false
          gitleaks: false
          zap: false
        """,
        encoding="utf-8",
    )
    report_dir = tmp_path / ".security_reports"
    report_dir.mkdir()
    shutil.copyfile(FIXTURE_DIR / "gitleaks.json", report_dir / "gitleaks.json")
    (report_dir / "zap.html").write_text("stale", encoding="utf-8")

    def fail_if_called(*args: object, **kwargs: object) -> ToolRunResult:
        raise AssertionError("tool runner should not be called")

    monkeypatch.setattr(cli.tooling, "run_trivy", fail_if_called)
    monkeypatch.setattr(cli.tooling, "run_semgrep", fail_if_called)
    monkeypatch.setattr(cli.tooling, "run_gitleaks", fail_if_called)
    monkeypatch.setattr(cli.tooling, "run_zap", fail_if_called)

    exit_code = cli.main(["--project-root", str(tmp_path)])

    assert exit_code == 0
    assert not (report_dir / "zap.html").exists()
    report = json.loads((tmp_path / "security_audit.json").read_text(encoding="utf-8"))
    assert report["summary"]["tools_run"] == []
    assert report["findings"] == []
