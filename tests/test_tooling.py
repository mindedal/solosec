from __future__ import annotations

import subprocess
from pathlib import Path

from pytest import MonkeyPatch

from warden import tooling


def test_run_trivy_pretty_prints_its_report(monkeypatch: MonkeyPatch, tmp_path: Path) -> None:
    report_path = tmp_path / "trivy.json"

    def fake_run(args: list[str], **kwargs: object) -> subprocess.CompletedProcess[bytes]:
        del kwargs
        report_path.write_text('{"Results":[]}', encoding="utf-8")
        return subprocess.CompletedProcess(args, 0)

    monkeypatch.setattr(tooling.subprocess, "run", fake_run)

    result = tooling.run_trivy(tmp_path, tmp_path, [])

    assert tooling.tool_succeeded(result)
    assert report_path.read_text(encoding="utf-8") == '{\n  "Results": []\n}'


def test_prepare_report_dir_removes_previous_reports(tmp_path: Path) -> None:
    report_dir = tmp_path / ".security_reports"
    report_dir.mkdir()
    (report_dir / "trivy.json").write_text("{}", encoding="utf-8")
    (report_dir / "zap.html").write_text("stale", encoding="utf-8")
    (report_dir / "notes.txt").write_text("keep me", encoding="utf-8")

    prepared = tooling.prepare_report_dir(tmp_path)

    assert prepared == report_dir
    assert not (report_dir / "trivy.json").exists()
    assert not (report_dir / "zap.html").exists()
    assert (report_dir / "notes.txt").exists()


def test_prepare_report_dir_appends_to_an_existing_gitignore(tmp_path: Path) -> None:
    gitignore = tmp_path / ".gitignore"
    gitignore.write_text("*.log\n", encoding="utf-8")

    tooling.prepare_report_dir(tmp_path)

    assert ".security_reports/" in gitignore.read_text(encoding="utf-8").splitlines()
