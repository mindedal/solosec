from __future__ import annotations

import sys
from pathlib import Path

from pytest import MonkeyPatch

from fakes import RecordingRunner
from warden import tooling
from warden._models import ZAP_HTML_REPORT

HOST_PATH_VARIABLES = ("WARDEN_HOST_REPORT_DIR", "WARDEN_HOST_WORKSPACE", "GITHUB_WORKSPACE")


def _forget_host_path_variables(monkeypatch: MonkeyPatch) -> None:
    for name in HOST_PATH_VARIABLES:
        monkeypatch.delenv(name, raising=False)


def test_run_trivy_builds_its_command_line(tmp_path: Path) -> None:
    runner = RecordingRunner()

    tooling.run_trivy(tmp_path, tmp_path, [], runner)

    command = runner.commands[0]
    assert command.args == [
        "trivy",
        "fs",
        ".",
        "--format",
        "json",
        "--output",
        str(tmp_path / "trivy.json"),
        "--quiet",
    ]
    assert command.cwd == tmp_path.resolve()
    assert not command.stderr_to_devnull
    assert command.env_overrides is None


def test_run_trivy_joins_its_exclude_dirs_with_commas(tmp_path: Path) -> None:
    runner = RecordingRunner()

    tooling.run_trivy(tmp_path, tmp_path, ["build", "node_modules"], runner)

    assert runner.commands[0].args[-2:] == ["--skip-dirs", "build,node_modules"]


def test_run_semgrep_builds_its_command_line(tmp_path: Path) -> None:
    runner = RecordingRunner()

    tooling.run_semgrep(tmp_path, tmp_path, [], runner)

    command = runner.commands[0]
    assert command.args == [
        "semgrep",
        "scan",
        "--config=auto",
        "--json",
        "--output",
        str(tmp_path / "semgrep.json"),
        "--quiet",
        ".",
    ]
    assert command.cwd == tmp_path.resolve()
    assert command.stderr_to_devnull
    assert command.env_overrides == {"PYTHONUTF8": "1"}


def test_run_semgrep_repeats_its_exclude_flag_per_directory(tmp_path: Path) -> None:
    runner = RecordingRunner()

    tooling.run_semgrep(tmp_path, tmp_path, ["build", "", "node_modules"], runner)

    assert runner.commands[0].args[-4:] == [
        "--exclude",
        "build",
        "--exclude",
        "node_modules",
    ]


def test_run_gitleaks_builds_its_command_line(tmp_path: Path) -> None:
    runner = RecordingRunner()

    tooling.run_gitleaks(tmp_path, tmp_path, [], runner)

    command = runner.commands[0]
    assert command.args == [
        "gitleaks",
        "detect",
        "--source",
        ".",
        "--no-git",
        "--report-path",
        str(tmp_path / "gitleaks.json"),
        "--exit-code",
        "0",
    ]
    assert command.cwd == tmp_path.resolve()
    assert command.stderr_to_devnull
    assert command.env_overrides is None


def test_run_gitleaks_repeats_its_exclude_flag_per_directory(tmp_path: Path) -> None:
    runner = RecordingRunner()

    tooling.run_gitleaks(tmp_path, tmp_path, ["build", "", "node_modules"], runner)

    assert runner.commands[0].args[-4:] == [
        "--exclude-path",
        "build",
        "--exclude-path",
        "node_modules",
    ]


def test_an_empty_exclude_list_omits_the_exclude_flag(tmp_path: Path) -> None:
    runner = RecordingRunner()

    tooling.run_trivy(tmp_path, tmp_path, [], runner)
    tooling.run_semgrep(tmp_path, tmp_path, [], runner)
    tooling.run_gitleaks(tmp_path, tmp_path, [], runner)

    arguments = {argument for command in runner.commands for argument in command.args}
    assert not arguments & {"--skip-dirs", "--exclude", "--exclude-path"}


def test_run_zap_builds_its_docker_command_line(monkeypatch: MonkeyPatch, tmp_path: Path) -> None:
    _forget_host_path_variables(monkeypatch)
    runner = RecordingRunner()

    tooling.run_zap(tmp_path, "http://localhost:3000", runner)

    command = runner.commands[0]
    assert command.args == [
        "docker",
        "run",
        "--rm",
        "-v",
        f"{tmp_path.resolve()}:/zap/wrk/:rw",
        "-t",
        tooling.ZAP_IMAGE,
        "zap-full-scan.py",
        "-t",
        "http://host.docker.internal:3000",
        "-J",
        "zap.json",
        "-r",
        ZAP_HTML_REPORT,
        "-I",
    ]
    assert command.cwd == tmp_path.resolve()


def test_run_zap_mounts_the_host_report_dir_when_one_is_supplied(
    monkeypatch: MonkeyPatch, tmp_path: Path
) -> None:
    _forget_host_path_variables(monkeypatch)
    monkeypatch.setenv("WARDEN_HOST_WORKSPACE", "/host/workspace")
    runner = RecordingRunner()

    tooling.run_zap(tmp_path, "http://example.test", runner)

    mount = Path("/host/workspace") / ".security_reports"
    assert runner.commands[0].args[4] == f"{mount}:/zap/wrk/:rw"


def test_resolve_host_report_dir_prefers_the_explicit_report_dir(
    monkeypatch: MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("WARDEN_HOST_REPORT_DIR", "/host/reports")
    monkeypatch.setenv("WARDEN_HOST_WORKSPACE", "/host/workspace")
    monkeypatch.setenv("GITHUB_WORKSPACE", "/github/workspace")

    assert tooling.resolve_host_report_dir(tmp_path) == Path("/host/reports")


def test_resolve_host_report_dir_falls_back_to_the_host_workspace(
    monkeypatch: MonkeyPatch, tmp_path: Path
) -> None:
    _forget_host_path_variables(monkeypatch)
    monkeypatch.setenv("WARDEN_HOST_WORKSPACE", "/host/workspace")
    monkeypatch.setenv("GITHUB_WORKSPACE", "/github/workspace")

    expected = Path("/host/workspace") / ".security_reports"
    assert tooling.resolve_host_report_dir(tmp_path) == expected


def test_resolve_host_report_dir_falls_back_to_the_github_workspace(
    monkeypatch: MonkeyPatch, tmp_path: Path
) -> None:
    _forget_host_path_variables(monkeypatch)
    monkeypatch.setenv("GITHUB_WORKSPACE", "/github/workspace")

    expected = Path("/github/workspace") / ".security_reports"
    assert tooling.resolve_host_report_dir(tmp_path) == expected


def test_resolve_host_report_dir_falls_back_to_the_local_path(
    monkeypatch: MonkeyPatch, tmp_path: Path
) -> None:
    _forget_host_path_variables(monkeypatch)

    assert tooling.resolve_host_report_dir(tmp_path) == tmp_path.resolve()


def test_run_subprocess_reports_the_exit_code_and_applies_env_overrides(tmp_path: Path) -> None:
    result = tooling.run_subprocess(
        [sys.executable, "-c", "import os, sys; sys.exit(int(os.environ['WARDEN_TEST_EXIT']))"],
        cwd=tmp_path,
        stderr_to_devnull=True,
        env_overrides={"WARDEN_TEST_EXIT": "3"},
    )

    assert result.returncode == 3
    assert result.warning is None


def test_run_subprocess_warns_when_the_executable_is_missing(tmp_path: Path) -> None:
    result = tooling.run_subprocess(["warden-no-such-scanner"], cwd=tmp_path)

    assert result.returncode is None
    assert result.warning == "warden-no-such-scanner was not found on PATH."


def test_a_scanner_that_is_missing_warns_instead_of_raising(tmp_path: Path) -> None:
    runner = RecordingRunner(returncode=None, warning="trivy was not found on PATH.")

    result = tooling.run_trivy(tmp_path, tmp_path, [], runner)

    assert not tooling.tool_succeeded(result)
    assert not tooling.report_written(result)
    assert result.warning == "trivy was not found on PATH."


def test_semgrep_accepts_a_run_that_found_something(tmp_path: Path) -> None:
    runner = RecordingRunner(returncode=1)

    assert tooling.tool_succeeded(tooling.run_semgrep(tmp_path, tmp_path, [], runner))


def test_the_other_scanners_accept_only_a_clean_exit(tmp_path: Path) -> None:
    runner = RecordingRunner(returncode=1)

    assert not tooling.tool_succeeded(tooling.run_trivy(tmp_path, tmp_path, [], runner))
    assert not tooling.tool_succeeded(tooling.run_gitleaks(tmp_path, tmp_path, [], runner))
    assert not tooling.tool_succeeded(tooling.run_zap(tmp_path, "http://example.test", runner))


def test_run_trivy_pretty_prints_its_report(tmp_path: Path) -> None:
    runner = RecordingRunner(report_text='{"Results":[]}')

    result = tooling.run_trivy(tmp_path, tmp_path, [], runner)

    assert tooling.tool_succeeded(result)
    assert (tmp_path / "trivy.json").read_text(encoding="utf-8") == '{\n  "Results": []\n}'


def test_a_report_that_is_not_json_is_left_alone(tmp_path: Path) -> None:
    runner = RecordingRunner(report_text="not json")

    tooling.run_trivy(tmp_path, tmp_path, [], runner)

    assert (tmp_path / "trivy.json").read_text(encoding="utf-8") == "not json"


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
