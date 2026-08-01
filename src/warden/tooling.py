from __future__ import annotations

import json
import os
import subprocess
from collections.abc import Callable
from pathlib import Path
from typing import Final, Protocol

from ._models import ZAP_HTML_REPORT, CommandResult, ToolRunResult
from ._scanners import GITLEAKS, SCANNERS, SEMGREP, TRIVY, ZAP, Scanner

ZAP_IMAGE: Final[str] = "ghcr.io/zaproxy/zaproxy:stable"


class CommandRunner(Protocol):
    """How a built command line reaches the operating system."""

    def __call__(
        self,
        args: list[str],
        *,
        cwd: Path,
        stderr_to_devnull: bool = False,
        env_overrides: dict[str, str] | None = None,
    ) -> CommandResult: ...


StaticRunner = Callable[[str | Path, str | Path, list[str], CommandRunner], ToolRunResult]


def tool_succeeded(result: ToolRunResult) -> bool:
    return result.returncode in result.accepted_returncodes


def report_written(result: ToolRunResult) -> bool:
    return result.report_path.exists()


def _clear_stale_reports(report_dir: Path) -> None:
    for scanner in SCANNERS:
        (report_dir / scanner.report_file).unlink(missing_ok=True)
    (report_dir / ZAP_HTML_REPORT).unlink(missing_ok=True)


def _ignore_report_dir(root: Path) -> None:
    gitignore_path = root / ".gitignore"
    if not gitignore_path.exists():
        return

    existing_lines = gitignore_path.read_text(encoding="utf-8").splitlines()
    if any(line.strip() == ".security_reports/" for line in existing_lines):
        return

    with gitignore_path.open("a", encoding="utf-8") as handle:
        if existing_lines and existing_lines[-1].strip():
            handle.write("\n")
        handle.write(".security_reports/\n")


def prepare_report_dir(project_root: str | Path) -> Path:
    """Create `.security_reports/`, gitignore it, and drop any previous run's reports."""
    root = Path(project_root).resolve()
    report_dir = root / ".security_reports"
    report_dir.mkdir(parents=True, exist_ok=True)
    _clear_stale_reports(report_dir)
    _ignore_report_dir(root)
    return report_dir


def run_subprocess(
    args: list[str],
    *,
    cwd: Path,
    stderr_to_devnull: bool = False,
    env_overrides: dict[str, str] | None = None,
) -> CommandResult:
    """The production `CommandRunner`: hand the command line to the operating system."""
    environment = os.environ.copy()
    if env_overrides is not None:
        environment.update(env_overrides)

    try:
        completed = subprocess.run(
            args,
            cwd=str(cwd),
            env=environment,
            check=False,
            stderr=subprocess.DEVNULL if stderr_to_devnull else None,
        )
    except FileNotFoundError:
        return CommandResult(returncode=None, warning=f"{args[0]} was not found on PATH.")

    return CommandResult(returncode=completed.returncode)


def _prettify_json(path: Path) -> None:
    if not path.exists():
        return
    try:
        raw_data: object = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return
    path.write_text(json.dumps(raw_data, indent=2, ensure_ascii=False), encoding="utf-8")


def _tool_result(*, scanner: Scanner, result: CommandResult, report_path: Path) -> ToolRunResult:
    _prettify_json(report_path)
    return ToolRunResult(
        name=scanner.label,
        returncode=result.returncode,
        report_path=report_path,
        accepted_returncodes=scanner.accepted_returncodes,
        warning=result.warning,
    )


def run_trivy(
    project_root: str | Path,
    report_dir: str | Path,
    exclude_dirs: list[str],
    runner: CommandRunner,
) -> ToolRunResult:
    report_path = Path(report_dir) / TRIVY.report_file
    command = ["trivy", "fs", ".", "--format", "json", "--output", str(report_path), "--quiet"]
    if exclude_dirs:
        command.extend(["--skip-dirs", ",".join(exclude_dirs)])
    result = runner(command, cwd=Path(project_root).resolve())
    return _tool_result(scanner=TRIVY, result=result, report_path=report_path)


def run_semgrep(
    project_root: str | Path,
    report_dir: str | Path,
    exclude_dirs: list[str],
    runner: CommandRunner,
) -> ToolRunResult:
    report_path = Path(report_dir) / SEMGREP.report_file
    command = [
        "semgrep",
        "scan",
        "--config=auto",
        "--json",
        "--output",
        str(report_path),
        "--quiet",
        ".",
    ]
    for exclude_dir in exclude_dirs:
        if exclude_dir:
            command.extend(["--exclude", exclude_dir])
    result = runner(
        command,
        cwd=Path(project_root).resolve(),
        stderr_to_devnull=True,
        env_overrides={"PYTHONUTF8": "1"},
    )
    return _tool_result(scanner=SEMGREP, result=result, report_path=report_path)


def run_gitleaks(
    project_root: str | Path,
    report_dir: str | Path,
    exclude_dirs: list[str],
    runner: CommandRunner,
) -> ToolRunResult:
    report_path = Path(report_dir) / GITLEAKS.report_file
    command = [
        "gitleaks",
        "detect",
        "--source",
        ".",
        "--no-git",
        "--report-path",
        str(report_path),
        "--exit-code",
        "0",
    ]
    for exclude_dir in exclude_dirs:
        if exclude_dir:
            command.extend(["--exclude-path", exclude_dir])
    result = runner(command, cwd=Path(project_root).resolve(), stderr_to_devnull=True)
    return _tool_result(scanner=GITLEAKS, result=result, report_path=report_path)


# ZAP is absent by design: it takes a target URL rather than a project root, so its
# command line cannot be built from the same inputs as the static scanners'.
STATIC_RUNNERS: Final[dict[str, StaticRunner]] = {
    TRIVY.key: run_trivy,
    SEMGREP.key: run_semgrep,
    GITLEAKS.key: run_gitleaks,
}


def run_static_scanner(
    scanner: Scanner,
    project_root: str | Path,
    report_dir: str | Path,
    exclude_dirs: list[str],
    runner: CommandRunner,
) -> ToolRunResult:
    """Dispatch to a static scanner's runner."""
    return STATIC_RUNNERS[scanner.key](project_root, report_dir, exclude_dirs, runner)


def rewrite_zap_target(url: str) -> str:
    if "localhost" in url or "127.0.0.1" in url:
        return url.replace("localhost", "host.docker.internal").replace(
            "127.0.0.1", "host.docker.internal"
        )
    return url


def resolve_host_report_dir(report_dir: str | Path) -> Path:
    report_path = Path(report_dir).resolve()
    if host_report_dir := os.environ.get("WARDEN_HOST_REPORT_DIR"):
        return Path(host_report_dir)
    if host_workspace := os.environ.get("WARDEN_HOST_WORKSPACE"):
        return Path(host_workspace) / ".security_reports"
    if github_workspace := os.environ.get("GITHUB_WORKSPACE"):
        return Path(github_workspace) / ".security_reports"
    return report_path


def run_zap(report_dir: str | Path, url: str, runner: CommandRunner) -> ToolRunResult:
    report_path = Path(report_dir) / ZAP.report_file
    host_report_dir = resolve_host_report_dir(report_dir)
    target = rewrite_zap_target(url)
    command = [
        "docker",
        "run",
        "--rm",
        "-v",
        f"{host_report_dir}:/zap/wrk/:rw",
        "-t",
        ZAP_IMAGE,
        "zap-full-scan.py",
        "-t",
        target,
        "-J",
        ZAP.report_file,
        "-r",
        ZAP_HTML_REPORT,
        "-I",
    ]
    result = runner(command, cwd=Path(report_dir).resolve())
    return _tool_result(scanner=ZAP, result=result, report_path=report_path)
