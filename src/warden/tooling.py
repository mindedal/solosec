from __future__ import annotations

import json
import os
import subprocess
from collections.abc import Sequence
from pathlib import Path
from typing import Protocol

from ._models import CommandResult, ToolRunResult
from ._scanners import SCANNERS, Scanner, ScanRequest


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


def tool_succeeded(result: ToolRunResult) -> bool:
    return result.returncode in result.accepted_returncodes


def report_written(result: ToolRunResult) -> bool:
    return result.report_path.exists()


def _clear_stale_reports(report_dir: Path) -> None:
    for scanner in SCANNERS:
        for filename in (scanner.report_file, *scanner.extra_artifacts):
            (report_dir / filename).unlink(missing_ok=True)


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


def scan_request(
    scanner: Scanner,
    *,
    project_root: str | Path,
    report_dir: str | Path,
    exclude_dirs: Sequence[str] = (),
    url: str = "",
) -> ScanRequest:
    """Everything `scanner.build_command` needs, with the paths already resolved."""
    resolved_report_dir = Path(report_dir).resolve()
    return ScanRequest(
        project_root=Path(project_root).resolve(),
        report_dir=resolved_report_dir,
        report_path=resolved_report_dir / scanner.report_file,
        exclude_dirs=tuple(exclude_dirs),
        url=url,
    )


def run_scanner(scanner: Scanner, request: ScanRequest, runner: CommandRunner) -> ToolRunResult:
    """Build this scanner's command line, run it, and normalise what came back."""
    command = scanner.build_command(request)
    result = runner(
        command.args,
        cwd=command.cwd,
        stderr_to_devnull=command.stderr_to_devnull,
        env_overrides=command.env_overrides,
    )
    _prettify_json(request.report_path)
    return ToolRunResult(
        name=scanner.label,
        returncode=result.returncode,
        report_path=request.report_path,
        accepted_returncodes=scanner.accepted_returncodes,
        warning=result.warning,
    )
