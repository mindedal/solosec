from __future__ import annotations

import argparse
from pathlib import Path
from typing import cast

from . import aggregate, config, tooling
from ._models import CliOptions, ToolRunResult, ToolSelection
from ._scanners import SCANNERS, ZAP


def _parse_args(argv: list[str] | None = None) -> CliOptions:
    parser = argparse.ArgumentParser(prog="warden", description="Run the Warden security audit.")
    parser.add_argument(
        "-u",
        "--url",
        "-Url",
        "--Url",
        dest="url",
        default="",
        help="Optional DAST target URL",
    )
    parser.add_argument(
        "--project-root",
        default=".",
        help="Project root to scan (defaults to the current working directory)",
    )
    parser.add_argument("--config", default=None, help=f"Optional path to {config.CONFIG_FILENAME}")
    namespace = parser.parse_args(argv)
    project_root = Path(cast(str, namespace.project_root)).resolve()
    config_path_value = cast(str | None, namespace.config)
    return CliOptions(
        project_root=project_root,
        cli_url=cast(str, namespace.url),
        config_path=Path(config_path_value).resolve() if config_path_value is not None else None,
    )


def _print_result(result: ToolRunResult) -> None:
    if tooling.tool_succeeded(result) or tooling.report_written(result):
        print("   -> Done.")
        return
    if result.warning is not None:
        print(f"   -> Warning: {result.warning}")
        return
    print(f"   -> Warning: {result.name} exited with status {result.returncode}.")


def _run_zap_stage(
    stage: str,
    report_dir: Path,
    *,
    enabled: bool,
    url: str,
    runner: tooling.CommandRunner,
) -> None:
    """ZAP is not run like the others: it targets a URL through a container, or is skipped."""
    if not (enabled and url):
        print(f"{stage} Skipping {ZAP.label} (no URL provided or disabled).")
        return

    print(f"{stage} Running {ZAP.label}...")
    target = tooling.rewrite_zap_target(url)
    if target != url:
        print(
            "      (Detected localhost: switching to "
            "'host.docker.internal' for Docker compatibility)"
        )
        print(f"      Targeting: {target}")
    _print_result(tooling.run_zap(report_dir, target, runner))


def _run_enabled_tools(
    project_root: Path,
    report_dir: Path,
    tools: ToolSelection,
    url: str,
    exclude_dirs: list[str],
    runner: tooling.CommandRunner,
) -> None:
    total = len(SCANNERS)

    print()
    for step, scanner in enumerate(SCANNERS, start=1):
        stage = f"[{step}/{total}]"
        if scanner is ZAP:
            _run_zap_stage(
                stage, report_dir, enabled=tools.is_enabled(ZAP.key), url=url, runner=runner
            )
        elif not tools.is_enabled(scanner.key):
            print(f"{stage} Skipping {scanner.label} (disabled in {config.CONFIG_FILENAME}).")
        else:
            print(f"{stage} Running {scanner.label}...")
            _print_result(
                tooling.run_static_scanner(scanner, project_root, report_dir, exclude_dirs, runner)
            )


def run_audit(options: CliOptions, *, runner: tooling.CommandRunner) -> int:
    resolved = config.resolve_config(
        project_root=options.project_root,
        cli_url=options.cli_url,
        config_path=options.config_path,
    )
    report_dir = tooling.prepare_report_dir(options.project_root)
    output_file = options.project_root / "security_audit.json"

    print("STARTING SECURITY AUDIT")
    print(f"   Target: {options.project_root}")
    if resolved.url:
        print(f"   DAST URL: {resolved.url}")

    _run_enabled_tools(
        options.project_root,
        report_dir,
        resolved.tools,
        resolved.url,
        resolved.exclude_dirs,
        runner,
    )

    print("\n[*] Generating Final Report...")
    verdict = aggregate.generate_report(report_dir=report_dir, output_file=output_file)
    if verdict.failed:
        print("\nAUDIT FAILED!")
        print(f"Report saved to: {output_file}")
        return 1

    print("\nAUDIT COMPLETE!")
    print(f"Report saved to: {output_file}")
    return 0


def main(
    argv: list[str] | None = None,
    *,
    runner: tooling.CommandRunner = tooling.run_subprocess,
) -> int:
    return run_audit(_parse_args(argv), runner=runner)
