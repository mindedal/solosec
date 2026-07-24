from __future__ import annotations

import argparse
from collections.abc import Callable
from pathlib import Path
from typing import cast

from . import aggregate, config, tooling
from ._models import CliOptions, ToolRunResult, ToolSelection

StaticToolRunner = Callable[[Path, Path, list[str]], ToolRunResult]


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


def _run_zap(stage: str, report_dir: Path, url: str) -> None:
    print(f"{stage} Running ZAP...")
    target = tooling.rewrite_zap_target(url)
    if target != url:
        print(
            "      (Detected localhost: switching to "
            "'host.docker.internal' for Docker compatibility)"
        )
        print(f"      Targeting: {target}")
    _print_result(tooling.run_zap(report_dir, target))


def _run_enabled_tools(
    project_root: Path, report_dir: Path, tools: ToolSelection, url: str, exclude_dirs: list[str]
) -> None:
    # Built per call rather than at import time so the runners stay monkeypatchable.
    static_stages: tuple[tuple[str, bool, StaticToolRunner], ...] = (
        ("Trivy", tools.trivy, tooling.run_trivy),
        ("Semgrep", tools.semgrep, tooling.run_semgrep),
        ("Gitleaks", tools.gitleaks, tooling.run_gitleaks),
    )
    total = len(static_stages) + 1

    print()
    for step, (name, enabled, run_tool) in enumerate(static_stages, start=1):
        if not enabled:
            print(f"[{step}/{total}] Skipping {name} (disabled in {config.CONFIG_FILENAME}).")
            continue
        print(f"[{step}/{total}] Running {name}...")
        _print_result(run_tool(project_root, report_dir, exclude_dirs))

    zap_stage = f"[{total}/{total}]"
    if tools.zap and url:
        _run_zap(zap_stage, report_dir, url)
    else:
        print(f"{zap_stage} Skipping ZAP (no URL provided or disabled).")


def run_audit(options: CliOptions) -> int:
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
    )

    print("\n[*] Generating Final Report...")
    failed = aggregate.generate_report(report_dir=report_dir, output_file=output_file)
    if failed:
        print("\nAUDIT FAILED!")
        print(f"Report saved to: {output_file}")
        return 1

    print("\nAUDIT COMPLETE!")
    print(f"Report saved to: {output_file}")
    return 0


def main(argv: list[str] | None = None) -> int:
    return run_audit(_parse_args(argv))
