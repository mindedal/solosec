#!/usr/bin/env python
"""SoloSec config loader.

Supports a project-level config file: .solosec.yaml

This intentionally implements only a small YAML subset (enough for the repo's
example) to avoid adding runtime dependencies.

Supported keys:
  target_url: "http://..."   (alias: url)
  exclude_dirs:
    - "tests/"
    - "legacy/"
  tools:
    zap: true|false
    semgrep: true|false
    gitleaks: true|false
    trivy: true|false

Precedence:
  - CLI URL overrides config target_url.

Output formats:
  - json (default)
  - bash (key=value lines safe to eval)
"""

from __future__ import annotations

import argparse
import json
import os
from dataclasses import dataclass
from typing import Any, Dict, List, Optional


def _strip_comment(line: str) -> str:
    # Remove inline comments (naive, but good enough for simple config files).
    # We keep it simple: everything after the first unescaped # is ignored.
    out = []
    escaped = False
    for ch in line:
        if escaped:
            out.append(ch)
            escaped = False
            continue
        if ch == "\\":
            out.append(ch)
            escaped = True
            continue
        if ch == "#":
            break
        out.append(ch)
    return "".join(out).rstrip("\r\n")


def _parse_scalar(raw: str) -> Any:
    s = raw.strip()
    if not s:
        return ""

    # Quotes
    if (s.startswith('"') and s.endswith('"')) or (s.startswith("'") and s.endswith("'")):
        return s[1:-1]

    low = s.lower()
    if low in {"true", "yes", "on"}:
        return True
    if low in {"false", "no", "off"}:
        return False

    # int
    try:
        if low.isdigit() or (low.startswith("-") and low[1:].isdigit()):
            return int(low)
    except Exception:
        pass

    return s


def parse_minimal_yaml(text: str) -> Dict[str, Any]:
    cfg: Dict[str, Any] = {}

    context: Optional[str] = None
    for raw_line in text.splitlines():
        line = _strip_comment(raw_line)
        if not line.strip():
            continue

        indent = len(line) - len(line.lstrip(" "))
        stripped = line.strip()

        if indent == 0:
            # Top-level key
            if ":" not in stripped:
                continue
            key, value = stripped.split(":", 1)
            key = key.strip()
            value = value.strip()

            if value == "":
                # Section header - initialize appropriate container type
                if key == "exclude_dirs":
                    cfg[key] = []
                else:
                    cfg[key] = {}
                context = key
            else:
                cfg[key] = _parse_scalar(value)
                context = None
            continue

        # indented lines
        if context == "exclude_dirs":
            if stripped.startswith("-"):
                item = _parse_scalar(stripped[1:].strip())
                if isinstance(item, str) and item:
                    cfg.setdefault("exclude_dirs", []).append(item)
            continue

        if context == "tools":
            if ":" in stripped:
                k, v = stripped.split(":", 1)
                cfg.setdefault("tools", {})[k.strip()] = _parse_scalar(v)
            continue

        # ignore unknown nested sections for now

    return cfg


@dataclass
class ResolvedConfig:
    url: str
    exclude_dirs: List[str]
    tools: Dict[str, bool]


def resolve_config(
    *,
    project_root: str,
    cli_url: str,
    config_path: Optional[str] = None,
) -> ResolvedConfig:
    root = os.path.abspath(project_root)
    cfg_path = config_path or os.path.join(root, ".solosec.yaml")

    raw: Dict[str, Any] = {}
    if os.path.exists(cfg_path):
        try:
            with open(cfg_path, "r", encoding="utf-8") as f:
                raw = parse_minimal_yaml(f.read())
        except (OSError, IOError, ValueError):
            raw = {}

    target_url = str(raw.get("target_url") or raw.get("url") or "").strip()
    url = (cli_url or "").strip() or target_url

    exclude_dirs_raw = raw.get("exclude_dirs")
    exclude_dirs: List[str] = []
    if isinstance(exclude_dirs_raw, list):
        exclude_dirs = [str(x) for x in exclude_dirs_raw if str(x).strip()]

    tools_defaults: Dict[str, bool] = {
        "trivy": True,
        "semgrep": True,
        "gitleaks": True,
        "zap": True,
    }
    tools = dict(tools_defaults)

    tools_raw = raw.get("tools")
    if isinstance(tools_raw, dict):
        for k, v in tools_raw.items():
            key = str(k).strip().lower()
            if key in tools_defaults:
                tools[key] = bool(v)

    # If zap is disabled, we should not emit a URL even if present.
    if not tools.get("zap", True):
        url = ""

    return ResolvedConfig(url=url, exclude_dirs=exclude_dirs, tools=tools)


def _bash_escape(value: str) -> str:
    # Single-quote escaping suitable for: VAR='value'
    return "'" + value.replace("'", "'\\''") + "'"


def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(prog="solosec-config")
    p.add_argument("project_root", help="Project root directory")
    p.add_argument("--cli-url", default="", help="URL passed via CLI (overrides config)")
    p.add_argument("--config", default=None, help="Path to .solosec.yaml")
    p.add_argument("--format", choices=["json", "bash"], default="json")
    args = p.parse_args(argv)

    resolved = resolve_config(
        project_root=args.project_root,
        cli_url=args.cli_url,
        config_path=args.config,
    )

    if args.format == "json":
        print(
            json.dumps(
                {
                    "url": resolved.url,
                    "exclude_dirs": resolved.exclude_dirs,
                    "tools": resolved.tools,
                },
                ensure_ascii=False,
            )
        )
        return 0

    # bash
    print(f"SOLOSEC_URL={_bash_escape(resolved.url)}")
    print(f"SOLOSEC_EXCLUDE_DIRS={_bash_escape(','.join(resolved.exclude_dirs))}")
    for tool, enabled in resolved.tools.items():
        print(f"SOLOSEC_TOOL_{tool.upper()}={'1' if enabled else '0'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
