from __future__ import annotations

from pathlib import Path

from warden.config import parse_minimal_yaml, resolve_config


def test_parse_minimal_yaml_handles_lists_and_tools() -> None:
    raw_config = parse_minimal_yaml(
        """
        target_url: "http://localhost:3000"
        exclude_dirs:
          - "tests/"
          - "legacy/"
        tools:
          zap: false
          semgrep: true
        """
    )

    assert raw_config["target_url"] == "http://localhost:3000"
    assert raw_config["exclude_dirs"] == ["tests/", "legacy/"]
    assert raw_config["tools"] == {"zap": False, "semgrep": True}


def test_resolve_config_prefers_cli_url(tmp_path: Path) -> None:
    config_path = tmp_path / ".warden.yaml"
    config_path.write_text('target_url: "http://from-config"\n', encoding="utf-8")

    resolved = resolve_config(project_root=tmp_path, cli_url="http://from-cli")

    assert resolved.url == "http://from-cli"


def test_resolve_config_falls_back_to_url_alias(tmp_path: Path) -> None:
    config_path = tmp_path / ".warden.yaml"
    config_path.write_text('url: "http://from-alias"\n', encoding="utf-8")

    resolved = resolve_config(project_root=tmp_path, cli_url="")

    assert resolved.url == "http://from-alias"


def test_resolve_config_prefers_target_url_even_when_empty(tmp_path: Path) -> None:
    config_path = tmp_path / ".warden.yaml"
    config_path.write_text(
        """
        target_url: ""
        url: "http://from-alias"
        """,
        encoding="utf-8",
    )

    resolved = resolve_config(project_root=tmp_path, cli_url="")

    assert resolved.url == ""


def test_resolve_config_clears_url_when_zap_is_disabled(tmp_path: Path) -> None:
    config_path = tmp_path / ".warden.yaml"
    config_path.write_text(
        """
        target_url: "http://localhost:3000"
        tools:
          zap: false
        """,
        encoding="utf-8",
    )

    resolved = resolve_config(project_root=tmp_path, cli_url="")

    assert resolved.url == ""
    assert resolved.tools.zap is False
