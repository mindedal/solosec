from __future__ import annotations

import json
from collections.abc import Iterator, Mapping
from pathlib import Path
from typing import cast


def as_mapping(value: object) -> Mapping[str, object] | None:
    if isinstance(value, Mapping):
        return cast(Mapping[str, object], value)
    return None


def iter_list_items(value: object) -> Iterator[object]:
    if isinstance(value, list):
        yield from cast(list[object], value)


def iter_mappings(value: object) -> Iterator[Mapping[str, object]]:
    for item in iter_list_items(value):
        narrowed = as_mapping(item)
        if narrowed is not None:
            yield narrowed


def get_string(mapping: Mapping[str, object], key: str) -> str | None:
    value = mapping.get(key)
    return value if isinstance(value, str) and value.strip() else None


def get_int(mapping: Mapping[str, object], key: str) -> int | None:
    value = mapping.get(key)
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.strip().isdigit():
        return int(value.strip())
    return None


def load_json(path: str | Path) -> object | None:
    file_path = Path(path)
    if not file_path.exists():
        return None
    try:
        raw_data: object = json.loads(file_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        print(f"Warning: Could not parse {file_path.name}: {error}")
        return None
    return raw_data
