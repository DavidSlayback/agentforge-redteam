"""Load authored seed cases from YAML/JSON files under a directory.

A file may hold one case (a mapping) or several (a list, or a mapping with a `cases` key).
Names beginning with `_` are skipped, so `_template.yaml` documents the shape without being
run.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from redteam.evals.case import SeedCase


def load_cases(path: str | Path) -> list[SeedCase]:
    root = Path(path)
    files = sorted(p for p in root.rglob("*") if p.suffix in {".yaml", ".yml", ".json"} and not p.name.startswith("_"))
    cases: list[SeedCase] = []
    for file in files:
        data = yaml.safe_load(file.read_text(encoding="utf-8"))
        if data is None:
            continue
        raw = data.get("cases", data) if isinstance(data, dict) else data
        items = raw if isinstance(raw, list) else [raw]
        cases.extend(SeedCase.model_validate(item) for item in items)
    return cases
