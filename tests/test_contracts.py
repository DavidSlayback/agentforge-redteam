"""The generated target contracts stay in lockstep with the vendored snapshot.

This is the S0 behavioral seam: the drift test. It proves the committed pydantic
models are a faithful, reproducible generation of the pinned target schemas, so a
snapshot refresh that changes a shape can never land without regenerating.

The Zod-refinement guard from the in-repo scaffold cannot run here (we do not have
the target's Zod source in this black-box repo); that check moves to the snapshot
refresh procedure in vendor/agentforge-schemas/PROVENANCE.md.
"""

from __future__ import annotations

import copy
import subprocess
import sys
from pathlib import Path

import pytest
from pydantic import ValidationError

from redteam.contracts.target.LabResult import LabResult

REPO_ROOT = Path(__file__).resolve().parents[1]
GENERATOR = REPO_ROOT / "tools" / "generate_contracts.py"
COMMITTED = REPO_ROOT / "src" / "redteam" / "contracts" / "target"
SNAPSHOT = REPO_ROOT / "vendor" / "agentforge-schemas"

VALID_LAB = {
    "test_name": "Hemoglobin A1c",
    "value": "7.2",
    "unit": "%",
    "reference_range": "4.0-5.6",
    "collection_date": "2026-09-01",
    "abnormal_flag": "high",
    "confidence": 0.93,
    "citation": {
        "source_type": "document",
        "source_id": "doc-1",
        "page_or_section": "1",
        "field_or_chunk_id": "hba1c",
        "quote_or_value": "7.2 %",
        "bounding_box": [10, 20, 110, 40],
    },
}


def _read(path: Path) -> str:
    # core.autocrlf may check files out with CRLF; the generator writes LF.
    return path.read_text(encoding="utf-8").replace("\r\n", "\n")


def test_committed_contracts_match_a_fresh_generation(tmp_path: Path) -> None:
    subprocess.run([sys.executable, str(GENERATOR), "--output", str(tmp_path)], check=True)
    fresh = {p.name: _read(p) for p in tmp_path.glob("*.py")}
    committed = {p.name: _read(p) for p in COMMITTED.glob("*.py")}
    regenerate = "run `uv run python tools/generate_contracts.py` from the repo root"
    assert sorted(fresh) == sorted(committed), (
        f"generated contract files differ (missing: {sorted(fresh.keys() - committed.keys())}, "
        f"extra: {sorted(committed.keys() - fresh.keys())}); {regenerate}"
    )
    for name, text in fresh.items():
        assert committed[name] == text, f"src/redteam/contracts/target/{name} is stale; {regenerate}"


def test_snapshot_has_provenance() -> None:
    # A vendored snapshot without recorded provenance is unpinned and unsafe to trust.
    # PROVENANCE.md lives beside the schema dir, not inside it: the code generator
    # parses every file in its input dir as a schema.
    assert (SNAPSHOT.parent / "PROVENANCE.md").is_file()
    assert any(SNAPSHOT.glob("*.json")), "no vendored target schemas found"


def test_valid_lab_result_parses() -> None:
    assert LabResult.model_validate(VALID_LAB).citation.source_id == "doc-1"


@pytest.mark.parametrize(
    ("path", "value"),
    [
        (("unexpected_key",), "x"),  # .strict() -> extra='forbid'
        (("abnormal_flag",), "elevated"),  # enum
        (("confidence",), 1.5),  # max(1)
        (("test_name",), ""),  # min(1)
        (("citation", "page_or_section"), ""),  # exact W2 citation key, non-empty
        (("citation", "bounding_box"), [10, 20, 110]),  # 4-tuple
        (("citation", "bounding_box"), [-1, 20, 110, 40]),  # nonnegative
    ],
)
def test_lab_result_rejects_what_the_target_rejects(path: tuple[str, ...], value: object) -> None:
    sample = copy.deepcopy(VALID_LAB)
    target = sample
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = value
    with pytest.raises(ValidationError):
        LabResult.model_validate(sample)
