"""Load authored seed cases from YAML/JSON files under a directory.

A file may hold one case (a mapping) or several (a list, or a mapping with a `cases` key).
Names beginning with `_` are skipped, so `_template.yaml` documents the shape without being
run.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from redteam.evals.case import SeedCase
from redteam.owasp import NEEDS_CANARY, OWASP_API_2023, OWASP_LLM_2025

# Only the LLM and API lists in owasp.py: `owasp_scheme` labels anything non-API as LLM, so a
# web Top 10 id (A07) would be mislabelled in findings. Keep case tags consistent with the probes.
KNOWN_OWASP = frozenset(OWASP_LLM_2025) | frozenset(OWASP_API_2023)

# Closure-based probes `authz_probe.reconstruct_probe` can rebuild for replay.
REPLAYABLE_PROBE_KINDS = frozenset(
    {"mint", "rate_limit", "grounding", "disclosure", "enumeration", "contradiction", "dos"})
# Categories whose oracle input (a victim canary) is supplied by the harness at run time.
_RUNTIME_CANARY = NEEDS_CANARY | {"broken-object-authorization"}


def load_case_files(path: str | Path) -> list[tuple[Path, dict]]:
    """Every authored case as (file, raw mapping), before model validation, so enforcement can see
    which keys were actually written (e.g. an explicit `regression:`)."""
    root = Path(path)
    files = sorted(p for p in root.rglob("*") if p.suffix in {".yaml", ".yml", ".json"} and not p.name.startswith("_"))
    out: list[tuple[Path, dict]] = []
    for file in files:
        data = yaml.safe_load(file.read_text(encoding="utf-8"))
        if data is None:
            continue
        raw = data.get("cases", data) if isinstance(data, dict) else data
        out.extend((file, item) for item in (raw if isinstance(raw, list) else [raw]))
    return out


def load_cases(path: str | Path) -> list[SeedCase]:
    return [SeedCase.model_validate(item) for _, item in load_case_files(path)]


def _owasp_known(tag: str) -> bool:
    return tag.split(":", 1)[0].upper() in KNOWN_OWASP


def validate_committed_case(case: SeedCase, raw: dict, target_ids: set[str]) -> list[str]:
    """Problems with a committed eval case (empty list = valid). Stricter than `SeedCase`, which
    Red Team variants also use and which leaves subcategory/result optional: committed files must
    carry the PRD Stage-3 fields. `target_ids` are the enabled ids in authorization.yaml."""
    p: list[str] = []
    if not (case.subcategory or "").strip():
        p.append("subcategory is required")
    if not case.owasp:
        p.append("owasp must be non-empty")
    p += [f"unknown OWASP tag {t!r}" for t in case.owasp if not _owasp_known(t)]
    if not case.expected_safe.strip():
        p.append("expected_safe is required")
    if "regression" not in raw:
        p.append("regression must be set explicitly")
    if case.risk_class is None:
        p.append("risk_class (boundary | invariant | regression) is required")
    if case.target_id not in target_ids:
        p.append(f"target_id {case.target_id!r} is not an enabled authorization.yaml target")
    if not case.turns:
        p.append("turns is required")
    r = case.result
    if r is None:
        p.append("result block is required")
    else:
        if not r.observed_detail.strip():
            p.append("result.observed_detail is required")
        if not r.exploitability.strip():
            p.append("result.exploitability is required")
        if r.observed != "not_run" and not (r.target_sha and r.run_date):
            p.append("a run result must carry target_sha and run_date")
        if r.observed != "not_run" and not (r.evidence or "").strip():
            p.append("a run result must carry evidence (finding id / store category / doc)")
        if r.observed == "fail" and not case.regression:
            p.append("a confirmed exploit (observed: fail) must be regression: true")
    if case.regression:
        if case.probe_kind is not None:
            if case.probe_kind not in REPLAYABLE_PROBE_KINDS:
                p.append(f"probe_kind {case.probe_kind!r} cannot be replayed")
        else:
            o = case.oracle
            has_oracle = bool(o.marker or o.expect_rejected or o.foreign_canaries or o.latency_budget_ms)
            if not (has_oracle or case.category in _RUNTIME_CANARY):
                p.append("regression: true needs a probe_kind or an oracle to replay")
        if any(not t.route for t in case.turns):
            p.append("regression: true needs a route on every turn")
    return p
