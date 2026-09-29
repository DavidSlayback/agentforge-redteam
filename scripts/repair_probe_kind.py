"""One-time data repair: set `probe_kind` on regression cases frozen before the field existed.

Why this exists
---------------
Closure-based probes (the anonymous-mint and rate-limit probes) execute their real request in a
`produce` closure that sends `patient_uuid` as a **query param** (`params=`). The frozen `Turn`
only carries a `body`, so a faithful replay needs `SeedCase.probe_kind` — `dispatch` uses it to
rebuild the exact probe via `reconstruct_probe`. The current builders set `probe_kind`
(`mint`/`rate_limit`/`dos`), but findings frozen on 2026-09-29 predate the field, so their
`case_json.probe_kind` is `None`. Those replay through the generic authz path, which sends the
body form; the target 400s on request validation and the oracle reads a false "held".

This script sets `probe_kind` on any regression case where it is null, inferring it as the exact
inverse of the builders (never a fuzzy guess):

    broken-authentication + mint route          -> "mint"
    denial-of-service + body has "_count"        -> "rate_limit"
    denial-of-service + body has "message_len"   -> "dos"

It is idempotent (skips rows that already have a probe_kind) and prints every change. Back up the
store first; the repair only rewrites the `case_json` blob's `probe_kind` field.

Usage:  uv run python scripts/repair_probe_kind.py <store.db> [--apply]
        (dry-run by default; pass --apply to write)
"""

from __future__ import annotations

import json
import sqlite3
import sys

_MINT_ROUTES = {"/v1/demo-context", "/v1/source-document-context"}


def infer_probe_kind(case: dict) -> str | None:
    category = case.get("category")
    turns = case.get("turns") or []
    route = turns[0].get("route") if turns else None
    body = (turns[0].get("body") or {}) if turns else {}
    if category == "broken-authentication" and route in _MINT_ROUTES:
        return "mint"
    if category == "denial-of-service" and "_count" in body:
        return "rate_limit"
    if category == "denial-of-service" and "message_len" in body:
        return "dos"
    return None


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print(__doc__)
        return 2
    db = argv[1]
    apply = "--apply" in argv[2:]
    conn = sqlite3.connect(db)
    conn.row_factory = sqlite3.Row
    rows = conn.execute("SELECT case_id, finding_id, case_json FROM regression_cases").fetchall()
    changed = 0
    for row in rows:
        if not row["case_json"]:
            continue
        case = json.loads(row["case_json"])
        if case.get("probe_kind"):
            print(f"skip  {row['case_id']} ({row['finding_id']}): probe_kind={case['probe_kind']!r}")
            continue
        kind = infer_probe_kind(case)
        if kind is None:
            print(f"leave {row['case_id']} ({row['finding_id']}): not a closure probe; probe_kind stays null")
            continue
        case["probe_kind"] = kind
        print(f"SET   {row['case_id']} ({row['finding_id']}): probe_kind -> {kind!r}")
        if apply:
            conn.execute("UPDATE regression_cases SET case_json = ? WHERE case_id = ?",
                         (json.dumps(case), row["case_id"]))
        changed += 1
    if apply:
        conn.commit()
        print(f"\napplied: {changed} case(s) updated")
    else:
        print(f"\ndry-run: {changed} case(s) WOULD be updated (pass --apply to write)")
    conn.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
