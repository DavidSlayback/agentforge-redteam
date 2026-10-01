"""No frozen regression case changes outcome under the decoded-matching rules (GitLab #2, owner
decision 7: stored history is not re-judged; this only checks it).

Each frozen case's stored attempts are replayed offline: the stored response is served by a fake
sender to the case's own probe (`reconstruct_probe`), and the Judge's verdict is compared under two
views of the body: the current one (decoded values, echo stripping, normalized matching) and the
pre-decoding one (the raw body, no echo stripping on the probe path). Equal outcomes on every
attempt mean the refactor changes no frozen case.

The emulated raw view is faithful only where the text-matching changes are the whole difference,
so the check also asserts the preconditions that make it so: no frozen case carries a marker or
canaries (case-folding and decoding of those would be untested), and no attempt reaches the
rubric tier (whose input also changed).

Against real history, set REDTEAM_FROZEN_CHECK_STORE to a store file; the test copies it into a
temporary directory and opens the copy read-only. Without it, the check runs on a synthetic store
so the harness itself stays tested.
"""

from __future__ import annotations

import ast
import json
import os
import shutil
import sqlite3
from pathlib import Path

import pytest

from redteam import runner
from redteam.agents.judge.judge import Judge
from redteam.authz_probe import mint_probe, reconstruct_probe, run_probe
from redteam.evals.case import SeedCase
from redteam.executor.authorization import AuthorizationRegistry
from redteam.executor.executor import Executor
from redteam.executor.http_sender import ResponseRecord
from redteam.oracles.decode import RAW_PATH
from redteam.store.store import Store


class _Minter:
    def auth_fields(self, patient_uuid: str) -> dict:
        return {"patient_uuid": patient_uuid, "clinician_uuid": "c", "demo_token": "t"}


def _replaying(exchange: dict):
    """A sender that answers every request with the stored response. The rate-limit probe stores
    one summary row for its burst ({status: count}), so its statuses are replayed from the counts."""
    latency = exchange.get("latency_ms") or 1.0
    if (exchange.get("request") or {}).get("_repeated"):
        counts = ast.literal_eval((exchange.get("response") or "").split("statuses ", 1)[1])
        statuses = iter(s for s, n in counts.items() for _ in range(n))
        return lambda u, **k: ResponseRecord(next(statuses), "", latency)
    return lambda u, **k: ResponseRecord(exchange["status_code"], exchange.get("response"), latency)


def _raw_view(monkeypatch: pytest.MonkeyPatch) -> None:
    """The builder as it was before decoding: oracles read the raw body, and the probe path
    strips nothing (the frozen cases all come from probes; see the module docstring)."""
    monkeypatch.setattr(runner, "decoded_values", lambda text: ((RAW_PATH, text),))
    monkeypatch.setattr(runner, "strip_echo", lambda text, echoes: text)
    monkeypatch.setattr(runner, "strip_normalized_echo", lambda value, echoes: value.casefold())


def _rejudge(store_path: Path, tmp: Path) -> list[dict]:
    """Every frozen case's stored attempts, replayed through the case's probe with the current code."""
    con = sqlite3.connect(f"file:{store_path.as_posix()}?mode=ro", uri=True)
    con.row_factory = sqlite3.Row
    rows = []
    try:
        for frozen in con.execute("SELECT case_id, spec_id, case_json FROM regression_cases ORDER BY case_id"):
            case = SeedCase.model_validate_json(frozen["case_json"])
            auth = tmp / f"{frozen['case_id']}.yaml"
            auth.write_text(f"targets:\n  - id: {case.target_id}\n    origin: https://frozen.example\n"
                            "    proof: offline replay of stored evidence\n    enabled: true\n", encoding="utf-8")
            reg = AuthorizationRegistry.load(auth)
            target = reg.by_id(case.target_id)
            attempts = con.execute(
                "SELECT a.attempt_id, e.exchanges FROM attempts a JOIN evidence e ON e.attempt_id = a.attempt_id "
                "WHERE a.spec_id = ? OR a.spec_id LIKE ? ORDER BY a.started_at",
                (frozen["spec_id"], frozen["spec_id"] + "-rt%"))
            for attempt in attempts:
                exchanges = json.loads(attempt["exchanges"])
                if not exchanges:   # an unreachable target: nothing was judged, nothing to replay
                    continue
                probe = reconstruct_probe(case, Executor(reg, _replaying(exchanges[-1])), Judge(), target, _Minter())
                verdict, _ = probe.produce(target, [])
                rows.append({"case": frozen["case_id"], "attempt": attempt["attempt_id"], "frozen": case,
                             "outcome": verdict.outcome, "reason": verdict.reason,
                             "oracles": {r.oracle: r.outcome for r in verdict.oracle_results}})
    finally:
        con.close()
    return rows


def _check(store_path: Path, tmp: Path, monkeypatch: pytest.MonkeyPatch) -> int:
    decoded = _rejudge(store_path, tmp)
    for row in decoded:
        assert row["frozen"].oracle.marker is None and not row["frozen"].oracle.foreign_canaries, row["case"]
        assert row["reason"] != "no oracle applied to this attempt", row   # the rubric tier would run
    with monkeypatch.context() as m:
        _raw_view(m)
        raw = _rejudge(store_path, tmp)
    assert [r["attempt"] for r in raw] == [r["attempt"] for r in decoded]
    changed = [(d["case"], d["attempt"], r["outcome"], d["outcome"])
               for d, r in zip(decoded, raw) if (d["outcome"], d["oracles"]) != (r["outcome"], r["oracles"])]
    assert changed == [], f"frozen cases whose outcome changes under decoded matching: {changed}"
    return len(decoded)


def _synthetic_store(tmp_path: Path, issued_body: str) -> Path:
    """A store holding one frozen case: an anonymous mint that issued a token with `issued_body`."""
    p = tmp_path / "auth.yaml"
    p.write_text("targets:\n  - id: good\n    origin: https://good.example\n    proof: test fixture\n    enabled: true\n",
                 encoding="utf-8")
    reg = AuthorizationRegistry.load(p)
    store = Store.open(tmp_path / "s.db")
    run_probe(mint_probe(Executor(reg, lambda u, **k: ResponseRecord(200, issued_body, 3.0)), Judge(),
                         reg.by_id("good"), "fixture-patient-001"), store, reg)
    assert store.count("regression_cases") == 1
    store.close()
    return tmp_path / "s.db"


def test_the_check_runs_on_a_synthetic_frozen_case(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    body = json.dumps({"demo_token": "x", "patient_uuid": "fixture-patient-001", "note": 'a "quoted" value'})
    assert _check(_synthetic_store(tmp_path, body), tmp_path, monkeypatch) == 1


def test_the_check_reports_a_frozen_case_that_would_change(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # Positive control: markup the serializer escaped is visible only once decoded, so the stored
    # attempt gains an output-handling violation under the new rules.
    body = json.dumps({"demo_token": "x", "note": "<svg>"}).replace("<", "\\u003c")
    with pytest.raises(AssertionError, match="outcome changes under decoded matching"):
        _check(_synthetic_store(tmp_path, body), tmp_path, monkeypatch)


@pytest.mark.skipif(not os.environ.get("REDTEAM_FROZEN_CHECK_STORE"),
                    reason="set REDTEAM_FROZEN_CHECK_STORE to a store file to check real frozen cases")
def test_no_frozen_regression_case_changes_outcome(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    copy = tmp_path / "store-copy.db"
    shutil.copyfile(os.environ["REDTEAM_FROZEN_CHECK_STORE"], copy)   # never open the original
    assert _check(copy, tmp_path, monkeypatch) > 0
