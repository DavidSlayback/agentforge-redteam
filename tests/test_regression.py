"""Confirmed findings freeze into regression cases; replay classifies held vs reappeared."""

from __future__ import annotations

from pathlib import Path

from redteam.agents.judge.judge import Judge
from redteam.evals.case import OracleConfig, SeedCase, Turn
from redteam.executor.authorization import AuthorizationRegistry
from redteam.executor.executor import Executor
from redteam.executor.http_sender import ResponseRecord
from redteam.regression import replay
from redteam.runner import run_case
from redteam.store.store import Store

MARK = "ZZ-REG"


def _registry(tmp_path: Path) -> AuthorizationRegistry:
    p = tmp_path / "auth.yaml"
    p.write_text("targets:\n  - id: good\n    origin: https://good.example\n    enabled: true\n", encoding="utf-8")
    return AuthorizationRegistry.load(p)


def _vuln_case() -> SeedCase:
    return SeedCase(
        case_id="c1", category="prompt-injection", owasp=["LLM01"], target_id="good",
        turns=[Turn(ordinal=1, route="/v1/x", body={})], oracle=OracleConfig(marker=MARK),
        expected_safe="refuses",
    )


def test_confirmed_finding_freezes_a_regression_case(tmp_path: Path) -> None:
    reg = _registry(tmp_path)
    store = Store.open(tmp_path / "s.db")
    echo = Executor(reg, lambda u, **k: ResponseRecord(200, f"ok {MARK}", 4.0))  # SUCCESS
    run_case(_vuln_case(), reg, echo, Judge(), store)
    assert store.count("regression_cases") == 1
    store.close()


def test_replay_reports_held_then_reappeared(tmp_path: Path) -> None:
    reg = _registry(tmp_path)
    store = Store.open(tmp_path / "s.db")
    echo = Executor(reg, lambda u, **k: ResponseRecord(200, f"ok {MARK}", 4.0))
    run_case(_vuln_case(), reg, echo, Judge(), store)   # freezes one regression case

    # a "fixed" build: the marker no longer leaks -> the fix holds
    fixed = Executor(reg, lambda u, **k: ResponseRecord(200, "refused", 4.0))
    r1 = replay(store, reg, fixed, Judge(), target_sha="sha-fixed")
    assert r1.held and not r1.reappeared and r1.ok

    # a regressed build: the marker leaks again -> reappearance
    r2 = replay(store, reg, echo, Judge(), target_sha="sha-regressed")
    assert r2.reappeared and not r2.ok
    assert r2.reappeared[0]["category"] == "prompt-injection"
    store.close()


def test_mint_finding_replays_faithfully_not_fake_green(tmp_path: Path) -> None:
    # T1.6: the closure-based mint probe (our real critical finding) must replay through the SAME
    # probe. Before the fix it degraded to a generic path and fake-greened; now an open mint
    # reappears (red) and a fixed mint holds (green).
    from redteam.authz_probe import mint_probe, run_probe

    reg = _registry(tmp_path)
    store = Store.open(tmp_path / "s.db")
    target = reg.by_id("good")
    issues_token = lambda u, **k: ResponseRecord(200, '{"demo_token":"x","patient_uuid":"p"}', 2.0)  # noqa: E731
    run_probe(mint_probe(Executor(reg, issues_token), Judge(), target, "fixture-patient-001"), store, reg)
    assert store.count("regression_cases") == 1        # the mint finding froze

    # OPEN build: mint still issues a token anonymously -> must NOT be a fake green
    r_open = replay(store, reg, Executor(reg, issues_token), Judge(), target_sha="open")
    assert r_open.reappeared and not r_open.held and not r_open.ok

    # FIXED build: the mint now requires auth (401) -> the fix holds, suite green
    denied = lambda u, **k: ResponseRecord(401, "unauthorized", 1.0)  # noqa: E731
    r_fixed = replay(store, reg, Executor(reg, denied), Judge(), target_sha="fixed")
    assert r_fixed.held and r_fixed.ok
    store.close()


def test_replay_surfaces_unreplayable_pre_migration_cases(tmp_path: Path) -> None:
    reg = _registry(tmp_path)
    store = Store.open(tmp_path / "s.db")
    echo = Executor(reg, lambda u, **k: ResponseRecord(200, f"ok {MARK}", 4.0))
    run_case(_vuln_case(), reg, echo, Judge(), store)
    # simulate a case frozen before case_json existed
    store.conn.execute("UPDATE regression_cases SET case_json = NULL")
    store.conn.commit()
    r = replay(store, reg, echo, Judge(), target_sha="sha-x")
    assert r.unreplayable and not r.reappeared and not r.held
    store.close()
