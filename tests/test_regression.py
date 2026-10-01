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


# --- cross-category regression flagging (P5) ---------------------------------------------

def _freeze_two_categories(reg, store):
    """Freeze an anonymous-mint finding (broken-authentication) on /v1/demo-context and a
    rate-limit finding (denial-of-service) on /v1/source-document-context — two distinct
    categories on distinct endpoints, so a replay sender can drive each independently."""
    from redteam.authz_probe import mint_probe, rate_limit_probe, run_probe

    def success(url, **k):  # both probes succeed -> both promote + freeze
        if "source-document-context" in url:
            return ResponseRecord(200, "ok", 1.0)                 # rate: no 429 -> SUCCESS
        return ResponseRecord(200, '{"demo_token":"x"}', 2.0)      # mint: token -> SUCCESS

    ex = Executor(reg, success)
    target = reg.by_id("good")
    run_probe(mint_probe(ex, Judge(), target, "p", endpoint="/v1/demo-context"), store, reg)
    run_probe(rate_limit_probe(ex, target, "p", endpoint="/v1/source-document-context", n=3), store, reg)
    assert store.count("regression_cases") == 2


def test_cross_category_regression_flagged_when_a_fix_reopens_another_category(tmp_path: Path) -> None:
    reg = _registry(tmp_path)
    store = Store.open(tmp_path / "s.db")
    _freeze_two_categories(reg, store)

    # prior build: mint OPEN (200+token -> SUCCESS), rate HELD (a 429 -> throttled -> FAIL)
    def prior(url, **k):
        if "source-document-context" in url:
            return ResponseRecord(429, "slow down", 1.0)
        return ResponseRecord(200, '{"demo_token":"x"}', 2.0)
    replay(store, reg, Executor(reg, prior), Judge(), target_sha="sha-prior")

    # new build: mint HELD (401 -> FAIL, a fix landed for broken-authentication) while rate
    # REOPENS (all 200, no 429 -> SUCCESS for denial-of-service)
    def new(url, **k):
        if "source-document-context" in url:
            return ResponseRecord(200, "ok", 1.0)
        return ResponseRecord(401, "unauthorized", 1.0)
    r = replay(store, reg, Executor(reg, new), Judge(), target_sha="sha-new")

    assert r.fixed_categories == {"broken-authentication"}
    assert r.regressed_categories == {"denial-of-service"}
    assert r.cross_category_regression is True
    assert not r.ok                       # a reappearance is never green
    store.close()


def test_plain_reappearance_without_a_fix_is_not_cross_category(tmp_path: Path) -> None:
    reg = _registry(tmp_path)
    store = Store.open(tmp_path / "s.db")
    _freeze_two_categories(reg, store)

    # prior: both HELD
    def prior(url, **k):
        if "source-document-context" in url:
            return ResponseRecord(429, "slow down", 1.0)          # rate HELD
        return ResponseRecord(401, "unauthorized", 1.0)           # mint HELD
    replay(store, reg, Executor(reg, prior), Judge(), target_sha="sha-prior")

    # new: rate reopens, mint stays held -> a regression, but NO fix landed -> not cross-category
    def new(url, **k):
        if "source-document-context" in url:
            return ResponseRecord(200, "ok", 1.0)                 # rate reopens
        return ResponseRecord(401, "unauthorized", 1.0)           # mint still held
    r = replay(store, reg, Executor(reg, new), Judge(), target_sha="sha-new")

    assert r.regressed_categories == {"denial-of-service"}
    assert r.fixed_categories == set()
    assert r.cross_category_regression is False   # nothing was fixed, so nothing "caused" it
    assert r.newly_regressed and not r.ok
    store.close()


def test_mint_exhausting_classifies_probe_kinds() -> None:
    from redteam.regression import _mint_exhausting

    assert _mint_exhausting('{"probe_kind": "rate_limit"}') is True
    assert _mint_exhausting('{"probe_kind": "dos"}') is True
    assert _mint_exhausting('{"probe_kind": "grounding"}') is False
    assert _mint_exhausting('{"probe_kind": "contradiction"}') is False
    assert _mint_exhausting(None) is False
    assert _mint_exhausting("not json") is False
    assert _mint_exhausting('{"no_kind": 1}') is False


def test_replay_orders_mint_exhausting_probes_last() -> None:
    """Rate-limit/DoS probes must replay after mint-dependent ones, so the rate-limit burst
    cannot starve a sibling's token mint into a false INCONCLUSIVE."""
    from redteam.regression import _mint_exhausting

    rows = [
        {"case_id": "rl", "case_json": '{"probe_kind": "rate_limit"}'},
        {"case_id": "gr", "case_json": '{"probe_kind": "grounding"}'},
        {"case_id": "dos", "case_json": '{"probe_kind": "dos"}'},
        {"case_id": "co", "case_json": '{"probe_kind": "contradiction"}'},
    ]
    ordered = sorted(rows, key=lambda r: _mint_exhausting(r["case_json"]))  # stable sort
    assert [r["case_id"] for r in ordered[:2]] == ["gr", "co"]              # mint-dependent first
    assert {r["case_id"] for r in ordered[2:]} == {"rl", "dos"}            # mint-exhausting last
