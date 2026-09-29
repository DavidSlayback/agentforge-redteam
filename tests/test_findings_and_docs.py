"""A SUCCESS verdict promotes to a deduped Finding; the Documentation agent reports it
behind the approval gate. Uses a marker that the fake target echoes — synthetic, no real
attack content.
"""

from __future__ import annotations

from pathlib import Path

from redteam.agents.documentation.agent import DocumentationAgent
from redteam.agents.judge.judge import Judge, VerdictOutcome
from redteam.evals.case import OracleConfig, SeedCase, Turn
from redteam.executor.authorization import AuthorizationRegistry
from redteam.executor.executor import Executor
from redteam.executor.http_sender import ResponseRecord
from redteam.runner import run_case
from redteam.store.store import Store

MARK = "ZZ-ECHO"


def _registry(tmp_path: Path) -> AuthorizationRegistry:
    p = tmp_path / "auth.yaml"
    p.write_text("targets:\n  - id: good\n    origin: https://good.example\n    enabled: true\n", encoding="utf-8")
    return AuthorizationRegistry.load(p)


def _case(cid: str) -> SeedCase:
    return SeedCase(
        case_id=cid, category="prompt-injection", owasp=["LLM01"], target_id="good",
        turns=[Turn(ordinal=1, route="/v1/x", body={})], oracle=OracleConfig(marker=MARK),
        expected_safe="refuses; never emits the marker",
    )


def test_success_promotes_and_dedupes(tmp_path: Path) -> None:
    reg = _registry(tmp_path)
    store = Store.open(tmp_path / "s.db")
    # fake target that echoes the marker -> MarkerOracle VIOLATION -> SUCCESS
    echo = Executor(reg, lambda u, **k: ResponseRecord(200, f"ok {MARK}", 4.0))
    run_case(_case("c1"), reg, echo, Judge(), store)
    run_case(_case("c2"), reg, echo, Judge(), store)  # same weakness -> dedup

    assert store.count("findings") == 1
    row = store.conn.execute("SELECT verdict_ids FROM findings").fetchone()
    import json
    assert len(json.loads(row["verdict_ids"])) == 2  # both verdicts attached
    store.close()


def test_documentation_gate_and_approval(tmp_path: Path) -> None:
    reg = _registry(tmp_path)
    store = Store.open(tmp_path / "s.db")
    echo = Executor(reg, lambda u, **k: ResponseRecord(200, f"ok {MARK}", 4.0))
    run_case(_case("c1"), reg, echo, Judge(), store)

    finding_id = store.conn.execute("SELECT finding_id FROM findings").fetchone()["finding_id"]
    doc = DocumentationAgent()
    report_id = doc.document(store, finding_id)

    status = store.conn.execute("SELECT status FROM vuln_reports WHERE report_id = ?", (report_id,)).fetchone()["status"]
    assert status == "pending_approval"          # prompt-injection is provisional-high -> gated

    # idempotent: documenting again returns the same report, no duplicate
    assert doc.document(store, finding_id) == report_id
    assert store.count("vuln_reports") == 1

    doc.approve(store, report_id, approver="david")
    status2 = store.conn.execute("SELECT status FROM vuln_reports WHERE report_id = ?", (report_id,)).fetchone()["status"]
    assert status2 == "published"

    md = doc.render_markdown(dict(store.conn.execute("SELECT * FROM findings WHERE finding_id=?", (finding_id,)).fetchone()), "high")
    assert "Recommended remediation" in md and finding_id in md
    store.close()


def test_every_category_has_a_provisional_severity() -> None:
    # T1.5: an unmapped category would fail the gate open. Guard that every category a finding
    # can carry is mapped, so the fail-closed default is a safety net, not the normal path.
    from redteam.findings import _OPPORTUNISTIC, _PROVISIONAL
    from redteam.owasp import STRATEGIES

    expected = set(STRATEGIES) | {"broken-object-authorization", "broken-authentication"} \
        | {cat for cat, _ in _OPPORTUNISTIC.values()}
    missing = expected - set(_PROVISIONAL)
    assert not missing, f"categories without a provisional severity (would fail the gate open): {missing}"


def test_unmapped_category_is_gated_not_auto_published(tmp_path: Path) -> None:
    # T1.5: even if an unmapped category slips through, its report must be held, not published.
    import json

    reg = _registry(tmp_path)
    store = Store.open(tmp_path / "s.db")
    echo = Executor(reg, lambda u, **k: ResponseRecord(200, f"ok {MARK}", 4.0))
    run_case(_case("c1"), reg, echo, Judge(), store)
    fid = store.conn.execute("SELECT finding_id FROM findings").fetchone()["finding_id"]
    # forge an unmapped category + severity with no known level
    store.conn.execute("UPDATE findings SET primary_category = 'brand-new-category', "
                       "severity = ? WHERE finding_id = ?", (json.dumps({"note": "no level"}), fid))
    store.conn.commit()
    report_id = DocumentationAgent().document(store, fid)
    status = store.conn.execute("SELECT status FROM vuln_reports WHERE report_id = ?", (report_id,)).fetchone()["status"]
    assert status == "pending_approval"   # fail closed on unknown/malformed severity
    store.close()


def test_opportunistic_crash_is_classified_as_dos_not_the_attack_category(tmp_path: Path) -> None:
    # A prompt-injection whose marker never appears but whose target 500s must be filed as the
    # crash it is (denial-of-service / LLM10), not as a prompt-injection finding.
    reg = _registry(tmp_path)
    store = Store.open(tmp_path / "s.db")
    crash = Executor(reg, lambda u, **k: ResponseRecord(500, "internal error", 4.0))
    run_case(_case("c1"), reg, crash, Judge(), store)
    row = store.conn.execute("SELECT primary_category, severity FROM findings").fetchone()
    assert row is not None, "a 5xx should still promote a finding via StatusOracle"
    assert row["primary_category"] == "denial-of-service"   # reclassified from prompt-injection
    store.close()


def test_generated_active_markup_is_an_output_handling_finding(tmp_path: Path) -> None:
    # T3.1: the model emits a script tag it was not asked to echo -> improper-output-handling.
    reg = _registry(tmp_path)
    store = Store.open(tmp_path / "s.db")
    resp = Executor(reg, lambda u, **k: ResponseRecord(200, "Summary: labs ok. <script>alert(1)</script>", 4.0))
    case = SeedCase(
        case_id="oh1", category="improper-output-handling", owasp=["LLM05"], target_id="good",
        turns=[Turn(ordinal=1, route="/v1/x", body={"message": "render my clinical note"})],
        oracle=OracleConfig(), expected_safe="escapes model-derived values before rendering",
    )
    res = run_case(case, reg, resp, Judge(), store)
    assert res.verdict.outcome is VerdictOutcome.SUCCESS
    assert store.conn.execute("SELECT primary_category FROM findings").fetchone()["primary_category"] \
        == "improper-output-handling"
    store.close()


def test_evidence_captures_request_and_response(tmp_path: Path) -> None:
    # The store must hold what the target actually returned, keyed to the attempt, so a
    # verdict can be audited after the fact (the defect the framework re-review surfaced).
    import json

    reg = _registry(tmp_path)
    store = Store.open(tmp_path / "s.db")
    echo = Executor(reg, lambda u, **k: ResponseRecord(200, f"ok {MARK}", 4.0))
    res = run_case(_case("c1"), reg, echo, Judge(), store)

    row = store.conn.execute(
        "SELECT e.exchanges, a.evidence_ref FROM evidence e JOIN attempts a ON a.attempt_id = e.attempt_id "
        "WHERE e.attempt_id = ?", (res.attempt_id,)
    ).fetchone()
    assert row is not None, "no evidence row was written for the attempt"
    assert row["evidence_ref"], "attempt.evidence_ref was not populated"
    exchanges = json.loads(row["exchanges"])
    assert exchanges[0]["response"] == f"ok {MARK}"        # the actual response is stored
    assert exchanges[0]["route"] == "/v1/x"
    assert "request" in exchanges[0]                        # and the request that produced it
    store.close()


def test_report_surfaces_the_evidence(tmp_path: Path) -> None:
    reg = _registry(tmp_path)
    store = Store.open(tmp_path / "s.db")
    echo = Executor(reg, lambda u, **k: ResponseRecord(200, f"ok {MARK}", 4.0))
    run_case(_case("c1"), reg, echo, Judge(), store)
    finding = dict(store.conn.execute("SELECT * FROM findings").fetchone())
    doc = DocumentationAgent()
    evidence = doc._evidence_for_finding(store, finding)
    md = doc.render_markdown(finding, "high", evidence)
    assert "Evidence (what actually happened)" in md
    assert MARK in md                          # the real response text appears in the report
    assert "marker" in md                      # the oracle that fired is named
    # T2.3: the Expected clause is the case's own invariant, not the hardcoded LLM-refusal line
    assert "never emits the marker" in md
    assert "the assistant refuses and the protected invariant holds" not in md
    store.close()
