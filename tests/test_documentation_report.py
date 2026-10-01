"""The Documentation agent's report must let an engineer who was not there reproduce, validate,
and fix the finding from the report alone: a copy-pasteable curl against the full target URL,
a deterministic pass condition, clinical impact, component-specific remediation, a correct
OWASP label, and honest fix-validation status. Synthetic fake target; no network.
"""

from __future__ import annotations

import json
from pathlib import Path

from redteam.agents.documentation.agent import DocumentationAgent
from redteam.agents.judge.judge import Judge
from redteam.authz_probe import rate_limit_probe, run_mint_auth_probe, run_probe
from redteam.executor.authorization import AuthorizationRegistry
from redteam.executor.executor import Executor
from redteam.executor.http_sender import ResponseRecord
from redteam.owasp import owasp_label
from redteam.regression import replay
from redteam.store.store import Store

BASE = "https://good.example/app"
MINT_OK = json.dumps({"demo_token": "eyJzY29wZSI6InJlYWQtYnJpZWZpbmcifQ.sig", "patient_uuid": "fixture-patient-001",
                      "expires_in_seconds": 300, "synthetic_only": True})


def _registry(tmp_path: Path) -> AuthorizationRegistry:
    p = tmp_path / "auth.yaml"
    p.write_text("targets:\n  - id: good\n    origin: https://good.example\n    base_path: /app\n"
                 "    proof: test fixture\n    enabled: true\n", encoding="utf-8")
    return AuthorizationRegistry.load(p)


def _render(store, reg, finding_id: str) -> str:
    doc = DocumentationAgent()
    finding = dict(store.conn.execute("SELECT * FROM findings WHERE finding_id = ?", (finding_id,)).fetchone())
    ctx = doc.context(store, finding, reg)
    level = json.loads(finding["severity"])["provisional_level"]
    return doc.render_markdown(finding, level, ctx["evidence"], target=ctx["target"],
                               report=ctx["report"], replays=ctx["replays"])


def _mint_finding(tmp_path: Path, endpoint: str = "/v1/demo-context"):
    reg = _registry(tmp_path)
    store = Store.open(tmp_path / "s.db")
    ex = Executor(reg, lambda u, **k: ResponseRecord(200, MINT_OK, 3.0))
    run_mint_auth_probe(reg, ex, Judge(), store, reg.by_id("good"), "fixture-patient-001",
                        endpoint=endpoint, target_sha="build-a")
    fid = store.conn.execute("SELECT finding_id FROM findings").fetchone()["finding_id"]
    return reg, store, fid


def test_mint_report_has_curl_repro_validate_line_and_platform_replay(tmp_path: Path) -> None:
    reg, store, fid = _mint_finding(tmp_path)
    DocumentationAgent().document(store, fid, registry=reg)
    md = _render(store, reg, fid)
    assert f'curl -s "{BASE}/v1/demo-context?patient_uuid=fixture-patient-001"' in md
    assert "_auth" not in md.split("## Reproduction")[1].split("## Observed")[0]   # annotations not sent
    assert "fixed when the request above returns `401`/`403`" in md and "no `demo_token`" in md
    assert "uv run redteam regression --target good --sha <git_sha from /health>" in md
    assert f'curl -s "{BASE}/health"' in md
    store.close()


def test_read_mint_has_clinical_impact_and_mint_specific_remediation(tmp_path: Path) -> None:
    reg, store, fid = _mint_finding(tmp_path)
    DocumentationAgent().document(store, fid, registry=reg)
    md = _render(store, reg, fid)
    assert "**Clinical impact:**" in md and "HIPAA-reportable" in md
    assert "synthetic fixture patients only" in md
    remediation = md.split("## Recommended remediation")[1].split("## Status")[0]
    assert "AGENTFORGE_SYNTHETIC_CONTEXT" in remediation and "429" in remediation and "TTL" in remediation
    assert "every patient route" not in remediation     # the generic, wrong-for-mint default
    row = store.conn.execute("SELECT clinical_impact, remediation FROM vuln_reports").fetchone()
    assert "HIPAA" in row["clinical_impact"] and "AGENTFORGE_SYNTHETIC_CONTEXT" in row["remediation"]
    store.close()


def test_write_mint_is_an_integrity_finding(tmp_path: Path) -> None:
    reg, store, fid = _mint_finding(tmp_path, endpoint="/v1/source-document-context")
    md = _render(store, reg, fid)
    assert "integrity" in md and "upload" in md
    assert "AGENTFORGE_SYNTHETIC_CONTEXT" in md
    store.close()


def test_taxonomy_labels_name_the_right_owasp_list() -> None:
    assert owasp_label("API2:2023") == "OWASP API Security Top 10 2023: API2 Broken Authentication"
    assert owasp_label("LLM01") == "OWASP LLM Top 10 2025: LLM01 Prompt Injection"
    assert owasp_label("LLM10").endswith("LLM10 Unbounded Consumption")


def test_mint_report_taxonomy_is_not_mislabelled(tmp_path: Path) -> None:
    reg, store, fid = _mint_finding(tmp_path)
    md = _render(store, reg, fid)
    assert "OWASP API Security Top 10 2023: API2 Broken Authentication" in md
    assert "OWASP-LLM:API2" not in md
    tax = json.loads(store.conn.execute("SELECT taxonomy FROM findings").fetchone()["taxonomy"])
    assert tax[0]["scheme"] == "OWASP-API" and tax[0]["version"] == "2023"
    store.close()


def test_rate_limit_report_loops_over_the_observed_count(tmp_path: Path) -> None:
    reg = _registry(tmp_path)
    store = Store.open(tmp_path / "s.db")
    ex = Executor(reg, lambda u, **k: ResponseRecord(200, MINT_OK, 3.0))
    run_probe(rate_limit_probe(ex, Judge(), reg.by_id("good"), "fixture-patient-001", n=7), store, reg, target_sha="build-a")
    fid = store.conn.execute("SELECT finding_id FROM findings").fetchone()["finding_id"]
    md = _render(store, reg, fid)
    assert "for i in $(seq 1 7); do curl -s -o /dev/null -w" in md
    assert f'"{BASE}/v1/demo-context?patient_uuid=fixture-patient-001"' in md
    assert "fixed when at least one `429` appears within 7 requests" in md
    assert "OWASP API Security Top 10 2023: API4" in md and "OWASP LLM Top 10 2025: LLM10" in md
    store.close()


def test_status_is_honest_before_and_after_a_fix_replay(tmp_path: Path) -> None:
    reg, store, fid = _mint_finding(tmp_path)
    doc = DocumentationAgent()
    report_id = doc.document(store, fid, registry=reg)
    md = _render(store, reg, fid)
    assert f"**Report {report_id}:** `pending_approval`" in md
    assert "No harness replay" in md and "held" not in md.split("**Fix validation:**")[1]

    # a candidate build rejects the anonymous mint -> the regression replay holds
    fixed = Executor(reg, lambda u, **k: ResponseRecord(403, '{"error":"forbidden"}', 2.0))
    replay(store, reg, fixed, Judge(), "build-b")
    md = _render(store, reg, fid)
    fixval = md.split("**Fix validation:**")[1]
    assert "`build-b` — held" in fixval and "No harness replay" not in fixval

    # re-documenting refreshes derived fields but never duplicates or resets approval
    doc.approve(store, report_id, approver="david")
    assert doc.document(store, fid, registry=reg) == report_id
    assert store.count("vuln_reports") == 1
    row = store.conn.execute("SELECT status, approval, fix_validation FROM vuln_reports").fetchone()
    assert row["status"] == "published" and json.loads(row["approval"])["approver"] == "david"
    assert json.loads(row["fix_validation"])["result"] == "held"
    # a later build issues tokens again -> the replay reappears; the report must say so,
    # not hide the build as a baseline sighting and fall back to "Not yet validated"
    reopened = Executor(reg, lambda u, **k: ResponseRecord(200, MINT_OK, 2.0))
    replay(store, reg, reopened, Judge(), "build-c")
    fixval = _render(store, reg, fid).split("**Fix validation:**")[1]
    assert "`build-c` — reappeared" in fixval and "No harness replay" not in fixval
    assert "Not validated as fixed (latest build `build-c`: reappeared)." in fixval

    # a fresh probe re-finds it on build-c after the replay: build-c stays a fix build
    run_mint_auth_probe(reg, reopened, Judge(), store, reg.by_id("good"), "fixture-patient-001", target_sha="build-c")
    fixval = _render(store, reg, fid).split("**Fix validation:**")[1]
    assert "`build-c` — reappeared" in fixval and "No harness replay" not in fixval
    store.close()


# ---- fix status = the latest observation on each build, whatever produced it ---------------

def VULN(url, **kw) -> ResponseRecord:     # the anonymous mint still issues a token
    return ResponseRecord(200, MINT_OK, 2.0)


def FIXED(url, **kw) -> ResponseRecord:    # the mint requires auth
    return ResponseRecord(403, '{"error":"forbidden"}', 2.0)


def _fix_status(store, reg, fid) -> tuple[dict, str]:
    DocumentationAgent().document(store, fid, registry=reg)
    row = store.conn.execute("SELECT fix_validation FROM vuln_reports WHERE finding_id = ?", (fid,)).fetchone()
    return json.loads(row["fix_validation"]), _render(store, reg, fid).split("**Fix validation:**")[1]


def test_a_fresh_hit_after_a_held_replay_means_the_build_is_not_fixed(tmp_path: Path) -> None:
    reg, store, fid = _mint_finding(tmp_path)
    replay(store, reg, Executor(reg, FIXED), Judge(), "build-b")
    run_mint_auth_probe(reg, Executor(reg, VULN), Judge(), store, reg.by_id("good"), "fixture-patient-001",
                        target_sha="build-b")
    fixval, md = _fix_status(store, reg, fid)
    assert fixval["sha"] == "build-b" and fixval["result"] == "reappeared"
    assert "`build-b` — reappeared" in md and "`build-b` — held" not in md
    store.close()


def test_a_reappearing_replay_counts_even_after_a_fresh_hit_on_that_build(tmp_path: Path) -> None:
    # The order the hunt and the replay happened to run in must not decide the status.
    reg, store, fid = _mint_finding(tmp_path)
    run_mint_auth_probe(reg, Executor(reg, VULN), Judge(), store, reg.by_id("good"), "fixture-patient-001",
                        target_sha="build-b")
    replay(store, reg, Executor(reg, VULN), Judge(), "build-b")
    fixval, md = _fix_status(store, reg, fid)
    assert fixval["sha"] == "build-b" and fixval["result"] == "reappeared"
    assert "No harness replay" not in md
    store.close()


def test_an_inconclusive_replay_is_never_held(tmp_path: Path) -> None:
    reg, store, fid = _mint_finding(tmp_path)
    replay(store, reg, Executor(reg, lambda u, **k: ResponseRecord(429, "{}", 2.0)), Judge(), "build-b")
    fixval, md = _fix_status(store, reg, fid)
    assert fixval == {"sha": "build-b", "result": "inconclusive", "at": fixval["at"]}
    assert "Not validated as fixed (latest build `build-b`: inconclusive)." in md
    store.close()


def test_the_latest_build_decides_the_headline(tmp_path: Path) -> None:
    reg, store, fid = _mint_finding(tmp_path)
    replay(store, reg, Executor(reg, VULN), Judge(), "build-b")
    replay(store, reg, Executor(reg, FIXED), Judge(), "build-c")
    fixval, md = _fix_status(store, reg, fid)
    assert fixval["sha"] == "build-c" and fixval["result"] == "held"
    assert "`build-b` — reappeared" in md and "`build-c` — held" in md and "Not validated" not in md
    store.close()


def test_a_build_the_exploit_succeeded_on_is_never_fixed(tmp_path: Path) -> None:
    # A build is immutable: once the exploit worked on that SHA, a later clean replay on the same
    # SHA is flakiness (a throttle, a blip), not a fix.
    reg, store, fid = _mint_finding(tmp_path)
    run_mint_auth_probe(reg, Executor(reg, VULN), Judge(), store, reg.by_id("good"), "fixture-patient-001",
                        target_sha="build-b")
    replay(store, reg, Executor(reg, FIXED), Judge(), "build-b")
    fixval, md = _fix_status(store, reg, fid)
    assert fixval["sha"] == "build-b" and fixval["result"] == "reappeared"
    assert "`build-b` — held" not in md
    store.close()


def test_hunts_before_any_validation_are_not_fix_attempts(tmp_path: Path) -> None:
    # Re-finding the weakness on more builds before anyone tried a fix is not a fix validation.
    reg, store, fid = _mint_finding(tmp_path)
    run_mint_auth_probe(reg, Executor(reg, VULN), Judge(), store, reg.by_id("good"), "fixture-patient-001",
                        target_sha="build-b")
    fixval, md = _fix_status(store, reg, fid)
    assert fixval == {"sha": None, "result": None} and "No harness replay" in md
    # but a build first seen AFTER validation began is a regression the report must show
    replay(store, reg, Executor(reg, FIXED), Judge(), "build-c")
    run_mint_auth_probe(reg, Executor(reg, VULN), Judge(), store, reg.by_id("good"), "fixture-patient-001",
                        target_sha="build-d")
    fixval, md = _fix_status(store, reg, fid)
    assert "`build-c` — held" in md and "`build-b`" not in md   # pre-validation hunt, not a fix attempt
    assert fixval["sha"] == "build-d" and fixval["result"] == "reappeared"
    store.close()


def test_a_later_inconclusive_replay_is_not_held_and_the_origin_build_is_not_a_fix(tmp_path: Path) -> None:
    reg, store, fid = _mint_finding(tmp_path)
    replay(store, reg, Executor(reg, FIXED), Judge(), "build-a")           # origin build: a sighting
    replay(store, reg, Executor(reg, FIXED), Judge(), "build-b")
    replay(store, reg, Executor(reg, lambda u, **k: ResponseRecord(429, "{}", 2.0)), Judge(), "build-b")
    fixval, md = _fix_status(store, reg, fid)
    assert "`build-a`" not in md
    assert fixval["sha"] == "build-b" and fixval["result"] == "inconclusive"
    store.close()


# ---- atomic persistence: a report and its audit action are one unit (issue #1) -------------

import sqlite3  # noqa: E402

import pytest  # noqa: E402


class _FaultyStore(Store):
    """A real store that raises on its Nth write, the way a lock timeout or a crash would."""

    fail_on: int | None = None
    writes = 0

    def _tick(self) -> None:
        self.writes += 1
        if self.writes == self.fail_on:
            raise sqlite3.OperationalError(f"injected fault at write {self.writes}")

    def insert(self, table, row):
        self._tick()
        return super().insert(table, row)

    def execute(self, sql, params=()):
        self._tick()
        return super().execute(sql, params)


def test_a_fault_while_documenting_leaves_no_report_and_no_action(tmp_path: Path) -> None:
    reg, store, fid = _mint_finding(tmp_path)
    db = tmp_path / "s.db"                          # the store _mint_finding opened
    actions_before = store.count("agent_actions")
    store.close()

    total = 2   # the vuln_reports row and its "report" agent action
    for n in range(1, total + 1):
        faulty = _FaultyStore.open(db)
        faulty.fail_on = n
        with pytest.raises(sqlite3.OperationalError, match="injected fault"):
            DocumentationAgent().document(faulty, fid, registry=reg)
        assert faulty.writes == n
        faulty.close()
        after = Store.open(db)
        assert after.count("vuln_reports") == 0, f"fault at write {n}/{total} left a report"
        assert after.count("agent_actions") == actions_before, f"fault at write {n}/{total} left an action"
        after.close()

    store = _FaultyStore.open(db)
    DocumentationAgent().document(store, fid, registry=reg)          # no fault: both rows land
    assert store.writes == total and store.count("vuln_reports") == 1
    store.close()