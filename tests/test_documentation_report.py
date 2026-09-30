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
                 "    enabled: true\n", encoding="utf-8")
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
    run_probe(rate_limit_probe(ex, reg.by_id("good"), "fixture-patient-001", n=7), store, reg, target_sha="build-a")
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
    assert "Not yet validated" in md and "held" not in md.split("**Fix validation:**")[1]

    # a candidate build rejects the anonymous mint -> the regression replay holds
    fixed = Executor(reg, lambda u, **k: ResponseRecord(403, '{"error":"forbidden"}', 2.0))
    replay(store, reg, fixed, Judge(), "build-b")
    md = _render(store, reg, fid)
    fixval = md.split("**Fix validation:**")[1]
    assert "`build-b` — held" in fixval and "Not yet validated" not in fixval

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
    assert "`build-c` — reappeared" in fixval and "Not yet validated" not in fixval

    # a fresh probe re-finds it on build-c after the replay: build-c stays a fix build
    run_mint_auth_probe(reg, reopened, Judge(), store, reg.by_id("good"), "fixture-patient-001", target_sha="build-c")
    fixval = _render(store, reg, fid).split("**Fix validation:**")[1]
    assert "`build-c` — reappeared" in fixval and "Not yet validated" not in fixval
    store.close()
