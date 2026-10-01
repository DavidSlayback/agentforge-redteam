# ATO-style evidence packet (E15)

An authorization-to-operate style packet: the evidence a security reviewer needs to decide whether
the AgentForge Red Team platform may run unattended against the authorized target. It assembles
existing artifacts; each row links to the authoritative source rather than restating it.

## 1. Architecture + data-flow

- **Architecture:** `ARCHITECTURE.md` — four agents + three deterministic services over one SQLite
  store; mermaid interaction diagram; the eight Stage-4 design answers; AI-use disclosure.
- **Data flow (trust-ordered):** `agent_actions`/campaign → Red Team emits attack *specs as data*
  (no network, no creds) → **Executor is the only component with network access**; it checks the
  authorization registry on every request → live target (synthetic patients) → attempt + full
  request/response evidence → Judge (deterministic oracles, then independent rubric) → finding
  (deduped) → Documentation report behind the human approval gate. Entity/lineage detail:
  `docs/DATA_MODEL.md`.

## 2. Authorization & access model

- **Target authorization:** `authorization.yaml` lists only owner-operated/permitted origins with
  recorded proof; `Executor.assert_authorized` runs before every send; redirects pinned off
  (`follow_redirects=False`). Tested: `tests/test_authorization.py`. (SA1)
- **Session/credential model & RBAC:** `docs/DATA_MODEL.md` §E11 — who writes/reads exploits,
  approval-before-publish, CLI-only run triggers, read-only dashboard. (SA3)
- **External APIs:** `docs/EXTERNAL_APIS.md` — auth + rate-limit + failure handling per dependency.

## 3. Dependency inventory

- Declared in `pyproject.toml`, locked in `uv.lock` (reproducible via `uv sync --frozen`), Python
  `>=3.13,<3.15`. Runtime: pydantic 2.13.5 (`>=2.13.5`), httpx 0.28.1 (`>=0.28`), pyyaml 6.0.3
  (`>=6.0`). Dev group: jsonschema 4.26.0, datamodel-code-generator 0.83.0 (pinned `==`), pytest 9.1.1.
  Optional `jev` group: typesafe-sdk 0.7.2. The target's own route schemas are vendored as a snapshot
  in `vendor/agentforge-schemas/` (`vendor/PROVENANCE.md`), not target code. **PyRIT, garak and spikee
  are not dependencies** (they are named in earlier planning documents).

## 4. Platform self-scan / self-checks

- **Contract drift gate:** `.gitlab-ci.yml` regenerates the *target's* route contracts
  (`tools/generate_contracts.py`) and fails on drift, then runs the full suite, which includes the
  inter-agent schema tests. **The pipeline has no runner, so no pipeline has executed;** the same
  commands are run locally.
- **Regression full-scan SLO:** `tests/test_slo.py` asserts hot queries are index-backed and a stub
  replay stays under 5 s (E12). Run locally; not verified in CI for the same reason. Measured
  overhead is in `docs/PERF.md`.
- **Platform vulnerability scan: `not done`.** No dependency or code scan (for example `pip-audit`
  or a SAST run) has been run on the platform itself; the self-checks here are the test suite and
  the review rounds in `docs/PLAN.md`. An ATO reviewer should treat this item as open.
- **Harness integrity:** the platform's own review loop (docs/PLAN.md 2026-09-30 review rounds)
  confirmed no false-finding / fake-pass path; the discovery tier emits candidates, never findings.
- **Fail-closed posture:** missing evidence → INCONCLUSIVE (never a pass); provider blocks and
  degraded retrieval are typed non-passes.

## 5. Test evidence

- `uv run pytest -q` = **415 passed, 1 skipped** on the 2026-10-01 base commit (Python 3.14.7; the
  integration record also reports 3.13), covering unit, contract, eval-suite, oracle, regression, SLO,
  data-quality, redaction, atomic-persistence fault injection and frozen-case checks. The skip is the
  opt-in real-store check. Offline (no target, no keys). Live runs are recorded in the store with the
  target SHA (172 attempts, 7 findings); observability via `redteam report` / `dashboard.html`. Judge
  calibration: `redteam calibrate` agrees on 10 of 10 deterministic entries (`NOT VALIDATED` until a
  human reviews the labels).

## 6. Sample incident / postmortem

**Incident (2026-09-30): discovery-tier reviews all errored on first run.**
- *Impact:* the first `redteam discover` pass returned 0 candidates / 29 errors — no security impact
  (discovery is advisory, emits candidates only), but the pass produced no leads.
- *Root cause:* the reviewer model (`deepseek-v4-pro`) is a reasoning model; its hidden
  `reasoning_content` consumed the 400-token budget, leaving an empty `content` → JSON parse error.
- *Fix:* raised `max_tokens` to 2000 and added an empty-content guard that returns a typed error
  (never a fabricated candidate). Re-run surfaced the internal-metadata-disclosure lead (F-ca9486ff1b).
- *Prevention:* the empty-content guard makes the failure explicit; the discovery pass is wrapped so
  a reviewer failure can never abort the poll's trust-critical regression reporting.
- *Standing availability note (operator-relevant):* the deploy runbook (`agentforge-week1
  deploy/vultr/deploy.sh`) records a 2026-09-26 ~10-min dashboard 502 when an SSH session dropped
  mid-`up --build`; mitigated by building all images before replacing any container and polling the
  SHA health loop detached.
