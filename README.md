# AgentForge Red Team

A multi-agent adversarial evaluation platform that continuously red-teams the AgentForge
Clinical Co-Pilot (an OpenEMR AI layer), converts confirmed exploits into a regression
harness, documents findings as reproducible vulnerability reports, and tracks whether the
target is getting more or less resilient build over build. Week 3 of the AgentForge track.

- **Deployed target (live):** <https://dtstest.64.177.10.182.nip.io/agentforge-w2/> —
  `GET /health` returns the running `git_sha`, which every run records.
- **Current status:** 7 findings (5 fixed and validated by regression replay, 2 permanently
  risk-accepted anonymous mints); see [docs/findings/README.md](docs/findings/README.md). The plan
  and per-item status are in [docs/PLAN.md](docs/PLAN.md); the wired / tested / live status table is
  at the end of [ARCHITECTURE.md](ARCHITECTURE.md).

## Architecture in one paragraph

A deterministic control plane calls four agents in-process — **Orchestrator** (deterministic
ranker + optional Jev selector, hard budget/no-signal halt), **Red Team** (Qwen; generates
and mutates attacks as data only), **Judge** (deterministic oracles first, then a
non-Qwen rubric tier, DeepSeek in use, for criteria no oracle covers), and **Documentation**
(a deterministic, template-driven report writer behind a fail-closed human approval gate) — plus
deterministic services: the **Executor** (the only component with network access to the target;
checks the authorization registry on every request), the **Regression runner** (replay of frozen
findings through their original probes), and **Recon** (`redteam poll`, SHA change triggers a
regression run). One SQLite store is the audit trail, the regression suite, and the
observability substrate; it is not a work queue. Details, diagram, and tradeoffs:
[ARCHITECTURE.md](ARCHITECTURE.md); decisions: [docs/adr/](docs/adr/).

## Deliverables

| Deliverable | Where |
|---|---|
| Threat model | [THREAT_MODEL.md](THREAT_MODEL.md) |
| Users | [USERS.md](USERS.md) |
| Architecture | [ARCHITECTURE.md](ARCHITECTURE.md) (+ [docs/architecture.html](docs/architecture.html)) |
| Key metrics | [KEY_METRICS.md](KEY_METRICS.md) |
| Eval dataset + results | [evals/](evals/) |
| Vulnerability reports | [docs/findings/](docs/findings/) |
| AI cost analysis (token-based estimate; billed USD is `OWNER TO SUPPLY`) | [docs/COST_ANALYSIS.md](docs/COST_ANALYSIS.md) |
| AI-use disclosure (agent roles + development-time AI use) | [ARCHITECTURE.md](ARCHITECTURE.md#ai-use-disclosure) |
| Inter-agent contracts (v1 JSON Schema) | [contracts/](contracts/) |
| Integration packet (solo adaptation; no peer integration) | [docs/INTEGRATION_PACKET.md](docs/INTEGRATION_PACKET.md) |
| Observability snapshot | [dashboard.html](dashboard.html) (regenerate with `redteam dashboard`) |
| Data model, data quality, access controls (E9–E11) | [docs/DATA_MODEL.md](docs/DATA_MODEL.md) |
| External APIs: auth / rate limits / handling (E7) | [docs/EXTERNAL_APIS.md](docs/EXTERNAL_APIS.md) |
| Build-vs-configure decision record (E3) | [docs/adr/0005-build-vs-configure.md](docs/adr/0005-build-vs-configure.md) |
| Performance baseline + load profile (E13/E14) | [docs/PERF.md](docs/PERF.md) |
| Triage exercise (E4) | [docs/TRIAGE_EXERCISE.md](docs/TRIAGE_EXERCISE.md) |
| ATO-style evidence packet (E15) | [docs/ATO_PACKET.md](docs/ATO_PACKET.md) |
| Discovery-tier triage record | [docs/DISCOVERY_TRIAGE.md](docs/DISCOVERY_TRIAGE.md) |

## Setup

Requires Python 3.13–3.14 and [uv](https://docs.astral.sh/uv/).

```bash
uv sync --dev
uv run pytest -q
```

The test suite runs offline (no target, no model keys) and includes the contract tests. On the
2026-10-12 cleanup branch it reads `509 passed, 1 skipped` (the skip is an opt-in
real-store check); the GitLab pipeline in `.gitlab-ci.yml` has no runner, so run it locally.

### Configuration

Model keys live in a `.env` file at the repo root (gitignored; real environment variables
win over it). Commands that run with no model key: `authz`, `report`, `dashboard`, `document`,
`evidence`, `approve`, `integrity`, `poll` (without `--discover`), `benign`, `disclosure`,
`grounding`, `calibrate` (deterministic entries only), and `regression`. `regression` replays
frozen cases with no attacker model and no attacker key (`_wire_replay`); a frozen case that only the
rubric can decide, with no rubric configured, comes back INCONCLUSIVE and fails the gate rather than
crashing.

| Variable | Needed by | Purpose |
|---|---|---|
| `AGENTFORGE_REDTEAM_BASE_URL` | `campaign` | OpenAI-compatible endpoint for the Red Team model |
| `AGENTFORGE_REDTEAM_API_KEY` | `campaign` | Key for that endpoint |
| `AGENTFORGE_REDTEAM_MODEL` | `campaign` | Attacker model (in use: `qwen3.8-flash`; override per `campaign` run with `--model`). `AGENTFORGE_REDTEAM_TIMEOUT` (seconds, default 90) raises the attacker-call timeout |
| `AGENTFORGE_REDTEAM_RUBRIC_MODEL` | `campaign`, `regression` (optional) | Enables the rubric Judge tier; must be a non-Qwen family (in use: `deepseek-v4-pro`) |
| `AGENTFORGE_REDTEAM_RUBRIC_BASE_URL`, `AGENTFORGE_REDTEAM_RUBRIC_KEY` | optional | Separate rubric endpoint/key; fall back to the Red Team endpoint/key |
| `AGENTFORGE_REDTEAM_JEV_KEY` | `campaign --selector jev` (optional) | Jev orchestrator selector; deterministic selector otherwise |
| `AGENTFORGE_REDTEAM_DISCOVERY_MODEL` | `discover` / `poll --discover` (optional) | Model for the open-ended discovery reviewer. Defaults to the rubric model (non-Qwen); an explicit value is honored even if same-family, since discovery emits candidates (leads), not verdicts. **Recommended: `qwen3.8-max`** — it out-performed DeepSeek as the reviewer in the 2026-09-30 comparison (higher signal, fewer false positives) |

### Authorization (read before running anything)

The platform attacks **only** targets listed and `enabled` in
[authorization.yaml](authorization.yaml), each with recorded proof of ownership or written
permission. The Executor refuses any other origin (`authorization_denied`). The one enabled
target is `agentforge-w2`, the owner-operated Co-Pilot above, which serves synthetic
patients only. This is not a scanner for third-party systems — see [AGENTS.md](AGENTS.md).

## Running against the live target

On Windows Git Bash, prefix commands that pass a `--route` with `MSYS_NO_PATHCONV=1`, or
the leading `/` is rewritten to a Windows path. PowerShell is unaffected.

**1. Record the build under test.**

```bash
curl -s https://dtstest.64.177.10.182.nip.io/agentforge-w2/health
```

Pass the returned `git_sha` as `--target-sha` below so results trend by version. (`redteam poll`
does this observation for you and runs the regression suite when the SHA changes.)

**2. Deterministic authorization battery (no model key).** BOLA, missing/forged token,
anonymous read/write mint, and mint rate-limit probes:

```bash
uv run redteam authz --target agentforge-w2 --patient fixture-patient-001 --victim-patient fixture-patient-002 --target-sha <git_sha>
```

**3. Multi-agent campaign (needs model keys).** Orchestrator picks a category, Red Team
generates and mutates, Executor sends, Judge verdicts, findings are promoted:

```bash
uv run redteam campaign --target agentforge-w2 --category prompt-injection --route /v1/follow-up-evidence --patient fixture-patient-001 --max-campaigns 3 --target-sha <git_sha>
```

Other seeded categories and their exact commands are in [evals/README.md](evals/README.md).
`--max-model-calls` (default 200) is the cost circuit-breaker; `--max-mutations N` (default 1, `0`
disables) bounds the attacker-model mutations tried after a defended attempt, each a metered call.

**4. Inspect results.**

```bash
uv run redteam report
```

`redteam dashboard --out dashboard.html` writes the same view as a self-contained page:
coverage per category, pass/fail by category and build, resilience trend, open/resolved
findings, per-run cost and a cost trend (in model calls; `usd` is `None` when a call is unpriced, so
read it as unpriced, not free), pass/fail over time by category and build, and a per-agent trace that
is newest-first over the most recent N actions (`agent_trace_chronological` returns the same window
in order). `redteam evidence <attempt_id>` dumps
the exact request/response behind any verdict. `redteam integrity` opens the store read-only
and lists any attempt without a verdict or finding without a frozen regression case (exit 1 if
it finds one; exit 2 if a crashed write left a journal that a normal open must recover first).

**5. Reports and approval.** `redteam document <finding_id>` renders an evidence-backed
report. Critical/high reports are held until an operator runs
`redteam approve <report_id> --approver <name>`.

**6. Regression after a target change.** Replays every frozen finding against the build
and flags any that reappear:

```bash
uv run redteam regression --target agentforge-w2 --sha <new git_sha>
```

The store defaults to `var/redteam.db` (gitignored); pass `--store` to use another. `redteam
--help` lists every command; beyond those above: `poll [--discover]` (SHA change triggers
regression), `discover` / `candidates` / `triage` (the open-ended discovery tier), `disclosure` and
`grounding` (deterministic AI-layer probes), `benign` (over-refusal set), and `calibrate` (Judge
agreement against the calibration set).

## Repository layout

| Path | Purpose |
|---|---|
| `src/redteam/` | Platform: agents, Executor, oracles, store, CLI |
| `evals/cases/` | Declarative seed cases, each mapped to OWASP |
| `contracts/v1/` | Versioned inter-agent message + error schemas |
| `authorization.yaml` | Authorization registry (human-edited only) |
| `docs/` | Plan, ADRs, harness spec, findings, cost, performance, integration packet, prior-art research |
| `scripts/`, `tools/` | `bench.py` (load profile), contract generation for the target's own schemas |
| `tests/` | Unit, contract, and eval-suite tests |

## Target changes for testability (Stage 1)

The platform needs no target code access; it reaches the Co-Pilot over HTTP only. It uses
the Co-Pilot's synthetic-context mint (`/v1/demo-context`, enabled by
`AGENTFORGE_SYNTHETIC_CONTEXT` on the demo deployment) to obtain patient-scoped session
tokens for fixture patients. That same mint is the root of four of the seven reported
findings (the anonymous read and write mints, the missing rate limit, and the open-namespace
enumeration); the other three are AI-layer issues in `/v1/follow-up-evidence` (off-condition
misinformation, internal-metadata disclosure, and contradictory chart facts). See
[docs/findings/](docs/findings/).
