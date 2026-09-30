# AgentForge Red Team

A multi-agent adversarial evaluation platform that continuously red-teams the AgentForge
Clinical Co-Pilot (an OpenEMR AI layer), converts confirmed exploits into a regression
harness, documents findings as reproducible vulnerability reports, and tracks whether the
target is getting more or less resilient build over build. Week 3 of the AgentForge track.

- **Deployed target (live):** <https://dtstest.64.177.10.182.nip.io/agentforge-w2/> —
  `GET /health` returns the running `git_sha`, which every run records.
- **Current status:** see [docs/PLAN.md](docs/PLAN.md) (single plan file; requirements
  matrix + per-item status) and the honest built-vs-designed section at the end of
  [ARCHITECTURE.md](ARCHITECTURE.md).

## Architecture in one paragraph

A deterministic control plane coordinates four agents — **Orchestrator** (deterministic
ranker + optional Jev selector, hard budget/no-signal halt), **Red Team** (Qwen; generates
and mutates attacks as data only), **Judge** (deterministic oracles first, then an
independent DeepSeek rubric tier for criteria no oracle covers), and **Documentation**
(evidence-backed reports behind a fail-closed human approval gate) — plus deterministic
services: the **Executor** (the only component with network access to the target; checks
the authorization registry on every request) and the **Regression runner** (faithful
replay of frozen findings against a build). One SQLite store is the work queue, audit
trail, and observability substrate. Details, diagram, and tradeoffs:
[ARCHITECTURE.md](ARCHITECTURE.md); decisions: [docs/adr/](docs/adr/).

## Submission deliverables

| Deliverable | Where |
|---|---|
| Threat model | [THREAT_MODEL.md](THREAT_MODEL.md) |
| Users | [USERS.md](USERS.md) |
| Architecture | [ARCHITECTURE.md](ARCHITECTURE.md) (+ [docs/architecture.html](docs/architecture.html)) |
| Key metrics | [KEY_METRICS.md](KEY_METRICS.md) |
| Eval dataset + results | [evals/](evals/) |
| Vulnerability reports | [docs/findings/](docs/findings/) |
| AI cost analysis | [docs/COST_ANALYSIS.md](docs/COST_ANALYSIS.md) |
| Inter-agent contracts (v1 JSON Schema) | [contracts/](contracts/) |
| Observability snapshot | [dashboard.html](dashboard.html) (regenerate with `redteam dashboard`) |

## Setup

Requires Python 3.13–3.14 and [uv](https://docs.astral.sh/uv/).

```bash
uv sync --dev
uv run pytest -q
```

The test suite runs offline (no target, no model keys) and includes the contract tests.

### Configuration

Model keys live in a `.env` file at the repo root (gitignored; real environment variables
win over it). Only the commands that call a model need keys — `authz`, `regression`,
`report`, `dashboard`, `document`, and `evidence` run with none.

| Variable | Needed by | Purpose |
|---|---|---|
| `AGENTFORGE_REDTEAM_BASE_URL` | `campaign` | OpenAI-compatible endpoint for the Red Team model |
| `AGENTFORGE_REDTEAM_API_KEY` | `campaign` | Key for that endpoint |
| `AGENTFORGE_REDTEAM_MODEL` | `campaign` | Attacker model (default in use: `qwen3.8-flash`; override per run with `--model`) |
| `AGENTFORGE_REDTEAM_RUBRIC_MODEL` | `campaign` (optional) | Enables the rubric Judge tier; must be a non-Qwen family (in use: `deepseek-v4-pro`) |
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

Pass the returned `git_sha` as `--target-sha` below so results trend by version.

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
`--max-model-calls` (default 200) is the cost circuit-breaker.

**4. Inspect results.**

```bash
uv run redteam report
```

`redteam dashboard --out dashboard.html` writes the same view as a self-contained page:
coverage per category, pass/fail by category and build, resilience trend, open/resolved
findings, run cost, and the ordered per-agent trace. `redteam evidence <attempt_id>` dumps
the exact request/response behind any verdict.

**5. Reports and approval.** `redteam document <finding_id>` renders an evidence-backed
report. Critical/high reports are held until an operator runs
`redteam approve <report_id> --approver <name>`.

**6. Regression after a target change.** Replays every frozen finding against the build
and flags any that reappear:

```bash
uv run redteam regression --target agentforge-w2 --sha <new git_sha>
```

The store defaults to `var/redteam.db` (gitignored); pass `--store` to use another.

## Repository layout

| Path | Purpose |
|---|---|
| `src/redteam/` | Platform: agents, Executor, oracles, store, CLI |
| `evals/cases/` | Declarative seed cases, each mapped to OWASP |
| `contracts/v1/` | Versioned inter-agent message + error schemas |
| `authorization.yaml` | Authorization registry (human-edited only) |
| `docs/` | Plan, ADRs, harness spec, findings, cost analysis, prior-art research |
| `tests/` | Unit, contract, and eval-suite tests |

## Target changes for testability (Stage 1)

The platform needs no target code access; it reaches the Co-Pilot over HTTP only. It uses
the Co-Pilot's synthetic-context mint (`/v1/demo-context`, enabled by
`AGENTFORGE_SYNTHETIC_CONTEXT` on the demo deployment) to obtain patient-scoped session
tokens for fixture patients. That same mint is the root of the three reported findings;
see [docs/findings/](docs/findings/).
