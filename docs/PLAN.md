# AgentForge Red Team — plan

The single plan file (see `AGENTS.md`). Keep it current at decision boundaries.

**Goal:** by Friday noon CT, a deployed multi-agent adversarial platform runs live
against the authorized Clinical Co-Pilot target, converts confirmed exploits into a
regression harness, documents findings professionally, and proves fixes hold without
raising over-refusal — every claim tied to a target SHA and a reproducible run.

## Status (2026-09-28)

Scaffold only. Repo created and handed off from the `agentforge-week1` session. No
agents built yet. First task: design the architecture (Stage 4), starting Stages 1–2 in
parallel. See `KICKOFF.md`.

## Source record

| Source | Path |
|---|---|
| PRD (18 pp) | `.scratch/assignments/w3.txt` (gitignored; from the assignment PDF) |
| Prior art | `docs/W3_ADVERSARIAL_PRIOR_ART_RESEARCH_2026-09-27.md` |
| Idea bank | `.scratch/assignments/w3-idea-bank.md` (gitignored, speculative) |

## Requirements matrix

To fill from `.scratch/assignments/w3.txt` at the start of the first session: one row per
hard gate and required platform component, with owner, state, and evidence.

## Settled decisions

- Language: Python (uv, pydantic); HTTP-only access to the target.
- Judge: deterministic oracles first; narrow different-family LLM judge only where no
  oracle exists; human lane for clinical-harm calls.
- Tools: PyRIT as a library; garak/spikee as sidecars; own finding store.
- Authorization-gated execution; synthetic data only.

## Execution slices

To be defined during architecture design. Candidate order: (S0) confirm live target +
requirements matrix; (S1) threat model; (S2) architecture + contracts; (S3) one live
agent role + seed evals across 3 categories; (S4) judge + regression harness; (S5)
orchestrator + observability; (S6) documentation agent + reports; (S7) hardening drill,
metrics, cost analysis, deploy, demo.
