# AgentForge Red Team — agent rules

This repo is the Week 3 deliverable: a multi-agent adversarial evaluation platform
that continuously red-teams the AgentForge Clinical Co-Pilot (an OpenEMR AI layer
built in Weeks 1–2). The global contract in `~/AGENTS.md` applies; these rules are
W3-specific and override convenience.

## Authorized-target boundary (non-negotiable)

- The platform attacks **one target: the AgentForge Clinical Co-Pilot that David owns
  and deploys.** It is target-agnostic in *architecture* (pluggable target adapter) but
  **authorization-gated in execution**: a target runs only if it is in an explicit
  authorization registry with recorded proof (owned, or written permission + scope).
- Never point the platform at a system David does not own or is not authorized to test.
  This is also a graded PRD requirement (Appendix, "Trust & Safety for the Platform
  Itself": prevent the platform from being turned against systems it should not attack).
- This repo is not a general vulnerability scanner for arbitrary public/third-party
  systems, and must not be built or described as one.

## Data and technique norms

- **Synthetic data only.** Never process, log, or store real PHI. Redaction is tested
  against a real workflow trace, not a hand-built one.
- Attack techniques are executed at runtime by pinned tools (PyRIT, garak, spikee) and
  the Red Team Agent against the authorized target. The repo holds *seed cases* for the
  eval suite, scoped to that target; it is not a catalog of general-purpose payloads.
- Do not name a simulation the real thing. A word-overlap check is not a judge; an
  in-memory map is not a real datastore. If you simulate, label it a simulation in code,
  output, and docs.

## What "done" means

A capability is done only when: the deployed/orchestrated path calls it; a test or eval
exercises that path and fails when you break it; and it is observed working against the
live target. Otherwise report it as `implemented, not wired`, `wired, untested`, or
`not done`, and say which. Fail loudly; a missing verdict is never a pass.

## Judge independence

The Judge Agent must be independent of the attack engine (different context, ideally a
different model family). An agent that both generates and grades attacks is compromised
by design. Prefer deterministic oracles (canaries, state diffs, scope checks) over an LLM
verdict wherever one exists. Document how a drifting judge is detected and corrected.

## Process

- One plan file: `docs/PLAN.md`. Update it; do not spawn parallel status docs.
- Inter-agent messages use versioned JSON Schemas in `/contracts` (min `v1`); a breaking
  change needs a version bump, a migration note, and updated contract tests.
- Map every eval case to its OWASP category.
- Commit messages: Conventional Commits. Add `Assisted-by:` trailers naming any AI tool
  that helped.

## Remotes

- Primary (graded): GitLab `origin` on `labs.gauntletai.com`.
- Mirror: private GitHub (`github`). Push both; the GitLab remote is the source of truth.

## Source of truth

- PRD text: `.scratch/assignments/w3.txt` (gitignored; from the assignment PDF).
- Prior art: `docs/W3_ADVERSARIAL_PRIOR_ART_RESEARCH_2026-09-27.md`.
- Kickoff / current state: `KICKOFF.md`, then `docs/PLAN.md`.
