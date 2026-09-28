# AgentForge Red Team

A multi-agent adversarial evaluation platform that continuously red-teams the AgentForge
Clinical Co-Pilot (an OpenEMR AI layer) and proves fixes hold without breaking the
clinician. Week 3 of the AgentForge track.

**Status:** scaffold. Architecture and agents are being designed — see
[KICKOFF.md](KICKOFF.md) and [docs/PLAN.md](docs/PLAN.md).

## Scope

The platform attacks **one authorized target**: the AgentForge Clinical Co-Pilot that the
owner deploys, with synthetic data only. It is target-agnostic in architecture but
**authorization-gated in execution** — a target runs only if it is in an authorization
registry with recorded proof of ownership or written permission. It is not a scanner for
arbitrary third-party systems. See [AGENTS.md](AGENTS.md).

## Layout

| Path | Purpose |
|---|---|
| `KICKOFF.md` | Handoff + first-session orientation |
| `AGENTS.md` | Repo agent contract (boundary, honesty, process) |
| `THREAT_MODEL.md` | Attack-surface map (PRD Stage 2) |
| `ARCHITECTURE.md` | Multi-agent platform architecture (PRD Stage 4) |
| `KEY_METRICS.md`, `USERS.md` | Metrics and users (PRD hard gates) |
| `evals/` | Adversarial test suite + reproducible results |
| `contracts/` | Versioned inter-agent message schemas |
| `docs/` | Plan, prior-art research |

## Target

Deployed W2 Co-Pilot (owner-operated): `https://dtstest.64.177.10.182.nip.io/agentforge-w2/`
(`/health` reports the running SHA). The platform reaches it over HTTP only.
