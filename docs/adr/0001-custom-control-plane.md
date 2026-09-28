---
status: accepted
date: 2026-09-28
---

# Custom control plane over a shared SQLite store

Agents coordinate through a hand-rolled, deterministic controller and one SQLite store
that doubles as the work queue, the audit trail, and the observability substrate the
Orchestrator reads. Agents are isolated workers with their own context; they take typed
tasks from the store and write typed results back (JSON Schemas in `/contracts`). The
controller, not any agent, owns target authorization, budget, halting, and lifecycle
transitions. We chose this because the platform's hardest requirements are independence
(the Judge must not share the Red Team's context), auditability (every agent action
ordered and replayable), and one source of truth the Orchestrator can query; a single
store makes handoffs, audit, and orchestration signals the same rows.

## Considered options

- **Pipeline with LLM steps.** Rejected: the PRD states a single-agent or pipeline
  architecture does not satisfy the assignment.
- **LangGraph.** Viable and familiar to reviewers. Rejected because its checkpointer
  would be a second state store beside SQLite, and graph abstractions add little for
  four agents whose handoffs are queue items. Revisit if agent count or branching grows.
- **Conversational multi-agent (AutoGen, CrewAI).** Rejected: agents share a
  conversation, which breaks Judge independence by construction, and turn-taking is
  nondeterministic and costly.
- **Inspect AI as backbone.** Strong logs, scorers, and viewer, but shaped for eval runs,
  not a long-lived campaign loop with findings and lifecycle state. May still be used as
  a component.
- **One existing red-team tool as the platform (PyRIT, garak, promptfoo).** None provides
  an orchestrator, regression harness, or documentation agent. They are used as
  components (PyRIT library; garak/spikee sidecars) instead.

## Consequences

- We own retry, timeout, and recovery logic that a framework would provide; failure
  handling must be tested explicitly.
- The W2 Co-Pilot already uses a hand-rolled supervisor for the same audit reasons, so
  the pattern is consistent across the two systems.
