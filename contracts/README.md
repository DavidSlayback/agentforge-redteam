# /contracts — versioned inter-agent message schemas

Every inter-agent message (Orchestrator→RedTeam, RedTeam→Judge, Judge→Documentation)
and every typed error response is a versioned JSON Schema here (minimum `v1`).
Contract tests verify producer and consumer both conform. Breaking change ⇒ version bump + migration note.

> STATUS: STUB — schemas added during architecture + build.
