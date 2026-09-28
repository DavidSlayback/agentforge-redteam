# AgentForge Red Team

A multi-agent platform that continuously attacks one authorized target, the AgentForge
Clinical Co-Pilot, and proves whether its weaknesses are found, fixed, and stay fixed.

## Language

### Target

**Target**:
The one system the platform is authorized to attack: the AgentForge Clinical Co-Pilot.
_Avoid_: system under test, victim, app

**Target build**:
A specific deployed or local instance of the Target identified by its git SHA; every result belongs to exactly one.
_Avoid_: version, release

### Attack lifecycle

**Seed case**:
An authored, versioned attack specification: category, OWASP mapping, expected safe behavior, and the oracle that judges it.
_Avoid_: test case, payload, prompt

**Variant**:
A case the Red Team Agent derived from a parent seed case or variant.
_Avoid_: mutation (that is the act, not the thing)

**Campaign**:
A bounded unit of attack work the Orchestrator chooses: which surface, which cases, what budget.
_Avoid_: run, job, session

**Attempt**:
One execution of a seed case or variant against one Target build, with its exact exchanges recorded.
_Avoid_: test, trial, exploit

**Oracle**:
A deterministic check that decides an outcome from observable evidence without a model.
_Avoid_: detector, assertion

**Verdict**:
The Judge Agent's ruling on one attempt: success, partial, fail, or inconclusive, with the evidence it used.
_Avoid_: result, score, grade

**Provider block**:
An outcome where a model provider's own content filter, not the Target's defenses, stopped a generation or response; never evidence that a defense held.
_Avoid_: refusal (reserve for the Target's own behavior)

**Finding**:
A distinct weakness in the Target, established by one or more success verdicts and deduplicated by root cause.
_Avoid_: exploit, bug, vuln (as a stored noun)

**Vulnerability report**:
The Documentation Agent's professional write-up of one finding.
_Avoid_: ticket, writeup

**Regression case**:
A frozen, replayable attempt derived from a finding, re-run against every new Target build.
_Avoid_: regression test, eval

**Lineage**:
The chain of links from any record back to the decisions and evidence that produced it, retrievable on demand.
_Avoid_: provenance (reserve for source documents), history

## Relationships

- A **Campaign** produces many **Attempts**; each **Attempt** executes one **Seed case** or **Variant**.
- Each **Attempt** receives exactly one **Verdict**.
- A **Finding** is backed by one or more success **Verdicts**; many **Attempts** can map to one **Finding**.
- Each **Finding** has at most one current **Vulnerability report** and one or more **Regression cases**.
- **Lineage** connects every record to its parents, so a **Finding** can be explained back to the **Campaign** that surfaced it.

## Flagged ambiguities

- The PRD uses "exploit" for both the weakness and the evidence of it. Resolved: the weakness is a **Finding**; the evidence is **Attempts** with **Verdicts**. "Exploit" stays in prose only.
