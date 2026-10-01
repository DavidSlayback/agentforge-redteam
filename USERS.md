# Users

Who this platform is for, how they work, and why continuous automation — not manual
pen-testing — is the right solution. (PRD submission requirement.)

## Primary users

### 1. Security / AppSec engineer (the operator)
Runs the platform against the Clinical Co-Pilot, triages findings, and validates fixes.
- **Workflow:** start a campaign (`redteam campaign`), review the dashboard, read the
  Documentation agent's reports, approve critical/high findings (`redteam approve`), and
  confirm fixes hold (`redteam regression`).
- **Needs:** reproducible findings (an engineer not present at discovery can replay them),
  a deterministic regression gate, and confidence the Judge's verdicts are trustworthy.

### 2. AI / platform engineer (the Co-Pilot owner)
Owns the target. Consumes findings, ships fixes, and must know a fix holds without breaking
the clinician.
- **Workflow:** receive a vuln report → fix → the regression suite replays the frozen case
  on the new build → `held` (fix holds) or `reappeared` (regression).
- **Needs:** a fix that holds across *mutations* of the attack, not just the exact string,
  and evidence the fix didn't raise over-refusal. *Today the platform replays the exact frozen
  case (a mutated-variant replay is not built), and over-refusal was measured once, on one build
  (`KEY_METRICS.md` #3, #4).*

### 3. Engineering leadership / hospital CISO (the decider)
Decides whether to trust the Co-Pilot in production and the platform to guard it.
- **Workflow:** read the coverage and resilience trends and the open/closed findings.
- **Needs:** a small set of defensible metrics (`KEY_METRICS.md`), and assurance the
  platform cannot be turned against systems it should not attack (the authorization
  registry, ADR 0002).

## Why automation is the right solution

- **The attack surface evolves faster than manual testing.** New prompt-injection and
  agent-abuse techniques appear continuously; a one-time pen test is stale within weeks.
  The Red Team agent mutates attacks and the Orchestrator prioritizes from live state.
- **Findings must be reproduced on every change.** A vulnerability fixed once and never
  re-tested reappears under a slightly different variant. The regression harness replays
  every confirmed exploit against every new build. `redteam poll` does this on a SHA change and is
  cron-friendly; nothing schedules it for you yet, so today it runs when an operator runs it.
- **The cost of a miss is high and the volume is large.** A single cross-patient PHI leak
  is a reportable event. Continuous testing at scale is only economical with cheap,
  deterministic oracles and a low-cost attacker model — not a human running prompts.
- **Deterministic verification beats human judgment for the repeatable part.** Canary,
  scope, and state-diff oracles decide most verdicts with no model and no drift, freeing
  human attention for the ambiguous, clinically-consequential calls (the human gate).

## Where a human stays in the loop

Publishing critical/high reports and changing the authorization registry are human decisions
(Q6/Q15), enforced in the code: the approval gate fails closed, and the registry is a git-tracked
file only a human edits. Triage of `INCONCLUSIVE` verdicts and of discovery candidates is also
human, but there is no review queue: inconclusive verdicts are counted in `redteam report` and
candidates are listed by `redteam candidates`. A clinical-harm review lane is not built. The
platform never proposes or applies fixes to the target — it only recommends remediation in report
text.
