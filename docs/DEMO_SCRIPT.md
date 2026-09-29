# Demo script — AgentForge Red Team (~4:30)

A shot list for the submission video: what to do, what to run, and what to say. The platform
runs live against the authorized, owner-operated target with synthetic patients only.

## Before you hit record (do these once)

1. **Open a PowerShell terminal**, not Git Bash. Git Bash rewrites a leading-slash
   `--route /v1/...` into a Windows path and the request 400s. (If you must use Git Bash,
   prefix each command with `MSYS_NO_PATHCONV=1`.)
2. **Work from the main checkout**, which holds the full-history store:
   ```
   cd C:\Users\david\repos\agentforge-redteam
   ```
3. **Confirm the suite is green and the target is up** (off-camera):
   ```
   uv run pytest -q
   curl -s https://dtstest.64.177.10.182.nip.io/agentforge-w2/health
   ```
   Copy the `git_sha` from that health response. Set it once so every command below can reuse it:
   ```
   $SHA = (curl -s https://dtstest.64.177.10.182.nip.io/agentforge-w2/health | ConvertFrom-Json).git_sha
   ```
4. **Dry-run the campaign step once** (step 5 below). It calls the attacker + judge models and
   takes tens of seconds; you want to know its timing before recording.
5. **Have these files open in tabs** so you can cut to them fast:
   `docs/architecture.html`, `authorization.yaml`,
   `docs/findings/F-831d4df407broken-authentication-demo-context.md`, and a browser tab ready for
   `dashboard.html`.
6. **Screen + mic**: capture the terminal at a readable font size. Keep total length 3–5 min.

---

## Shot list

### 1 · Framing + architecture — 0:00–0:35
- **Do:** show `docs/architecture.html` (the diagram).
- **Say:** "AgentForge Red Team continuously attacks one authorized target — our own Clinical
  Co-Pilot. Four agents: an Orchestrator that prioritizes, a Red Team that generates attacks, an
  independent Judge that grades them, and a Documentation agent that writes reports. A single
  deterministic Executor is the only component that can reach the target."

### 2 · Safety boundary — 0:35–0:55
- **Do:** show `authorization.yaml`, then run a target that is not in it:
  ```
  uv run redteam authz --target some-unlisted-system --patient fixture-patient-001
  ```
- **Expect:** `target 'some-unlisted-system' is not in authorization.yaml` — no network call.
- **Say:** "The platform refuses any target not in the authorization registry with recorded proof
  of ownership. It cannot be pointed at a system we don't own."

### 3 · The live build — 0:55–1:10
- **Do:**
  ```
  curl -s https://dtstest.64.177.10.182.nip.io/agentforge-w2/health
  ```
- **Say:** "This is the deployed target. Every result we record is tied to this build SHA."

### 4 · Deterministic authorization battery, live — 1:10–2:10
- **Do:**
  ```
  uv run redteam authz --target agentforge-w2 --patient fixture-patient-001 --victim-patient fixture-patient-002 --target-sha $SHA
  ```
- **Point at the output:** the cross-patient and forged/missing-token probes are rejected with
  403; the anonymous token-mint probes succeed.
- **Say:** "No attacker model here — these are deterministic probes. The access-control checks
  hold: a token is bound to its patient, and mismatched or missing tokens get a 403 before any
  model runs. What does not hold is the demo token mint: it hands out a valid token to an
  anonymous caller. That's the root of all three of our findings."

### 5 · Multi-agent loop, live — 2:10–3:05
- **Do:**
  ```
  uv run redteam campaign --target agentforge-w2 --category prompt-injection --route /v1/follow-up-evidence --patient fixture-patient-001 --max-campaigns 1 --target-sha $SHA
  ```
- **Say:** "Now the full loop. The Orchestrator picks a category, the Red Team generates an
  attack, the Executor sends it, and the independent Judge rules. Here the verdict is FAIL —
  meaning the attack failed and the Co-Pilot's defense held. A cost cap is the circuit-breaker so
  a run can't spend without producing signal."

### 6 · Observability — 3:05–3:45
- **Do:**
  ```
  uv run redteam dashboard --out dashboard.html
  ```
  then open `dashboard.html`.
- **Say:** "One store is the source of truth. The dashboard answers the operator's questions:
  coverage per category, pass/fail by build, open findings, run cost, and the ordered trace of
  what each agent did."

### 7 · Report + human gate — 3:45–4:10
- **Do:** open `docs/findings/F-831d4df407broken-authentication-demo-context.md`. Scroll to
  **Reproduction** and **Recommended remediation**.
- **Say:** "The Documentation agent writes these. An engineer who wasn't here can reproduce it
  from one curl command and knows exactly when it's fixed. Critical findings are held for human
  approval before they're published — the platform never files a critical report on its own."

### 8 · Regression + what's next — 4:10–4:30
- **Do:**
  ```
  uv run redteam regression --target agentforge-w2 --sha $SHA
  ```
- **Say:** "Confirmed findings become frozen regression cases. The fix is on a branch in the
  target repo. After it deploys, this same command re-runs against the new build — and a finding
  only counts as fixed if the exact probe now returns a 401 or 429, not because the model got
  quieter. That's the whole point: prove the fix, don't assume it."

---

## Honest framing to say out loud
- All three findings share one root cause: a demo-convenience token mint that shipped enabled.
  Everything aimed at the LLM layer itself — prompt injection, cross-patient leakage — held.
- Synthetic data only; no real PHI is ever processed.

## If something goes wrong on camera
- **Campaign hangs / model error:** stop it, say "the attacker model is rate-limited, here's a
  prior run," and cut to `redteam report` or the dashboard, which show earlier results.
- **A command 400s:** you're probably in Git Bash — switch to PowerShell.
- **Target 5xx:** the platform records this as `INCONCLUSIVE`, not a pass. Say so; it's a feature.
