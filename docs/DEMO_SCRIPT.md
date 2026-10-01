# Demo script — AgentForge Red Team (~4:45)

A shot list for the submission video: what to do, what to run, and what to say. The platform
runs live against the authorized, owner-operated target with synthetic patients only.

**The arc is find → fix → prove.** As of the current build we have **7 findings across two planes** —
an *authorization* plane (anonymous token mints, no-rate-limit, patient enumeration) and an
*AI/reasoning* plane (misinformation/grounding, metadata disclosure, data-integrity). **Five are
fixed, deployed, and validated live; two (the anonymous read/write mints) are a permanently
accepted risk** with compensating controls. The demo shows the loop catching them *and* the
regression harness proving the deployed fixes hold.

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
   curl.exe -s https://dtstest.64.177.10.182.nip.io/agentforge-w2/health
   ```
   > In PowerShell, `curl` is an alias for `Invoke-WebRequest` (different flags — `curl -s` will
   > hang at a `Uri:` prompt). Always type `curl.exe` for the real binary.

   Set the SHA once so every command below can reuse it. `Invoke-RestMethod` parses the JSON for you:
   ```
   $SHA = (Invoke-RestMethod https://dtstest.64.177.10.182.nip.io/agentforge-w2/health).git_sha
   $SHA   # expected: 34232592d3238ad4de5161d914b0fbf7f8fb48ad (confirmed 2026-10-01)
   ```
4. **⚠ Rate-limit ordering (new — read this).** The rate-limit *fix* is deployed, so the mint
   endpoint now returns `429` after ~9 rapid mints in a 60 s window. Shot 4 (authz battery) and
   Shot 8 (regression) both hit the mint. If you run them back-to-back on the same store, Shot 8's
   two accepted-risk mints come back `INCONCLUSIVE (429)` instead of `REAPPEARED`, which muddies the
   "held=5 reappeared=2" headline. **Either** run Shot 8 on a fresh copy of the store, **or** wait
   ~60 s between Shot 4 and Shot 8, **or** narrate the 429 as the deployed rate-limiter doing its job.
   A clean copy is simplest:
   ```
   Copy-Item var\redteam.db var\redteam.demo.db
   ```
   and pass `--store var\redteam.demo.db` on the live commands so the canonical store stays pristine.
5. **Dry-run the campaign step once** (Shot 5). It calls the attacker + judge models and takes tens
   of seconds (Qwen can time out — raise `AGENTFORGE_REDTEAM_TIMEOUT` if so); know its timing before
   recording.
6. **Have these files open in tabs** so you can cut to them fast:
   `docs/architecture.html`, `authorization.yaml`,
   `docs/findings/F-831d4df407broken-authentication-demo-context.md`, `docs/findings/README.md`
   (the find→fix→prove table), and a browser tab ready for `dashboard.html`.
7. **Screen + mic**: capture the terminal at a readable font size. Keep total length 3–5 min.

---

## Shot list

### 1 · Framing + architecture — 0:00–0:35
- **Do:** show `docs/architecture.html` (the diagram).
- **Say:** "AgentForge Red Team continuously attacks one authorized target — our own Clinical
  Co-Pilot. Four agents: an Orchestrator that prioritizes, a Red Team that generates attacks, an
  independent Judge that grades them, and a Documentation agent that writes reports. A single
  deterministic Executor is the only component that can reach the target. The goal isn't just to
  find bugs — it's to find them, fix them, and prove the fix holds on the next deploy."

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
  curl.exe -s https://dtstest.64.177.10.182.nip.io/agentforge-w2/health
  ```
- **Say:** "This is the deployed target. Every result we record is tied to this build SHA —
  right now `34232592`."

### 4 · Deterministic authorization battery, live — 1:10–2:15
- **Do:**
  ```
  uv run redteam --store var\redteam.demo.db authz --target agentforge-w2 --patient fixture-patient-001 --victim-patient fixture-patient-002 --target-sha $SHA
  ```
- **Expect (live, 2026-10-01):** `{'SUCCESS': 2, 'FAIL': 6, 'INCONCLUSIVE': 2}` — i.e. **2 SUCCESS**
  (the two anonymous mints still mint), **6 FAIL** (cross-patient read, forged/missing tokens — the
  attack failed, access control held), and **2 INCONCLUSIVE**: a `429` (the deployed rate-limiter)
  and a `400` (the provisioned-only enumeration fix refusing an unknown id).
- **Say:** "No attacker model here — these are deterministic probes. Access control holds: tokens
  are bound to their patient, and mismatched or missing tokens get a 403. Two things *do* succeed —
  the anonymous demo-context mints. Those are our two critical findings, and we've made a deliberate
  decision to accept them as a risk, because the only real fix is authentication and that breaks the
  public demo. But look at the two INCONCLUSIVE lines: a 429 and a 400. Those are *deployed fixes*
  showing up right here — a rate-limiter throttling repeated mints, and provisioned-only issuance so
  the patient namespace can't be enumerated."

### 5 · Multi-agent loop, live — 2:15–3:05
- **Do:**
  ```
  uv run redteam --store var\redteam.demo.db campaign --target agentforge-w2 --category prompt-injection --route /v1/follow-up-evidence --patient fixture-patient-001 --max-campaigns 1 --target-sha $SHA
  ```
- **Expect:** `campaigns=1 tested=1 findings_opened=0` — the verdict is FAIL (attack failed; the
  Co-Pilot's defense held).
- **Say:** "Now the full loop. The Orchestrator picks a category, the Red Team generates an attack,
  the Executor sends it, and the independent Judge rules. Here the verdict is FAIL — the attack
  failed and the Co-Pilot defended. A cost cap is the circuit-breaker so a run can't spend without
  producing signal."

### 6 · Observability — 3:05–3:40
- **Do:**
  ```
  uv run redteam --store var\redteam.demo.db dashboard --out dashboard.html
  ```
  then open `dashboard.html`.
- **Say:** "One store is the source of truth. The dashboard answers the operator's questions:
  coverage per category, pass/fail by build, open findings, run cost, and the ordered trace of
  what each agent did."

### 7 · Report + human gate — 3:40–4:05
- **Do:** open `docs/findings/F-831d4df407broken-authentication-demo-context.md`. Scroll to
  **Reproduction** and **Recommended remediation**. Optionally cut to `docs/findings/README.md`
  to show the full 7-finding table with fix status.
- **Say:** "The Documentation agent writes these. An engineer who wasn't here can reproduce it
  from one curl command and knows exactly when it's fixed. This critical is held for human approval
  before it's published — the platform never files a critical report on its own. The table shows all
  seven: two accepted-risk mints with compensating controls, and five fixed."

### 8 · Regression — the fix is deployed and proven — 4:05–4:45
- **Do:** (fresh store — see the rate-limit note in step 4; or wait 60 s after Shot 4)
  ```
  Copy-Item var\redteam.db var\redteam.regress.db
  uv run redteam --store var\redteam.regress.db regression --target agentforge-w2 --sha $SHA
  ```
- **Expect:** `regression @ 34232592: held=5 reappeared=2 inconclusive=0 -> ATTENTION`.
- **Say:** "Confirmed findings become frozen regression cases. The fixes are already deployed on
  this build — and the harness proves it: five held. A finding only counts as held if the exact
  probe now returns a 401, 429, or the expected refusal — not because the model got quieter. Two
  reappear: those are the anonymous mints we accepted as a risk, and the harness stays honest — it
  shows ATTENTION and refuses to go green while an exploitable critical is live by design. That's the
  whole point: prove the fix, don't assume it, and never let an accepted risk quietly disappear."

---

## Honest framing to say out loud
- **Seven findings, two planes.** Authorization plane: two anonymous mints (accepted risk), plus
  no-rate-limit and patient-enumeration (both fixed). AI/reasoning plane: misinformation/grounding,
  metadata disclosure, and data-integrity (all three fixed). Five fixed and validated live; two
  accepted with compensating controls (rate limit, `aud` check, 300 s TTL, token↔patient binding,
  provisioned-only issuance, cross-origin binding, mint audit log).
- **The accepted risk is bounded.** The anonymous mint issues only a synthetic-claim token; it
  structurally cannot reach a real OpenEMR chart (claim-gated routing). The real production path
  mints from an authenticated OpenEMR session — so the critical is a demo-mode property, remediated
  in authenticated production and accepted for the public demo.
- **Trustworthy negatives:** direct + indirect prompt injection defended; cross-patient BOLA held;
  forged/missing tokens 403; oversized-input DoS handled; multi-turn injection N/A (stateless
  composer). Real results, not untested gaps.
- Synthetic data only; no real PHI is ever processed.

## If something goes wrong on camera
- **Shot 8 shows `reappeared=0 inconclusive=2` instead of `reappeared=2`:** you ran it right after
  Shot 4 on the same store and the deployed rate-limiter returned 429 on the mints. Use a fresh
  store copy (step 4 / Shot 8) or wait ~60 s. Or just narrate it: "that 429 is our rate-limit fix
  firing." Either is honest.
- **Campaign hangs / model error:** stop it, say "the attacker model is rate-limited, here's a
  prior run," and cut to `redteam report` or the dashboard, which show earlier results.
- **A command 400s on `--route`:** you're probably in Git Bash — switch to PowerShell.
- **`curl` hangs at a `Uri:` prompt:** you typed `curl`, not `curl.exe`. Press Ctrl+C and retry
  with `curl.exe`.
- **Target 5xx:** the platform records this as `INCONCLUSIVE`, not a pass. Say so; it's a feature.
- **`TargetUnreachable: attacker model endpoint … timed out` in the agent trace:** that's the
  attacker model (Qwen) timing out, not the target. The platform records it and moves on — honest
  evidence it degrades gracefully. Point at it, don't hide it.
- **A campaign adds nothing to the store / `brief_error` with a `C:/Program Files/Git/...` route:**
  you ran it in Git Bash and the `/v1/...` route was path-mangled. Re-run in PowerShell.
