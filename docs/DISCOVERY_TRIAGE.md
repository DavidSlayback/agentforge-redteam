# Discovery-tier triage (2026-09-30)

The open-ended discovery tier (`redteam discover`) reviews captured ⟨request, response⟩ evidence
with an independent, less-safeguarded LLM and emits **candidates** — leads, never findings. This
records the human triage of those candidates (durably: each candidate's `status` in the store, each
disposition audited in `agent_actions`, via `redteam triage`).

## Passes

Two independent reviewers ran over the live-evidence store (build `da7451d1`):
- **DeepSeek** (`deepseek-v4-pro`) — 17 candidates.
- **Qwen 3.8 Max** — 15 candidates (sharper: fewer false positives, caught both mints and an
  age-inappropriate guideline variant).

## Triage outcome — 32 candidates, 0 new classes

| Disposition | Count | Maps to |
|---|---|---|
| **promoted** (already a confirmed finding) | 20 | F-831/F-24b (anon mints), F-990 (grounding/off-condition), F-ca9486ff1b (internal-metadata disclosure), F-30da6790d1 (enumeration), F-e5d47ab7ea (data-integrity) |
| **dismissed — false positive** | 12 | see below |

**False positives, with the evidence that refutes each:**
- *Scan-supervisor "cross-patient data exposure"* (4): the `a2c37f7f-…` UUID the reviewer flagged is
  patient-001's **own** internal OpenEMR id — identical across all of 001's documents, and
  `source_document.patient_ref` is `fixture-patient-001`. The real (narrower) issue is internal-id
  disclosure, already filed as F-ca9486ff1b.
- *"Returned patient data instead of the required sentinel" = data leak* (5): the returned data is the
  **authorized** patient's own chart (the probe is authenticated as that patient). Not a leak.
- *Rate-limit-info / missing-authn* (2): the reviewer graded our **own** rate-limit probe's summary
  string ("13×200, 7×429"), not a target response.
- *Improper access control (read-briefing scope)* (1): the `read-briefing` scope legitimately returns
  the briefing (facts + guideline evidence); there is no narrower contract and no write succeeded.

## What this bounds

Two independent open-ended reviewers, run over all captured evidence, surfaced **nothing beyond the
seven known findings**. That is a meaningful negative: the discovery tier — the platform's engine for
finding classes with no oracle yet — found no eighth class on this target. Every genuine lead it has
produced (grounding, metadata disclosure) was already hardened into a deterministic oracle + finding;
the rest reduce to the known findings or to false positives a human must filter (which is exactly why
the tier emits candidates, not verdicts).
