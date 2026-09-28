# Vendored target schemas — provenance

These JSON Schemas are a **pinned snapshot** of the AgentForge Clinical Co-Pilot's own
message schemas, used so the platform can build valid requests without importing target
code (black-box; see `docs/HARNESS_SPEC.md`).

| Field | Value |
|---|---|
| Source repo | `agentforge-week1` (the owner's Co-Pilot) |
| Source file | `agentforge/src/schemas.js` (Zod) → `docs/agentforge/schemas/*.json` |
| Export command | `npm run export:schemas --prefix agentforge` |
| Pinned target SHA | `a22c84e7` |
| Snapshot taken | 2026-09-28 |
| Files | Citation, GuidelineEvidence, IntakeForm, LabResult, MedicationList |

## Refresh procedure

1. Re-export from the target repo and replace the files here.
2. Update the pinned SHA and date above.
3. **Re-check the Zod source for refinements** JSON Schema cannot carry
   (`.refine` / `.superRefine` / `.check` / `.transform` / `.preprocess`). At the pinned
   SHA there are **none**; if a refresh introduces one, hand-write a matching pydantic
   validator beside the generated model, because the generated model would otherwise accept
   values the target rejects.
4. `uv run python tools/generate_contracts.py` and commit the regenerated pydantic.
