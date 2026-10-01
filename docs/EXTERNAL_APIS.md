# External APIs: auth, rate limits, and failure handling (E7)

Every external dependency the platform calls, with its authentication, the rate-limit/quota it is
subject to, and how the platform handles saturation or failure. The platform's primary cost/rate
control is a **hard budget cap** (`--max-model-calls`, the Governor), not per-call exponential
backoff — stated honestly below so the handling column is not overclaimed. A failure is always a
**typed outcome that fails closed to `INCONCLUSIVE`**, never a silent pass.

| API | Used by | Auth | Rate limit / quota | Handling on saturation or failure |
|---|---|---|---|---|
| **Target Co-Pilot** (`dtstest…nip.io/agentforge-w2`) | Executor (the only component with network access) | synthetic `demo_token` minted per patient; origin must be `enabled` in `authorization.yaml` | the target itself rate-limits the mint (per-client, 15 per 60 s; `429` with `Retry-After` after ~9 rapid requests — F-6ee fix) | single-door Executor; `follow_redirects=False`; 90s timeout (`http_sender` default, not env-configurable); transport failure → `TargetUnreachable` → attempt scored **INCONCLUSIVE** (never a pass). A `429` on a probe response → INCONCLUSIVE, not a defense-held. **No Executor-level retry or backoff.** The one exception is the token minter: on a mint `429` it waits `Retry-After` (capped at 60 s) and re-mints, up to 2 retries, then raises `TargetUnreachable`. |
| **Qwen attacker** (Alibaba Bailian, OpenAI-compatible) | Red Team generation/mutation | `Authorization: Bearer` (`AGENTFORGE_REDTEAM_API_KEY`) | Bailian account quota; the attacker also hits Alibaba's `DataInspectionFailed` content filter | timeout configurable via `AGENTFORGE_REDTEAM_TIMEOUT` (default 90s; raised for slow models); a content block → typed `ProviderBlock` (distinct outcome; measured, non-Alibaba fallback is the documented path); HTTP ≥400 or transport error → `TargetUnreachable`. **Volume is bounded by `--max-model-calls` (the cost circuit breaker, default 200)**: every call is metered before it is made, and reaching the cap raises `BudgetExceeded`, which stops the run cleanly (the brief is `budget_halted`) rather than retrying. In the store, 40 of 47 brief errors were attacker read timeouts at the 90 s default. |
| **DeepSeek rubric / discovery** (Bailian, non-Qwen) | Judge rubric tier; Discovery tier | reuses the Bailian key (or `_RUBRIC_`/`_DISCOVERY_` overrides) | Bailian account quota | reasoning-model `max_tokens` headroom handled (empty-content guard); any failure → rubric returns `INCONCLUSIVE` (never credits a defense), discovery returns `error` (never a candidate). Independence enforced (must be non-Qwen unless an explicit discovery override). |
| **Jev selector** (TypeSafe, pinned `jev-1.13.0`) | Orchestrator candidate selection | `AGENTFORGE_REDTEAM_JEV_KEY` (optional) | vendor quota | key-gated and optional; a vendor outage or low-confidence band **falls back to the deterministic selector** (confidence-band logic), so orchestration never stalls on it. |
| **Observability backends** | none | n/a | n/a | The platform has no external observability backend: its store is local SQLite and the dashboard is a static file. |

**Pagination.** None of the called APIs is paginated: the target's routes, `/health`, and the
chat-completions endpoints each return one response per request.

**Queueing/abort model.** The Executor is the single serialized door to the target (ADR 0002), which
is the accepted throughput bottleneck (see `docs/PERF.md` / E14). There is no multi-worker queue
today; the control that matters is the budget cap (abort-to-INCONCLUSIVE), not backpressure. A
worker pool behind the auth gate is the documented scale-up fix (E14). Full cost projections at
100/1K/10K/100K runs: `docs/COST_ANALYSIS.md`.
