# W3 adversarial evaluation: prior-art research

**Purpose.** Prepare decisions for the W3 PRD teaser by surveying public evaluation patterns, standards, benchmarks, and tools for a defensive, synthetic-data evaluation of AgentForge.

**Research snapshot:** reports dated 2026-09-27; live version and conflict checks repeated 2026-09-28. Versions below are snapshots, not durable pins; pin exact versions in `uv.lock` when implementation begins.

**Provenance.** Researched 2026-09-27 and 2026-09-28 from primary sources: papers (arXiv and venue proceedings), official repositories and documentation, package metadata, and the standards bodies' own publications. Primary sources are linked inline and in Sources. Version/date checks used PyPI project pages for PyRIT, garak, spikee, Inspect AI, hypothesis-jsonschema, avidtools, and DeepTeam; OpenAI and Promptfoo statements; the ATLAS data repository; and the primary paper/spec sources listed below.

**Legend:** **Fact** means the cited source explicitly documents the point. **Inference** means a fit or recommendation for our system, derived from the cited facts. Recommendations are not W3 requirements; the PRD is not available.

**Scope boundary:** Defensive evaluation of our own synthetic-data Clinical Co-Pilot. This note includes no operational attack strings, jailbreak text, or step-by-step attack recipe. The attack-generation section remains at tool and integration level.

## Summary by teaser clause

| Teaser clause | Adopt | Borrow the idea | Skip |
|---|---|---|---|
| Discover vulnerabilities | **Inference:** Python HTTP harness with schema-driven and stateful API exploration, plus route/trace/config recon exposed by the target. Keep discovery bounded and reproducible. [RESTler](https://arxiv.org/abs/1806.09739), [Schemathesis](https://schemathesis.readthedocs.io/en/stable/explanations/stateful/), [AgentDojo](https://arxiv.org/abs/2406.13352) | Rank by changed routes/contracts and observed workflow state; retain diverse categories. [AFLGo](https://doi.org/10.1145/3133956.3134020) | Do not equate request volume or LLM-generated scenarios with coverage. |
| Generate and mutate attacks | **Inference:** reuse PyRIT converters/targets and selected PyRIT attacks; optionally run garak and spikee as JSONL sidecars. Use promptfoo only with remote generation disabled and an explicit provider. [PyRIT](https://github.com/microsoft/PyRIT), [garak](https://github.com/NVIDIA/garak), [spikee](https://github.com/ReversecLabs/spikee), [promptfoo](https://www.promptfoo.dev/docs/red-team/strategies/) | Static transforms are cheap; dynamically generated cases need a query budget and staged escalation. [spikee](https://github.com/ReversecLabs/spikee) | Do not accept remote generation defaults, or make an LLM the only success oracle. |
| Judge independently | **Inference:** deterministic state/canary/schema oracles first; narrowly scoped independent model checks only when no deterministic oracle exists; human review for ambiguous clinical harm. [AgentDojo](https://arxiv.org/abs/2406.13352), [JudgeBench](https://arxiv.org/abs/2410.12784) | Calibrate judge agreement on held-out synthetic cases; make disagreement `INCONCLUSIVE`. [HarmBench](https://arxiv.org/abs/2402.04249), [Judging the Judges](https://arxiv.org/abs/2406.12624) | Do not use a free-text judge verdict as the sole proof of a security outcome. |
| Prioritize coverage from system state | **Inference:** collect reachable route, workflow, trace, version and change signals through the HTTP surface; allocate a transparent budget to unvisited/high-risk surfaces and changed behavior. [RESTler](https://arxiv.org/abs/1806.09739), [AFLGo](https://doi.org/10.1145/3133956.3134020) | Use stateful resource graphs and feedback to avoid repeating equivalent requests. [RESTler](https://arxiv.org/abs/1806.09739) | Do not claim source-code coverage from a black-box harness. |
| Document findings professionally | **Inference:** versioned finding schema, pinned taxonomy tags, CVSS v4 for demonstrated technical impact, a separate clinical safety axis, and SARIF 2.1.0 output. [SARIF 2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html), [FIRST CVSS v4](https://www.first.org/cvss/v4.0/specification-document) | Optional AVID export for exchange; retain an internal pydantic model as system of record. [AVID Python SDK](https://docs.avidml.org/developer-tools/python-sdk) | Do not infer severity from taxonomy labels or use CVSS as a clinical-harm score. |
| Prove fixes hold without over-refusal | **Inference:** replay finding seed, frozen variants and bounded adaptive search; run benign utility and over-refusal checks on the same candidate SHA. [On Evaluating Adversarial Robustness](https://arxiv.org/abs/1902.06705), [XSTest](https://arxiv.org/abs/2308.01263), [HealthBench](https://arxiv.org/abs/2505.08775) | Report worst case per scenario and paired utility changes; retain every confirmed finding as a regression case. [AgentDojo](https://arxiv.org/abs/2406.13352) | Do not describe a finite campaign as proof of general robustness. |
| Unattended drill against planted vulnerabilities | **Inference:** one-command, bounded, resumable campaign with per-bug `reached / triggered / detected`, a clean-build false-positive baseline, auditable report and nonzero exit on failed acceptance. [Magma](https://arxiv.org/abs/2009.01120), [LAVA](https://www.ieee-security.org/TC/SP2016/papers/0824a110.pdf) | Validate every planted condition and track partial progress, not only a pass/fail aggregate. [Magma](https://arxiv.org/abs/2009.01120), [Cybench](https://arxiv.org/abs/2408.08926) | Do not treat a seeded bug as valid until its trigger is independently demonstrated. |

## Target and evidence boundary

**Fact:** the repo's W3 plan section records a Python 3.13 `redteam/` scaffold, generated pydantic contracts and drift checks; it says the scaffold has no attack code and is not deployed. [PLAN.md, W3 section](PLAN.md)

**Fact:** the W3 platform reaches the Node AgentForge service over HTTP only (PLAN.md, W3 section). The architecture is described in `W2_ARCHITECTURE.md` and the routes are defined in `agentforge/src/server.js`. (both in the target repo, `agentforge-week1`)

**Inference:** the natural boundary is a black-box HTTP harness whose authoritative observations are response data and explicitly exposed state such as traces, read-back routes, and synthetic OpenEMR effects. Do not assume access to target internals or treat hidden implementation coverage as measured.

**Fact:** the AgentDojo design defines utility/security functions over pre- and post-environment state; that external-state pattern transfers to an HTTP-evaluated agent. [AgentDojo paper](https://arxiv.org/abs/2406.13352)

**Inference:** the harness should attach every result to target URL, target build SHA when exposed, harness revision, contract/taxonomy versions, configuration, model/provider identity, budget, and timestamp. A missing build identity makes same-SHA claims inconclusive.

## 1. Discover vulnerabilities

### Known patterns

**Fact:** RESTler derives stateful sequences from OpenAPI dependencies and learns producer-consumer relationships; its checks include authorization and resource-lifecycle properties. [RESTler paper](https://arxiv.org/abs/1806.09739), [Microsoft RESTler checker guide](https://github.com/microsoft/restler-fuzzer/blob/main/docs/user-guide/Checkers.md)

**Fact:** Schemathesis supports schema-based examples, coverage, fuzzing and stateful phases for OpenAPI and GraphQL, with runtime links learned from schemas, OpenAPI links, response `Location`, or explicit extended links. [Schemathesis checks](https://schemathesis.readthedocs.io/en/stable/reference/checks/), [stateful testing](https://schemathesis.readthedocs.io/en/stable/explanations/stateful/)

**Fact:** PyPI metadata for Schemathesis 4.28.0 lists `hypothesis` (and `hypothesis-graphql`) but not `hypothesis-jsonschema` as a dependency (checked 2026-09-28); the latter remains an optional strategy source outside the built-in engine. [Schemathesis on PyPI](https://pypi.org/project/schemathesis/), [hypothesis-jsonschema](https://github.com/python-jsonschema/hypothesis-jsonschema)

**Fact:** RESTler's stateful checks include namespace isolation, resource hierarchy and data leakage after failed create; namespace checks require two identities. [RESTler checker guide](https://github.com/microsoft/restler-fuzzer/blob/main/docs/user-guide/Checkers.md)

**Fact:** AFLFast prioritizes lower-frequency paths and AFLGo directs search toward changed code locations. The transfer is a design analogy, not a claim that those source-instrumented fuzzers can measure AgentForge HTTP coverage. [AFLFast](https://doi.org/10.1145/2976749.2978428), [AFLGo](https://doi.org/10.1145/3133956.3134020)

**Fact:** GPTFuzzer and AgentVigil are research on feedback-guided seed selection and black-box agent red-teaming. [GPTFuzzer](https://arxiv.org/abs/2309.10253), [AgentVigil](https://arxiv.org/abs/2505.05849)

### Fit for AgentForge

**Inference:** use the generated JSON Schemas already present in the repository to create valid and boundary HTTP inputs, then maintain explicit workflow sequences for upload, scan/read-back, answer, draft, confirmation, and authorization-sensitive operations. [W2 schemas (vendored)](../vendor/agentforge-schemas/), [Schemathesis](https://schemathesis.readthedocs.io/en/stable/)

**Inference:** stateful exploration should record a case graph: action, response, created resource identifier, observable state change, and next permitted action. Check patient scope, stale/missing identifiers, denied-action side effects, and read-after-write behavior using synthetic identities.

**Inference:** use route enumeration, documented auth requirements, traces, exposed build SHA, and config surfaced by the target as prioritization inputs. A target that does not expose a state signal should receive a documented `unknown`, not a fabricated coverage score.

### Recommendation

**Inference — adopt:** a small deterministic HTTP discovery layer and schema-driven stateful sequences; use Schemathesis as the likely API exploration engine if its generated cases can express the target's auth/session and multipart flows.

**Inference — build:** route/workflow inventory and prioritizer that operates only on target-visible data; direct budget toward unvisited routes, changed contracts/builds, prior findings, and high-impact invariants.

**Inference — measure honestly:** report endpoint/operation sequence coverage and observed-state coverage. Keep them separate from source line or branch coverage.

## 2. Generate and mutate attacks

### Maintained tool patterns

**Fact:** PyRIT exposes HTTP targets, prompt targets, converters, seed dataset loaders, multi-turn attacks, and both model-based and deterministic scorers. [PyRIT repository](https://github.com/microsoft/PyRIT), [PyRIT on PyPI](https://pypi.org/project/pyrit/)

**Fact:** garak provides REST and function generators, probes, mutation/buff operators and detectors; its REST generator sends the latest conversation message, so it does not itself preserve a multi-turn application session. [garak repository](https://github.com/NVIDIA/garak), [garak REST generator docs](https://garak.readthedocs.io/en/latest/garak.generators.rest.html)

**Fact:** spikee separates static seed generation from target testing, supports custom targets, and can use canary/regex or LLM judges; its documented dynamic strategies run after static inputs do not succeed. [spikee repository](https://github.com/ReversecLabs/spikee), [spikee on PyPI](https://pypi.org/project/spikee/)

**Fact:** promptfoo supports HTTP providers, session parsing and response transforms; its documented red-team strategies include dynamic strategies. Remote generation is enabled by default in the inspected configuration and must be disabled explicitly for the intended local/provider-controlled setup. [HTTP provider](https://www.promptfoo.dev/docs/providers/http/), [strategies](https://www.promptfoo.dev/docs/red-team/strategies/), [configuration](https://www.promptfoo.dev/docs/red-team/configuration/)

**Fact:** the OpenAI and Promptfoo announcements dated 2026-03-09 say Promptfoo had agreed to be acquired, that closing was subject to customary conditions, and that Promptfoo intended to remain open source. The announcement alone does not verify whether the deal subsequently closed. [OpenAI announcement](https://openai.com/index/openai-to-acquire-promptfoo/), [Promptfoo announcement](https://www.promptfoo.dev/blog/promptfoo-joining-openai/)

**Fact:** PyRIT's multi-turn attack methods can make multiple model calls; converters are generally local transformations. Exact call counts depend on selected strategy, rounds, retries and target behavior, so no universal per-test cost is claimed here. [PyRIT docs](https://microsoft.github.io/PyRIT/), [spikee docs](https://github.com/ReversecLabs/spikee)

### Fit and recommendation

**Inference — adopt:** keep seeds and transformations as versioned data; allow pure local transformations at no inference cost; reserve model-generated mutations for bounded campaigns after deterministic probes.

**Inference — integrate:** wrap the target with a thin HTTP/session adapter, keep credentials and synthetic identities outside the attack corpus, record every request/response hash and model call count, and make the attack generator unable to set the security verdict. In Python, call PyRIT's HTTP target from the campaign process; invoke garak and spikee as subprocess sidecars with JSONL inputs/outputs; and use promptfoo's Python provider or HTTP provider only with remote generation disabled. [PyRIT](https://github.com/microsoft/PyRIT), [garak](https://garak.readthedocs.io/en/latest/), [spikee](https://github.com/ReversecLabs/spikee), [promptfoo Python provider](https://www.promptfoo.dev/docs/providers/python/)

**Inference — candidate choices:** PyRIT as the primary import for converters and selected attacks; spikee as a seed/campaign sidecar for document-carrying scenarios; garak as an optional static sweep and corpus source. promptfoo is an optional plugin reference or sidecar only after remote generation is disabled and its provider/session behavior is checked against our flow.

**Fact:** spikee runs dynamic generation only after static inputs fail. **Inference:** apply the same staged escalation across tools and keep LLM-heavy frameworks out of the inner loop. [spikee](https://github.com/ReversecLabs/spikee), [PyRIT](https://github.com/microsoft/PyRIT)

**Inference:** add campaign controls for wall time, request count, model-call count, spend ceiling, concurrency, retry cap, and resumable state. A hard budget stop is a valid `INCONCLUSIVE` outcome, not a pass.

**Call-cost profile:** local PyRIT converters and fixed seed replay use zero generation calls; selected model-based attack strategies add calls according to their configured rounds/retries. garak static probes and regex/string detectors can use zero generation/judge calls, while model-based probes or detectors add calls. spikee static dataset generation/testing can run without dynamic generation; its staged dynamic paths add calls only when enabled and reached. promptfoo's remote generation adds external calls unless disabled; static strategies can avoid generation calls, while configured model graders still add calls. Count actual calls per case in the run record; strategy names do not imply one invariant call count. [PyRIT](https://microsoft.github.io/PyRIT/), [garak](https://garak.readthedocs.io/en/latest/), [spikee](https://github.com/ReversecLabs/spikee), [promptfoo](https://www.promptfoo.dev/docs/red-team/configuration/)

**Research pointers:** “GPTFUZZER: Red Teaming Large Language Models with Auto-Generated Jailbreak Prompts” (arXiv:2309.10253) and “AgentVigil: Generic Black-Box Red-teaming for Indirect Prompt Injection against LLM Agents” (arXiv:2505.05849) are existence/architecture pointers only; this note does not compare their attack techniques. [GPTFuzzer](https://arxiv.org/abs/2309.10253), [AgentVigil](https://arxiv.org/abs/2505.05849)

## 3. Judge independently

### Known patterns and limits

**Fact:** MT-Bench/Chatbot Arena research reports position, verbosity and self-enhancement biases in LLM-as-judge; paired answers can be judged in both orders, with disagreement treated as a tie. [Zheng et al.](https://arxiv.org/abs/2306.05685)

**Fact:** JudgeBench evaluates judges on objectively labelled hard pairs and reports that strong models can perform only slightly better than chance on its hardest cases. [JudgeBench](https://arxiv.org/abs/2410.12784)

**Fact:** AgentDojo uses deterministic utility/security functions over environment state to avoid a compromised agent also compromising its evaluator. [AgentDojo](https://arxiv.org/abs/2406.13352)

**Fact:** the Gemini report measures attack success as exfiltration of planted synthetic information, and HarmBench grades one category by hashing rather than an LLM. **Inference:** canary detection, EHR state diffs, cross-patient identifier checks, schema/citation checks and side-effect checks are the deterministic oracle candidates for our synthetic system. [Gemini indirect prompt injection report](https://arxiv.org/abs/2505.14534), [HarmBench](https://arxiv.org/abs/2402.04249)

**Fact:** HealthBench uses physician-written criteria and model grading; MedHELM reports a model jury compared with clinician ratings. Neither benchmark is a direct evaluation of AgentForge's workflow. [HealthBench](https://arxiv.org/abs/2505.08775), [MedHELM](https://arxiv.org/abs/2505.23802)

### Recommended judge stack

1. **Tier 0 — authoritative deterministic checks.** Use synthetic canaries, patient isolation assertions, permitted write diffs, schema validity, citations, refusal/status codes, and trace invariants. Emit `PASS`, `FAIL`, or `INCONCLUSIVE`; missing evidence fails closed to `INCONCLUSIVE` or `FAIL` according to the criterion.
2. **Tier 1 — narrow model rubric.** Use only for criteria with no deterministic oracle. Ask separate boolean rubric questions, use an evaluator model family different from the target composer, delimit and treat target text as untrusted input, and report pairwise order disagreement as `INCONCLUSIVE`. [Zheng et al.](https://arxiv.org/abs/2306.05685), [Raina et al.](https://arxiv.org/abs/2402.14016)
3. **Tier 2 — generic harm classifier.** Use a standard classifier as secondary evidence for generic content-harm categories, not clinical correctness or authorization. [Llama Guard 4 model card](https://huggingface.co/meta-llama/Llama-Guard-4-12B)
4. **Calibration.** Maintain held-out synthetic cases with human labels; report confusion matrix, per-category agreement, and a chance-corrected statistic such as Cohen's kappa or Scott's pi. Recalibrate after a judge prompt/model change. [Judging the Judges](https://arxiv.org/abs/2406.12624), [HarmBench](https://arxiv.org/abs/2402.04249)
5. **Human review lane.** Escalate ambiguous or clinically consequential judgments; an automated score is not a clinical determination. [Lessons From Red Teaming 100 Generative AI Products](https://arxiv.org/abs/2501.07238)

**Inference:** store oracle type, evidence pointer, judge/model/prompt version, raw verdict label, calibration set version, and reviewer disposition per result. Keep graded target text immutable and avoid storing unsanitized synthetic patient data in logs.

## 4. Prioritize coverage from system state

**Fact:** stateful REST testing uses resource dependencies and feedback from responses; AFLGo shows how a search budget can be directed toward target locations such as changed code. [RESTler](https://arxiv.org/abs/1806.09739), [AFLGo](https://doi.org/10.1145/3133956.3134020)

**Inference:** the team's local W3 idea bank proposes recon from route inventory, traces, configuration/build differences, trust boundaries and untrusted-source-to-sink flows; these are proposals from the teaser, not verified current platform capabilities. (Source: `.scratch/assignments/w3-idea-bank.md`, gitignored and local only.)

**Inference:** represent coverage as a vector, not one percentage: endpoints, HTTP methods, auth modes, workflow transitions, document carriers, oracle categories, planted bugs reached, and observed side effects.

**Inference:** compute a stable priority score from (a) never/rarely visited workflow edges, (b) changed routes/schema/prompts since the prior tested SHA, (c) high-impact invariants and prior findings, and (d) estimated campaign cost. Publish inputs and weights in the run record so the score can be audited.

**Inference:** use coverage diversity controls to prevent a campaign from spending its budget on many near-duplicate cases from one route/category. Keep exploration and exploitation budgets visible.

**Recommendation:** build a small, interpretable prioritizer after the PRD clarifies what “system state” means. If the PRD provides source-level diff or traces, record exactly which signals are available and whether they are target-side or harness-side.

## 5. Document findings professionally

### Taxonomy and reporting

**Fact:** checked on 2026-09-27: OWASP Top 10 for LLM Applications 2025, OWASP Agentic Top 10 2026, MITRE ATLAS data release 2026.09, NIST AI 100-2 E2025 / AI 600-1, CWE 4.20, CVSS 4.0, the MSRC AI bug bar, SARIF 2.1.0 and AVID. These versions and mappings must be refreshed at PRD/implementation time. [OWASP LLM Top 10](https://genai.owasp.org/llm-top-10/), [OWASP Agentic Top 10](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/), [ATLAS 2026.09](https://github.com/mitre-atlas/atlas-data/releases/tag/v2026.09)

**Fact:** MITRE's current ATLAS source is `mitre-atlas/atlas-data` under `dist/v6`; the older `dist/ATLAS.yaml` is deprecated and frozen at 5.6.0. Technique-page URL construction was not verified, and an example guessed URL returned 404. Store technique IDs and release version rather than depending on a page URL. [ATLAS data](https://github.com/mitre-atlas/atlas-data), [release list](https://github.com/mitre-atlas/atlas-data/releases)

**Fact:** CWE List 4.20 was as released 2026-04-30; the index page carries a conflicting older timestamp. Use the dated CWE news and diff report as evidence for 4.20, not the stale index stamp. [CWE 2026 news](https://cwe.mitre.org/news/archives/news2026.html), [4.19.1–4.20 diff](https://cwe.mitre.org/data/reports/diff_reports/v4.19.1_v4.20.html)

**Fact:** CWE's mapping guidance allows a Base CWE such as CWE-1427 for LLM prompt input neutralization, CWE-639 for user-controlled key authorization bypass, or CWE-200 for unauthorized disclosure; it warns against using CWE-1426 as the mapped weakness and CWE-1446 as a prohibited category. [CWE-1427](https://cwe.mitre.org/data/definitions/1427.html), [CWE-639](https://cwe.mitre.org/data/definitions/639.html), [CWE-200](https://cwe.mitre.org/data/definitions/200.html), [CWE-1426](https://cwe.mitre.org/data/definitions/1426.html), [CWE-1446](https://cwe.mitre.org/data/definitions/1446.html)

**Fact:** SARIF 2.1.0 supports taxonomies as `toolComponent`s, results with rule references and levels, web request/response evidence, `partialFingerprints`, and `baselineState`. We found no documented SARIF output for promptfoo red-team results specifically. [SARIF 2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html), [errata](https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/sarif-v2.1.0-errata01-os-complete.html)

**Fact:** AVID's pydantic report model includes references, impact, metrics, and taxonomy mappings; `avidtools` is the associated Python toolkit. [AVID Python SDK](https://docs.avidml.org/developer-tools/python-sdk), [avidtools on PyPI](https://pypi.org/project/avidtools/)

### Recommended finding schema

**Inference:** use a typed internal record with at least:

| Field | Recommended content |
|---|---|
| `finding_id` | Stable ID derived from scenario class and target identity; retain a separate run ID. |
| `target` | Base URL alias, exposed build SHA, target environment label, and synthetic-data declaration. |
| `entry_point` | HTTP method/path or named workflow edge; never include secret credentials. |
| `threat_model` | Attacker capability, identity/scope, trust boundary, and protected asset. |
| `taxonomy[]` | `{scheme, version, id}` per tag; retain release pin for each scheme. |
| `severity` | CVSS v4 vector/score for demonstrated technical impact, with Safety supplemental value where justified; keep clinical utility/harm on a separate axis. [CVSS v4 spec](https://www.first.org/cvss/v4.0/specification-document), [CVSS v4 FAQ](https://www.first.org/cvss/v4.0/faq) |
| `evidence` | Request/response references, oracle inputs/outputs, state diff, redacted trace IDs, and timestamps. |
| `reproducibility` | Seed/case ID, mutation family ID, budget, harness revision, model/provider versions, and random seed where available. |
| `lifecycle` | `new`, `confirmed`, `fixed`, `retested`, `accepted`, `inconclusive`, with SHA and reviewer. |
| `baseline` | SARIF `partialFingerprints` and `baselineState`; use `kind: pass/fail` for regression replay. [SARIF spec](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html) |

**Inference:** export one SARIF rule per finding class, declare OWASP/ATLAS/CWE taxonomy components and versions, and place safe HTTP evidence in web request/response objects. Optionally export AVID `Report` JSON. Keep AVID and SARIF as interchange formats, not canonical state stores.

**Inference:** pin `OWASP-LLM=2025`, `OWASP-ASI=2026` when relevant, `MITRE-ATLAS=2026.09`, `CWE=4.20`, and `NIST-AML=E2025` only when mapped to an applicable objective/attack. Confirm the relevant taxonomy IDs from the release artifact before emitting them.

**Fact:** FIRST's CVSS v4 supports supplemental Safety, and its FAQ distinguishes severity scoring from risk. **Inference:** keep clinical-harm or quality regressions separate from CVSS. [CVSS v4 spec](https://www.first.org/cvss/v4.0/specification-document), [CVSS v4 FAQ](https://www.first.org/cvss/v4.0/faq)

**Inference:** use the MSRC AI bug bar as a qualitative severity aid, not a replacement for demonstrated-impact scoring. [MSRC AI bug bar](https://www.microsoft.com/msrc/aibugbar)

## 6. Prove fixes hold without over-refusal

### Security and utility evidence

**Fact:** XSTest pairs safe prompts that appear risky with unsafe contrasts, and labels full compliance, partial refusal and full refusal. [XSTest](https://arxiv.org/abs/2308.01263)

**Fact:** HealthBench uses physician-written rubric criteria; MedSafetyBench assesses harmful medical requests rather than clinical utility; neither directly tests AgentForge's document and EHR path. [HealthBench](https://arxiv.org/abs/2505.08775), [MedSafetyBench](https://arxiv.org/abs/2403.03744)

**Fact:** AgentDojo reports benign utility, utility under attack and targeted attack success as separate metrics. [AgentDojo](https://arxiv.org/abs/2406.13352)

**Fact:** adversarial robustness evaluation guidance calls for an explicit threat model, adaptive evaluation of the complete defense, utility measurement, sanity checks, convergence/budget checks, and per-example outcomes; later agent-defense research reports that adaptive evaluation can invalidate static-only security claims. [Carlini et al.](https://arxiv.org/abs/1902.06705), [The Attacker Moves Second](https://arxiv.org/abs/2510.09023)

### Recommended fix-holds protocol

1. **Baseline record:** finding class, synthetic asset/canary, entry point, oracle, original vulnerable SHA, exact seed ID, and reviewer-confirmed result.
2. **Candidate record:** require an exposed candidate SHA; run on the exact candidate and retain the same harness, contract, judge and case-set versions.
3. **Replay:** run the original case, a frozen set of variants from distinct transformation/carrier families, and a bounded adaptive search with a published query budget. Do not store operational examples in this note.
4. **Worst-case reporting:** retain per-case verdicts and worst case for each scenario; aggregate metrics are additional summaries, never substitutes for case-level evidence.
5. **Utility checks:** on the same SHA, run benign clinician workflow cases and an XSTest-style over-refusal contrast set. Use deterministic extraction/citation/write checks where possible; use rubric review where criteria are subjective.
6. **Decision:** accept the fix only if security criteria pass across seed, frozen variants and adaptive budget; benign utility does not materially regress under the predeclared paired comparison; and over-refusal does not exceed its threshold. Report `INCONCLUSIVE` for missing evidence or unmet budget.
7. **Sanity checks:** verify the finding reproduces on the pre-fix build or an approved test mutation; verify the oracle catches a known positive and stays quiet on a clean baseline; compare doubled search budget for convergence; manually review any apparent success that might be a scorer artifact.
8. **Claim wording:** say “not detected by this case set at budget B on SHA X.” Do not claim the system is generally robust.

**Inference:** thresholds and paired statistical test should be selected only after the PRD defines target metrics, case counts and confidence requirements. No numerical threshold is proposed from the teaser alone.

## 7. Unattended Hardening Drill against planted vulnerabilities

### Benchmark precedent

**Fact:** LAVA argues that planted, validated bugs enable measurement of misses and false alarms, and that trigger design can bias which testing methods succeed. [LAVA paper](https://www.ieee-security.org/TC/SP2016/papers/0824a110.pdf)

**Fact:** Magma scores each real bug at three levels: reached, triggered and detected. It warns that raw crash counts are unreliable when deduplication is imperfect. [Magma paper](https://arxiv.org/abs/2009.01120), [Magma repository](https://github.com/HexHive/magma)

**Fact:** OWASP FinBot CTF is an intentionally vulnerable multi-agent target with event-driven challenge evaluation and no static flags. **Inference:** its detector/evaluator pattern is relevant prior art, not as a drop-in platform dependency. [FinBot repository](https://github.com/OWASP-ASI/finbot-ctf), [OWASP FinBot page](https://genai.owasp.org/resource/finbot-agentic-ai-capture-the-flag-ctf-application/)

**Fact:** Cybench uses subtasks for partial credit, and CVE-Bench uses sandboxed targets with automated exploit grading. [Cybench](https://arxiv.org/abs/2408.08926), [CVE-Bench](https://arxiv.org/abs/2503.17332)

### Proposed drill contract

**Inference:** make each planted vulnerability an independent record with stable ID, affected boundary, validated trigger condition, expected side effect, detection oracle, expected mapping, and the commit/fixture that introduced it. A plant is eligible for scoring only after its maintainer or independent validator proves the trigger and the clean baseline is negative.

| Per-plant measure | Operational definition |
|---|---|
| Reached | The drill exercised the relevant HTTP route/workflow edge or observable sink. |
| Triggered | The planted condition became true, independently recorded by the plant's controlled state or event. |
| Detected | The platform emitted a finding with the correct plant identity/class and oracle evidence. |
| False positive | The platform reported a finding on a clean build or non-triggering control case. |

**Inference:** keep the plant oracle independent from the detector under evaluation; do not leak plant IDs or triggers into attack-generation prompts. The drill should learn which bugs were planted only after the run is scored.

**Inference:** run one command with a versioned configuration; persist checkpoints after each case; support safe resume; cap HTTP requests, time, model calls, and cost; write a human-readable report plus SARIF; and return nonzero for missed mandatory plants, false-positive threshold breach, incomplete required coverage, or internal error.

**Inference:** report per-bug records, denominator counts, a clean-build false-positive baseline and confidence/limitations. A single aggregate score can hide whether a bug was never reached, never triggered, or triggered but missed by the judge.

## Tools snapshot

**Current release checks:** re-checked on 2026-09-28 using the linked PyPI project pages. “Maintained” reflects repository activity checked 2026-09-27, not a guarantee about future support. HTTP support describes the documented integration boundary, not successful fit to every AgentForge session.

| Tool | Language | License | Latest version + release date checked | Maintained? | HTTP target support | Reuse and verdict |
|---|---|---|---|---|---|---|
| PyRIT | Python | MIT | 1.1.0 — 2026-09-04 [PyPI](https://pypi.org/project/pyrit/) | Yes [repo](https://github.com/microsoft/PyRIT) | HTTP target classes/callback pattern | Import converters, dataset loaders and selected bounded attacks. **Adopt as library.** |
| garak | Python | Apache-2.0 | 0.17.0 — 2026-09-09 [PyPI](https://pypi.org/project/garak/) | Yes [repo](https://github.com/NVIDIA/garak) | REST generator; single latest message limitation | Static sweep, detectors and seed corpus via JSONL. **Optional sidecar.** |
| spikee | Python | Apache-2.0 | 0.9.2 — 2026-09-11 [PyPI](https://pypi.org/project/spikee/) | Yes [repo](https://github.com/ReversecLabs/spikee) | Custom target modules | Seed/dataset composition and staged generation/testing. **Adopt pattern; evaluate sidecar.** |
| Inspect AI | Python | MIT | 0.3.271 — 2026-09-26 [PyPI](https://pypi.org/project/inspect-ai/) | Yes; frequent releases [repo](https://github.com/UKGovernmentBEIS/inspect_ai) | Custom model API or solver can call HTTP | Logs, epochs, caching, scorers and viewer; custom stateful workflow solvers needed. **Candidate backbone, not required.** |
| hypothesis-jsonschema | Python | MPL-2.0 | 0.23.1 — 2024-02-28 [PyPI](https://pypi.org/project/hypothesis-jsonschema/) | Low activity [repo](https://github.com/python-jsonschema/hypothesis-jsonschema) | Generates cases, not an HTTP runner | Use only for schema strategies outside Schemathesis. **Do not make a core dependency.** |
| avidtools | Python | Apache-2.0 | 0.3.2 — 2026-03-19 [PyPI](https://pypi.org/project/avidtools/) | Active enough for optional export [repo](https://github.com/avidml/avidtools) | No target runner; report schema/export | Optional AVID interchange adapter. **Do not use as finding store.** |
| promptfoo | TypeScript / Node | MIT | 0.123.1 — 2026-09-18 (checked 2026-09-27; not re-queried 2026-09-28) [npm](https://www.npmjs.com/package/promptfoo) | Yes [repo](https://github.com/promptfoo/promptfoo) | HTTP provider and session parser | Plugin ideas or isolated sidecar with remote generation disabled. **Conditional; ownership transaction status unverified.** |
| Giskard v3 | Python | Apache-2.0 scan; MIT component packages | giskard 3.0.0 — 2026-08-26 (checked 2026-09-27) [repo](https://github.com/Giskard-AI/giskard-oss) | Yes | Async callable target | Design inspiration; LLM-generated and judged scenarios are costly. **Do not adopt as core.** |
| DeepTeam | Python | Apache-2.0 | 1.0.9 — 2026-08-12 [PyPI](https://pypi.org/project/deepteam/) | Yes [releases](https://github.com/confident-ai/deepteam/releases) | Callback target | Taxonomy reference only; LLM-heavy defaults. **Do not adopt in the inner loop.** |
| Schemathesis | Python | MIT | 4.28.0 — 2026-09-22 (checked 2026-09-28) [PyPI](https://pypi.org/project/schemathesis/) | Yes [repo](https://github.com/schemathesis/schemathesis) | OpenAPI-driven HTTP runner | Contract and stateful API exploration. **Adopt if auth/session/multipart flows fit.** |

**Release conflicts and caveats:** PyPI shows DeepTeam 1.0.9 uploaded 2026-08-12, while the GitHub release page associates v1.0.9 with 2025-11-12; use the PyPI upload date for package availability and flag the tag-date mismatch. [PyPI](https://pypi.org/project/deepteam/), [GitHub releases](https://github.com/confident-ai/deepteam/releases)

**Current version verification record:** PyRIT 1.1.0 (Sep 4); garak 0.17.0 (Sep 9); spikee 0.9.2 (Sep 11); Inspect AI 0.3.271 (Sep 26); hypothesis-jsonschema 0.23.1 (Feb 28, 2024); avidtools 0.3.2 (Mar 19). Each page was checked 2026-09-28. [PyRIT](https://pypi.org/project/pyrit/), [garak](https://pypi.org/project/garak/), [spikee](https://pypi.org/project/spikee/), [Inspect AI](https://pypi.org/project/inspect-ai/), [hypothesis-jsonschema](https://pypi.org/project/hypothesis-jsonschema/), [avidtools](https://pypi.org/project/avidtools/)

**Fact:** `inspect-evals` was 0.22.0 dated 2026-09-25 (checked 2026-09-27; not re-checked 2026-09-28). [inspect_evals repository](https://github.com/UKGovernmentBEIS/inspect_evals)

**Cost interpretation:** PyPI versions and licenses are tool metadata; per-test inference cost is strategy/configuration dependent. PyRIT converter-only transformations can avoid model calls; dynamic attacks and model judges add calls. garak probes can run with static detectors, while spikee can stage static seeds before dynamic cases. Do not quote a cost per test until the specific campaign is measured. [PyRIT](https://github.com/microsoft/PyRIT), [garak](https://github.com/NVIDIA/garak), [spikee](https://github.com/ReversecLabs/spikee)

## 8. Tool integration, benchmarks, defenses and evaluator architectures

### Attack-generation integration detail

**Fact:** PyRIT separates targets, attacks, converters, scorers and memory. Its HTTP target supports a caller-defined HTTP request/response parser, and `HTTPXAPITarget` supports API-style JSON/form/file requests. The target can be wrapped behind an AgentForge-specific Python adapter. [PyRIT HTTP target](https://microsoft.github.io/PyRIT/latest/code/targets/http-target/), [PyRIT target API](https://microsoft.github.io/PyRIT/latest/api/pyrit-prompt-target/), [framework concepts](https://microsoft.github.io/PyRIT/latest/code/framework/)

**Fact:** PyRIT converters transform text or other modalities; some are deterministic and others use a converter target. Model-backed conversion therefore has a separate generation-call cost from sending each resulting case to AgentForge. [PyRIT converters](https://microsoft.github.io/PyRIT/latest/code/converters/converters/), [converter API](https://microsoft.github.io/PyRIT/latest/api/pyrit-converter/)

**Fact:** garak organizes testing as generators, probes, detectors and optional buffs; its REST generator provides an HTTP boundary. Probe expansion and detector selection determine the number of requests and judge calls, so a “case” may represent multiple target attempts. [garak repository](https://github.com/NVIDIA/garak), [garak documentation](https://garak.readthedocs.io/en/latest/)

**Fact:** spikee provides `generate` for datasets from seed collections and transformation plugins, `test` for custom targets, and local basic judges or LLM judges. Its documented dynamic attack modules run only when the static case has not succeeded; retries, iterations, threads and sampling are configurable. [spikee repository and usage](https://github.com/ReversecLabs/spikee)

**Fact:** Promptfoo separates input-generating plugins, delivery strategies and targets. Its configuration records generation requests/tokens when available, supports local generation, and offers `PROMPTFOO_DISABLE_REDTEAM_REMOTE_GENERATION=true`; its default remote generation may send generation context outside the local harness. The number of tests, strategy branches, concurrency and model grader all affect call volume. [Promptfoo architecture](https://www.promptfoo.dev/docs/red-team/architecture/), [configuration and token accounting](https://www.promptfoo.dev/docs/red-team/configuration/), [cost troubleshooting](https://www.promptfoo.dev/docs/red-team/troubleshooting/remote-generation/)

| Tool | Python HTTP-harness integration | Inference/cost shape | W3 fit |
|---|---|---|---|
| PyRIT | In-process HTTP target; custom parser/adapter can map our request, session and response envelope. | Deterministic converter and replay can be zero generation calls; model-backed converters, adversarial generation and LLM scoring add separately countable calls. | Strongest library candidate; leave orchestration, finding store, state oracle and budget enforcement in `redteam/`. |
| garak | Sidecar CLI with REST generator; exchange a bounded corpus/results file and preserve campaign IDs. | Static probes with deterministic detectors may avoid model calls; buffs multiply candidate count; model-based detectors add calls. Measure each probe/detector pairing. | Optional static sweep and seed source; verify its single-message REST semantics before using on a session workflow. |
| spikee | Sidecar `generate` and `test`; implement a custom target module that posts to AgentForge and returns the response. | Dataset transforms can be local; dynamic attacks only run when configured and reached; each iteration/retry and LLM judge can add calls. | Useful for document/indirect-injection seed workflows and staged generation; keep custom target bounded. |
| Promptfoo | HTTP provider or Python provider; use target session parsing for multi-turn behavior. | Records generation request/token usage when available; remote generation can incur external calls. Static strategy/replay lowers generator calls; grading may still call a model. | Optional sidecar/plugin reference only with remote generation explicitly disabled and provider/cost logs checked. |

**Inference:** record separate counters for generation, conversion, target, retry and judging calls. Distinguish one authored seed from its expanded target requests; report both counts and observed tokens/cost. Use a fixed per-case maximum and stop before exceeding the run budget.

**Research pointers:** research the tools implement is identified by paper title and arXiv ID only: “GPTFUZZER: Red Teaming Large Language Models with Auto-Generated Jailbreak Prompts” (arXiv:2309.10253), “DrAttack: Prompt Decomposition and Reconstruction Makes Powerful LLM Jailbreakers” (arXiv:2402.16914), and “AgentVigil: Generic Black-Box Red-teaming for Indirect Prompt Injection against LLM Agents” (arXiv:2505.05849). These are provenance pointers for tool capabilities; no technique-by-technique comparison is made. [GPTFuzzer](https://arxiv.org/abs/2309.10253), [DrAttack](https://arxiv.org/abs/2402.16914), [AgentVigil](https://arxiv.org/abs/2505.05849)

### Agent and indirect-injection benchmarks

| Benchmark / paper | What it tests | Transferable design point and limitation |
|---|---|---|
| BIPIA — “Benchmarking and Defending Against Indirect Prompt Injection Attacks on Large Language Models” (arXiv:2312.14197) | Model use of external content; analyzes failures to distinguish information from instructions and proposes boundary-awareness and reminder defenses. | Use as a source for trust-boundary cases; it is an LLM/content benchmark, not an EHR action workflow. [paper](https://arxiv.org/abs/2312.14197), [official repo](https://github.com/microsoft/BIPIA) |
| InjecAgent — “Benchmarking Indirect Prompt Injections in Tool-Integrated Large Language Model Agents” (arXiv:2403.02691) | Tool-integrated agent cases with distinct user tools, attacker tools, harmful side effects and private-data exfiltration goals. | Model both user-intended work and attacker goal; score the external action/effect, not only response text. [paper](https://arxiv.org/abs/2403.02691) |
| AgentDojo — “A Dynamic Environment to Evaluate Prompt Injection Attacks and Defenses for LLM Agents” (arXiv:2406.13352) | Stateful task environment, paired utility and security cases, attacks and defenses. Its published benchmark contains 97 tasks and 629 security cases. | Best pattern for state-based utility/security oracles and extensible tasks; results are tied to its simulated tools/tasks and must not be presented as AgentForge coverage. [paper](https://arxiv.org/abs/2406.13352), [project](https://agentdojo.spylab.ai/) |
| ASB — “Agent Security Bench: Formalizing and Benchmarking Attacks and Defenses in LLM-based Agents” (arXiv:2410.02644) | Multiple agent scenarios, tools, attack/defense approaches and metrics, including prompt, tool and memory surfaces. | Source categories for threat mapping; breadth of attack/defense methods does not make a single ASR score sufficient. [paper](https://arxiv.org/abs/2410.02644), [official repo](https://github.com/agiresearch/ASB) |
| AgentHarm — “A Benchmark for Measuring Harmfulness of LLM Agents” (arXiv:2410.09024) | Multi-step agent misuse behaviors with synthetic tools and grading rubrics. | Borrow synthetic-tool and task-completion scoring; its malicious-request focus is not a clinical-utility benchmark. [paper](https://arxiv.org/abs/2410.09024) |
| WASP — “Benchmarking Web Agent Security Against Prompt Injection Attacks” (arXiv:2504.18575) | End-to-end attacks in an isolated web environment with realistic web-agent objectives. It distinguishes partial attacker progress from full goal completion. | Report attempted/partial/achieved states separately; an agent may be insecure even when it fails to finish the attacker goal. [paper](https://arxiv.org/abs/2504.18575), [official repo](https://github.com/facebookresearch/wasp) |
| REDAgentBench — “Executable Red Teaming and Faithful Measurement of LLM Agent Systems” (arXiv:2608.10669) | Executable cases run in isolated service sandboxes; verifies effects from service receipts and final-state changes, and identifies visibility/adjudication as separate from actual violations. | Closest pattern for the drill's evidence model: preserve exposure, execution, observation and adjudication separately. The paper's reported systems and benchmark do not establish results for AgentForge. [paper](https://arxiv.org/abs/2608.10669) |

**Fact:** REDAgentBench argues that a single attack-success rate can collapse exposure, execution, observation and adjudication. Its method checks service receipts and final-state changes, making the evidence path explicit. [REDAgentBench](https://arxiv.org/abs/2608.10669)

**Fact:** WASP reports a gap between partial attacker progress and complete attacker-goal success in its benchmark, which it describes as “security by incompetence.” Keep intermediate execution evidence so failures to complete a goal do not erase unsafe behavior. [WASP](https://arxiv.org/abs/2504.18575)

**Fact:** a 2025 benchmark-analysis paper, “Indirect Prompt Injections: Are Firewalls All You Need, or Stronger Benchmarks?” (arXiv:2510.05244), reports that existing agent benchmarks can contain weak attacks, flawed success metrics and implementation bugs, and advocates stronger adaptive cases. **Inference:** before adopting a benchmark subset, audit its oracle against known-positive and clean cases, pin a version, and record modifications. [paper](https://arxiv.org/abs/2510.05244)

### Defenses worth evaluating

| Defense pattern | Published source | Evaluation implication for AgentForge |
|---|---|---|
| Context boundary / instruction hierarchy | BIPIA (arXiv:2312.14197); “The Instruction Hierarchy: Training LLMs to Prioritize Privileged Instructions” (arXiv:2404.13208) | Evaluate as a model/prompt defense, but retain benign contrasts and over-refusal checks; instruction prioritization alone does not authorize a write. [BIPIA](https://arxiv.org/abs/2312.14197), [Instruction Hierarchy](https://arxiv.org/abs/2404.13208) |
| Data/control-flow isolation and capabilities | CaMeL, “Defeating Prompt Injections by Design” (arXiv:2503.18813) | Test whether untrusted retrieved/document content can affect control flow or disclose data through unauthorized channels; evaluate the enforcing boundary and resulting state. [CaMeL](https://arxiv.org/abs/2503.18813) |
| Privilege control over tool calls | Progent, “Securing AI Agents with Privilege Control” (arXiv:2504.11703) | Check tool/action name and argument constraints at execution time; distinguish blocked calls from calls that execute with an unacceptable side effect. [Progent paper](https://arxiv.org/abs/2504.11703), [official implementation](https://github.com/Agentic-AI-Risk-Mitigation/progent) |
| Input/output firewalls at agent-tool boundary | “Indirect Prompt Injections: Are Firewalls All You Need, or Stronger Benchmarks?” (arXiv:2510.05244) | Treat filtering as an evaluated defense layer; test false positives and adaptive cases, and do not rely on benchmark headline scores without reproducing their oracles. [paper](https://arxiv.org/abs/2510.05244) |
| Independent adaptive re-evaluation of out-of-band enforcement | “Adaptive Evaluation of Out-of-Band Defenses Against Prompt Injection in LLM Agents” (arXiv:2606.26479) | Recent work reports one small-scale Progent reproduction against a limited adaptive setup while explicitly leaving stronger attacks open; this supports evaluation discipline, not a general security conclusion. [paper](https://arxiv.org/abs/2606.26479) |

**Inference:** prioritize defenses that constrain observable actions outside the language model—patient authorization, write policy, scope, and confirmation gates—then test model-facing prompt/content filters as an additional layer. This follows the cited design patterns; whether W3 must test or modify these boundaries depends on the PRD.

### Autonomous multi-agent evaluator architectures

**Fact:** AutoRedTeamer's published system uses a strategy-proposer agent to research and propose attack additions and a red-team agent with specialized risk analysis, seed generation, strategy selection, attack memory, evaluation and relevance checks. The paper describes its target as a text LLM and lists extending to agents as future work. It was published in the 39th NeurIPS 2025 proceedings. [NeurIPS 2025 paper](https://papers.nips.cc/paper_files/paper/2025/file/f810a445357d94070669d970a95fc5d8-Paper-Conference.pdf), [arXiv:2503.15754](https://arxiv.org/abs/2503.15754)

**Fact:** Co-RedTeam (arXiv:2602.02164) describes coordinated discovery and validation with execution feedback, code-aware analysis and long-term memory. Its code-aware setting is not a direct match for a strictly black-box HTTP harness. [paper](https://arxiv.org/abs/2602.02164)

**Inference — narrow W3 architecture:** use a deterministic campaign controller around bounded roles: (1) recon/coverage planner proposes cases from exposed metadata and changed contracts; (2) generator emits typed case specifications within a budget; (3) HTTP executor runs only allowlisted targets and records receipts; (4) independent oracle/judge scores read-only evidence; (5) triage/dedup/report role packages confirmed evidence. The controller owns authorization, call limits, checkpoints and final verdict; model agents cannot alter these controls.

**Inference — reject self-modifying runtime scope:** paper-driven attack-library updates can be a separate reviewed maintenance process. Do not let an unattended campaign fetch arbitrary new strategy code and execute it during a Hardening Drill. Promote a candidate only after source review, synthetic fixture validation, budget accounting and a versioned regression case.

**Inference — staged autonomy:** deterministic recon and fixed corpus first; invoke generative roles only for uncovered/high-priority cases; ask an independent verifier to confirm effects; route uncertain/clinical judgments to human review. The division minimizes duplicate agents and keeps a reproducible audit trail.

**Research pointers:** “AutoRedTeamer: Autonomous Red Teaming with Lifelong Attack Integration” (arXiv:2503.15754), “Co-RedTeam: Orchestrated Security Discovery and Exploitation with LLM Agents” (arXiv:2602.02164), and “REDAgentBench: Executable Red Teaming and Faithful Measurement of LLM Agent Systems” (arXiv:2608.10669). These support architectural patterns and measurement cautions, not claims that their systems are validated for AgentForge.

## Gaps and remaining limits

- Attack generation is covered at tool and integration level only; this note deliberately makes no technique-by-technique comparison.
- No W3 PRD exists in the supplied material. The teaser clauses may not map to final acceptance criteria.
- Tool versions and licenses are snapshots; reconfirm when selecting dependencies.

## Unverified and conflict resolutions

- **DeepTeam date:** PyPI's 1.0.9 release page lists 2026-08-12; the GitHub release page lists a 2025-11-12 release. Treat the package upload date as the current distribution fact and preserve the mismatch.
- **CWE index stamp:** the index page says last updated 2024-11-19, while CWE news and the v4.19.1-to-v4.20 diff document 4.20 in 2026. Use the dated release evidence; the index stamp is stale/conflicting.
- **ATLAS technique URL:** direct example path `atlas.mitre.org/techniques/AML.T0051` was reported as 404. Current data source is the versioned YAML; URL pattern remains unverified. Record IDs and versions.
- **AutoRedTeamer venue (resolved 2026-09-28):** the official NeurIPS proceedings PDF identifies the paper as part of the 39th NeurIPS 2025 conference. [NeurIPS proceedings PDF](https://papers.nips.cc/paper_files/paper/2025/file/f810a445357d94070669d970a95fc5d8-Paper-Conference.pdf)
- **Promptfoo acquisition:** March 2026 announcements state “agreed to be acquired” subject to closing. Whether it closed by 2026-09-28 was not established by the current source checks.
- **Llama Guard 4 custom categories:** not confirmed from the prompt-format documentation in the supplied report. Treat it as a standard secondary classifier, not a customized clinical judge.
- **Other open uncertainties:** Raina venue; JudgeBench/JudgeDeceiver/AdaptiveAttackAgent license metadata; JailbreakBench agreement figures; OR-Bench refusal-labeling method; AgentDojo current benchmark-version equivalence; formal SARIF 2.2 status; AIVSS release details/license; publication of the ARIA summary; promptfoo HMAC support; Inspect cache behavior for grader models; Giskard telemetry defaults and tool fit. Verify each against its primary source before relying on it.
- Current checks verified the six requested Python package version/date facts. Promptfoo's raw-report version, current release date, and ownership closing state were not freshly verified.

## Open questions for the W3 PRD

1. What exact target must the drill evaluate: our deployed W2 service, a local candidate build, or a separately provided application? Must every finding be confirmed on a public URL?
2. Does “multi-agent” describe the evaluator architecture, target environment, or both? Are specific frameworks mandatory?
3. What does “system state” mean: source diff, HTTP traces, deployment config, runtime coverage, queue state, or all of these? Which signals are available over HTTP?
4. Which attack classes, identity roles, data flows, upload types, and mutation families are required? Are external benchmark datasets permitted under the synthetic-only constraint?
5. What are the time, request, model-call, spend, concurrency and provider limits? May any generation leave the local environment?
6. What is the independent judge requirement? Does it prohibit shared model providers, shared prompts, or shared state? Which outputs require clinician/SME review?
7. Which report format/taxonomy/severity scheme is required, and what fields, redaction rules, artifact retention and dedup behavior are hard gates?
8. How are planted vulnerabilities validated and hidden from the evaluator? Must they be code mutations, configuration changes, behavioral markers, or supplied hidden cases?
9. What constitutes clinician utility, unacceptable over-refusal, and statistical non-regression? Which benign case set and thresholds are authoritative?
10. What does unattended mean operationally: CI, scheduled run, single CLI command, retry/resume, expected exit codes, and maximum runtime?
11. What evidence must the final claim name: SHA, public URL, hardening-drill run, regression proof, clinician utility result, and manual validation?

## Sources

The following sources support the claims in this note.

### Frameworks, tools, and schemas

- [PyRIT repository](https://github.com/microsoft/PyRIT) · [PyPI](https://pypi.org/project/pyrit/) · [Docs](https://microsoft.github.io/PyRIT/)
- [garak repository](https://github.com/NVIDIA/garak) · [PyPI](https://pypi.org/project/garak/) · [REST generator](https://garak.readthedocs.io/en/latest/garak.generators.rest.html)
- [spikee repository](https://github.com/ReversecLabs/spikee) · [PyPI](https://pypi.org/project/spikee/)
- [promptfoo strategies](https://www.promptfoo.dev/docs/red-team/strategies/) · [HTTP provider](https://www.promptfoo.dev/docs/providers/http/) · [configuration](https://www.promptfoo.dev/docs/red-team/configuration/) · [OpenAI acquisition announcement](https://openai.com/index/openai-to-acquire-promptfoo/) · [Promptfoo announcement](https://www.promptfoo.dev/blog/promptfoo-joining-openai/)
- [Inspect AI repository](https://github.com/UKGovernmentBEIS/inspect_ai) · [PyPI](https://pypi.org/project/inspect-ai/) · [extensions](https://inspect.aisi.org.uk/extensions.html) · [logs](https://inspect.aisi.org.uk/eval-logs.html) · [caching](https://inspect.aisi.org.uk/caching.html) · [scorers](https://inspect.aisi.org.uk/scorers.html)
- [inspect_evals repository](https://github.com/UKGovernmentBEIS/inspect_evals)
- [Giskard OSS](https://github.com/Giskard-AI/giskard-oss)
- [DeepTeam repository](https://github.com/confident-ai/deepteam) · [GitHub releases](https://github.com/confident-ai/deepteam/releases) · [PyPI](https://pypi.org/project/deepteam/)
- [Schemathesis repository](https://github.com/schemathesis/schemathesis) · [PyPI](https://pypi.org/project/schemathesis/) · [checks](https://schemathesis.readthedocs.io/en/stable/reference/checks/) · [stateful testing](https://schemathesis.readthedocs.io/en/stable/explanations/stateful/)
- [Schemathesis documentation](https://schemathesis.readthedocs.io/en/stable/)
- [hypothesis-jsonschema repository](https://github.com/python-jsonschema/hypothesis-jsonschema) · [PyPI](https://pypi.org/project/hypothesis-jsonschema/)
- [avidtools repository](https://github.com/avidml/avidtools) · [PyPI](https://pypi.org/project/avidtools/) · [AVID Python SDK](https://docs.avidml.org/developer-tools/python-sdk)
- [garak documentation](https://garak.readthedocs.io/en/latest/) · [PyRIT HTTP target](https://microsoft.github.io/PyRIT/latest/code/targets/http-target/) · [PyRIT target API](https://microsoft.github.io/PyRIT/latest/api/pyrit-prompt-target/) · [PyRIT framework](https://microsoft.github.io/PyRIT/latest/code/framework/) · [PyRIT converters](https://microsoft.github.io/PyRIT/latest/code/converters/converters/) · [PyRIT converter API](https://microsoft.github.io/PyRIT/latest/api/pyrit-converter/)
- [Promptfoo Python provider](https://www.promptfoo.dev/docs/providers/python/) · [architecture](https://www.promptfoo.dev/docs/red-team/architecture/) · [generation cost/troubleshooting](https://www.promptfoo.dev/docs/red-team/troubleshooting/remote-generation/) · [npm package](https://www.npmjs.com/package/promptfoo) · [repository](https://github.com/promptfoo/promptfoo)

### Standards and reporting

- [OWASP Top 10 for LLM Applications 2025](https://genai.owasp.org/llm-top-10/)
- [OWASP Top 10 for Agentic Applications 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
- [MITRE ATLAS data](https://github.com/mitre-atlas/atlas-data) · [releases](https://github.com/mitre-atlas/atlas-data/releases) · [v2026.09](https://github.com/mitre-atlas/atlas-data/releases/tag/v2026.09)
- [CWE 2026 news](https://cwe.mitre.org/news/archives/news2026.html) · [CWE 4.19.1 to 4.20 diff](https://cwe.mitre.org/data/reports/diff_reports/v4.19.1_v4.20.html) · [CWE-1427](https://cwe.mitre.org/data/definitions/1427.html) · [CWE-1426](https://cwe.mitre.org/data/definitions/1426.html) · [CWE-1446](https://cwe.mitre.org/data/definitions/1446.html) · [CWE-639](https://cwe.mitre.org/data/definitions/639.html) · [CWE-200](https://cwe.mitre.org/data/definitions/200.html)
- [CVSS v4.0 specification](https://www.first.org/cvss/v4.0/specification-document) · [FAQ](https://www.first.org/cvss/v4.0/faq) · [MSRC AI bug bar](https://www.microsoft.com/msrc/aibugbar)
- [SARIF v2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html) · [Errata 01](https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/sarif-v2.1.0-errata01-os-complete.html)
- [NIST AI 100-2 E2025](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-2e2025.pdf) · [NIST AI 600-1](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.600-1.pdf)

### Research papers and benchmark sources

- [RESTler](https://arxiv.org/abs/1806.09739) · [RESTler checks](https://github.com/microsoft/restler-fuzzer/blob/main/docs/user-guide/Checkers.md) · [Schemathesis paper](https://arxiv.org/abs/2112.10328)
- [AFLFast](https://doi.org/10.1145/2976749.2978428) · [AFLGo](https://doi.org/10.1145/3133956.3134020) · [GPTFuzzer](https://arxiv.org/abs/2309.10253) · [AgentVigil](https://arxiv.org/abs/2505.05849)
- [LAVA](https://www.ieee-security.org/TC/SP2016/papers/0824a110.pdf) · [Magma](https://arxiv.org/abs/2009.01120) · [Magma repository](https://github.com/HexHive/magma) · [mutation testing survey](https://doi.org/10.1109/TSE.2010.62) · [mutants and real faults](https://doi.org/10.1145/2635868.2635929)
- [AgentDojo](https://arxiv.org/abs/2406.13352) · [FinBot CTF](https://github.com/OWASP-ASI/finbot-ctf) · [Cybench](https://arxiv.org/abs/2408.08926) · [CVE-Bench](https://arxiv.org/abs/2503.17332)
- [MT-Bench / Chatbot Arena judging](https://arxiv.org/abs/2306.05685) · [JudgeBench](https://arxiv.org/abs/2410.12784) · [Judging the Judges](https://arxiv.org/abs/2406.12624) · [LLM Evaluators Recognize and Favor Their Own Generations](https://arxiv.org/abs/2404.13076) · [Raina et al.](https://arxiv.org/abs/2402.14016)
- [HarmBench](https://arxiv.org/abs/2402.04249) · [StrongREJECT](https://arxiv.org/abs/2402.10260) · [Llama Guard 4 model card](https://huggingface.co/meta-llama/Llama-Guard-4-12B)
- [XSTest](https://arxiv.org/abs/2308.01263) · [HealthBench](https://arxiv.org/abs/2505.08775) · [MedHELM](https://arxiv.org/abs/2505.23802) · [MedSafetyBench](https://arxiv.org/abs/2403.03744)
- [On Evaluating Adversarial Robustness](https://arxiv.org/abs/1902.06705) · [The Attacker Moves Second](https://arxiv.org/abs/2510.09023) · [Adaptive Attacks Break Defenses Against Indirect Prompt Injection](https://arxiv.org/abs/2503.00061) · [Lessons From Red Teaming 100 Generative AI Products](https://arxiv.org/abs/2501.07238) · [Gemini indirect prompt injection report](https://arxiv.org/abs/2505.14534)
- [AgentDojo project](https://agentdojo.spylab.ai/) · [BIPIA](https://arxiv.org/abs/2312.14197) · [BIPIA repository](https://github.com/microsoft/BIPIA) · [InjecAgent](https://arxiv.org/abs/2403.02691) · [Agent Security Bench](https://arxiv.org/abs/2410.02644) · [ASB repository](https://github.com/agiresearch/ASB)
- [AgentHarm](https://arxiv.org/abs/2410.09024) · [WASP](https://arxiv.org/abs/2504.18575) · [WASP repository](https://github.com/facebookresearch/wasp) · [REDAgentBench](https://arxiv.org/abs/2608.10669) · [benchmark critique](https://arxiv.org/abs/2510.05244)
- [Instruction Hierarchy](https://arxiv.org/abs/2404.13208) · [CaMeL](https://arxiv.org/abs/2503.18813) · [Progent](https://arxiv.org/abs/2504.11703) · [Progent implementation](https://github.com/Agentic-AI-Risk-Mitigation/progent) · [out-of-band defense evaluation](https://arxiv.org/abs/2606.26479)
- [AutoRedTeamer, NeurIPS 2025 proceedings](https://papers.nips.cc/paper_files/paper/2025/file/f810a445357d94070669d970a95fc5d8-Paper-Conference.pdf) · [AutoRedTeamer arXiv:2503.15754](https://arxiv.org/abs/2503.15754) · [Co-RedTeam](https://arxiv.org/abs/2602.02164)
- [FinBot CTF OWASP page](https://genai.owasp.org/resource/finbot-agentic-ai-capture-the-flag-ctf-application/) · [DrAttack](https://arxiv.org/abs/2402.16914)

### Repository-specific references

- [AgentForge plan](PLAN.md) · AgentForge architecture and HTTP server: `W2_ARCHITECTURE.md`, `agentforge/src/server.js` in `agentforge-week1` · [Generated schemas (vendored)](../vendor/agentforge-schemas/)
- The W3 idea bank (`.scratch/assignments/w3-idea-bank.md`) is gitignored and speculative; it is a local planning aid, not an authoritative requirement.
