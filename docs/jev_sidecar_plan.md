# Jev disclosure sidecar: session decisions and implementation plan

Status: research plan; no production-hook behavior change.
Recorded: 2026-09-19. Repository baseline reviewed: `3677b591ce600aff647c190688de9a7d2e6d8e5f`.

## Decision

Test whether TypeSafe's Jev can classify the disclosure behavior of visible tool operations across languages and interfaces. Start with a standalone, synthetic 100-scenario benchmark. Do not integrate Jev into VEIL's working hook until the benchmark and a subsequent shadow trial justify it.

The user-facing promise is: **Let the agent work with protected data, while controlling what reaches model context.** Configuration should describe protected sources and permitted disclosures, not every tool's syntax.

The experiment lives in [`experiments/jev-disclosure`](../experiments/jev-disclosure/README.md). Its scenario catalog, questions, thresholds, runbook, and runner are research artifacts, not an authorization mechanism.

## What this session established

1. Jev's value here is generic semantic interpretation. A SQL parser per integration is not the product. A Python script can contain SQL; a CLI can send JSON to an MCP service; a filesystem operation can emit records. The question is the information exposed, not the wrapper.
2. Reading a complete dataset inside an approved local process is not the same as exposing that dataset to a model. Counts, schema, approved structural summaries, and explicitly authorized bounded samples must be distinguishable from bulk records.
3. A sample is still disclosure. Approval, field restrictions, cumulative allowance, and byte limits matter. Neither `LIMIT 1` nor one JSON result proves a small disclosure. Repackaging, encoding, or returning a record collection through an aggregate function does not remove source content.
4. Jev evaluates a visible invocation and trusted context, not actual private rows or tool results. Give it code/arguments where safely available, not a precomputed interpretation that answers the question for it.
5. Operation text can itself contain secrets, private literals, record values, or sensitive names. A local pre-screen must produce an independently admissible request before any Jev call. Failed screening means no submission, never fallback to unscreened input.
6. Unknown implementation is different from unfamiliar syntax. An opaque remote job or unavailable script must be allowed to produce REVIEW. We do not expect a model to reconstruct unavailable behavior.
7. The classification should influence eventual allow/deny/review decisions. Existing hard denials and actual user permissions remain authoritative; model probabilities do not manufacture permission.
8. Low configuration burden is a requirement, not an afterthought. Avoid a per-tool policy manual or mandatory giant tool registry. Source protection, allowed information classes, optional samples, and uncertainty handling should be the main choices.
9. The hidden-model/authorship-detection idea is out of scope. Deterministic is not synonymous with safe: a deterministic remote service can disclose data, and a local tool can return raw records to the main model.
10. Borrow architectural ideas from `kbhuw/jev-sift`, not its implementation or broad file-access defaults. Its typed questions, compact judgments, bounded concurrency, and explicit errors are useful patterns. Its content-to-hosted-model relevance screening is not VEIL's privacy boundary.
11. Airlock remains complementary: it records boundary inputs and policy claims. Jev's fallible judgment and Airlock's mechanical findings must not be collapsed into a claim that a model proved a request safe.

## Hypothesis and non-goals

Hypothesis: a small fixed question set can separate permitted local processing/reduced output, authorized samples, prohibited disclosure, and insufficient visibility across unseen combinations of tools and languages at useful latency and interruption rates.

Not included: executing fixture operations; sending client data; detecting hidden model use; proving arbitrary programs safe; certifying anonymity of aggregates; adding a production SQL parser; replacing OS permissions, database permissions, network restrictions, or deterministic VEIL denials; enabling a hosted classifier by default; automatically installing hooks; running a live benchmark in this authoring session.

## Current integration boundary

At the reviewed baseline, VEIL handles Read/Grep/Bash and uses path extraction, sensitivity packs, and policy evaluation. It does not yet offer generic MCP SQL/output protection. `src/hook.rs` rejects unsupported tool names; `src/lib.rs` can select allow when no candidate outcomes exist; `src/evaluator.rs` contains fail-open internal-error/timeout branches. These are source observations, not a complete audit or demonstrated exploit. Do not silently alter these behaviors as part of the experiment.

A future generic adapter must preserve the actual tool name, arguments, output destination, and available implementation context. A hook sees top-level operations, not every syscall or remote internal action. Coverage of nested scripts and results must be documented, not inferred from the word "hook".

## Proposed sidecar contract

Input, assembled locally:

- The visible invocation: tool identity plus arguments, code where available, and nesting as it actually appears.
- Trusted source labels and endpoint/output routing. These are facts from the operator or local configuration, not declarations inside agent-generated code.
- The disclosure policy: permitted structural output; sample approval and remaining allowance; excluded fields; explicit destination restrictions.
- Relevant compact state, such as a protected intermediate artifact or a previous sampling allowance consumption. Do not send the whole conversation.
- Evidence of screening and any missing context. Sensitive identifiers can be stable placeholders; do not redact operators or limits that determine semantics.

Excluded from Jev requests: gold labels, expected probabilities, rationales, scenario IDs/family names that reveal labels, raw protected values, credentials, response payloads awaiting classification, and hidden test metadata.

Output: per-question probabilities, model ID, request identity, latency, usage, and an explicit validity/error state. A separate deterministic experimental decision policy maps valid probabilities to ALLOW/DENY/REVIEW. A probability is not a calibrated failure rate for this deployment.

Proposed questions: source-content exposure; permitted reduction/local-only processing; effective whole-operation bound; insufficient visibility; and a separate policy-violation question. The fifth question is intentional: the first four alone cannot distinguish the same bounded sample with approval from one without approval. Do not add these probabilities together or treat them as mutually exclusive.

## Pre-screening before the classifier

The benchmark uses only authored synthetic scenarios and planted canaries. Fixture-provided substitutions are an oracle-assisted test of preserving semantics during screening, NOT an implementation of general private-data detection. The runner must say so.

For actual integration, local screening needs a separately evaluated threat model. It should minimize fields, replace known protected values consistently, block credentials/embedded datasets, preserve structural meaning, and refuse when admissibility cannot be established. Private meaning can survive removal of identifiers; regex matching is not a general proof of safety. Screening must inspect the complete outbound request, including policy/context and questions, not just the command field. Screening must occur even in shadow mode.

Tests distinguish: (a) private values excluded from outbound bytes, (b) adequate operation semantics retained, and (c) safe refusal when those aims conflict. Unsupported encodings, opaque code, excessive input, or incomplete coverage should not be truncated into apparent safety.

## Benchmark design

Create 100 synthetic fixtures in 20 families of five. Keep each family in only one split: 60 development and 40 holdout. Include SQL, MCP JSON, Python, shell/CLI, filesystem, nested operations, sample-policy contrasts, misleading names/comments, record-packing aggregates, local-only processing, cumulative samples, output-side effects, missing implementations, and pre-screen canaries.

Gold labels are author judgments under the fixture policy, not established truth. Review them before live evaluation. Null per-question gold means genuinely indeterminate; score visibility and disposition without pretending the hidden outcome is known. Labels/rationales never enter a request. The public holdout is a procedural holdout, not a secret independent test set; once used to edit prompts it is development data and needs replacement.

One request per scenario contains all fixed questions. Pin a versioned model, not `jev-latest`. Capture exact screened request bytes and request/response model IDs. Do not silently retry against another model. Freeze question/threshold/corpus artifacts before holdout. Repeat held-out cases for stability; report repeated calls as correlated, not additional independent samples.

Success must include useful uninterrupted work, not just blocking everything. Report false ALLOW among DENY gold, false ALLOW among REVIEW gold, unnecessary DENY/REVIEW among ALLOW gold, review rate, per-family/wrapper results, Brier scores for non-null labels, question distributions, and p50/p95 end-to-end latency. Separate model-only latency, screening time, network failures, and screening refusal from semantic correctness. Transport failures become REVIEW; never count them as successful model detection.

Provisional gates for considering shadow integration: zero held-out unsafe ALLOWs; all known screening canaries withheld; at least 80% automatic ALLOW on permitted held-out cases; at least 80% REVIEW on opaque held-out cases; all transport/invalid-response cases REVIEW; p95 under 500 ms at serial concurrency and under 1 second at the tested concurrency. These are proposed product targets, not measured results. Freeze any revisions before holdout. Zero observed misses in a small corpus is not proof of zero risk; report denominators and confidence limits.

## Implementation stages

### 0. Research package (this change)

Documentation, corpus, pinned questions, exploratory thresholds, standalone runner, and offline tests. No production Rust modules, dependencies, config schema, hooks, or default permissions change. Runner default is offline preparation. Live requests require an explicit command and an API key supplied outside repository files.

### 1. Offline review and live development run (operator execution)

Review labels and policies. Run self-tests and request preparation; inspect the actual outbound requests. Supply `JEV_API_KEY` or `TYPESAFE_API_KEY` via the environment. Run development only, inspect misclassifications, revise questions, and choose thresholds. Record all revisions, not only the best run.

### 2. Frozen holdout

Use a fixed model, corpus, questions, and thresholds. Include repetitions for stability. Report every skipped, refused, errored, and completed scenario. Do not tune on holdout and retain the "held out" claim.

### 3. Shadow sidecar

Only after acceptable results, add an opt-in observer beside existing VEIL handling on approved operations. No decisions change yet. Record marginal detections and false alarms versus existing VEIL. Benchmark standalone results alone do not establish marginal VEIL improvement.

### 4. Conservative enforcement

Hard denials always win. Jev cannot grant samples or override existing protected-read denials. Unknown/invalid/timeout review must not inherit evaluator fail-open handling. Review decisions become human approval or denial according to the host; no spontaneous grants. Keep a kill switch that returns to unchanged baseline protection, not unrestricted operation. Caches must include operation, context, permissions, source/implementation identity, model, and question/policy versions; stale grants are unsafe.

### 5. Broader coverage and output control

Add generic tool adapters and optional local output holding where the host can prevent release before model ingestion. Do not claim a post-tool notification retracts information already exposed. Track protection through intermediate artifacts and cumulative sampling. Sample record/byte counters and explicit permissions are deterministic responsibilities, even when Jev identifies the operation's intent.

## Evidence and reproducibility

Retain screened requests, typed responses, errors, policy/question/model versions, corpus split, execution parameters, request identifiers, timestamps, and results. Keep run directories local and ignored by Git. An eventual Airlock adapter may attest Jev's requests. The experiment's logs are not an Airlock manifest or a guarantee of request safety.

No client-specific names, datasets, paths, contracts, or full conversation transcript should be committed to this public repository. This document records the design decisions, not private source material.

## References (checked 2026-09-19)

- [TypeSafe HTTP API](https://docs.typesafe.ai/api): `POST /v1/systemone`, `state`, `questions`, `answers`.
- [Noul](https://docs.typesafe.ai/primitives/noul): yes probabilities; no separate confidence field.
- [Models](https://docs.typesafe.ai/models): pinned `jev-1.13.0` and moving aliases.
- [Jev limitations](https://docs.typesafe.ai/model-jaggedness/jev-1.13): indirection, adversarial framing, and irrelevant context.
- [VEIL baseline hook](https://github.com/cmdrvl/veil/blob/3677b591ce600aff647c190688de9a7d2e6d8e5f/src/hook.rs), [evaluator](https://github.com/cmdrvl/veil/blob/3677b591ce600aff647c190688de9a7d2e6d8e5f/src/evaluator.rs), [hook flow](https://github.com/cmdrvl/veil/blob/3677b591ce600aff647c190688de9a7d2e6d8e5f/src/lib.rs).
- [Jev Sift](https://github.com/kbhuw/jev-sift): conceptual reference only; no source copied.
