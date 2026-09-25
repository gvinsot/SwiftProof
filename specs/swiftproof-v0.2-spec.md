# SwiftProof V0.2 — Evidence-driven review of AI-assisted changes

Extended by [swiftproof-v0.4-spec.md](swiftproof-v0.4-spec.md). §2 of that spec lists the only refinements; every other rule here remains binding.

**Status:** contract for the first implemented release.  
**Implementation:** portable Go CLI, standard library only.  
**Outputs:** `CONFIDENCE_REPORT.md`, `confidence-report.json`, retained experiment artifacts.

This revision refines the [initial proposal](verifiable-ai-code-v0-spec.md) into explicit comparison semantics, trust boundaries, evidence thresholds, budgets and acceptance criteria. It separates delivered capabilities from future work.

## 1. Product intent

Help developers spend less time reconstructing an AI-generated PR and more time judging its risky behavior. Identify the exact change, expose what was checked, preserve uncertainty and suggest traceable review locations.

The tool MUST NOT present correctness probabilities, equate passing tests with safety, automatically approve changes or treat model speculation as executable proof. A smaller review surface is not a success if it hides important regressions. Public CLI and documentation use English; freeform intent/hypotheses may use any language.

## 2. Architecture

```text
immutable Git base/head
        |
        +-- deterministic analysis ------------------+
        +-- isolated configured checks               |
        +-- optional reviewer <--> controlled tools -+--> evidence validation
                                                            |
                                                  targeted JSON + Markdown
```

Static lint MUST work without Docker, network, model or API key. Repository code executes only in the sandbox. Provider traffic is separate from sandbox networking. For `review`, a nonempty `reviewer.model` in trusted baseline policy or explicit `--config` enables investigation automatically. The default empty model makes no provider calls. Explicit `--reviewer=false` disables investigation for that run; `--reviewer` requires a configured model. `lint` MUST NOT activate a configured reviewer and rejects an explicit request to run one. Candidate policy MUST NOT enable or redirect provider traffic.

## 3. Comparison and trusted policy

- `--base main --head HEAD` compares the unique merge base to the head.
- `BASE..HEAD` or `--exact` compares exact endpoints; `BASE...HEAD` selects the merge base.
- Resolve refs once to full immutable IDs; retain requested refs and resolved IDs in the report.
- Only committed Git objects are analyzed. Ignore working-tree edits and untracked files.
- Parse NUL-delimited path metadata; preserve renames, old-side deletion locations, binaries and unusual names. Disable external diff/textconv.
- Ambiguous merge bases, missing history, malformed revisions and size limits MUST NOT silently produce a clean partial report.
- Load default policy from the resolved baseline. Candidate policy edits are reviewable changes and cannot alter their own checks or privileges.
- `--config PATH` explicitly selects a trusted local override.

## 4. Deterministic signals

Every signal includes a stable ID, kind, severity, path, side, line range, summary and evidence. Output order is deterministic. Signals are risks to investigate, not findings.

Delivered analysis includes:

1. Go AST comparisons of exported declarations/signatures and changed security/payment-sensitive function bodies using standard Go parsing facilities. Sensitive function names/receiver types are contextual heuristics, not vulnerability proofs; comment/formatting-only body changes are ignored. This is syntactic analysis, not whole-program type checking.
2. Lexical risk rules for network/DB/auth operations, removed validation/error handling, unsafe constructs/type suppressions, TODO/FIXME, branch growth and dependency manifests. Branch counts are not cyclomatic complexity.
3. Trusted sensitive-path patterns, binary/deletion/structural changes, and missing associated **changed tests**. The latter MUST NOT claim missing test coverage. A signal MAY state that a changed line was not executed only when it is derived from a coverage profile produced by a recorded sandbox run, retained as a hashed artifact and mapped to that file without inference; such a signal MUST say executed, never tested, verified or correct, and MUST distinguish a line that no instrumented block covers, and a line that was not measured, from a line that was not executed. An absent, truncated, unparsable or unmapped profile MUST render as not measured.

TypeScript semantic AST analysis, resolved fan-out and cross-file architecture rules are deferred. Heuristic evidence must be labelled. Parse failures and skipped oversized files remain visible.

Bound Git streams and source reads, avoid subprocesses per diff line, use bounded parallel analysis and stable sorting. Current bounds: 64 MiB Git output, 2 MiB analyzed source files, 100,000 files/tree entries and 250,000 parsed diff lines including context. Exhaustion is an explicit failure or analysis-limit signal.

## 5. Controlled tool surface

```text
read_file(path, start?, end?)
get_diff(path?)
search_code(query)
find_references(symbol)
inspect_symbol(symbol)
run_tests()
run_test(path)
run_typecheck()
run_build()
create_test(path, content, description?)
run_generated_test(test_id)
delete_generated_test(test_id)
```

`harness.ToolDefinitions` is the authoritative JSON schema. Reference/symbol lookup is textual in this version. Tools do not expose arbitrary shell or network requests.

Paths stay within sanitized snapshots: reject absolute paths, traversal, metadata directories and symlink escapes. Credential filenames are excluded. Bound reads, searches and responses; audit accepted/rejected calls. Mask common secrets, but document masking as best effort.

Trusted commands use argv arrays, without implicit shell interpretation. `{file}`/`{package}` substitution is limited to validated test paths. Generated tests cannot overwrite existing files. Creation counts consume the budget even after deletion.

## 6. Execution boundary

Require a preloaded trusted Docker image; do not pull/build images from candidate instructions. Each execution uses fresh disposable state, a sanitized read-only source mount, and a bounded ephemeral workspace copy. A coverage run MAY return one coverage profile to the host as a length-declared framed payload on the container's standard output, separately bounded and separate from the captured log. It introduces no writable host path, no additional mount, no volume and no post-exit container access; a payload whose declared length is not matched exactly is discarded and the measurement is reported as not measured.

Run non-root with read-only root filesystem, dropped capabilities, no new privileges, and CPU/RAM/PID/time/output limits. Do not mount the working checkout or Docker socket or forward host secret variables. Disable networking unless trusted policy and explicit `--allow-network` both enable it. Force-remove timed-out containers and clean temporary host snapshots on normal exit/cancellation.

No host-execution fallback. Missing Docker, image or toolchain is incomplete execution, never PASS. Dependencies are prepared outside review. Images are part of the trusted environment and should be digest-pinned. Docker isolation is not a defense against kernel/runtime vulnerabilities; hostile multi-tenant use may require disposable VMs.

Export exact Git blobs, bypassing checkout filters/export attributes. Execution snapshots reject symlinks/submodules rather than silently alter semantics. Limits: 512 MiB per file and 2 GiB per snapshot.

## 7. Evidence classification

Hypotheses contain title, severity, location, rationale, evidence IDs and status:

| Status | Required observation | Meaning |
| --- | --- | --- |
| `REPRODUCED` | Same generated-test command; baseline PASS and candidate FAIL; recorded differential evidence without recognized startup/infrastructure failure | An experiment distinguishes the change. Its assertion/relevance still requires human judgment. |
| `NOT_REPRODUCED` | Generated test passes on baseline and candidate | This experiment did not reproduce the suspicion. |
| `DISMISSED` | Recorded source observation plus explicit rationale | An investigation explanation, not correctness proof. |
| `UNVERIFIED` | Default for missing/fabricated evidence, timeout, budgets, unavailable dependencies, inconclusive baseline or unsupported claim | More investigation or human judgment needed. |

The report layer independently validates evidence/check IDs and matching commands. Models cannot create evidence records or check outcomes. Existing test failures alone are not demonstrated regressions introduced by the PR. Retain reproduced test source and SHA-256 artifacts.

In V0.2, validated generated-test execution is implemented for Go: parse test declarations, select exact generated test names, disable cached results and inspect structured `go test -json` events. Missing, skipped or unrelated test results cannot support reproduction. Other frameworks may execute experiments but remain `UNVERIFIED` until an adapter can validate equivalent named-test execution.

Recognized compilation/startup errors are unverified. Arbitrary frameworks can emit unfamiliar failures; reports preserve the redacted observation and MUST NOT imply a universally validated behavioral oracle. Even a differential test can assert the wrong expected behavior.

## 8. Reviewer protocol and budgets

The optional provider uses Chat Completions function calling. Send bounded sanitized context and tool observations. Require remote HTTPS; allow HTTP on loopback. Refuse redirects and do not send provider keys into repository processes.

Automatic selection MUST use the same trusted configuration and evidence validation as explicit selection. A configured endpoint alone or an environment API key alone MUST NOT enable investigation. Validate active provider settings before invoking the harness; permit an explicit disabled reviewer without contacting or validating its endpoint. Empty changes skip provider calls. Provider failures retain the deterministic report with an explicit incomplete-investigation entry. `--checks=false` skips initial checks only; reviewer-requested execution remains sandboxed. `--no-network` restricts sandbox traffic, not provider traffic; combine with `--reviewer=false` to disable both.

Repository text, PR intent and tool output are untrusted data. Prompt instructions favor counterexamples and reject embedded instructions; actual enforcement is the tool boundary.

Defaults: 20 iterations, 10 test creations, 600 seconds total sandbox runtime, 120 seconds per command, 64 KiB captured output, 1 GiB RAM and 2 CPUs. Provider request/response bytes, completion size and total calls have separate limits. Budget exhaustion becomes an explicit unverified area.

## 9. Reports and surface calculation

Canonical versioned JSON fields: `version`, `tool_version`, `generated_at`, `change`, `linter`, `checks`, `hypotheses`, `evidence`, `reproduced_issues`, `unverified`, `review_targets`, `review_surface`, `coverage`, `artifacts`, `audit`, `exit_code`.

Markdown contains Change Summary, Automated Checks, Investigation Summary, Reproduced Issues, Unverified Areas, Suggested Human Review, Review Surface and Changed-line Execution. Escape repository/model text. Sanitize disk/provider output and mask entire sensitive-file diff bodies.

Targets use file + old/new side + inclusive range. Merge overlapping targets and count each changed line once. Denominator = additions + deletions; exclude context and unavailable binary line counts. Deletions point to baseline coordinates. `0 / N` focused lines never means no review is necessary. Binary-only changes remain reviewable despite a zero line denominator.

Replace each report file atomically. Re-rendering imported JSON does not authenticate it. Reports are unsigned audit records, not attestations.

## 10. CLI, configuration and CI

```sh
swiftproof init
swiftproof lint --base main
swiftproof review --base main --ci
swiftproof review main..HEAD                  # uses the configured reviewer automatically
swiftproof review main..HEAD --reviewer=false # skip the configured reviewer
swiftproof report
```

Strict versioned JSON (`.swiftproof.json`) avoids extra runtime dependencies and ambiguous shell strings. Unknown fields/invalid bounds fail. Generated defaults are starting points; projects configure their actual checks and prepared image.

The optional `coverage` command key enables changed-line execution measurement. Its argv MUST contain the token `{coverage_out}` exactly once; the tool expands that token to the in-container profile path and MUST NOT append a coverage flag of its own, so the executed argv equals the reviewed argv. Measurement is Go-only in this version and `swiftproof init --language go` seeds `["go","test","-covermode=count","-coverprofile={coverage_out}","./..."]`; other languages seed no coverage command. The command runs last and IN ADDITION to `test`, against the same `sandbox.max_runtime_seconds` budget. An absent key is `not_configured`, not a failure.

Release ordering is mandatory. Policy decoding uses `DisallowUnknownFields` and validates command names against a whitelist, so a policy containing the `coverage` key makes an OLDER binary exit 3; the released v0.1.0 whitelist has four command names. The key MAY only be committed to a base-branch policy after a release whose binary accepts it has been published and CI has been re-pinned to that release.

Exit codes: `0` completed without reproduced high/critical issue; `1` reproduced high/critical issue; `2` human review required with `--ci`; `3` argument/configuration/comparison error; `4` operational analysis/harness/output error. Outside CI, unresolved areas may return `0`; document this distinction.

CI uses trusted pinned binaries/images, complete Git history and read-only credentials. Upload JSON/Markdown/artifacts even on failure. Keep provider secrets outside candidate execution. PR comment publishing and automatic approval are deferred.

## 11. Acceptance and product validation

- Static lint works with Git and one binary, without an account or Docker.
- A trusted configured model automatically runs the reviewer; absent models, explicit disabling, lint and empty changes make no provider calls. Candidate-only provider settings never enable it. Provider failures preserve static results and record incomplete investigation.
- Real Git fixtures cover additions, deletions, renames, binaries, immutable refs and baseline policy trust.
- Fabricated/duplicate evidence IDs cannot produce reproduced issues.
- Tests distinguish differential failure, both-pass, both-fail, setup failures and timeouts.
- Traversal, output floods, unauthorized tools, redirects, sensitive inputs and Markdown injection are tested.
- Reports agree on evidence and deduplicated surface counts, including deletions.
- CI builds/tests on Linux/Windows/macOS; a supported runner performs race checks and optional real container integration.
- Performance measurements identify workload/environment/scope; do not extrapolate microbenchmarks into end-to-end or human-review speed claims.

Product validation remains open: measure actual review duration, missed important regressions, usefulness of signals and provider cost across representative real PRs against reviewers using original diffs/tests. Optimize useful evidence, not minimal displayed line counts.

## 12. Later work

Semantic TypeScript analysis, non-Go coverage formats, base-side coverage comparison and coverage regression detection on unchanged code, symbol indexes, property/mutation testing, differential existing suites, commit/policy/image-keyed caching, SARIF, signed attestations and PR platform adapters are future extensions, not current capabilities.
