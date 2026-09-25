# SwiftProof

**Spend review time on the changes that need your judgment.**

SwiftProof is a Go CLI for reviewing AI-assisted pull requests. It maps Git changes to risk signals, optionally runs isolated checks and adversarial tests, and produces a focused review plan with traceable evidence.

It works without an AI provider. It does not assign confidence percentages or automatically approve PRs. Passing tests and a small review surface are not correctness guarantees.

## Quick start

Download a binary for Windows, Linux or macOS from [GitHub Releases](https://github.com/gvinsot/SwiftProof/releases). Git is required at runtime. Docker with Linux containers is required only to execute repository code.

To build from source, install Go 1.23+ and run from the `app` directory of the repository:

```sh
go build -o swiftproof ./cmd/swiftproof
go test ./...
```

To build Windows amd64 **and Linux amd64/arm64** together, run from the `app` directory on any supported host:

```sh
go run ./tools/build
```

Binaries are written to `dist/windows-amd64/swiftproof.exe`, `dist/linux-amd64/swiftproof` and `dist/linux-arm64/swiftproof`. The same command produces portable ZIP/tar.gz archives and `dist/SHA256SUMS`. Every successful CI run retains these archives as the `swiftproof-build` artifact.

Put the binary on your PATH, then run `swiftproof lint --base main` in a Git repository. Windows builds produce `swiftproof.exe` when using `go build ./cmd/swiftproof`. The [release workflow](docs/RELEASE.md) prepares portable archives for distribution.

Open `.swiftproof/CONFIDENCE_REPORT.md`; see a [real example report](examples/CONFIDENCE_REPORT.md). Its companion `confidence-report.json` contains commit IDs, changed lines, signals, checks, hypotheses, evidence, audit events and artifact hashes. Add `.swiftproof/` to your project's `.gitignore`.

```sh
swiftproof init
# Review .swiftproof.json and commit it to your base branch.
swiftproof review --base main --ci
```

Checks require an **image containing the toolchain and project dependencies**: preload it, or let the trusted base-branch policy derive it with an optional `prepare` command ([dependency preparation](docs/PREPARE.md)). SwiftProof never pulls images and never installs dependencies from candidate content. For a Go project without third-party dependencies, preload the default image in a trusted environment:

```sh
docker pull golang:1.26-bookworm
swiftproof review --base main
```

Use `--config .swiftproof.json` to explicitly try the local policy before committing it. Missing Docker or images produce an operational error; execution never falls back to your host.

**See what needs your attention, even when tests pass.** In this [real example report](examples/CONFIDENCE_REPORT.md), all three checks passed, but SwiftProof highlighted a changed authorization function for human review. No AI provider was used. Excerpt from the generated `.swiftproof/CONFIDENCE_REPORT.md`:

```markdown
## Automated Checks

- **PASS** test (check-1; exit 0; 6646 ms)
- **PASS** typecheck (check-2; exit 0; 5425 ms)
- **PASS** build (check-3; exit 0; 599 ms)

## Suggested Human Review

- **high** auth.go:4–4 (new): Authentication or authorization function body changed
- **low** auth.go:4–4 (old): No nearby test file changed

## Review Surface

Focused review: **2 / 2 changed lines**.
```

Start with the flagged lines and the reason for each review target. These signals guide your review; they do not establish a confirmed bug.

## Capabilities

- Immutable Git comparisons: renames, deletions, binaries and merge-base semantics.
- Go AST comparison of exported declarations and changed security/payment function bodies, plus labelled lexical risk signals and branch-growth heuristics across text files.
- Signals for sensitive paths, dependencies, network/DB calls, authentication, removed validation/error handling, unsafe constructs, missing associated changed tests, and added Go lines that a recorded coverage run did not execute.
- Configured test, typecheck and build commands executed as argv arrays in disposable containers.
- An optional reviewer with bounded source/search/test tools and temporary generated tests.
- Differential evidence: a generated test passing on baseline and failing on candidate can support a reproduced issue. Missing evidence remains **UNVERIFIED**.
- Deduplicated review ranges with old/new coordinates and counts of actual changed lines.
- Optional trusted dependency preparation (`prepare` policy object): the base branch's own command runs on inputs exported from the base commit, and its container becomes the local image for every check of the run ([dependency preparation](docs/PREPARE.md)).
- An opt-in baseline execution cache (`--cache-dir`) and up to four initial checks at a time (`--parallel`); a replayed baseline run never supports a positive result ([execution cache](docs/EXECUTION_CACHE.md)).
- Changed baseline tests (`--base-tests`): the baseline version of each Go test function the change modified or removed runs on baseline and candidate code, and a baseline pass with a candidate failure is reported as `FAILS_ON_CANDIDATE` for review, not as a defect ([changed baseline tests](docs/BASE_TESTS.md)).
- Impact analysis (`--impact`, on by default): a static Go index lists callers of changed functions and the existing tests that reach them, labelled approximate; `--impacted-tests` runs those tests on both revisions ([impact analysis](docs/IMPACT.md)).
- Optional deterministic differential fuzzing (`fuzz` policy object): changed functions whose signature is unchanged run on identical seeded inputs on both revisions, without a model, and a confirmed difference is shown with both values ([differential fuzzing](docs/FUZZ.md)).
- Optional mutation of added Go lines (`mutation` policy object): surviving mutants are reported for review, killed mutants are only counted, and no mutation score is computed ([mutation of added lines](docs/MUTATION.md)).
- Observation experiments: a generated test may record values instead of asserting them, and a value that differs between revisions, after a live baseline repeat agreed with the first baseline run, is shown with both values as a behavior divergence for a human to judge ([observations](docs/OBSERVATIONS.md)).
- Acceptance criteria from `--intent` or `--intent-file`: the reviewer may write a candidate-only test for one quoted criterion, and a failure is reported as `INTENT_TEST_FAILED`, apart from reproduced issues and without a baseline control ([intent criteria](docs/INTENT.md)).
- Evidence-only exports: `--format sarif,pr-comment` writes only findings backed by recorded evidence, and an empty export is not approval ([exports](docs/EXPORTS.md)).

Go risk signals come from syntactic analysis. Impact analysis builds a static index of the repository's own Go packages on the host from committed source, without running repository code or loading imports from outside the repository, so its call graph is approximate and partial: interface edges are possible dispatch only, and an absent caller is not proof of absence. TypeScript support is lexical in this version. Signals are reasons to investigate, not confirmed bugs. Missing test changes do not establish missing coverage. A recorded coverage run establishes only which added lines ran and which did not; neither establishes that a line is tested.

## Commands

```sh
swiftproof lint --base main                       # no Docker or API
swiftproof review --base main                     # configured sandbox checks
swiftproof review --base main --checks=false      # explicitly skip execution
swiftproof review main..HEAD                      # exact endpoints
swiftproof review main...HEAD                     # common ancestor to head
swiftproof review --base main --intent-file PR.md # acceptance criteria
swiftproof review --base main --base-tests        # baseline versions of changed Go tests
swiftproof review --base main --impacted-tests    # existing Go tests that reach changed functions
swiftproof lint --base main --impact=false        # skip the static impact index
swiftproof review --base main --cache-dir "$HOME/.cache/swiftproof" --parallel 2
swiftproof review --base main --deadline 25m      # overall bound for execution stages
swiftproof review --base main --format markdown,json,sarif,pr-comment
swiftproof report --input .swiftproof/confidence-report.json
swiftproof review --help
```

`--base main` uses the merge base by default; `--exact` selects a direct comparison. Only **committed** files are reviewed. Both refs resolve to immutable IDs. Local edits and untracked files are excluded. CI needs enough Git history to resolve the base.

`--out DIR` sets the report directory. `--format` selects the files to write: `markdown` (`CONFIDENCE_REPORT.md`), `json` (`confidence-report.json`), `sarif` (`confidence-report.sarif`) and `pr-comment` (`PR_COMMENT.md`); the default is `markdown,json`, and console output stays concise. Re-rendering a saved report neither reruns nor authenticates its evidence.

| Flag | Commands | Default | Effect |
| --- | --- | --- | --- |
| `--report-url URL` | review, lint, report | none | Links the full report from `PR_COMMENT.md`. Requires `pr-comment` in `--format` and an `https` URL. |
| `--base-tests` | review | off | Runs the baseline versions of changed Go tests on candidate code. |
| `--fuzz` | review | on | `--fuzz=false` skips differential fuzzing configured in policy. |
| `--impact` | lint, review | on | `--impact=false` skips the static impact index. |
| `--impacted-tests` | review | off | Runs the existing Go tests that reach changed functions on both revisions. |
| `--cache-dir DIR` | review | none: no cache | Enables the baseline execution cache in DIR, which must be outside the repository and the report directory. |
| `--parallel N` | review | 1 | Runs up to N (at most 4) initial checks at a time. The runtime budget is unchanged. |
| `--allow-prepare-network` | review | off | Lets the policy's `prepare` command use the network, only if the policy also enables it. |
| `--deadline D` | review | none | Bounds preparation, sandbox runs and the reviewer to D (1m to 24h), keeping 30 s to write the report. |

The execution flags (`--base-tests`, `--fuzz`, `--impacted-tests`, `--cache-dir`, `--parallel`, `--allow-prepare-network` and `--deadline`) apply to `review` only: set explicitly on `lint`, they exit 3. `--base-tests` and `--impacted-tests` also exit 3 with `--checks=false`, and `--impacted-tests` exits 3 with `--impact=false`. Every flag error exits 3 before any container starts. `--no-network` also keeps the `prepare` container offline.

| Exit | Meaning |
| --- | --- |
| 0 | Report completed without a reproduced high/critical issue. Without `--ci`, unresolved areas and other review requests do not change this code. |
| 1 | High/critical hypothesis supported by differential failure. Nothing else produces 1: not divergences, not tests failing on candidate code, not intent-test failures, not surviving mutants. |
| 2 | With `--ci`: human review required, including high-risk signals, unverified areas, incomplete checks, behavior divergences, baseline or impacted tests that fail on candidate code (`FAILS_ON_CANDIDATE`), intent-test failures, inconclusive fuzz results, incomplete mutation runs and configured stages that did not run. |
| 3 | Invalid arguments, flag combination, output format, Git comparison or trusted configuration, including an unusable `--cache-dir` and an intent that is not UTF-8 or contains NUL. No container starts. |
| 4 | Harness, analysis or report-writing operational error, including dependency preparation that failed or was not permitted, and a baseline-side fuzz harness that could not be built. |

## Configuration and trust

`swiftproof init` generates `.swiftproof.json`; see [the Go example](examples/swiftproof.go.json). Policy comes from the **tip of the base branch** (`--base`, `main` by default), never implicitly from the candidate checkout. The diff still starts at the merge base, so a branch forked before the policy landed still gets it. The report records the policy commit, and SwiftProof warns when no policy exists there and built-in defaults apply. `--config PATH` explicitly selects a local file you trust.

Commands are argv arrays, not shell strings. Configure only checks your project provides. `generated_test` accepts `{file}` and `{package}`; Go's default uses the test's package so it can exercise unexported code. Verified Go experiments require one standalone target placeholder; use `-tags=integration` for valued flags. Multi-package commands, execution wrappers and overlays cannot produce verified Go evidence. Avoid scripts that silently skip generated tests.

v0.4 adds three optional top-level policy objects, `fuzz`, `mutation` and `prepare`, which `init` never writes. Every binary before v0.4.0 rejects a policy that contains one of them with exit 3, so read the [release ordering](docs/CI.md#release-ordering-for-v04) before committing one to a base branch.

### Verified TypeScript/JavaScript experiments

A JavaScript or TypeScript `generated_test` command supports differential evidence when it runs the generated file as one standalone `{file}` argument and writes a Jest-compatible JSON report to `{results_out}` (exactly once, and only in this command). Vitest and Jest both produce this format:

```json
{
  "commands": {
    "generated_test": ["npx", "--no", "vitest", "run", "{file}", "--reporter=json", "--outputFile={results_out}"]
  }
}
```

For Jest: `["npx", "--no", "jest", "{file}", "--json", "--outputFile={results_out}"]`. `swiftproof init --language typescript` writes the Vitest form. The report travels back on the sandbox payload channel, apart from the command's log, so log text cannot impersonate it; code executing in the sandbox can still write it. It is normalized (redacted, bounded messages), stored in the check's `results` field and retained as a hashed `test_results` artifact.

A run is verified only when the report has exactly one entry for `/workspace/<generated path>` and each generated title appears once in it at top level: every title passed for a passing run, and at least one failed for a failing run. Generated files must declare uniquely titled `test("…", …)` or `it("…", …)` calls at column 0, with static titles (no escapes or `${}`) and no `describe` block. A missing or truncated report, skipped or nested tests, and failures unrelated to the generated titles are inconclusive. `npm`, `yarn`, `pnpm`, `bun`, `sh`, `bash` and `env` cannot start the template, since they run repository-defined scripts; call the runner binary (for example through `npx`). The image must provide the runner and the project's dependencies, for example installed under `/node_modules`, which Node resolves from `/workspace`. Existing policies without `{results_out}` keep working, with `UNVERIFIED` results.

Sandbox networking requires both `sandbox.network: true` and `--allow-network`. `--no-network` forces it off. This controls test containers; a configured reviewer separately makes provider HTTP requests from the CLI. Use `--reviewer=false` to disable those calls.

Trust and preferably digest-pin the preloaded image. Prepare dependencies in it outside review execution, or through the trusted policy's `prepare` command, and configure commands to use them. Stock Node/Python images do not contain project dependencies; their commands must be adapted accordingly.

### Changed-line execution (optional `coverage` command)

Add a `coverage` command to the trusted policy to measure which **added** Go lines a recorded sandbox run actually executed. Its argv must contain the token `{coverage_out}` exactly once:

```json
{
  "commands": {
    "coverage": ["go", "test", "-covermode=count", "-coverprofile={coverage_out}", "./..."]
  }
}
```

SwiftProof expands `{coverage_out}` to the in-container profile path and never appends a coverage flag of its own, so the executed argv equals the argv you reviewed. That fragment is the Go default written by `swiftproof init --language go`. Adding `-coverpkg=./...` is your choice and is what attributes execution across packages: without it, a line exercised only through another package's tests is reported as not executed. Profile entries are matched through the root `go.mod` and the `use` modules of a root `go.work`, so a Go module kept in a subdirectory (for example `app/`) is measured under its own module path; configure such a repository with workspace patterns such as `./app/...`.

The coverage command runs **after the other configured checks and in addition to** `test`, before the v0.4 evidence stages and the reviewer, so it roughly doubles sandbox time against `sandbox.max_runtime_seconds`; raise that budget before enabling it. An existing `.swiftproof.json` does **not** acquire the key automatically: `init` refuses to overwrite an existing file, and policy decoding starts from an empty command map rather than merging the defaults. Add the key by hand, and read the release-ordering rule in [CI integration](docs/CI.md) first — an older pinned binary rejects the key with exit 3.

Each added Go line in a changed non-test file is reported in exactly one of four states: **executed**, **not executed**, **not inside any instrumented block**, or **not measured**. Absent, truncated, unparsable or unmapped profile data is always reported as *not measured*, never as not executed. Executed means the line ran at least once; it does not mean the line is tested, asserted, correct or safe.

## Optional AI investigation

`swiftproof review` automatically uses the LLM when `reviewer.model` is nonempty in trusted policy or in the deployment environment (see [provider settings from the deployment](#provider-settings-from-the-deployment)). No model anywhere (the default) keeps review independent of any provider. `swiftproof lint` always stays offline with respect to the reviewer, even when a model is configured.

Set the following fields in `.swiftproof.json`, using the model identifier and endpoint supplied by your provider. This is a fragment to merge into the configuration generated by `swiftproof init`:

```json
{
  "reviewer": {
    "endpoint": "https://your-provider.example/v1",
    "model": "your-tool-capable-model",
    "api_key_env": "SWIFTPROOF_API_KEY",
    "max_iterations": 20,
    "max_generated_tests": 10
  }
}
```

Commit the policy to the trusted base branch, or use `--config .swiftproof.json` to explicitly select your local policy. Candidate PR changes cannot activate or redirect the reviewer. The provider must support Chat Completions function calling. Both a `/v1` base URL and a full `/chat/completions` URL are accepted. Remote endpoints require HTTPS; local servers may use HTTP on loopback (for example `http://127.0.0.1:1234/v1`). Local providers may work without an API key. Redirects are refused.

```sh
# Set SWIFTPROOF_API_KEY using your shell or CI secret store.
swiftproof review --base main --max-iterations 20
# Override automatic activation for this run:
swiftproof review --base main --reviewer=false
# Try a local configuration before committing it:
swiftproof review --base main --config .swiftproof.json
```

Configuring a model enables transmission of bounded, redacted source context during `review`. Common secret patterns and sensitive filenames are masked, but masking is best effort. Use static analysis or a local provider if source must stay local. API credentials come from the named environment variable or its Docker secret and never enter test containers. `--reviewer` remains supported as an explicit request and fails if no model is configured. `--checks=false` skips initial checks but still lets the configured reviewer request sandbox experiments; combine it with `--reviewer=false` for static analysis only, or use `lint`.

Model claims are checked against harness evidence before entering reproduced issues. Tools cover file reads, diffs, source search, reference, symbol and caller lookup (a static Go index when available, labelled approximate, with a lexical fallback), existing checks, generated-test creation/execution/deletion and, when the intent contains acceptance criteria, candidate-only intent tests. Iteration, input, response, test-count, output and runtime budgets bound investigations. Provider failures and exhausted budgets leave deterministic results in the report and mark investigation incomplete; `--ci` requests human review. Invalid active provider settings fail before investigation. Empty changes do not call the provider.

The LLM can investigate business rules and interactions beyond static patterns and propose concrete counterexamples. Its findings remain hypotheses until supported by evidence. Better review quality or time savings must be measured on representative PRs; adding a model alone does not establish either.

### Provider settings from the deployment

The provider belongs to the deployment rather than to the reviewed repository, so the same binary and the same committed policy can be pointed at an operator's endpoint without a policy change:

| Setting | Source | Notes |
|---------|--------|-------|
| `reviewer.endpoint` | `SWIFTPROOF_REVIEWER_ENDPOINT` | Overrides the policy value; the same URL rules apply. |
| `reviewer.model` | `SWIFTPROOF_REVIEWER_MODEL` | Overrides the policy value and enables `review` on its own. |
| API key | `SWIFTPROOF_API_KEY`, else `SWIFTPROOF_API_KEY_FILE`, else `/run/secrets/SWIFTPROOF_API_KEY` | The variable name is `reviewer.api_key_env`; `<NAME>_FILE` and `/run/secrets/<NAME>` follow it. |

A blank variable counts as unset and leaves the policy value in place. The key file is read whole, with surrounding whitespace stripped; a file named by `<NAME>_FILE` must be readable, and any mounted key file that cannot be used fails the run with exit 3 instead of silently sending an unauthenticated request. Only these three settings come from the environment: the sandbox image, commands, budgets and sensitive paths stay decisions of the trusted policy. When the reviewer runs, the run log names each value's source — the variable or file name, never the credential.

In a Docker Swarm deployment the key is a [Docker secret](https://docs.docker.com/engine/swarm/secrets/), mounted as a file and never present in `docker service inspect`:

```yaml
services:
  swiftproof:
    image: registry.example/swiftproof:v0.3.0
    environment:
      - SWIFTPROOF_REVIEWER_ENDPOINT=https://provider.internal/v1
      - SWIFTPROOF_REVIEWER_MODEL=your-tool-capable-model
    secrets:
      - source: swiftproof_SWIFTPROOF_API_KEY
        target: SWIFTPROOF_API_KEY

secrets:
  swiftproof_SWIFTPROOF_API_KEY:
    external: true
```

On the PulsarCD cluster this is automatic: a variable whose name ends in `_KEY` is converted into the Docker secret `<stack>_<NAME>` at deployment, removed from the `environment:` block and mounted at `/run/secrets/<NAME>`, so declaring `SWIFTPROOF_API_KEY=${SWIFTPROOF_API_KEY}` in the compose file and putting the value in `devops/.env` is enough. Keep the name aligned with `reviewer.api_key_env` if you change it, and never commit the value.

## Evidence stages beyond the initial checks

v0.4 adds stages that record more deterministic evidence and depend less on a model. Each one is opt-in or bounded, only adds evidence or review requests, and never produces exit 1: only a reproduced high/critical hypothesis does. During `review` they run in this order: dependency preparation, initial checks, coverage, changed baseline tests, impacted tests, differential fuzzing, mutation of added lines, then the reviewer, whose experiments may record observations or run intent tests. `lint` executes none of them; it builds only the static impact index. Every sandbox run shares the one `sandbox.max_runtime_seconds` budget; dependency preparation has its own timeout instead.

A stage's JSON object is present exactly when the stage was requested or configured, and its `status` then says what happened, including `not_run` with a reason. The [v0.4 specification](../specs/swiftproof-v0.4-spec.md) holds the binding rules.

<!-- F8:begin -->
<!-- F8:end -->

<!-- F7:begin -->
<!-- F7:end -->

<!-- F3:begin -->
<!-- F3:end -->

<!-- F6:begin -->
<!-- F6:end -->

<!-- F2:begin -->
<!-- F2:end -->

<!-- F4:begin -->
<!-- F4:end -->

<!-- F1:begin -->
<!-- F1:end -->

<!-- F5:begin -->
<!-- F5:end -->

<!-- F9:begin -->
<!-- F9:end -->

## Boundaries and development

For the coding-to-deployment workflow, see the [agent loop](docs/AGENT_WORKFLOW.md),
[reusable PR workflow](docs/CI.md) and [PulsarCD integration](docs/PULSARCD.md).

SwiftProof never exits 1 except for a reproduced high/critical hypothesis. Divergences, baseline versions of changed tests failing on candidate code, and intent-test failures request human review; surviving mutants are reported for review. No equivalence, completeness or mutation-score claims. Impacted tests that fail on candidate code, inconclusive fuzz results and configured stages that did not run also request human review (exit 2 with `--ci`).

Containers run non-root, without network by default, with read-only source/root mounts, no added capabilities and CPU/RAM/PID/time limits. The Docker socket, working checkout and API keys are never mounted. The optional `prepare` container is the one documented exception: it has a writable root filesystem, may run as root when the trusted policy says so, and has network only when the policy and `--allow-prepare-network` both allow it ([dependency preparation](docs/PREPARE.md)). See [security boundaries](docs/SECURITY.md).

Generated tests cannot overwrite source. Every executed run uses a fresh environment; with `--cache-dir`, a baseline run of byte-identical inputs may instead be replayed from recorded live runs, and the report marks each replay. Go experiments select the generated test names and verify their actual execution from structured test events; TypeScript/JavaScript experiments verify them from the Jest-compatible JSON report written to `{results_out}`. Other frameworks can execute experiments but remain `UNVERIFIED` until equivalent execution validation exists. Reproductions retain test source and hashed artifacts. Reviewers still judge whether a test's assertion reflects intended behavior.

Execution snapshots currently reject symlinks/submodules. Large inputs fail explicitly or emit analysis-limit signals. There is no dependency installation from candidate content, semantic TypeScript engine, complete call graph, coverage proof, coverage threshold gate, mutation score, formal verification, automatic merge or PR comment publishing: SARIF and PR-comment exports are files that a separate job may publish. Changed-line execution is measured for Go only when a coverage command is present in the trusted policy; repositories whose `.swiftproof.json` predates this release measure nothing until that policy is updated by hand. An executed line is an observation, not proof that it is tested.

```sh
go test ./...
go vet ./...
go test -race ./...                 # supported native C toolchain required
go test ./internal/linter -bench . -benchmem
```

Tests use real temporary Git repositories, CLI/report integration, simulated providers, evidence validation and sandbox-policy checks. For real Docker integration, preload an appropriate Go image and set `SWIFTPROOF_TEST_DOCKER_IMAGE` to its name before running the harness tests.

See [CI integration](docs/CI.md), [validation results](docs/VALIDATION.md), [performance measurements](docs/PERFORMANCE.md), the [report schema](schema/confidence-report.schema.json), the [V0.2 specification](../specs/swiftproof-v0.2-spec.md) and its [V0.4 extension](../specs/swiftproof-v0.4-spec.md). Contributions should include reproducible counterexamples for new rules. Licensed under the AGPL-3.0 with an attribution term, see [LICENSE](../LICENSE) and [NOTICE](../NOTICE).
