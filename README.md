# SwiftProof

**Spend review time on the changes that need your judgment.**

SwiftProof is a Go CLI for reviewing AI-assisted pull requests. It maps Git changes to risk signals, optionally runs isolated checks and adversarial tests, and produces a focused review plan with traceable evidence.

It works without an AI provider. It does not assign confidence percentages or automatically approve PRs. Passing tests and a small review surface are not correctness guarantees.

## Quick start

Download a binary for Windows, Linux or macOS from [GitHub Releases](https://github.com/gvinsot/SwiftProof/releases). Git is required at runtime. Docker with Linux containers is required only to execute repository code.

To build from source, install Go 1.23+ and run:

```sh
go build -o swiftproof ./cmd/swiftproof
go test ./...
```

To build Windows amd64 **and Linux amd64/arm64** together, run from the repository root on any supported host:

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

Checks require a **preloaded image containing the toolchain and project dependencies**. SwiftProof never pulls images or installs dependencies during review. For a Go project without third-party dependencies, preload the default image in a trusted environment:

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
- Signals for sensitive paths, dependencies, network/DB calls, authentication, removed validation/error handling, unsafe constructs and missing associated changed tests.
- Configured test, typecheck and build commands executed as argv arrays in disposable containers.
- An optional reviewer with bounded source/search/test tools and temporary generated tests.
- Differential evidence: a generated test passing on baseline and failing on candidate can support a reproduced issue. Missing evidence remains **UNVERIFIED**.
- Deduplicated review ranges with old/new coordinates and counts of actual changed lines.

Go analysis is syntactic, not whole-program type or call-graph analysis. TypeScript support is lexical in this version. Signals are reasons to investigate, not confirmed bugs. Missing test changes do not establish missing coverage.

## Commands

```sh
swiftproof lint --base main                       # no Docker or API
swiftproof review --base main                     # configured sandbox checks
swiftproof review --base main --checks=false      # explicitly skip execution
swiftproof review main..HEAD                      # exact endpoints
swiftproof review main...HEAD                     # common ancestor to head
swiftproof review --base main --intent-file PR.md # acceptance criteria
swiftproof report --input .swiftproof/confidence-report.json
swiftproof review --help
```

`--base main` uses the merge base by default; `--exact` selects a direct comparison. Only **committed** files are reviewed. Both refs resolve to immutable IDs. Local edits and untracked files are excluded. CI needs enough Git history to resolve the base.

`--out DIR` sets the report directory. `--format markdown,json` selects files to write; console output stays concise. Re-rendering a saved report neither reruns nor authenticates its evidence.

| Exit | Meaning |
| --- | --- |
| 0 | Report completed without a reproduced high/critical issue. Without `--ci`, unresolved areas do not change this code. |
| 1 | High/critical hypothesis supported by differential failure. |
| 2 | With `--ci`: human review required, including high-risk signals, unverified areas or incomplete checks. |
| 3 | Invalid arguments, Git comparison or trusted configuration. |
| 4 | Harness, analysis or report-writing operational error. |

## Configuration and trust

`swiftproof init` generates `.swiftproof.json`; see [the Go example](examples/swiftproof.go.json). Default policy comes from the **resolved baseline commit**, never implicitly from the candidate checkout. `--config PATH` explicitly selects a local file you trust.

Commands are argv arrays, not shell strings. Configure only checks your project provides. `generated_test` accepts `{file}` and `{package}`; Go's default uses the test's package so it can exercise unexported code. Verified Go experiments require one standalone target placeholder; use `-tags=integration` for valued flags. Multi-package commands, execution wrappers and overlays cannot produce verified Go evidence. Avoid scripts that silently skip generated tests.

Sandbox networking requires both `sandbox.network: true` and `--allow-network`. `--no-network` forces it off. This controls test containers; a configured reviewer separately makes provider HTTP requests from the CLI. Use `--reviewer=false` to disable those calls.

Trust and preferably digest-pin the preloaded image. Prepare dependencies in it outside review execution and configure commands to use them. Stock Node/Python images do not contain project dependencies; their commands must be adapted accordingly.

## Optional AI investigation

`swiftproof review` automatically uses the LLM when `reviewer.model` is nonempty in trusted policy. An empty model (the default) keeps review independent of any provider. `swiftproof lint` always stays offline with respect to the reviewer, even when a model is configured.

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

Configuring a model enables transmission of bounded, redacted source context during `review`. Common secret patterns and sensitive filenames are masked, but masking is best effort. Use static analysis or a local provider if source must stay local. API credentials come from the named environment variable and never enter test containers. `--reviewer` remains supported as an explicit request and fails if no model is configured. `--checks=false` skips initial checks but still lets the configured reviewer request sandbox experiments; combine it with `--reviewer=false` for static analysis only, or use `lint`.

Model claims are checked against harness evidence before entering reproduced issues. Tools cover file reads, diffs, source search, textual reference/symbol lookup, existing checks, and generated-test creation/execution/deletion. Iteration, input, response, test-count, output and runtime budgets bound investigations. Provider failures and exhausted budgets leave deterministic results in the report and mark investigation incomplete; `--ci` requests human review. Invalid active provider settings fail before investigation. Empty changes do not call the provider.

The LLM can investigate business rules and interactions beyond static patterns and propose concrete counterexamples. Its findings remain hypotheses until supported by evidence. Better review quality or time savings must be measured on representative PRs; adding a model alone does not establish either.

## Boundaries and development

Containers run non-root, without network by default, with read-only source/root mounts, no added capabilities and CPU/RAM/PID/time limits. The Docker socket, working checkout and API keys are never mounted. See [security boundaries](docs/SECURITY.md).

Generated tests cannot overwrite source. Baseline and candidate runs use fresh environments. Go experiments select the generated test names and verify their actual execution from structured test events. Other frameworks can execute experiments but remain `UNVERIFIED` until equivalent execution validation exists. Reproductions retain test source and hashed artifacts. Reviewers still judge whether a test's assertion reflects intended behavior.

Execution snapshots currently reject symlinks/submodules. Large inputs fail explicitly or emit analysis-limit signals. There is no automatic dependency installation, semantic TypeScript engine, global call graph, coverage proof, formal verification, automatic merge or PR comment publishing.

```sh
go test ./...
go vet ./...
go test -race ./...                 # supported native C toolchain required
go test ./internal/linter -bench . -benchmem
```

Tests use real temporary Git repositories, CLI/report integration, simulated providers, evidence validation and sandbox-policy checks. For real Docker integration, preload an appropriate Go image and set `SWIFTPROOF_TEST_DOCKER_IMAGE` to its name before running the harness tests.

See [CI integration](docs/CI.md), [validation results](docs/VALIDATION.md), [performance measurements](docs/PERFORMANCE.md), the [report schema](schema/confidence-report.schema.json) and the [V0.2 specification](specs/swiftproof-v0.2-spec.md). Contributions should include reproducible counterexamples for new rules. MIT licensed.
