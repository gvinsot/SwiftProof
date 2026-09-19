# SwiftProof

**Spend review time on the changes that need your judgment.**

SwiftProof is a Go CLI for reviewing AI-assisted pull requests. It maps Git changes to risk signals, optionally runs isolated checks and adversarial tests, and produces a focused review plan with traceable evidence.

It works without an AI provider. It does not assign confidence percentages or automatically approve PRs. Passing tests and a small review surface are not correctness guarantees.

## Quick start

Requirements: Go 1.23+ and Git. Docker with Linux containers is required only to execute repository code.

Build from this source checkout (no release is published by this change):

```sh
go build -o swiftproof ./cmd/swiftproof
go test ./...
```

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

Sandbox networking requires both `sandbox.network: true` and `--allow-network`. `--no-network` forces it off. This controls test containers; `--reviewer` separately enables provider HTTP requests from the CLI.

Trust and preferably digest-pin the preloaded image. Prepare dependencies in it outside review execution and configure commands to use them. Stock Node/Python images do not contain project dependencies; their commands must be adapted accordingly.

## Optional AI investigation

Set `reviewer.model`, `reviewer.endpoint` and `reviewer.api_key_env` in trusted policy. The provider must support Chat Completions function calling. Remote endpoints require HTTPS; local servers may use HTTP on loopback. Redirects are refused.

```sh
# Set SWIFTPROOF_API_KEY using your shell or CI secret store.
swiftproof review --base main --reviewer --max-iterations 20
```

This transmits bounded, redacted source context. Common secret patterns and sensitive filenames are masked, but masking is best effort. Use static analysis or a local provider if source must stay local. API credentials never enter test containers. Model claims are checked against harness evidence before entering reproduced issues.

Tools cover file reads, diffs, source search, textual reference/symbol lookup, existing checks, and generated-test creation/execution/deletion. Iteration, input, response, test-count, output and runtime budgets bound investigations. Exhaustion is explicitly reported.

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
