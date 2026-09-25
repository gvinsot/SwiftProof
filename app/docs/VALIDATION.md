# Implementation validation

Validated locally on 2026-09-19. These checks establish tested implementation behavior, not a measurement of human review-time savings.

- Full Go tests and `go vet` pass on Windows amd64 with Go 1.27.1.
- Full tests with `-race`, and `go vet`, pass in Linux with Go 1.26 and networking disabled.
- Cross-compilation succeeds for Windows, Linux and macOS on amd64/arm64, with CGO disabled and version metadata injected. Cross-compilation does not substitute for native execution on those platforms.
- Real Docker tests use the official `golang:1.26-bookworm` image (observed digest `sha256:a688600ca24f8a4d3ca77f95b0dd40704a9fc787c826660eb7ba0b641b8b175d`).
- Container tests check absent host secrets, excluded credential files, blocked network, non-root identity, read-only source/root, ephemeral writes and unchanged host input.
- Real generated Go experiments verify both a baseline-pass/candidate-fail regression and a passing generated test despite an unrelated failing existing candidate test.
- A complete CLI test uses real commits, a scripted local provider and real containers. It asserts the reproduced-issue exit code, named-test evidence, retained source artifacts, merged audit history and unchanged checkout.
- Provider tests cover structured tool calling, input/iteration/time limits, unsupported tools, malformed responses and redirect refusal. No live paid/cloud model was required for these tests.
- The public JSON schema is checked as Draft 2020-12. Reports, output escaping, credential masking, evidence references and focused-line calculations have targeted tests.

Reproduce ordinary checks:

```sh
go test ./...
go vet ./...
go test -race ./...
```

For actual container tests, preload a trusted Go image and set `SWIFTPROOF_TEST_DOCKER_IMAGE=golang:1.26-bookworm`, then run:

```sh
go test ./internal/harness ./internal/cli -run Docker -count=1 -v
```

Tests without that environment variable intentionally skip real Docker integration. The included CI workflow enables it on Linux.

<!-- F0c:begin -->
### v0.4 harness foundation (F0c, 2026-09-25)

Environment: Windows 11 Pro host with Docker; Go in `golang:1.26-bookworm` (image `sha256:a688600ca24f…`, Go 1.26) and `golang:1.23-bookworm` (Go 1.23.12). Scope: the run primitives (`run.go`: budget reservation, per-run timeout and ceiling, capped tee, mutation ledger, execution-cache consult and store), `stage.go`, `existingtests.go`, the harness stubs, `internal/dockerutil` and `gitrepo.Tree`/`ReadBlobs` with `Snapshot` rebuilt on them.

- `go vet ./...` and `go test ./...` pass in `golang:1.26-bookworm`. In `golang:1.23-bookworm`, `go vet ./...` and the `internal/harness`, `internal/gitrepo` and `internal/dockerutil` tests pass.
- `go test -race` passes for `internal/harness`, `internal/gitrepo` and `internal/dockerutil`.
- Windows amd64 test binaries run on the host with `SWIFTPROOF_TEST_DOCKER_IMAGE=golang:1.26-bookworm` and `-test.run Docker` pass: the eight harness Docker tests (including `TestDockerRunOptionsTimeoutTeeLedgerAndCache` and `TestDockerExistingTestOutcomesFromRealGoTest`), `TestDockerInspectAndInfo` (dockerutil) and `TestDockerReviewEndToEnd` (cli). The full harness, dockerutil and gitrepo suites also pass natively on Windows.
- End-to-end runs with a Windows binary built from the branch (`-X main.version=F0c-e2e`) on a two-commit Go fixture repository, with the policy passed through `--config` from outside the fixture:
  - `review` with checks and no reviewer: test, typecheck, build and coverage checks PASS; exit 0, and 0 with `--ci`.
  - `review --checks=false --ci` with a scripted local provider (`create_test`, `run_generated_test`, `find_callers`, `submit_hypothesis`): one `differential_test` evidence record REPRODUCED from `check-1` (baseline PASS) and `check-2` (candidate FAIL), one high reproduced issue, exit 1. `find_callers` answered through the lexical fallback. The checkout stayed clean and no `swiftproof-` container remained.
  - `report` re-render of that JSON: Markdown and JSON byte-identical to the originals.

The execution-cache paths were exercised only with an in-memory test store; the on-disk cache behind `--cache-dir` is not part of this foundation.
<!-- F0c:end -->

The published v0.1.0 binaries are used by the new PR and deployment adapters.
The reusable PR workflow and pilot pass `actionlint`. The companion PulsarCD
implementation passes 528 targeted tests (API, security, build scripts and
SwiftProof), including an actual SwiftProof CLI invocation through its temporary
provider bridge with a simulated local provider. Tests cover changed image
digests, missing/corrupt evidence, human approval, absent LLM gates and separate
QA/production baselines. These integration changes have been validated locally;
their GitHub workflows and deployment gate have not been activated on the live
cluster by this task.
