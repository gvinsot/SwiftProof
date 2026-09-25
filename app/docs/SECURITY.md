# Security boundaries

SwiftProof treats candidate code, generated tests, model output and repository text as untrusted. Static analysis uses immutable Git objects with external diff/textconv disabled. Execution uses Docker only; the source checkout is never executed or mounted.

Policy comes from the tip of the base ref (`--base`, `main` by default) unless the caller explicitly supplies `--config`; the report records that commit. The diff still starts at the merge base, but the policy never comes from the candidate or from any commit only the candidate branch contains. The base ref is a trust decision: select a protected branch or trusted commit, never a branch the change author can write to, and pin the binary used in CI. Candidate policy changes cannot implicitly alter image, commands, provider or budgets. A nonempty `reviewer.model` in this trusted policy enables provider requests automatically during `review`. Use `--reviewer=false` to disable them for a run. `lint` never calls the provider. `--no-network` applies only to sandbox containers.

The process environment is the second trusted input, at the same level as the pinned binary: `SWIFTPROOF_REVIEWER_ENDPOINT`, `SWIFTPROOF_REVIEWER_MODEL` and the API key (variable, `<NAME>_FILE`, or the Docker secret at `/run/secrets/<NAME>`) override the policy's provider, and a model supplied this way enables provider requests exactly as a policy model does. Whoever can set that environment can therefore choose where redacted source context is sent, so it belongs to the deployment operator and not to the reviewed change; candidate commits, PR branches and untrusted forks never reach it. Image, commands, budgets and sensitive paths remain policy-only. The credential is read at most once per run, is never written to a report, and the run log names only its source.

Containers use a non-root UID, `--network none`, read-only source/root mounts, bounded tmpfs workspace, `--cap-drop=ALL`, `no-new-privileges`, CPU/memory/PID limits and forced cleanup. These controls follow the [Docker run reference](https://docs.docker.com/reference/cli/docker/container/run/) and [network isolation documentation](https://docs.docker.com/engine/network/drivers/none/). Docker shares a kernel; hostile multi-tenant submissions may require disposable VMs. See [Docker Engine security](https://docs.docker.com/engine/security/). The optional dependency-preparation container is the one exception: it has a writable root filesystem, may run as root when the trusted policy says so, and has network only when the policy and `--allow-prepare-network` both allow it. Its full profile is in [dependency preparation](PREPARE.md).

Trust the preloaded image and its environment, files and dependencies. Never bake credentials into it. SwiftProof never pulls images. It installs dependencies only when the trusted base-branch policy defines a `prepare` command, which runs on inputs exported from the base commit before any candidate code; candidate dependencies are never installed. Compromised dependencies can influence experiments; tests remain observations, not mathematical proofs.

Known credential paths are excluded from readable/executable snapshots. Common tokens, passwords and private-key patterns are masked in outputs, reports and provider context. This is best effort: custom secret formats, encodings and deliberate transformations may escape masking. Avoid remote reviewers when transmitting source is unacceptable.

A coverage profile is written by the candidate revision's own test suite and is untrusted input. It can move verdicts in both directions: fabricated execution suppresses a signal, and fabricated non-execution manufactures one. Coverage data may therefore add signals and add sentences; it may never delete a signal, lower a severity, support a dismissal or mark anything resolved, and no conclusion is drawn from a line being executed. The profile leaves the sandbox only as a length-declared framed payload on the container's standard output, separately bounded and derived from `sandbox.max_output_bytes`; repository code gains no writable host path, no volume and no container that outlives the run.

Generated tests create new test paths only and run against separate baseline/candidate copies. A misleading assertion can cause a differential failure; humans must evaluate its relevance. Recognized build/setup failures, timeouts, missing dependencies and inconclusive baseline failures do not establish a reproduced behavioral issue. Arbitrary framework output cannot always be classified reliably.

Providers have no unrestricted shell or URL fetcher. All functions and responses are bounded. HTTPS is required remotely, redirects and environment proxies are refused, and HTTP is limited to loopback. The integration follows the [function-calling protocol](https://developers.openai.com/api/docs/guides/function-calling).

Reports/hashes are unsigned. Someone able to edit JSON can forge evidence. Check provenance through trusted CI storage and immutable commit IDs; `swiftproof report` only renders. Output directories must be trusted and should not be shared with other writers during review.

Normal completion/cancellation cleans temporary files and containers. Power loss or abruptly killing the host can leave resources behind; container names begin with `swiftproof-` for administrative inspection. Retained redacted artifacts deliberately remain in the chosen report directory. Two other outputs persist by design and only when requested: images derived by a policy's `prepare` command, and the entries of an explicit `--cache-dir`.

## Evidence added in v0.4

New evidence may add review requests. It never suppresses, lowers or dismisses anything a live execution recorded. The only v0.4 conclusion that can rest on a non-fresh execution is a negative one backed by an opt-in cache entry that two live runs agreed on; the report lists it in `execution.replay_backed`.

Repository code executing in the sandbox can write every channel that carries its results back:

- the check log (standard output and standard error, bounded and redacted), which also carries `go test -json` events such as Go `t.Attr` observations;
- the single payload file a run may return on the length-declared framed channel: a coverage profile, a Jest-compatible report written to `{results_out}` (including Vitest `task.meta` values), or a fuzz observation stream.

These structured values are kept apart from the log so log text cannot impersonate them; code executing in the sandbox can still write them. A status derived from them, such as `NOT_REPRODUCED`, `NOT_DIVERGED`, `PASSES_ON_CANDIDATE` or `INTENT_TEST_PASSED`, describes the recorded run only and is not tamper-proof. Every recorded `results` value is unchanged by redaction, and structured results are limited to 16 MiB per report; larger ones are kept only as hashed artifacts.

Models still create no evidence. A model may propose hypotheses, write tests and attach a labelled judgment to a divergence, but only the harness records checks and evidence, and `report.Finalize` re-derives every status from the recorded checks, including when `swiftproof report` re-renders a saved report.

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
