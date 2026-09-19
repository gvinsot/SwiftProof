# Security boundaries

SwiftProof treats candidate code, generated tests, model output and repository text as untrusted. Static analysis uses immutable Git objects with external diff/textconv disabled. Execution uses Docker only; the source checkout is never executed or mounted.

Policy comes from the comparison baseline unless the caller explicitly supplies `--config`. A baseline is a trust decision: select a trusted commit and pin the binary used in CI. Candidate policy changes cannot implicitly alter image, commands, provider or budgets.

Containers use a non-root UID, `--network none`, read-only source/root mounts, bounded tmpfs workspace, `--cap-drop=ALL`, `no-new-privileges`, CPU/memory/PID limits and forced cleanup. These controls follow the [Docker run reference](https://docs.docker.com/reference/cli/docker/container/run/) and [network isolation documentation](https://docs.docker.com/engine/network/drivers/none/). Docker shares a kernel; hostile multi-tenant submissions may require disposable VMs. See [Docker Engine security](https://docs.docker.com/engine/security/).

Trust the preloaded image and its environment, files and dependencies. Never bake credentials into it. SwiftProof does not pull images or install dependencies automatically. Compromised dependencies can influence experiments; tests remain observations, not mathematical proofs.

Known credential paths are excluded from readable/executable snapshots. Common tokens, passwords and private-key patterns are masked in outputs, reports and provider context. This is best effort: custom secret formats, encodings and deliberate transformations may escape masking. Avoid remote reviewers when transmitting source is unacceptable.

Generated tests create new test paths only and run against separate baseline/candidate copies. A misleading assertion can cause a differential failure; humans must evaluate its relevance. Recognized build/setup failures, timeouts, missing dependencies and inconclusive baseline failures do not establish a reproduced behavioral issue. Arbitrary framework output cannot always be classified reliably.

Providers have no unrestricted shell or URL fetcher. All functions and responses are bounded. HTTPS is required remotely, redirects and environment proxies are refused, and HTTP is limited to loopback. The integration follows the [function-calling protocol](https://developers.openai.com/api/docs/guides/function-calling).

Reports/hashes are unsigned. Someone able to edit JSON can forge evidence. Check provenance through trusted CI storage and immutable commit IDs; `swiftproof report` only renders. Output directories must be trusted and should not be shared with other writers during review.

Normal completion/cancellation cleans temporary files and containers. Power loss or abruptly killing the host can leave resources behind; container names begin with `swiftproof-` for administrative inspection. Retained redacted artifacts deliberately remain in the chosen report directory.
