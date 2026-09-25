# PulsarCD deployment integration

The companion implementation in PulsarCD adds an opt-in SwiftProof gate to its
shared deployment function, including manual and MCP-triggered deployments.
Its setup guide is `PulsarCD/docs/SWIFTPROOF.md`.

Enable **Require SwiftProof before deployment** in the project's **Test → Deploy**
transition. Leave **Use the LLM configured in PulsarCD** enabled to inherit its
effective endpoint, model and credentials automatically. No second provider
configuration is required. This integration is implemented in the companion
PulsarCD checkout and must be deployed before the controls appear in its UI.

PulsarCD uses a temporary loopback/SSH bridge to keep the provider key in its
backend. SwiftProof receives a job token and its usual bounded investigation
tools, without the deployment agent's MCP tools. Model output still requires
SwiftProof evidence validation.

The bridge needs no policy change to redirect a review: `SWIFTPROOF_REVIEWER_ENDPOINT`
and `SWIFTPROOF_REVIEWER_MODEL` override the baseline policy's provider for the
run, and the job token is read from `SWIFTPROOF_API_KEY`, from the file named by
`SWIFTPROOF_API_KEY_FILE`, or from the Docker secret the cluster mounts at
`/run/secrets/SWIFTPROOF_API_KEY` — the `_KEY` suffix makes that conversion
automatic, so the value never appears in the compose file or in
`docker service inspect`. Only these three settings come from the environment;
image, commands and budgets stay with the deployed commit's policy.

Deployment reviews compare the **exact deployed commit** against the candidate
using `--exact --ci`, with policy from the deployed commit. Reports are tied to
both SHAs, built image digests, the trusted binary, baseline policy and model
configuration. Code 0 passes this gate, code 1 blocks, code 2 needs a named human
approval of the evidence, and configuration/execution failures block. Existing
tests and QA approval still apply.

The first baseline must be verified by an administrator. Later successful
production deployments advance it automatically; QA deployments do not. The
build/deployment scripts maintain provenance and pin the final compose images
by digest. An old PR report alone cannot authorize a different deployment.

The adapter explicitly passes `--reviewer=true/false`, making it compatible with
the published v0.1.0 binary as well as current automatic model activation.
The PulsarCD installer pins release archive checksums for Linux amd64/arm64.
The deployment host also needs a prepared test image and a reviewed baseline
`.swiftproof.json`. Existing projects remain opt-in.
