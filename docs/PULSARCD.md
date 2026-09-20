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
