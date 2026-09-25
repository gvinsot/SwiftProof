# SwiftProof development workflow

The repository has four areas: `app/` (the Go CLI and its docs), `web/` (the
promotional website), `devops/` (PulsarCD deployment of the website) and
`specs/` (product specifications).

Run `go test ./...` and `go vet ./...` from `app/` (or `go test ./app/...` from
the root, through `go.work`) for relevant Go changes. Tests which need real
Docker require `SWIFTPROOF_TEST_DOCKER_IMAGE` and a preloaded trusted image.

Before handing over committed code, use an installed trusted SwiftProof binary
to run `swiftproof lint --base origin/main`. Before requesting PR review, also
run `swiftproof review --base origin/main --ci` when the prepared sandbox image
is available. Read `.swiftproof/CONFIDENCE_REPORT.md` and report reproduced
issues, unresolved hypotheses and incomplete checks in the handoff.

SwiftProof only analyzes committed files. Do not create commits just for these
checks without authorization; state when the working changes are outside the
analyzed range. Never alter the baseline/policy to hide findings or claim that
a model assertion or a zero exit code proves correctness. Use
`--reviewer=false` when provider use is not configured or appropriate.

See `app/docs/AGENT_WORKFLOW.md`, `app/docs/CI.md`, and `app/docs/PULSARCD.md`
for the complete agent, PR and deployment integration.
