# CI integration

Install a **trusted pinned** SwiftProof binary, fetch full base/candidate history, and preload an image containing the project's dependencies. Then run:

```sh
swiftproof review --base "$BASE_COMMIT" --head "$HEAD_COMMIT" --ci --out .swiftproof
```

The base identifies the trusted target branch. SwiftProof uses its merge base with the candidate for comparison and policy; `--exact` selects a direct comparison. Any explicit `--config` must be supplied from a trusted source outside candidate control.

Preserve the exit status while uploading Markdown, JSON and `.swiftproof/artifacts/`, including after failure. Exit 2 requests human review; it is not a confirmed bug. Exit 4 means execution/reporting failed, for example because the image was unavailable. Set branch protection accordingly.

In GitHub Actions use `permissions: contents: read`, checkout with `fetch-depth: 0` and `persist-credentials: false`, and an `if: always()` upload step. Pin action versions to reviewed commit SHAs in production workflows. Follow GitHub's [workflow security guidance](https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions).

Fork PR lint needs no provider secret. `review` automatically invokes a model configured in trusted baseline policy; provide its named API-key environment variable if the provider requires authentication. Use `--reviewer=false` in jobs that must not contact a provider or cannot access its credentials. Remote investigation belongs in an execution context that keeps credentials outside candidate processes. Do not build/run candidate-controlled automation with privileged `pull_request_target` tokens. SwiftProof never posts comments or approves/merges PRs.

Start by collecting reports without gating merges. Measure signal usefulness on representative PRs, tune paths/commands, then incorporate high-risk areas and incomplete checks into the review policy.

## Changed-line execution and gating

SwiftProof does not fail a build for added lines that were not executed; they are reported as medium signals, or low when the coverage run did not pass. A coverage run that was configured but could not be measured does request human review with `--ci`. To enforce your own policy, read `coverage.not_executed_lines` from `.swiftproof/confidence-report.json` in a following step and decide there.

Adding the optional `coverage` command to a base-branch policy is a **release-ordered** change. Policy decoding rejects unknown fields and validates command names against a whitelist, so a policy containing the `coverage` key makes an older binary exit 3; the released v0.1.0 whitelist has four command names. Publish a release whose binary accepts the key, re-pin the workflow to that release, and only then commit the key to the base branch. A pipeline that pins v0.1.0 breaks the moment the key lands.

One asymmetry is known and deliberate: `swiftproof report` re-renders a saved report with plain `json.Unmarshal`, which ignores unknown fields. An older binary re-rendering a newer report therefore silently drops the coverage object instead of failing. Render reports with the binary that produced them.

## Included GitHub workflows

`.github/workflows/pr-review.yml` starts an informational pilot on this
repository's PRs. `.github/workflows/review.yml` is reusable: it installs the
published v0.1.0 binary with a pinned checksum, preloads a trusted Docker image,
reviews immutable SHAs and retains reports and experiments for 30 days.
The workflow explicitly selects the reviewer flag for v0.1.0 compatibility.

After publishing these workflow files, another repository can use:

```yaml
name: SwiftProof
on: [pull_request]
permissions:
  contents: read
jobs:
  review:
    uses: gvinsot/SwiftProof/.github/workflows/review.yml@REPLACE_WITH_REVIEWED_COMMIT_SHA
    with:
      enforce: false
      reviewer: false
```

Replace the placeholder with a reviewed commit **containing this workflow**;
the existing v0.1.0 tag predates it. The example is not usable until then.
Supply `base-sha` and `head-sha` explicitly when calling outside a PR event.
For another language/dependency image, set `sandbox-image` to match the trusted
baseline policy's image. It must already contain the project's dependencies.

To investigate with a model on same-repository PRs, configure it in trusted
baseline policy, set `reviewer: true` and explicitly map the
`reviewer-api-key` secret. The workflow exports it as `SWIFTPROOF_API_KEY`.
Fork PRs force the investigator off. The repository pilot starts without a
provider. The PulsarCD provider bridge is a separate deployment integration;
GitHub-hosted runners do not automatically acquire its internal credentials.

`enforce: true` fails on code 1 or operational/configuration failure. Code 2
produces a warning and still requires normal human PR approval: the check's
green status is not that approval. Configure required reviews, dismissal of
stale approvals and protection of workflow/policy changes in repository rules
before making this check mandatory. The workflow does not change those rules.

See the [agent loop](AGENT_WORKFLOW.md) and [PulsarCD integration](PULSARCD.md)
for checks before the PR and before production deployment.
