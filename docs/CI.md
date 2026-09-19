# CI integration

Install a **trusted pinned** SwiftProof binary, fetch full base/candidate history, and preload an image containing the project's dependencies. Then run:

```sh
swiftproof review --base "$BASE_COMMIT" --head "$HEAD_COMMIT" --ci --out .swiftproof
```

The base identifies the trusted target branch. SwiftProof uses its merge base with the candidate for comparison and policy; `--exact` selects a direct comparison. Any explicit `--config` must be supplied from a trusted source outside candidate control.

Preserve the exit status while uploading Markdown, JSON and `.swiftproof/artifacts/`, including after failure. Exit 2 requests human review; it is not a confirmed bug. Exit 4 means execution/reporting failed, for example because the image was unavailable. Set branch protection accordingly.

In GitHub Actions use `permissions: contents: read`, checkout with `fetch-depth: 0` and `persist-credentials: false`, and an `if: always()` upload step. Pin action versions to reviewed commit SHAs in production workflows. Follow GitHub's [workflow security guidance](https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions).

Fork PR lint needs no provider secret. Remote investigation belongs in an execution context that keeps credentials outside candidate processes. Do not build/run candidate-controlled automation with privileged `pull_request_target` tokens. SwiftProof never posts comments or approves/merges PRs.

Start by collecting reports without gating merges. Measure signal usefulness on representative PRs, tune paths/commands, then incorporate high-risk areas and incomplete checks into the review policy.
