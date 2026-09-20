# Using SwiftProof in an agent coding loop

Add the following instructions to a project's agent guidance after installing a
trusted SwiftProof binary and committing its reviewed `.swiftproof.json` policy:

> Before handing over a committed change, run `swiftproof lint --base origin/main`.
> Inspect `.swiftproof/CONFIDENCE_REPORT.md`, investigate relevant findings, and
> rerun after corrections. Before requesting PR review, run `swiftproof review`
> when the project's prepared Docker image is available. Include reproduced
> issues, unresolved hypotheses and incomplete checks in the PR description.
> Never treat a model assertion or a zero exit code as proof of correctness.
> Do not change the baseline policy to make findings disappear. Do not create
> commits solely to satisfy this check when the task does not authorize commits;
> explain that uncommitted changes are outside SwiftProof's analysis.

Use `--reviewer=false` for a provider-free review. A configured LLM is used
automatically by the current source version; v0.1.0 requires `--reviewer`.
The CI adapter explicitly supplies this flag to work with either version.
