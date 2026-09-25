# Using SwiftProof in an agent coding loop

Add the following instructions to a project's agent guidance after installing a
trusted SwiftProof binary and committing its reviewed `.swiftproof.json` policy:

> Before handing over a committed change, run `swiftproof lint --base origin/main`.
> Inspect `.swiftproof/CONFIDENCE_REPORT.md`, investigate relevant findings, and
> rerun after corrections. Before requesting PR review, run `swiftproof review`
> when the project's prepared Docker image is available. In the handoff, report
> each of these separately:
>
> - reproduced issues;
> - baseline versions of changed tests that fail on candidate code, and impacted
>   tests that fail on candidate code (`FAILS_ON_CANDIDATE`);
> - behavior divergences, with both recorded values: a divergence does not say
>   which revision is right;
> - intent-test failures, listed apart from reproduced issues: the test and its
>   reading of the criterion are model-written, and no baseline run controls them;
> - surviving mutants, which may be equivalent to the original code and are not
>   defects or missing tests by themselves;
> - unresolved hypotheses;
> - incomplete checks, including stages that did not run, inconclusive fuzz
>   results and incomplete mutation runs.
>
> Never treat a model assertion, a passing check or a zero exit code as proof of
> correctness. Do not change the baseline policy to make findings disappear. Do
> not create commits solely to satisfy this check when the task does not
> authorize commits; explain that uncommitted changes are outside SwiftProof's
> analysis.

To share results on a pull request, render them with `--format pr-comment` and
post `PR_COMMENT.md` as a PR **comment**, never into the PR description. The
description is the usual `--intent-file` source: SwiftProof removes its own
marked comment block from the intent, but any other text copied there is read
as intent, and its list items can become acceptance criteria. Put the handoff
list above in a PR comment or the handoff message for the same reason. See
[exports](EXPORTS.md) and [intent criteria](INTENT.md).

Use `--reviewer=false` for a provider-free review. A configured LLM is used
automatically by the current source version; v0.1.0 requires `--reviewer`.
The CI adapter explicitly supplies this flag to work with either version.
