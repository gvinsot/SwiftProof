> Example generated from a local authorization-regression fixture. All three existing checks passed, but the changed authorization body still requires human review. No AI provider was used for this report.

# Change Confidence Report

## Change Summary

1 additions / 1 deletions · 1 files changed

Base: b115162f172436cdeb766ef5b7dadf5950702de1

Candidate: 2c1c4a0221c6e262e7ca40ccb53ed1422fb183f1

Exit code: 2. No confidence percentage is assigned.

## Automated Checks

- **PASS** test (check-1; exit 0; 6646 ms)
- **PASS** typecheck (check-2; exit 0; 5425 ms)
- **PASS** build (check-3; exit 0; 599 ms)

## Investigation Summary

No structured hypotheses were investigated.


## Reproduced Issues

No issue was reproduced by a passing baseline and failing candidate experiment.


## Unverified Areas

No specific unresolved area was recorded. This does not establish correctness.

## Suggested Human Review

- **high** auth.go:4–4 (new): Authentication or authorization function body changed
- **low** auth.go:4–4 (old): No nearby test file changed

## Review Surface

Focused review: **2 / 2 changed lines**.

Distinct changed coordinates; removed and added lines count separately. Focused review is a prioritization aid, not proof that the remaining diff is correct. NOT\_REPRODUCED means only that the recorded experiment did not reproduce the concern.

## Recorded Evidence


## Artifacts

- check-output.txt (check\_output)


