# claude-review-p0-source

Scratch SOURCE repo for the phase 0 platform tests of the OperationCode Claude PR reviewer. A test org ruleset requires `.github/workflows/p0-required.yml` from this repo, pinned by SHA, on `OperationCode/claude-review-test` only. This repo is never a target.

Test plan: [TESTING-P0.md in claude-review-test](https://github.com/OperationCode/claude-review-test/blob/main/TESTING-P0.md).

- Every push to `main` makes a new SHA. The ruleset pin does not move by itself: an org owner moves it and reads the ruleset back.
- The `P0_*` values in the workflow are non-secret IDs of a TEST federation rule. Keep them empty unless V3 or V9 runs.
- `collect` runs on the target repo variable `P0_COLLECT_RUNS_ON` when it is set (default `ubuntu-latest`). Set it to a label no runner has only to hold a run in `queued` (V6 matrix), then delete it.
- No secrets, no checkout, no third-party actions.
