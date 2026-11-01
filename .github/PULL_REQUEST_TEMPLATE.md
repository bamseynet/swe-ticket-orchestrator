Closes #

<!-- Keep `Closes #N` on its own line. One issue, one PR, branched from main (no stacked PRs). -->

## Summary

<!-- What changed and why, in a few lines. -->

## Acceptance criteria

<!-- Map each criterion of the issue (and the standing criteria in docs/STAGES.md) to evidence: test names, CI run URLs. A criterion is met when CI shows it. -->

| Criterion | Evidence |
|---|---|
|  |  |

## Files outside the issue's declared list

<!-- "None", or list each file and why it had to change. -->

## Unverified until D12

<!-- Anything that depends on AWS or live services and so cannot be proved offline. Write "Nothing" if truly nothing. -->

## Independent review

<!-- Link to the review by a fresh session that did not write this code. Review loops are capped at 3 rounds. -->

- Review: 

## Checklist

- [ ] Based on `main`, not stacked on another PR
- [ ] Tests written first for behaviour; only targeted tests run locally
- [ ] `ci-required` is green
- [ ] No real account IDs, tokens, internal URLs or customer data
