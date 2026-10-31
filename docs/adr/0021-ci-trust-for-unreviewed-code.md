# ADR-0021: Code no human has approved runs without CI secrets

**Status:** Accepted, with the default open as Q6 in PLAN.md section 0. Revised after pass 2 of the adversarial review, which showed the first version's gate came too late.

## Context

The sandbox holds no SCM credentials, but team CI holds secrets, and pushing model-written code starts that CI. CI starts on `push` and `pull_request`, and an App token does trigger them [S75], so it does not wait for our `ci` stage. An injected implementer can change `package.json`, a `Makefile`, tests or a composite action. That can read every secret and OIDC role the job has, with open egress. A path deny list cannot close this, because a change must be able to touch files CI runs.

## Decision

- **Floor:** code no human has approved at this `patch_id` runs without secrets, **on every round**, because `qa_fix`, `merge_conflict` and `changes_requested` all produce new code after an earlier approval.
- **Default: the gate comes before the push.** The patch waits in S3, and no branch or PR exists until a person approves it at `pre_push_gate`. It is a real stage in the template, reached through a `trust_route` that is evaluated fresh each round, so the static proofs cover it (V16). The claim on `branch.push` checks it again at run time.
- **It is not a review.** It has its own type, role, loop and page, and does not count as the review gate.
- **Attestation can only say `attested` or `unknown`,** and unknown means the gate. It needs every condition in PLAN.md section 12, re-checks each round and expires after 90 days. Two conditions cannot be read from any API: a named human confirms that Actions is the only CI, and attests the OIDC trust.
- **`promote` stage:** after the review gate, the approved SHA moves to `sto-approved/<run>`, the branch where QA secrets are allowed. It is a template stage, so each fix round re-promotes.
- **An org admin can waive the floor for a named repo,** which is audited.
- A hostile test on the throwaway repo must not read a canary secret (D4-15).
- The same applies to this repo: `live-github.yml` secrets sit in an Environment with Peter as required reviewer.

## Alternatives

| Option | Why not |
|---|---|
| **Fork as the default** (the first review's recommendation) | On public repos, by default "all first-time contributors require approval to run workflows", and on private repos an org that disables fork workflows cannot be overridden per repo [S69]. It also needs a bot account. It stays a design, in D4-28, unsupported until D4-23 passes |
| **A gate at the `ci` stage** (this ADR's first version) | CI has already started by then |
| **Attestation that passes when nothing bad is found** | It fails open for CI outside Actions, a permissive `GITHUB_TOKEN`, `pull_request_target`, and OIDC trust, none of which secret names reveal |
| Path deny list only | Cannot work, as above. It remains a second layer |
| Run tests only in the sandbox, with no team CI before the gate | Team CI is the authority on test results, and reviewers want green CI before they read |

## Consequences

Repos that have not attested get an extra human step on every round, and no PR exists until it passes, so reviewers see the diff from S3 first. Attestation is still a claim about a customer's repo, which our canary cannot prove, so the attesting person and date appear on every gate. D4-28's fork stages are in the template rather than a separate overlay, because `promote` also serves `no_secrets`.
