# ADR-0021: Model-written code gets no CI secrets before the first human gate

**Status:** Accepted, with the default open as Q6 in PLAN.md section 0.

## Context

The sandbox holds no SCM credentials, but team CI holds secrets, and the default flow pushes model-written code to the team's repo and runs CI before the review gate. An injected implementer can change `package.json`, a `Makefile`, tests or a composite action. That can read every secret and OIDC role the job has, with open egress, before any human has looked. A path deny list cannot close this, because a change must be able to touch files CI runs. The adversarial review of this plan found it (P0-1), and it was the most serious gap.

## Decision

- **Floor:** a `checks` stage before the first human gate runs without secrets.
- **Each repo reports a `ci_trust` mode,** from a connection test:

| Mode | How | Cost |
|---|---|---|
| `fork` | Code goes to a bot-owned fork, and `pull_request` from a fork gets no secrets [S69] | Needs a bot account, and approval and policy settings must allow it |
| `no_secrets` | Secrets only in GitHub Environments with protection rules, OIDC trust excludes `sto/*`, no self-hosted runners | Repo owners must arrange this. Attestation reads names and rules through the API, and is best effort |
| none attested | **An automatic human gate before CI** | One more click per round |

- After the review gate, `branch.promote` moves the approved SHA into the same repo for QA suites that need secrets, because a human has now seen the code.
- An org admin can waive the floor for a named repo, which is audited.
- A hostile test on the throwaway repo must not read a canary secret (D4-15).
- The same applies to this repo: `live-github.yml` secrets sit in an Environment with Peter as required reviewer, because "not on fork PRs" does not stop a same-repo branch from editing the workflow.

## Alternatives

| Option | Why not |
|---|---|
| **Fork as the default** (the review's recommendation) | By default "all first-time contributors require approval to run workflows", and an org that disables fork workflows on private repos cannot be overridden per repo [S69]. A default that can stall an autonomous bot, or needs a bot account first, is a poor out-of-box path. It stays the preferred attested mode |
| Path deny list only | Cannot work, as above. It remains a second layer |
| Run tests only in the sandbox, with no team CI before the gate | Team CI is the authority on test results, and reviewers want green CI before they read |
| Trust the sandbox boundary | The boundary is not where this attack happens |

## Consequences

Repos that have not attested get an extra human step, so onboarding docs lead with attestation. The real behaviour of forks with required checks is unverified, and D4-23 settles it.
