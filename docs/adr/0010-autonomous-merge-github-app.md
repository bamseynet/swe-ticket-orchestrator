# ADR-0010: Autonomous merge through a GitHub App, with a read-back merge guard

**Status:** Accepted. Peter's decision: the orchestrator merges reviewed, green PRs itself.

## Decision

- Default templates merge after the QA gate, with no further human action. A team can place the merge directly
  after the review gate.
- **A GitHub App**, because only Apps can write check runs [S36]. Its key is held in KMS, and the JWT is signed
  by KMS, so the key is never in memory or env. Tokens are narrowed per call to one repo and the needed permissions,
  for at most an hour [S37].
- **AgentCore Identity is not used for GitHub App tokens,** because the documented GitHub provider is an OAuth App
  user flow [S21]. It is used for Jira OAuth, and for other providers where it fits.
- **Merge guard:** check everything in or just before an atomic claim (PLAN.md section 6.4), and request the merge through the **async merge API** with the approved SHA. GitHub recommends it, and the sync endpoint "does not support ... merging with a merge queue" [S60]. `sha` does not guard the base, so the head must also contain the base tip, by default. Read back the result, because `enqueued` does not mean merged.
- **Base updates use `POST /merges`,** which returns a SHA, so a receipt is possible [S62]. It cannot carry an expected head, so we check before and read back the first parent. `update-branch` returns 202 with no SHA, which would look like a human commit.
- **A hold after approval,** default 10 minutes, keeps the Stop window real, on merge, release and a done transition.
- **Check runs raise the bar, and do not close it.** A check attaches to a commit, and neutral counts as passing [S59]. So neutral is posted only for a SHA no run has ever produced, with a tombstone, which stops merging a run's exact SHA before approval. It does not stop someone pushing different code to another branch, which the reconciler detects. An earlier version of this ADR claimed more, and the adversarial review corrected it.
- **Revert PRs use `sto-revert/*`,** outside the gate check, so they are not stuck during an incident.
- **If branch protection requires a human GitHub review,** the App cannot satisfy that, and should not bypass it by
  default. Use `decision_surfaces: [github]`, so the reviewer's real GitHub review is the decision. A ruleset bypass
  for the App [S42] is a documented team choice, not the default.
- **Controls:** team and org merge switches, sprint freeze windows, merge queue support [S43], and a revert PR path
  for post-merge failure, which still goes through review.

## Alternatives

| Option | Why not |
|---|---|
| Human clicks merge | Peter's decision is otherwise. Available by ending the workflow before `pr.merge` |
| GitHub auto-merge | Good when all rules are in GitHub, but cannot re-check our gates, SoD or freeze at the moment of merge |
| PAT or OAuth App | No check runs, broad scope, tied to a person |
| Long-lived private key in Secrets Manager | KMS signing avoids the key ever being readable |
| Giving the agent merge tools | Violates ADR-0013. An injected agent could merge |
| The sync merge endpoint | Not recommended by GitHub, and cannot use a merge queue [S60] |

## Consequences

- A bad merge is a real risk, so G13 and G15 and the read-back are required before this is enabled. It runs live on
  the throwaway repo in D4.
- Merge queues need an organization-owned repo, and private repos need Enterprise Cloud [S43]. Org-owned repos are also needed for ruleset bypass lists [S42]. Personal repos can still use required checks. `bamseynet` is a personal
  account, so the throwaway repo cannot test a bypass or a queue, and D4-24 checks what the plan allows.
