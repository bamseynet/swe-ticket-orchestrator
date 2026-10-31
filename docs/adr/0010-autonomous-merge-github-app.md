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
- **Merge guard:** re-read everything immediately before merge (PLAN.md section 6.4), and call merge with the SHA of the
  approved gate instance, so a moved head gets a 409 [S44]. `sha` does not guard the base, so the head must also contain the base
  tip, by default. Read back the result.
- **A hold after approval,** default 10 minutes, keeps the Stop window real, since otherwise a merge would follow at once.
- **GitHub-enforced gates:** publish `sto/review-gate` and `sto/qa-gate` check runs on `sto/*` heads, and a neutral result on other
  PRs, so human and revert PRs are not blocked. Teams require them per template, pinned to our App ID [S41], so GitHub blocks
  an out-of-band merge too.
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

## Consequences

- A bad merge is a real risk, so G13 and G15 and the read-back are required before this is enabled. It runs live on
  the throwaway repo in D4.
- Org-owned repos are needed for ruleset bypass lists [S42]. Personal repos can still use required checks. `bamseynet` is a personal
  account, so the throwaway repo cannot test a bypass, and D4-02 checks what the plan allows.
