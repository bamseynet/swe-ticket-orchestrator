# `regulated`

An overlay on `standard@1` (`templates/regulated/overlay.yaml`, PLAN.md section 7.8): extra
gates for security and change approval.

## When to use

Use it for a team whose changes need a security officer's approval, two reviewers, and, for
high-risk tickets, a change manager. It adds `security_gate` (a `custom` gate) and a
`change_route` on `risk` leading to `change_gate`. Review panel reviewers are all required and
`fail_closed`, `block_on: medium`. Every gate uses `carry_over: none`, so every base move asks all
the humans again: use a merge queue (PLAN.md section 6.4). Gates expire (`expire_after`) into
`closed_expired` and never approve. The evidence comment is posted after the post-merge check.

Separation of duties is wider than the default: `security_gate` also excludes whoever approved
`review_gate`, and `qa_gate` excludes both earlier approvers.

## Checks to require

- `sto/review-gate` in branch protection.
- QA suite checks `integration`, `e2e` and `performance` (`qa_auto`, 6h).
- The CI checks named by `team_default`, and the post-merge check (`post_merge`, 2h).

Org policy: this overlay relies on the org owning the extra gates, or the team's own admin could
remove them. `OrgPolicy.teams.<team>.required_gates` should list `security_gate` (role
`security_officer`) and `change_gate` (role `change_manager`, `when: { field: risk, value: high }`),
with `route_orders.risk: [low, medium, high]`, `min_quorum: { review: 2 }` and
`allowed_carry_over: [none]`. `templates/org-policy.yaml` does exactly this for team `ledger`.
`decision_surfaces` must name `custom` as well as `review` and `qa`. The org forbids `waive`.
