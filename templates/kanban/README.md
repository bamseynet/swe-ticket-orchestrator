# `kanban`

An overlay on `standard@1` (`templates/kanban/overlay.yaml`, PLAN.md section 7.7): trunk-based,
QA on staging after merge.

## When to use

Use it when a team merges to `main` after the review gate and tests on a shared staging
environment, then releases the tested SHA. It drops `refine`, `plan`, `promote`, `qa_env` and
`post_merge`, adds a `release` effect (`release.trigger`), and uses `carry_over: none` for QA.
A QA rejection opens a revert PR. A run blocked by another run's rejected commit goes back to
`qa_auto` under `release_stale`.

Teams that cannot accept this order use `standard`. Read the "Rules for merging before QA" in
PLAN.md section 7.7 first: staging holds other runs' merges, and release checks them all.

## Checks to require

- `sto/review-gate`, and only that one, in branch protection: the QA check cannot pass before
  this merge.
- `staging-smoke`: the `qa_auto` stage waits for it (`required: [staging-smoke]`, 1h).
- The CI checks named by `team_default` (the `ci` stage, 45m).

## An org that requires `qa_gate` with role `qa`

The overlay's `qa_gate` has `eligible_roles: [qa, reviewer]` and no `quorum`. An
`OrgPolicy.teams.<team>.required_gates` entry `{ id: qa_gate, role: qa }` is satisfied only by a
gate whose decider really is `qa`: with no `quorum`, that means `eligible_roles` is exactly
`[qa]`. So add a quorum to the team's overlay:

```yaml
stages:
  qa_gate:
    gate:
      eligible_roles: [qa, reviewer]
      quorum: [{role: qa, count: 1}]
```

For short, `quorum: [{role: qa, count: 1}]` on `qa_gate`. The role in the quorum must be one of
`eligible_roles`, and the org must allow `reviewer` on QA gates (`mandatory_gate_roles.qa`
including `reviewer`, as in `templates/org-policy.yaml`), or drop `reviewer` from
`eligible_roles`. The test `test_the_kanban_overlay_needs_that_quorum...` checks both outcomes.
