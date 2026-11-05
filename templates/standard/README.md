# `standard`

The bundled template (`templates/standard/workflow.yaml`, PLAN.md section 7.6). Teams do not
edit it: they publish an overlay that extends `standard@1`, plus a `TeamConfig`.

## When to use

Use it, with a thin overlay, for most teams, in particular a Scrum team that wants every
change reviewed by a person and tested by QA before it merges. The order is: triage, refine,
plan, implement, an optional `pre_push_gate`, CI, LLM review, `review_gate`, QA environment and
suite, `qa_gate`, merge, post-merge checks, ticket done.

Both gates use `carry_over: patch_id`. Merging after QA means any other merge moves the base, so a
clean update re-runs CI and the QA suite and asks nobody again unless the code changed.

For a trunk-based team that releases straight after merge, use the `kanban` overlay on it. Where
an extra approver is mandatory, use the `regulated` overlay on it. Both extend this template.

## Checks to require

Require these in the repository's branch protection, and in `TeamConfig` / the org policy:

- `sto/review-gate`: the platform's status for the review gate. A merge needs a valid review
  approval for that code, so branch protection should require this check. (QA comes before the merge
  in this template, so a team may also require the QA gate's status. An overlay that merges before
  QA, such as `kanban`, must not.)
- The CI checks your repo needs, named by `team_default`. A `checks` stage with `required:
  team_default` must resolve to at least one, or the run blocks.
- QA suite checks `integration` and `e2e` (the `qa_auto` stage waits for both).

Org policy: the QA gate takes role `qa`, the review and pre-push gates role `reviewer`, and
`decision_surfaces` must name `pre_push`, `review`, `qa` and `custom`. A type the policy does not
name permits no surface (V10). `org-policy.yaml` shows all four.
