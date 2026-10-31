# ADR-0006: Declarative, versioned, statically proved workflow config

**Status:** Accepted

## Decision

- Workflows are YAML, checked against a JSON Schema generated from typed models, then by semantic rules
  (PLAN.md section 7.3).
- **Safety properties are proved on the graph before anything runs:**
  - Every cycle has a named, capped loop edge (V3).
  - **Gate dominance (V4):** remove a gate's `approved` edge, and any effect requiring it must become
    unreachable from `start`.
  - **Freshness (V5):** the same from each code-changing stage.
- **Four documents:** `OrgPolicy` and `TeamConfig` are live, resource bindings are live, and `Workflow` is versioned. Budgets, calendars and floors are not pinned, because a raised budget or a tightened floor must reach runs in flight.
- **Overlays use JSON Merge Patch on a stage map keyed by ID.** Maps merge, lists replace and `null` removes. Stage order has no meaning, so no `insert_after` is needed. Teams write an overlay, not a copy, which a 100-line fork in YAML would be.
- **Publishing flattens,** and a run pins a manifest digest over workflow, profiles, effects and prompts.
- **Teams add their own reviewers** through custom profiles, with no platform PR.
- A closed `route` stage handles risk routing, with no expressions, so proofs still hold.
- Teams can dry-run with the fake LLM.

## Alternatives

| Option | Why not |
|---|---|
| Python per team | That is a fork by another name, and cannot be statically proved |
| A general language such as CEL or Starlark for transitions | Harder to prove. Declared outcomes cover the known needs, and expressions can come later for definition-of-done checks |
| BPMN | Poor fit and heavy tooling for developer teams. The stage graph UI gives the visual benefit |
| Team-authored ASL | Exposes engine internals, no floors |

## Consequences

- New stage kinds or effects need code, which is intended. A team's stages, order, tools, calendars and
  policies do not.
- Examples in PLAN.md are checked by the validator from D2 onward. For this PR, they were checked by a scratch
  script implementing V1 to V6, V8, V11, V13 and V14 on the flattened overlays.
- Intake uses closed selectors, because arbitrary JQL cannot be proved disjoint.
