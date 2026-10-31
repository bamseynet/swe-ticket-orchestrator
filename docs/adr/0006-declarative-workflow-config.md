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
- Layers: platform floors, org defaults, template, team overlay. Lower layers cannot weaken floors.
- Published versions are immutable, and every run pins one.
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
  script implementing V1 to V6.
