# ADR-0014: Model catalog and tiers, with IDs as verified data

**Status:** Accepted

## Decision

- Stages use tiers: `fast` (Haiku 5.5), `standard` (Sonnet 5.5), `deep` (Opus 5.5). IDs are in
  [RESEARCH.md](../RESEARCH.md) section 3, checked against the model cards on 2026-10-31.
- A **catalog** holds each model's ID per geography, capabilities (`tool_choice`, thinking behaviour, long-context
  pricing), EOL date, and prices with source and date.
- `sto doctor --aws` (D12) calls `GetInferenceProfile` from the source Region and makes one small `Converse` per model,
  checks IAM covers the routed destinations, and fails loudly. **No ID is trusted until this has passed.**
- At deploy, one **application inference profile per team and tier** [S31], tagged for cost allocation.
- Callers use `bedrock-runtime` with Converse through Strands, since AWS recommends it and Mantle lacks Guardrails
  and invocation logs on these models [S26].
- Workflows name tiers. An org can pin a tier to another model, and the catalog warns on profiles with limited model
  selection [S30] and on approaching EOL.

## Alternatives

| Option | Why not |
|---|---|
| Model IDs in code or env | How the PoCs got unverified IDs |
| `global.` by default | Simplest and most available, but residency rules vary. A deploy setting (Q4) |
| One model everywhere | Wasteful on triage, weak on review |

## Consequences

Behaviour from the model cards must be respected: no forced tools on Opus or Sonnet 5.5, adaptive thinking always on
for Opus, and no count tokens on `bedrock-runtime`.
