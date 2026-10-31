# ADR-0011: Effects through an outbox, with idempotency keys and read-back receipts

**Status:** Accepted

## Decision

- State changes plan effects in the same transaction. An executor claims them and acts.
- Classes: `internal`, `scoped`, `exposing` for `branch.push`, and `gated` (PLAN.md section 6.3). Gated effects require a decision ID and re-check gate,
  run and subject immediately before acting.
- Delivery is at-least-once, so every adapter write takes an idempotency key derived from
  `(run, stage, visit number, effect type, subject digest)`, with narrower scopes declared in the catalog, so `pr.ensure_draft` finds or creates.
- **Status comes only from a receipt with read-back.** The UI cannot say "written" otherwise. Local simulated writes
  are labelled.
- Markers used for idempotency are trusted only when written by our own bot identity.
- **The claim is a transaction** checking run, gate and switches, so a re-read cannot race with Stop.
- **Commits are recorded before the ref moves:** create the commit object, record its SHA, then move the ref without force. A crash leaves a known SHA. This is also what separation of duties relies on.
- **Effects with no idempotency, such as a workflow dispatch,** carry the key as a required input, and ambiguity goes to `BLOCKED` rather than retrying a deploy.

## Alternatives

| Option | Why not |
|---|---|
| Write inline in the step | A crash leaves unknown state. The transaction cannot cover an external call |
| Exactly-once delivery | Not achievable across outside APIs |
| Trust a success response | The brief's "written back shown when nothing was written" came from trusting less than a verified result. An API may also accept but not apply, as Jira screens can |

## Consequences

Each adapter needs read-after-write logic, which costs extra API calls and is worth it for the gated class.
