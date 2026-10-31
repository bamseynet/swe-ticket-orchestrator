# ADR-0015: Fail-closed budgets, first-class cancel, layered kill switch

**Status:** Accepted

## Decision

Details are in PLAN.md section 14.

- **Budgets** at step, stage, run, team and org, enforced by reservation in a Strands hook before each model call. If
  the ledger is unreachable, calls stop.
- **Budget exhaustion is `BLOCKED`, not failure.** Work is kept, and an admin can raise it.
- **Cancel** is a run state, with ordered steps, a 60 second target, and tests that count model calls after cancel.
- **`AbortableBedrockModel`** carries forward, because Strands clears its cancel signal while unwinding.
- **Kill switch** levels: pause, stop, merge off, and break-glass explicit-deny IAM that works even if the app is
  broken.
- **Concurrency** uses a DynamoDB lease semaphore.

## Alternatives

| Option | Why not |
|---|---|
| AWS Budgets alone | Delayed, account-level, cannot stop a run. Kept as a backstop |
| Lambda reserved concurrency as a brake | Counted every request and throttled unrelated endpoints (Strands PoC) |
| Token limits only per invocation | Nothing stops many invocations. Strands' limits remain as an inner bound |
| Closing a connection cancels | Tied to connection lifetime, as in the Strands PoC, which cannot work with days-long runs |
| Fail open on ledger outage | Silent overspend |

## Consequences

Reservations are conservative, so a run can stop slightly early. Without count tokens on `bedrock-runtime`, D12 calibrates
the estimate. Prices are estimates until reconciled with billing.
