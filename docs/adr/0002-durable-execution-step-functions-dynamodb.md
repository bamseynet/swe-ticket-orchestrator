# ADR-0002: Step Functions Standard as durable driver, DynamoDB as authority

**Status:** Accepted

## Context

A run can wait days or weeks for a human, must survive restarts and deployments, and must be stoppable.
[RESEARCH.md](../RESEARCH.md) section 4 has the comparison.

## Decision

- **One generic interpreter state machine** (Standard workflow) for all teams:
  `Advance -> Choice -> RunStep | WaitHuman | RunEffect | AwaitChecks | Finish -> Advance`.
- **DynamoDB is the authority** for run, gate, effect and decision state. Every change is a conditional
  transaction.
- **Task tokens are wake-up signals only.** `.waitForTaskToken` holds the execution with no compute. A token
  carries only IDs back. The engine re-reads the store.
- Step Functions carries IDs, never payloads, so its 256 KiB limit is irrelevant.
- `max_steps_per_run` is capped at 500. A test computes the upper bound on history events, staying well under
  the 25,000 limit, so continue-as-new is not needed. `max_run_age` is capped below 1 year.
- Timers are one-shot EventBridge Scheduler entries, which re-read state and are safe if late or repeated.

## Alternatives

| Option | Why not |
|---|---|
| **AgentCore sessions hold the wait** | 8 hours on microVM, 14 days on Instances [S14]. Memory is billed while alive [S19]. Session storage is preview, and a version update resets it [S12]. Not a place to keep an approval |
| **DynamoDB and SQS only** | Fits gate atomicity and testing, but we would build timers, heartbeats, retries, stop and execution visibility: a workflow engine |
| **Step Functions alone, with state in the execution** | No atomic gate decision with audit. Second-token calls give `TaskTimedOut` but no record of who won. History retained only 90 days. Poor offline testing of logic |
| **One compiled state machine per workflow version** | `CreateStateMachine` refills at 1 per second. Publishing would need AWS. Logic in ASL is hard to test offline, and the whole engine would need rebuilding for local dev |
| **AgentCore harness via Step Functions** | Request Response only, 15 minute limit, no callback, and stopping the execution does not stop the harness [S24] |

## Compatibility

An execution keeps the definition it started with, for up to 300 days. So the command JSON between ASL and Lambdas is a versioned envelope, and D11-02 tests old ASL against new handlers, and the reverse (R5). Reducer state has its own replay test, from D2-20.

## Consequences

- Runs need two systems, with a relay between them. The outbox relay and a reconciler cover the gap, and G6
  tests a crash at every point.
- `Driver` is a port, with `LocalDriver` for local use, so the product runs with no AWS at all.
- Offline ASL testing is partial. D11-03 is a spike, and `TestState` runs in D12.
