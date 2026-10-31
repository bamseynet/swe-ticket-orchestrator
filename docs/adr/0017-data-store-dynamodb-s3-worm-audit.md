# ADR-0017: DynamoDB, S3, and hash-chained WORM audit

**Status:** Accepted

## Decision

- **DynamoDB** single-table design for operational state (PLAN.md section 11), with explicit indexes for queues and
  lists. No scan-based listing.
- **S3** for artifacts, snapshots and sessions, KMS-encrypted, with lifecycle rules and per-session credentials.
- **Audit:** separate table, hash-chained per run through a chain head item, written in the same transaction as the change. A stream copies to S3 with
  **Object Lock**, in compliance mode by default for regulated deployments. Scheduled **KMS-signed checkpoints** over chain heads and counts go in the locked bucket, because an unkeyed chain could be recomputed or have its tail removed.
- **Honest limit:** app roles have a deny on update and delete, but need `PutItem`, which can replace an item, so DynamoDB alone is not tamper-proof. Protection starts when an event reaches the locked bucket. Iterator age alarms sit well under the stream's 24 hours.
- PITR on, deletion protection on, retention stacks keep audit data through `cdk destroy`.

## Alternatives

| Option | Why not |
|---|---|
| **Aurora Serverless (Postgres)** | Better ad hoc queries, but VPC, connection management and idle cost. We need few access patterns and strong conditional writes. Analytics export to S3 and Athena |
| **SQLite on EFS** (LangGraph PoC) | One writer, as that PoC found |
| **QLDB** | Not relevant to a new build. The chain and Object Lock provide the needed evidence |
| **AgentCore Memory for state** | Designed for agent context, with a 365 day event cap [S14] |

## Consequences

Transactions cap at 100 items, well above what a decision needs, and a test bounds it. Insights use streams to a separate
aggregate rather than scanning.
