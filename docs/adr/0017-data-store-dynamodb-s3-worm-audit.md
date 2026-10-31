# ADR-0017: DynamoDB, S3, and hash-chained WORM audit

**Status:** Accepted

## Decision

- **DynamoDB** single-table design for operational state (PLAN.md section 11), with explicit indexes for queues and
  lists. No scan-based listing.
- **S3** for artifacts, snapshots and sessions, KMS-encrypted, with lifecycle rules and per-session credentials.
- **Audit:** separate table, hash-chained per run, written in the same transaction as the change. A stream copies to S3 with
  **Object Lock**. App roles have an explicit deny on update and delete.
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
