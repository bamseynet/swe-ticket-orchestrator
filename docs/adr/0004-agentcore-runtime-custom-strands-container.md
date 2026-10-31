# ADR-0004: Our own Strands container on AgentCore Runtime, with disposable sessions

**Status:** Accepted

## Decision

- Run agents in **our container** on AgentCore Runtime, microVM compute, platform V2, one session per step
  attempt (`run-<id>-step-<n>-a<attempt>`, at least 33 characters).
- **Invoke asynchronously:** the entrypoint accepts work and returns. `add_async_task` keeps the session
  `HealthyBusy`, the blocking work runs off the ping thread, and the SDK handles status [S16].
- **Progress and results go through SQS,** not the invoke response. There is no 60 minute stream limit and no
  block-size trouble (the Strands PoC's 1 KiB read issue).
- **A session is disposable.** Everything needed to continue is in S3, DynamoDB or the branch. A lost session
  means retry the attempt. Session storage (preview) is not used for anything critical.
- Session credentials use context keys, so a session can only reach its own S3 prefix [S8], [S15].
- Inner boto clients use `total_max_attempts=1`, because a retried invoke starts a second billable run.

## Alternatives

| Option | Why not |
|---|---|
| **AgentCore harness** (GA per release notes, though the FAQ says preview [S8], [S9]) | Attractive for simple agents, with per-invocation caps. We need Strands hooks for budgets, redaction, cancellation and tool policy, which Peter's brief asks for, and control of the worker pattern. Revisit as a worker runtime |
| **Lambda** | 15 minutes, no microVM per session |
| **Fargate tasks** | Workable, but AgentCore gives per-session isolation, scaling and built-in tools without us building them, and the brief names it |
| **Instances compute** | 14 day sessions would tempt us to hold state in them. Consider only for GPU or capacity reasons |

## Consequences

- 2 vCPU, 8 GB and a 2 GB image limit apply [S14], which is why heavy builds stay in team CI.
- The real arm64 image on real AgentCore is unproven until D12.
