# Architecture decision records

Each record is one decision, with the alternatives considered. Sources are in
[RESEARCH.md](../RESEARCH.md), cited as `[S1]` and so on. All were accepted on 2026-10-31 as part of the
plan PR, and Peter can overturn any of them on review. New decisions get the next number, and a changed
decision gets a new record that supersedes the old one.

| # | Decision |
|---|---|
| [0001](0001-deterministic-engine-with-strands-stage-orchestrators.md) | A deterministic stage engine runs the workflow, and Strands orchestrators run inside each stage |
| [0002](0002-durable-execution-step-functions-dynamodb.md) | Step Functions Standard as durable driver, DynamoDB as authority, for days-long waits |
| [0003](0003-agents-as-tools-inside-stages.md) | Agents-as-tools inside stages, with no Graph or Swarm for now |
| [0004](0004-agentcore-runtime-custom-strands-container.md) | Our own Strands container on AgentCore Runtime, with sessions treated as disposable |
| [0005](0005-gate-integrity-model.md) | Gate model: subject binding, veto, single close, atomic audit |
| [0006](0006-declarative-workflow-config.md) | Declarative, versioned, statically proved workflow config with platform floors |
| [0007](0007-multi-tenancy-rbac-separation-of-duties.md) | Team tenancy, server-side RBAC, decision-time separation of duties |
| [0008](0008-sso-cognito-as-federation-broker.md) | Cognito user pool as SSO federation broker, behind an issuer-based API |
| [0009](0009-integration-spi-webhooks-as-nudges.md) | Narrow adapter SPI, webhooks as nudges, shared conformance suite |
| [0010](0010-autonomous-merge-github-app.md) | Autonomous merge through a GitHub App with a read-back merge guard |
| [0011](0011-effect-outbox-with-read-back-receipts.md) | Effects through an outbox, with idempotency keys and read-back receipts |
| [0012](0012-sandboxed-workspaces-and-repo-access.md) | Sandboxes with no SCM credentials and a minimal role, and private repo access through a broker |
| [0013](0013-tools-via-gateway-policy-and-injection-posture.md) | Read-only tools through Gateway and Policy, assuming injection succeeds |
| [0014](0014-model-catalog-and-tiers.md) | Model catalog and tiers, with IDs as verified data |
| [0015](0015-budgets-cancellation-kill-switch.md) | Fail-closed budgets, first-class cancel, layered kill switch |
| [0016](0016-web-hosting-and-event-delivery.md) | CloudFront, API Gateway, and a cursor event log with a WebSocket nudge |
| [0017](0017-data-store-dynamodb-s3-worm-audit.md) | DynamoDB, S3, and hash-chained WORM audit |
| [0018](0018-observability-otel.md) | OpenTelemetry through ADOT to CloudWatch |
| [0019](0019-offline-first-testing-and-live-milestone.md) | Offline-first testing, with a credential-blocked live milestone |
| [0020](0020-stack-and-repo-layout.md) | Python, TypeScript, one repo, and layout built for parallel PRs |
| [0021](0021-ci-trust-for-unreviewed-code.md) | Model-written code gets no CI secrets before the first human gate |
