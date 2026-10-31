# ADR-0009: Narrow adapter SPI, webhooks as nudges, shared conformance suite

**Status:** Accepted. Peter's decision: GitHub, Jira and Slack are first-class and fully built. GitHub is tested
live on a throwaway repo, and Jira and Slack are contract-tested against recorded and fake APIs until credentials
arrive.

## Decision

- Ports: `TicketSource`, `ScmProvider`, `Notifier`, `WebhookVerifier`, `CredentialBroker`. Each adapter declares
  its capabilities, and the validator uses them to reject a workflow that needs something missing.
- **A webhook only says something changed.** Ingest verifies the signature on the raw body, dedupes and enqueues
  inside vendor deadlines. Consumers re-read current state. A reconciler sweeps open runs, so a missed webhook only
  adds delay.
- **Conformance suite:** one set of behaviour tests run against each adapter's fake server. When real credentials
  exist, the same tests run against the real API, and a difference is a bug in the fake.
- Jira and Slack are **production adapters, not stubs.** Only the server under them is fake until D12.
- Recorded fixtures are scrubbed of anything real, because this repo is public.
- Connections are org-level where a vendor forces it, one Slack bot and one shared Jira registration, with resource bindings routing to teams. A Jira service account is the default, because 3LO acts as a person [S46].

## Alternatives

| Option | Why not |
|---|---|
| Treat webhook bodies as truth | Jira documents no ordering [S45], and GitHub's redelivery reads as manual [S40]. Bodies can also be stale |
| Polling only | The LangGraph PoC's polling read every open issue, and is slow and costly |
| Gateway's built-in Jira and Slack integrations for everything | Good for agent reads. The effect executor needs idempotency and read-back, which is ours to own. Agents never get write tools |
| A fat `Integration` interface | Azure DevOps has no check runs, Jira has no merge. Narrow ports with capabilities fit |

## Consequences

Fakes are real work, and carry drift risk, which D12 measures. Each adapter ships with its fake.
