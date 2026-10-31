# ADR-0007: Team tenancy, server-side RBAC, decision-time separation of duties

**Status:** Accepted, assuming one deployment per company (Q1)

## Decision

- One deployment holds one org with many teams. Everything is keyed by team. Repository functions require a
  verified `TeamScope`, and a test fails any query without one.
- Roles are data, resolved server-side on each request from `(idp, group) -> (team, role)` mappings.
- Admin rights never imply eligibility to approve.
- Separation of duties is evaluated **at decision time,** not at gate open. The floor excludes anyone who authored or
  pushed code in the PR. Teams can add author, requester and prior approver of another gate.
- **Git author fields are free text, so they are not trusted.** A commit in the run's own push receipts is the platform's.
  Any other commit is human and unattributed, and blocks the gate until a team admin attributes it: fail closed.
- **Two humans:** the requester cannot approve review, and nobody can approve both review and QA, unless `OrgPolicy` waives it (Q5). An empty floor would let one person pass both mandatory gates, because the agent writes the code.
- `requester` comes from the audited intake event, `author` is the union of every assignee seen, and an unresolved term fails closed.
- An admin who changes a mapping, attributes a commit or clears an exclusion is ineligible for that round, and mapping changes do not reach open gates.
- **Resource bindings** from repo, project and channel to team are org-admin-owned, and enforced at publish, in the credential broker and in the tool layer. "Connections per team" alone would not stop team A naming team B's repo.
- Per-team: inference profiles, budgets, Gateway rate limits [S8], S3 prefixes.

## Alternatives

| Option | Why not |
|---|---|
| One deployment per team | Wasteful, and cross-team reporting and floors are lost. Still possible, since one team in an org is a valid case |
| Roles only in token claims | Stale up to token lifetime, and limited by claim size |
| Per-team AWS accounts | Strong isolation but heavy. A later option for high-assurance teams |
| Requester always excluded | Would block small teams, when an agent wrote the code. Available as a stricter setting |

## Consequences

If Q1 becomes multi-company SaaS, add an org key above teams, per-tenant KMS and IdP config. The `TeamScope`
pattern makes that a contained change.
