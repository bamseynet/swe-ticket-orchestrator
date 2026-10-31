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
- Per-team: inference profiles, connections, budgets, Gateway rate limits [S8], S3 prefixes.

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
