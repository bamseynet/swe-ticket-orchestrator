# ADR-0008: Cognito user pool as SSO federation broker, behind an issuer-based API

**Status:** Accepted. Peter's decision: enterprise SSO through OIDC and SAML, IdP-agnostic, with team and role
mapping from IdP groups.

## Decision

- **Cognito user pool brokers sign-in.** Customers connect an OIDC or SAML IdP such as Entra ID, Okta or Ping,
  without code changes [S51], [S52], [S53].
- The web app uses authorization code with PKCE, on HTTPS only.
- **The API trusts an issuer and JWKS,** not Cognito. API Gateway's JWT authorizer and our local fake issuer use
  the same validation, so another broker can replace Cognito by configuration.
- **Groups:** an attribute mapping passes IdP groups to the pool, and a pre token generation trigger normalises
  them with `groupOverrideDetails` [S54]. The platform's own mapping table then gives team and role, on every
  request. The token supplies the fact of membership, and the platform decides what it means.
- **Lifetimes:** access token 15 minutes, refresh 8 hours, as defaults. Gate decisions re-check mappings and
  `auth_time`, and can require recent authentication.

## Why Cognito

- Fits deployment by CDK, with no other vendor account, so anyone can deploy from this repo.
- OIDC and SAML in one place, with claim mapping, and a straightforward JWT authorizer path.
- Offline, a small fake issuer stands in for it.

## Alternatives

| Option | Why not |
|---|---|
| **Direct OIDC from each IdP** | Clean for OIDC-only customers, but SAML needs a broker. Still reachable through the issuer-based API |
| **IAM Identity Center** | Good for AWS workforce access, less suited as a general web app identity broker, and adds an org-level dependency |
| **Auth0 or Okta as broker** | Strong features, but a paid outside dependency for each deployer. A team that already has one can use it through the issuer config |
| **Self-hosted Keycloak** | Full control, but a stateful service to run and patch |
| **AgentCore Identity for humans** | Its inbound auth secures agents and tools, not our product UI |

## What we have not verified

Tracked in D3-01 and D12, and the design tolerates each going badly:

- **Large group lists:** custom attribute size limits, and some IdPs' group overage behaviour. Fallback: map only
  app-relevant groups at the IdP, or look up groups in a trigger.
- **Step-up through a broker:** forcing re-authentication at the IdP. Fallback: a recent `auth_time`, enforced by
  a shorter session for decisions, or relying on the IdP's policy.
- **Refresh and SCIM:** assumed that a refresh may not re-query the IdP, and that SCIM is unavailable, so a removed person may keep
  a group claim for up to the session life. Decisions therefore need a recent `auth_time`, and an admin can disable a user with
  immediate effect, which the API checks on every request.

Slack and GitHub accounts link to an SSO identity through a signed flow, and email matching alone is never
accepted.
