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
  request, keyed on immutable group IDs.
- **Removal is handled explicitly.** Cognito "doesn't remove attributes from users when the source attribute is no longer sent" [S66], so an Inbound federation trigger rewrites the attribute on each sign-in, with Pre authentication as a fallback [S67].
- **Surfaces with no token:** a Slack or GitHub decision carries no `auth_time`. So each identity has a membership snapshot with `as_of`, and every decision on every surface needs it within `identity_max_age`. Otherwise it deep-links to sign in (G19). A port allows a directory or SCIM refresh.
- **Hardening:** no local users, admin-create-only, no `aws.cognito.signin.user.admin` scope.
- **Step-up:** UI decisions can use `prompt=login` and `max_age`, on managed login [S68].
- **Lifetimes:** access token 15 minutes, refresh 8 hours, as defaults.

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

Tracked in D12-10, and the design tolerates each going badly:

- **Whether a federated user can overwrite a mapped attribute** with self-service scopes. We remove the scope anyway.
- **Large group lists at real IdPs.** A value over 2,048 characters makes sign-in fail [S66]. Fallback: send only app-relevant groups, or look up in a trigger.
- **Whether a refresh re-queries the IdP.** We assume not, so the snapshot's `as_of` and an immediate admin disable are the controls.

Slack, GitHub and Jira accounts link to an SSO identity by completing that vendor's OAuth flow, and email matching alone is never
accepted.
