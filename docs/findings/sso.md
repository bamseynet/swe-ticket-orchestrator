# SSO findings and the D12-10 test plan

D3-01 builds OIDC validation against a fake issuer. The fake proves our logic. It cannot prove how
Cognito or a real enterprise IdP behaves. This file is the plan for D12-10 (L11, FF-13) and the
place where its results go. Nothing below has been observed yet.

## What the D3-01 review found, to check against the real thing

- **Issuer form.** The review of D3-01 notes that AWS recommends an `https://issuer-cognito-idp...`
  form of the issuer for some setups, which `cognito_config` cannot produce. `OidcConfig` takes any
  https issuer, so using it is config only. D12-10 reads the real `iss` claim and the discovery
  document and records which form the pool issues.
- **`aud` on access tokens.** `cognito_config` assumes access tokens carry `client_id` and no
  `aud`. That is not true for resource-bound access tokens, which can carry `aud`. Record what the
  pool issues for our app client, with and without a resource server, and set `audience_claim`
  to match.
- **M2M tokens and service identities.** A `client_credentials` token has `sub == client_id`, no
  groups and `token_use=access`. If its `client_id` is ours it validates today and yields a
  `VerifiedToken` with empty groups. PLAN 9.2 says service identities are distinct and never
  eligible for a gate, and D3-05 and D10 say the same. D3-01 does not classify them: nothing in
  `VerifiedToken` marks a token as a service identity. Safety rests on D3-02 (an unmapped user has
  no access) and D3-05 (service identities excluded), and neither says how a service identity is
  recognised. Decide that in D3-02 (for example `sub == client_id`, or a separate audience) and
  have D12-10 confirm it against a real M2M token.
- **SAML.** D12-10 requires a real SAML IdP as well as OIDC. The API only sees Cognito's OIDC
  tokens either way, so test that the group attribute arrives the same way from a SAML federation,
  including how multi-valued attributes are encoded in the claim.

## Group list size
- Put a test user in far more groups than the app needs. Confirm sign-in succeeds with only the
  app-relevant IDs, or fails visibly. Record the real limit (the 2,048 character attribute cap is
  documented, not observed).
- Confirm the Inbound federation trigger sends immutable group IDs only, never display names.

## Step-up
- Sign in with `prompt=login` and `max_age` through managed login. Confirm the IdP is asked again
  and `auth_time` moves, and that it does not move on a plain refresh.
- Reuse a session cookie. Confirm the token is fresh but `auth_time` (our `as_of`) is not.

## Revocation
- Remove a user from their last group at the IdP and sign in again. Confirm the groups attribute
  is cleared (Cognito keeps old attributes unless the trigger writes an explicit blank, which the
  validator normalises to no groups).
- Disable the user in the pool. Confirm the API refuses within one request, and record how long
  an already-issued access token (15 minute default) stays valid at the signature check alone.
- Remove a signing key from the JWKS and record how long `CachedJwks` keeps trusting it (the TTL,
  1 hour by default).

## Also check against the real pool
- Claim names: `client_id`, `token_use`, `cognito:groups` and `auth_time` on real tokens.
- A federated user cannot overwrite the mapped groups attribute (self-write attempt fails).
- Key rotation: rotate the pool's signing key and confirm `CachedJwks` picks up the new `kid`.

Anything unproven keeps its fallback in ADR-0008.
