# SSO findings and the D12-10 test plan

D3-01 builds OIDC validation against a fake issuer. The fake proves our logic. It cannot prove how
Cognito or a real enterprise IdP behaves. This file is the plan for D12-10 (L11, FF-13) and the
place where its results go. Nothing below has been observed yet.

## What the D3-01 review found, to check against the real thing

- **Issuer form.** AWS documents `https://issuer-cognito-idp.{region}.amazonaws.com/{pool}` as the
  "Updated issuer", "Recommended for all user pools", with the original
  `https://cognito-idp.{region}.amazonaws.com/{pool}` as the "current default"
  ([AWS: federation endpoints](https://docs.aws.amazon.com/cognito/latest/developerguide/federation-endpoints.html)).
  `cognito_config` produces only the original form. `OidcConfig` takes any https issuer, so the
  updated form is config only. D12-10 reads the real `iss` claim and the discovery document,
  records which form the pool issues, and switches `cognito_config` if it is the updated one.
- **`aud` on access tokens: a decision for D12-10.** `cognito_config` checks `client_id` and
  ignores `aud`. A resource-bound access token keeps `client_id` and adds `aud`, so a token from
  our app client that is bound to a different API is accepted today (reproduced in the D3-01
  review). Switching to `audience_claim="aud"` also means setting `audience` to our API's
  resource URL, and then tokens without that binding are refused. D12-10 records what the pool
  issues for our client with and without a resource server, and decides between: client-bound
  tokens only (today, accepting the cross-API case), or resource-bound tokens only (`aud` equal
  to our resource URL).
- **M2M tokens and service identities.** A `client_credentials` token has `sub == client_id`, no
  groups and `token_use=access`. If its `client_id` is ours it validates today and yields a
  `VerifiedToken` with empty groups. PLAN 9.2 says service identities are distinct and never
  eligible for a gate, and D3-05 and D13-12 say the same. D3-01 does not classify them: nothing in
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
