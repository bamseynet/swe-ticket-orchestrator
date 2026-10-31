# ADR-0016: CloudFront, API Gateway, and a cursor event log with a WebSocket nudge

**Status:** Accepted

## Decision

- **CloudFront** serves S3 for the app and routes `/api/*` and `/hooks/*` to an **API Gateway HTTP API**, with a JWT
  authorizer, on Lambda. Same origin, so no CORS.
- CloudFront forwards `Authorization` by origin request policy, since it otherwise removes it on GET and HEAD [S55]. A
  template test enforces this (H1).
- **Live updates:** clients read `GET /runs/{id}/events?after=<seq>`. AppSync Events sends a change signal over WebSocket
  [S58], and polling continues if the socket fails.
- **Webhook handlers** are small and separate, verifying and enqueueing, so vendor deadlines hold (GitHub 10 seconds [S40]).
  **The Slack interaction function** also opens modals synchronously, because `trigger_id` expires in 3 seconds [S48], and has
  provisioned concurrency.
- API requests are short, because all real work is asynchronous.

## Alternatives

| Option | Why not |
|---|---|
| **Lambda function URL with OAC** (Strands PoC) | Browser must compute `x-amz-content-sha256` on POST [S56], and `crypto.subtle` needs HTTPS, and `Authorization` is taken by the signature |
| **SSE** | A connection per viewer, trouble with auth headers through CloudFront, and a dropped stream needs replay. A cursor gets the same result more simply |
| **Reading AgentCore's stream to the UI** | 60 minute cap, and the block-size issue. Not needed |
| **Fargate behind an ALB** | Works, always billed, more to run. A customer can still host the same ASGI app |
| **REST API rather than HTTP API** | More features than needed, more cost |
| **API Gateway WebSockets** | More to build than AppSync Events for a signal-only channel |

## Consequences

Live view has short polling delays if the socket is unavailable, which is fine for a timeline. Token-by-token streaming
is not offered, and progress is at the event level.
