# swe-ticket-orchestrator
Reusable Strands + Bedrock AgentCore orchestrator-workers platform for SWE tickets, with configurable stages and human-in-the-loop gates

## Status

**Walking skeleton. Never deployed.** Nothing here has run on AWS or against a live service, and nothing
is production-ready. Every step is simulated and the source host is a fake. The real agents, GitHub and
AWS arrive in later stages (see [docs/PLAN.md](docs/PLAN.md) and [docs/STAGES.md](docs/STAGES.md)).

## Try it

From a fresh clone you need [uv](https://docs.astral.sh/uv/) and Node 24. You need no credentials and no Docker.

```sh
make doctor   # checks Python, uv, Node and the ports, and prints a fix for anything missing
make dev      # API on :8710, web UI on :5710, one demo run waiting at its first gate
```

`make dev` installs the web dependencies on first use (`npm ci`), starts the API and the UI, and starts a
demo run for ticket `DEMO-1` if there are no runs yet. Open <http://127.0.0.1:5710/>, follow the link to
**Runs**, and decide the review gate and then the QA gate: Approve, Request changes or Reject. A decision
other than Approve needs a comment. Ctrl-C (or closing the terminal) stops both processes. The data lives
in `.sto/dev.db` (ignored by git). `STO_API_PORT` and `STO_WEB_PORT` change the ports. `make dev` refuses to
start if either port is already in use.

There is no real sign-in yet. The API accepts a built-in dev token (`dev-token`, or `STO_DEV_TOKEN`, which
`make dev` also hands to the UI), it only works in local mode, and every decision is recorded as `dev`.

The demo run is started only when the database has no runs. A second `make dev` after you finished the demo
shows just that finished run: press **Start a run** on the Runs page for a new one, or delete `.sto/dev.db`
to begin again.

If `make dev` is interrupted during the first `npm ci`, the next run installs again; it does not trust a
half-installed `web/node_modules`.

## Tests

`make test T=<path>` runs a chosen test. CI runs the rest: the `e2e` job drives `scripts/dev.py` (the
`make dev` API) through approve-approve and a reject at each gate (`tests/e2e/test_skeleton.py`), and the
`ui-browser` job drives the UI in Chromium (`tests/ui/test_ui_v0.py`). See [CONTRIBUTING.md](CONTRIBUTING.md).
