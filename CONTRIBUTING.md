# Contributing

This repo is built by up to 8 agent workers and people at once, on one 7.4 GB laptop. The rules below come from
[docs/STAGES.md](docs/STAGES.md) ("Delivery rules" and "Standing acceptance criteria for every issue"), which is the
source of truth. If this file and STAGES.md disagree, STAGES.md wins and this file is the bug.

## Workflow

1. Pick one issue. Every issue has an ID (for example `D0-06`), a `Files` list and dependencies in `docs/STAGES.md`.
2. Branch from `main`, after the issue's dependencies have merged.
3. Open **one PR** with `Closes #<issue>` on its own line, using the PR template.
4. Get an independent review, wait for `ci-required` to be green, and let a person (or the merge flow) merge.

`main` is protected by a ruleset: no direct pushes, and the only required check is `ci-required`.

## Delivery rules

1. **No stacked PRs.** Stacks conflict after squash merges. An issue starts from `main`, after its dependencies have merged.
2. **One issue, one PR.** If it grows beyond its size, split the issue rather than growing the PR. Sizes: S is under about
   300 changed lines, M about 300 to 800, L about 800 to 1,500. Nothing larger.
3. **Tests first** for engine, gates, effects and budget code: write the failing test, see it fail, then implement.
4. **Independent review on every PR,** in a fresh session that did not write the code. Link it in the PR.
5. **Review loops are capped at 3 rounds.** After that, a person decides, or the remaining items become issues.
6. **Gate suite is a required check from D0-05, filling up from D1-11.** Changing an invariant test requires an ADR.
7. **Hermetic by default:** no test tier except `live` needs credentials, and tests block sockets.
8. **Say what is unproven.** A PR touching AWS behaviour lists what stays unverified until D12 (the PR template has a
   section for it). The README keeps "never deployed" until D12 closes.
9. **Nothing real is committed,** because this repo is public: no account IDs, tokens, internal URLs or real customer data in fixtures.
10. **Dependency lockfiles** are not counted as conflicts: re-lock on rebase.

## Declared files

Each issue lists its `Files` in `docs/STAGES.md`. Touch only those, plus their tests and an allow-list (lockfiles,
`pyproject.toml`, `Makefile`, `web/package.json`, docs). Anything else needs a reason in the PR body. A CI check (D0-10)
enforces this once it lands.

**Serial areas** are shared files, so an issue touching one must be `serial`, and only one such issue may be open per
file: `.github/workflows/ci.yml`, `src/sto/engine/reducer.py`, `src/sto/engine/commands.py`, `src/sto/domain/` and
`src/sto/gates/service.py`.

## Testing: what runs where

- **Locally, run only targeted tests for the code you touched:** `make test-changed`, or `make test T=<path>`. Plus
  `make lint` and `make typecheck` on what you changed.
  Do not run full suites, e2e, `cdk synth`, browsers or Docker locally.
- **Full suites, integration, e2e and synth run in GitHub Actions, and `ci-required` must be green before merge.** A claim in
  an acceptance criterion is met when CI shows it, not when it passed locally.
- **New unit, contract and gate tests are hermetic:** fake LLM, in-process fakes, no Docker, no network. Anything needing
  Docker or a browser carries the `integration` or `ui_browser` marker and runs in CI only.
- **A heavy CI job is never moved to a laptop to save time.** If a test is too slow for its tier, fix it or move it to a
  CI-only tier.

## Adding a CI job

Add the job with `needs: filter`, then add its id to the `needs:` list of `ci-required`. Never add a work job to the
ruleset. See the header of `.github/workflows/ci.yml`.

## Pull requests

The PR template asks for: the issue link, each acceptance criterion mapped to evidence (test names, CI run URLs), files
outside the declared list, **what stays unverified until D12**, and a link to the independent review.

Rebase onto `origin/main` if main moves and you conflict, then `git push --force-with-lease`. Never merge your own PR
without the review, and never bypass the ruleset.
