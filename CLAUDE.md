# CLAUDE.md

Instructions for agent workers. Full rules: [CONTRIBUTING.md](CONTRIBUTING.md). Source of truth:
[docs/STAGES.md](docs/STAGES.md) (delivery rules, standing acceptance criteria) and [docs/PLAN.md](docs/PLAN.md); decisions are in [docs/adr/](docs/adr/).

## Before you start
- Read your GitHub issue, its section in `docs/STAGES.md`, and the standing acceptance criteria there.
- Work on a branch from `main`. No stacked PRs. One issue, one PR, with `Closes #N` on its own line.
- Declared files: touch only the issue's `Files` and their tests. If you must touch anything else, say why in the PR body.
  Serial areas (`.github/workflows/ci.yml`, `src/sto/engine/reducer.py`, `src/sto/engine/commands.py`, `src/sto/domain/`,
  `src/sto/gates/service.py`) need the issue to be marked serial.

## Testing (the machine is small: up to 8 workers on 7.4 GB)
- Tests first where there is behaviour: write the failing test, run it, then implement.
- Locally run ONLY targeted checks: `make test T=<path>` or `make test-changed`, plus `make lint` and `make typecheck`.
- Never run the full suite, e2e, `cdk synth`, browsers or Docker locally. A heavy CI job is never moved to a laptop.
- Tests are hermetic: fake LLM, no network, no Docker, no credentials. Sockets are blocked. Docker or browser tests carry the `integration` or `ui_browser` marker and run in CI only.
- Push, then `gh pr checks <PR> --watch`. `ci-required` must be green. A criterion is met when CI shows it.

## Pull requests
- Fill in the PR template: acceptance criteria mapped to evidence, files outside the declared list, **Unverified until D12**, and the independent review link.
- Independent review comes from a fresh session that did not write the code. Review loops are capped at 3 rounds; after that a person decides or the remainder become issues.
- Do not merge. Main is protected. If main moves, rebase onto `origin/main` and `git push --force-with-lease`; lockfiles are re-locked, not merged.
- The gate suite is a required check; changing an invariant test requires an ADR.

## Never
- Commit anything real: account IDs, tokens, internal URLs or customer data. Nothing real is committed, because the repo is public.
- Touch AWS or live services; the README keeps "never deployed" until D12 closes.
