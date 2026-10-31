# ADR-0020: Python, TypeScript, one repo, and layout built for parallel PRs

**Status:** Accepted

## Decision

- **Python 3.12+** with uv for the backend and agents. Strands' Python SDK has the longest track record, and the PoCs' lessons
  are in Python.
- **TypeScript:** React and Vite for the web app, CDK for infra, Node 24 LTS, pinned by `.nvmrc`.
- **One repo:**

```text
src/sto/
  domain/         models, IDs, errors
  config/         schema, loader, validator
  engine/         reducer, commands, handlers/, drivers/
  gates/          decisions, SoD, timers
  effects/        outbox, executor
  budget/         ledger, hooks, kill switch
  identity/       OIDC validation, mapping, linking
  store/          ports, memory, sqlite, dynamodb
  tenancy/        resource bindings
  audit/          chain, checkpoints, evidence pack
  adapters/       github/ jira/ slack/ linear/ azure_devops/ fake/
  agents/         harness, profiles/, prompts/, tools/, models/
  workspace/      local_docker, agentcore_sandbox, code_interpreter
  qa/             evidence, browser, matrix
  api/routers/    one file per resource
  ingest/         webhooks per vendor
  lambdas/        thin entrypoints
  observability/  telemetry, metrics
templates/        bundled workflows
web/src/pages/    one folder per page
infra/lib/        one file per stack
tests/            mirrors src, plus gates/ e2e/ contract/ security/
```

- **Registries by discovery,** using entry points and glob imports for routers, adapters and pages, so parallel PRs do not all
  edit one file.
- **Seams for parallel work:** a reducer handler registry, gate hook points and an `AuditWriter`, so later rules add files. A list of serial areas names what remains shared, and a CI check compares each PR with its declared files. The first plan's file lists omitted integration points, so "parallel" was not true.
- **Ruff, mypy strict, pytest, Hypothesis, ESLint, tsc, Vitest, Playwright, cdk-nag.** CI runs all of them. Local hooks run
  only fast checks on changed files, to respect the shared laptop (ADR-0019).

## Alternatives

| Option | Why not |
|---|---|
| Strands TypeScript for agents | Younger, and the PoC evidence is Python |
| Separate repos | Contract drift, and harder to change across layers |
| CDK in Python | CDK still needs Node, and the PoCs' reasoning for TypeScript holds |

## Consequences

Agents working in parallel need the layout to hold. STAGES.md marks which issues can run in parallel on this basis.
