# ADR-0019: Offline-first testing, with a credential-blocked live milestone

**Status:** Accepted. Peter's decisions: no AWS account yet, so everything must be deployable with CDK and fully testable
offline or with local stubs, with a staged first deploy blocked on credentials. Also, up to 8 agent workers build this on
one 7.4 GB laptop, so heavy verification lives in GitHub Actions.

## Decision

- **Every AWS and vendor dependency sits behind a port,** with an in-repo fake.
- No test tier except `live` needs credentials. Sockets are blocked by default in tests, and host AWS config is hidden.
- **Workers run targeted tests only.** Unit, contract and gate tests are hermetic, with no Docker, and a local run aims for
  under 60 seconds and about 500 MB. Full suites, integration, browsers, e2e and `cdk synth` run in CI, and must be green
  before merge (PLAN.md section 15.1).
- **CI uses one workflow, with a filter job and one always-running aggregator as the only required check,** because a skipped
  workflow can leave a required check pending [S59].
- **Real SDKs, fake servers:** real Strands against scripted models, real botocore against local stubs, real adapters against
  fake vendor APIs. Only the far end is fake.
- **D12 is a single, explicit, blocked milestone,** listing every hypothesis offline tests cannot prove. Nothing else in the
  plan depends on it, except D14.
- **A cost guard (D12-00), then a one-day spike (D12-18), are the first things to run when credentials arrive,** with no dependency on D11, on the designs no fake can prove. About 180 PRs land before first contact with AWS, so issues resting on those designs are marked provisional.
- **CI lands straight after the skeleton,** with a ruleset on `main`, so every later issue has it as an ancestor, and a script checks that. No offline issue depends on a human step.
- The README states "never deployed" until D12 closes.
- GitHub is the exception: it is tested live on a throwaway repo from D4, under a tagged suite.
- D12 begins with cost protection: AWS Budgets alarm, kill switch verified, fake LLM deployment first, then one small real
  invocation at a time.

## Alternatives

| Option | Why not |
|---|---|
| Wait for AWS | Blocks everything for an unknown time |
| LocalStack for everything | Useful for some services, but paid tiers, and AgentCore coverage is uncertain. Ports plus focused stubs are more honest about what is proved |
| Heavy mocks of Strands | PoCs showed that driving the real event loop finds real bugs |
| Full suites on the laptop | Eight workers on 7.4 GB would run out of memory, and tests would fail for the wrong reasons |
| Docker for the store and fakes in every tier | Slow and memory-heavy per worker. DynamoDB Local stays in the CI integration tier, and the shared contract suite keeps the fast stores honest |
| Treat "stack synthesizes" as proof | The PoCs said plainly that it is not, and were right |

## Consequences

A meaningful risk stays until D12 by design, and the plan says so. Expect D12 to find things: it has budget for fixes, and
prompt quality work starts only there.
