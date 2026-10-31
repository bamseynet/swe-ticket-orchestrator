# ADR-0018: OpenTelemetry through ADOT to CloudWatch

**Status:** Accepted

## Decision

- Strands' OTel spans, plus our own for engine, gates and effects. ADOT in AWS, an OTLP or console exporter locally.
- Attributes carry team, run, stage, step, attempt, workflow version and model. Ticket and code text is excluded by default.
- Use AgentCore Observability and CloudWatch GenAI views, with Transaction Search on once per account [S19].
- Custom metrics are emitted for the things in PLAN.md section 14.5. Traces explain activity, and **Cost Explorer and CUR
  remain the billing truth** [S19].
- A local trace viewer through a Docker Jaeger or similar is available in `make dev-obs`.

## Alternatives

| Option | Why not |
|---|---|
| Langfuse or vendor-specific tracing | OTel keeps it open, and a team can export there |
| Logs only | LangGraph PoC's gap |
| Capturing prompts in traces always | Holds source and ticket text. Available as an opt-in with restricted storage |

## Consequences

Current span attribute names were not verifiable from docs on the research date, so D5-11 asserts on real SDK output.
