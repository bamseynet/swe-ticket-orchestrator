# ADR-0003: Agents-as-tools inside stages, with no Graph or Swarm for now

**Status:** Accepted

## Decision

- Each stage orchestrator is a Strands `Agent`, with workers as tools (`Agent.as_tool`) and
  `ConcurrentToolExecutor`. This was proved offline in the Strands PoC.
- Workers see only their brief, and return only their result.
- The panel in `llm_review` is **not** an LLM-coordinated team. Code runs each reviewer independently in a
  fresh session, then merges findings, so reviewers cannot anchor on each other.
- Only the orchestrator has a session manager, on S3 under the run's own prefix, used to resume in-stage
  interrupts. `SnapshotSessionManager` is tried first, as the docs recommend for new single-agent sessions, with
  `S3SessionManager` as the fallback (D5-14). Workers are ephemeral, with results stored as artifacts. Session managers are not thread-safe and
  take no lock [S6].
- Strands **interrupts** handle `ask_human` and high-risk team tool calls. The two gates do not use them.

## Alternatives

| Option | Why not, for now |
|---|---|
| Graph inside a stage | Useful if a team needs a fixed sub-pipeline. The port allows it later. Python multi-agent sessions do not hold each agent's conversation [S6], and no stage needs it yet |
| Swarm | No synthesis point and needs loop limits [S2]. Nothing here needs peer handoff |
| Workflow | DAG only, a failure halts dependents [S2] |

## Consequences

- PoC behaviours must be kept: read a worker's finish from its own stream, share turn and token limits across
  workers, check refusal stop reasons, and emit plans as tool calls.
- Strands multi-agent interrupt documentation was only partly retrievable, which is another reason not to
  depend on it. D5-02 pins the behaviour we do use with tests against the real SDK.
