# ADR-0001: A deterministic stage engine, with Strands orchestrators inside stages

**Status:** Accepted

## Context

The brief says an orchestrator agent takes a ticket through a team-configurable workflow. Two things pull
against a single top-level LLM orchestrator:

- Gates must hold when a model is fooled. Ticket text is untrusted, and all three PoCs note that prompt
  injection is reduced, not solved.
- The CrewAI PoC's sound decision was "code decides when to stop, not a model". The Strands PoC's was "the
  LLM does not mark its own homework".

## Decision

Two levels:

1. A **stage engine**, a pure reducer over declarative config, decides every transition. It contains no LLM.
2. A **Strands stage orchestrator** runs inside each `agent` stage. At run time it decides which specialist
   workers to call, and returns one outcome from a declared list. The engine validates that outcome.

This keeps the orchestrator-workers pattern where its value lies, in choosing work at run time. It removes the
model from decisions that need to be provable.

## Alternatives

| Option | Why not |
|---|---|
| One LLM orchestrator for the whole ticket, with stages as tools | A prompt could reorder or skip stages. Gates become a matter of model obedience. Cost and context grow across days |
| Strands Graph as the workflow engine, compiled from YAML | It has cycles and interrupts, and could run this. But state lives with one in-process run, session managers take no lock [S6], listing waiting gates needs a database anyway, and the authority for approvals would be a framework's resume path. The LangGraph PoC's worst bug came from exactly that: a framework replaying a saved resume value |
| Swarm | No coordinator, and handoffs can loop [S2] |
| Compile each workflow to its own ASL | See ADR-0002 |

## Consequences

- Gate and transition logic is property-testable with no model.
- **This is not literally "one agent runs the ticket".** Peter may read the brief differently, so PLAN.md
  section 0 flags it.
- Strands remains central: every stage's agent work uses it. Interrupts are used inside stages (ADR-0003).
