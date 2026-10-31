# ADR-0013: Read-only tools through Gateway and Policy, assuming injection succeeds

**Status:** Accepted

## Decision

- **Assume injection succeeds.** Ticket, code, CI, web and tool text can all carry instructions, and no prompt
  fully stops that.
- **Agents have no outward write tools at all.** All writes are engine effects. Gates, tokens, merges and config are
  unreachable from the agent plane, by IAM and by absence.
- **Allowlist twice:** at agent construction, and as Cedar policy at the Gateway, evaluated outside agent code [S23].
- **Rendering:** prompts rendered once in our code, untrusted text in tags with closing tags neutralised, and no
  framework substitution (CrewAI lesson).
- **Scan both directions:** tool output before the model, and patches before push.
- **Sessions load only from our own prefix** [S5]. Files in a repo are never treated as agent instructions unless
  a team opts in by naming a path, and then still framed as untrusted.
- Guardrails can add a filter, but are never the control.

## Alternatives

| Option | Why not |
|---|---|
| Rely on system prompts and delimiters | All three PoCs say that only reduces risk |
| Gateway's prebuilt write integrations | Would hand agents outward write tools |
| Allowlist only in Gateway | One layer, and absent in local dev. Two layers keep the local test meaningful |
| Agents act and a human reviews after | Violates the gate model |

## Consequences

Local dev has no Gateway, so the in-process registry enforces the same allowlist. Cedar is tested by unit tests on the
policies, and live in D12. The Policy CDK construct is alpha, so we use L1 [S8].
