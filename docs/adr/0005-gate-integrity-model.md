# ADR-0005: Gate integrity model

**Status:** Accepted

## Context

The PoCs produced specific bugs: a later reject losing to an earlier approve, a failed audit write letting an
old approval override a rejection, "written back" shown when nothing was written, and approval of a closed
ticket. The rules are in PLAN.md section 4.3. This record gives the reasons for the less obvious ones.

## Decisions

1. **A decision is bound to a subject digest** (`head_sha`, `patch_id`, evidence digest, ticket revision). A
   human approves what they saw, or the server refuses it.
2. **Reject and request-changes veto while a gate is open.** First-write-wins would let an approval that arrived
   first beat a rejection in a quorum gate, the exact bug class we found. Veto is the safe direction. Negative decisions
   are exempt from the digest match, so a moved subject cannot delay a veto.
3. **Single close by conditional write.** Decision, ledger, audit and outbox are one transaction.
4. **After close, Stop is the only override,** and executors re-check run state immediately before acting. This
   replaces the PoC's "a saved decision stands" with a clear path. A late reject gets a useful refusal and a Stop
   button, rather than silently losing.
5. **Patch-ID carry-over is opt-in, and narrow.** Re-approval after a clean rebase is pointless for most teams, but strict
   binding must remain available for regulated ones. It uses `git patch-id --verbatim`, because the default mode ignores
   whitespace. It re-enters the gate and creates a new instance at the new SHA, so "a merge needs an approved instance at this SHA"
   has no exception. Five conditions in PLAN.md section 4.6 must hold, so it cannot fill a quorum or hide a new problem.
6. **No `auto_approve` exists in the schema,** so it cannot be misconfigured.
7. **All surfaces call one decision function.** A second path is a second place for rules to differ (G16).

8. **Any non-approved close invalidates earlier approvals of that gate,** and only the most recent closed instance can be cited. Otherwise an old approval of the same patch could override a person's later request for changes, the bug class this ADR exists to stop (found by the adversarial review, P0-5).
9. **The claim is atomic.** An effect is claimed in a transaction checking run, gate and switches, so Stop and a claim cannot both win. A read-then-act check would leave a window.
10. **A hold follows approval** on merge, release and a done transition, so "use Stop" is a real option.
11. **Org floors are read live,** so a tightened rule reaches runs in flight.
12. **A gate once visited stays required, and route inputs are frozen with a ratchet.** Otherwise editing a Jira field could skip the regulated change gate (pass 2, finding B), since a gate not visited would not be required.
13. **"Then and now" eligibility needs a way out.** Mapping changes do not reach open gates, so an org admin can extend eligibility on one, and cannot vote in that round.

## Alternatives

| Option | Why not |
|---|---|
| Strands interrupts as gates | A saved interrupt response in a session is framework state, and session state is "trusted input" [S5]. Harder to query, quorum, audit or time out |
| Step Functions task token as the decision | No atomic audit, no veto or quorum, no subject binding |
| Approval bound to SHA only, always | Every base update needs a new human click, which teaches rubber-stamping |

## Consequences

The gate suite in PLAN.md section 15.3 is a required check from D1 onward, and grows by named invariant.
