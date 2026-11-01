import { useEffect, useLayoutEffect, useRef, useState } from "react";
import {
  ApiError,
  decide,
  getRun,
  listGates,
  stopRun,
  type DecisionKind,
  type Gate,
  type StopOption,
} from "../../../../../lib/api";
import { Layout, message } from "../../../../../lib/Layout";
import { usePoll } from "../../../../../lib/usePoll";

const ACTIONS: { label: string; kind: DecisionKind }[] = [
  { label: "Approve", kind: "approve" },
  { label: "Request changes", kind: "request_changes" },
  { label: "Reject", kind: "reject" },
];

/** The status each decision closes a gate as (the gate service's `_CLOSES_AS`). */
const CLOSES_AS: Record<DecisionKind, string> = {
  approve: "APPROVED",
  request_changes: "CHANGES_REQUESTED",
  reject: "REJECTED",
};
const KIND_OF: Record<string, DecisionKind> = {
  APPROVED: "approve",
  CHANGES_REQUESTED: "request_changes",
  REJECTED: "reject",
};

/** Waits (ms) before each repeat of a decision that is stored but was not delivered to the run. */
export const DELIVERY_BACKOFF_MS = [1000, 2000, 4000, 8000, 8000];
/** Polls in a row that show a decided gate while its run still waits at it, before Retry. */
export const STUCK_POLLS = 3;

interface Pending {
  kind: DecisionKind;
  digest: string;
  comment: string;
  state: "delivering" | "gave_up";
  error: string;
  /** Set when a read shows the gate closed by something other than this decision. */
  refused: string | null;
}

/** A closed gate is final: a read that started before the decision must not reopen it. */
function settle(prev: Gate | null | undefined, next: Gate): Gate {
  return prev != null && prev.status !== "OPEN" && next.status === "OPEN" ? prev : next;
}

/** If the gate closed as something else than `kind` asked for, say that this decision was
 * refused. (An approval later INVALIDATED did happen; OPEN means nothing closed it yet.) */
function refusal(kind: DecisionKind, status: string | null, closedBy: string | null): string | null {
  if (status === null || status === "OPEN" || status === "INVALIDATED" || status === CLOSES_AS[kind]) {
    return null;
  }
  const label = ACTIONS.find((a) => a.kind === kind)?.label.toLowerCase() ?? kind;
  return `Your ${label} was not recorded; this gate is ${status}, closed by ${closedBy ?? "no one (no decision)"}.`;
}

export default function GatePage({ params }: { params: Record<string, string> }) {
  const run = params["run"] ?? "";
  const name = params["name"] ?? "";
  const roundText = params["round"] ?? "";
  const validRound = /^[1-9][0-9]{0,3}$/.test(roundText);
  const round = Number(roundText);

  const [gate, setGate] = useState<Gate | null | undefined>(undefined);
  const [runState, setRunState] = useState<{ status: string; stage: string | null } | null>(null);
  const [pollError, setPollError] = useState<string | null>(null);
  const [actionError, setActionError] = useState<{ text: string; code: string } | null>(null);
  const [offerStop, setOfferStop] = useState<StopOption | null>(null);
  const [note, setNote] = useState<string | null>(null);
  const [comment, setComment] = useState("");
  const [sending, setSending] = useState(false);
  const [recorded, setRecorded] = useState(false);
  const [pending, setPending] = useState<Pending | null>(null);
  const [stuck, setStuck] = useState(false);
  const generation = useRef(0); // bumped by every decision, so older reads are dropped
  const busy = useRef(false);
  const stuckPolls = useRef(0);
  const lostKind = useRef<DecisionKind | null>(null); // the decision whose answer was lost
  const pendingNow = useRef<Pending | null>(null);
  pendingNow.current = pending;
  const statusLine = useRef<HTMLParagraphElement>(null);

  const refresh = async () => {
    const started = generation.current;
    try {
      const [g, r] = await Promise.all([listGates(run), getRun(run).catch(() => null)]);
      if (started !== generation.current) return;
      const found = g.gates.find((x) => x.name === name && x.round === round);
      setGate((prev) => (found ? settle(prev, found) : prev === undefined ? null : prev));
      setRunState(r ? { status: r.status, stage: r.stage } : null);
      setPollError(null);
      if (found && found.status !== "OPEN") {
        // the answer to a decision may have been lost; a closed gate shows it did not fail
        const lost = lostKind.current;
        const notRecorded = lost ? refusal(lost, found.status, found.closed_by) : null;
        setActionError((e) =>
          e?.code === "network" ? (notRecorded ? { text: notRecorded, code: "refused" } : null) : e,
        );
        const p = pendingNow.current;
        const refused = p ? refusal(p.kind, found.status, found.closed_by) : null;
        if (refused !== null) setPending((now) => (now ? { ...now, refused } : now)); // not back from null
      }
      const decided = found !== undefined && KIND_OF[found.status] !== undefined && found.closed_by !== null;
      const waiting = r?.status === "WAITING_HUMAN" && r.stage === name;
      // A later round means the decision did reach the run (it asked for another round).
      const newest = !g.gates.some((x) => x.name === name && x.round > round);
      stuckPolls.current = decided && waiting && newest ? stuckPolls.current + 1 : 0;
      setStuck(stuckPolls.current >= STUCK_POLLS);
    } catch (e) {
      if (started === generation.current) setPollError(message(e));
    }
  };
  usePoll(refresh, 2000, validRound);

  useLayoutEffect(() => {
    if (recorded || pending) statusLine.current?.focus(); // the form is gone: keep the person's place
  }, [recorded, pending?.state]);

  // A stored decision that did not reach the run: repeat the same request until the API says
  // accepted (202) or already closed (409 gate_closed), then offer a button if that gives up.
  const delivering = pending?.state === "delivering" ? pending : null;
  const isDelivering = delivering !== null;
  useEffect(() => {
    if (!delivering) return;
    let cancelled = false;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const finish = (e: ApiError | null) => {
      generation.current += 1;
      setPending(null);
      const refused =
        (e ? refusal(delivering.kind, e.gateStatus, e.closedBy) : null) ?? pendingNow.current?.refused ?? null;
      if (e && e.gateStatus !== null) {
        const status = e.gateStatus;
        setGate((prev) => (prev ? { ...prev, status, closed_by: e.closedBy } : prev));
      }
      if (refused !== null) {
        setActionError({ text: refused, code: "refused" });
        setOfferStop(e?.stop ?? null);
      } else {
        setRecorded(true);
      }
      void refresh();
    };
    const attemptAt = (n: number, last: string) => {
      const wait = DELIVERY_BACKOFF_MS[n];
      if (wait === undefined) {
        setPending((p) => (p ? { ...p, state: "gave_up", error: last } : p));
        return;
      }
      timer = setTimeout(() => {
        decide(run, name, round, delivering.kind, delivering.digest, delivering.comment).then(
          () => {
            if (!cancelled) finish(null);
          },
          (e: unknown) => {
            if (cancelled) return;
            if (e instanceof ApiError && e.code === "gate_closed") finish(e);
            else attemptAt(n + 1, message(e));
          },
        );
      }, wait);
    };
    attemptAt(0, delivering.error);
    return () => {
      cancelled = true;
      clearTimeout(timer);
    };
  }, [isDelivering]);

  const send = async (kind: DecisionKind) => {
    if (gate == null || busy.current) return;
    if (kind !== "approve" && comment.trim() === "") {
      setActionError({ text: "A comment is required to request changes or reject.", code: "comment" });
      return;
    }
    busy.current = true;
    lostKind.current = null;
    generation.current += 1;
    setSending(true);
    setActionError(null);
    setOfferStop(null);
    try {
      const res = await decide(run, name, round, kind, gate.subject_digest, comment);
      generation.current += 1;
      setGate((prev) => settle(prev, res.gate)); // the confirmation does not depend on a refresh
      setRecorded(true);
      void refresh();
    } catch (e) {
      generation.current += 1;
      if (e instanceof ApiError && e.decisionRecorded) {
        setPending({
          kind,
          digest: gate.subject_digest,
          comment,
          state: "delivering",
          error: e.message,
          refused: null,
        });
      } else if (e instanceof ApiError && e.code === "gate_closed") {
        setActionError({
          text: `This gate is already ${e.gateStatus ?? "closed"}, closed by ${e.closedBy ?? "no one (no decision)"}.`,
          code: e.code,
        });
        setOfferStop(e.stop);
        void refresh();
      } else {
        if (e instanceof ApiError && e.code === "network") lostKind.current = kind;
        setActionError({ text: message(e), code: e instanceof ApiError ? e.code : "error" });
        setOfferStop(e instanceof ApiError ? e.stop : null);
      }
    } finally {
      busy.current = false;
      setSending(false);
    }
  };

  /** The gate is decided but its run still waits at it (a page left during delivery): any
   * request on a closed gate redelivers, so repeat the decision the gate shows. */
  const retried = () => {
    setNote("Delivery retried.");
    stuckPolls.current = 0;
    setStuck(false);
  };
  const retryStuck = async () => {
    if (gate == null || busy.current) return;
    const kind = KIND_OF[gate.status];
    if (kind === undefined) return;
    busy.current = true;
    setActionError(null);
    setNote(null);
    try {
      await decide(run, name, round, kind, gate.subject_digest, "retrying delivery");
      retried();
    } catch (e) {
      if (e instanceof ApiError && e.code === "gate_closed") retried();
      else setActionError({ text: message(e), code: "error" }); // the button stays
    } finally {
      busy.current = false;
    }
  };

  const stop = async () => {
    setNote(null);
    try {
      await stopRun(run);
      setNote("Stop requested.");
      setOfferStop(null);
    } catch (e) {
      setActionError({ text: message(e), code: "error" });
    }
  };

  if (!validRound) {
    return (
      <Layout title="Gate">
        <p role="alert">No gate {name} round {roundText}: the round must be a whole number.</p>
      </Layout>
    );
  }
  const stopped = runState?.status === "CANCELLING" || runState?.status === "CANCELLED";
  return (
    <Layout title={`Gate ${name}, round ${String(round)}`}>
      <p>
        <a href={`/runs/${encodeURIComponent(run)}`}>Back to run {run}</a>
      </p>
      {stopped && (
        <p role="note">
          This run is {runState.status}. A stopped run&apos;s gate stays open for now, and deciding
          it changes nothing else.
        </p>
      )}
      {gate === null && <p role="alert">No gate {name} round {round} on this run.</p>}
      {pollError !== null && <p role="alert">{pollError}</p>}
      {actionError !== null && <p role="alert">{actionError.text}</p>}
      {offerStop !== null && (
        <button type="button" onClick={() => void stop()}>
          Stop
        </button>
      )}
      {note !== null && <p role="status">{note}</p>}
      {pending?.refused != null && <p role="alert">{pending.refused}</p>}
      {pending?.state === "delivering" && (
        <p role="status" ref={statusLine} tabIndex={-1}>
          {pending.refused === null
            ? "Decision recorded, delivering it to the run… Keep this page open."
            : "Delivering the decision that did close this gate… Keep this page open."}
        </p>
      )}
      {pending?.state === "gave_up" && (
        <>
          <p role="alert" ref={statusLine} tabIndex={-1}>
            {pending.refused === null
              ? `Decision recorded, but it was not delivered to the run: ${pending.error}`
              : `The decision that closed this gate was not delivered to the run: ${pending.error}`}
          </p>
          <button
            type="button"
            onClick={() => {
              setPending({ ...pending, state: "delivering" });
            }}
          >
            Retry delivery
          </button>
        </>
      )}
      {recorded && !pending && (
        <p role="status" ref={statusLine} tabIndex={-1}>
          Decision recorded.
        </p>
      )}
      {stuck && !pending && (
        <>
          <p role="alert">
            This gate is decided, but its run is still waiting at it: the decision may not have
            reached the run.
          </p>
          <button type="button" onClick={() => void retryStuck()}>
            Retry delivery
          </button>
        </>
      )}
      {gate != null && (
        <>
          <dl>
            <dt>Type</dt>
            <dd>{gate.type}</dd>
            <dt>Status</dt>
            <dd data-testid="gate-status">{gate.status}</dd>
            <dt>Head</dt>
            <dd>{gate.head_sha ?? "none"}</dd>
            <dt>Subject</dt>
            <dd>{gate.subject_digest}</dd>
          </dl>
          {gate.status === "OPEN" && !pending && !recorded ? (
            <form
              onSubmit={(e) => {
                e.preventDefault();
              }}
            >
              <label>
                Comment
                <textarea
                  aria-describedby="comment-hint"
                  value={comment}
                  onChange={(e) => {
                    setComment(e.target.value);
                  }}
                />
              </label>
              <p id="comment-hint">A comment is required to request changes or reject.</p>
              {ACTIONS.map((a) => (
                <button key={a.kind} type="button" disabled={sending} onClick={() => void send(a.kind)}>
                  {a.label}
                </button>
              ))}
            </form>
          ) : (
            gate.status !== "OPEN" && (
              <p data-testid="closed-by">
                {gate.status},{" "}
                {gate.closed_by === null ? "closed, no decision" : `closed by ${gate.closed_by}`}
              </p>
            )
          )}
        </>
      )}
    </Layout>
  );
}
