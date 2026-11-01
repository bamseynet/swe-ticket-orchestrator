import { useEffect, useRef, useState } from "react";
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

/** Waits (ms) before each repeat of a decision that is stored but was not delivered to the run. */
export const DELIVERY_BACKOFF_MS = [1000, 2000, 4000, 8000, 8000];

interface Pending {
  kind: DecisionKind;
  digest: string;
  comment: string;
  state: "delivering" | "gave_up";
  attempt: number; // changes on each manual retry, to restart the loop
  error: string;
}

/** A closed gate is final: a read that started before the decision must not reopen it. */
function settle(prev: Gate | null | undefined, next: Gate): Gate {
  return prev != null && prev.status !== "OPEN" && next.status === "OPEN" ? prev : next;
}

export default function GatePage({ params }: { params: Record<string, string> }) {
  const run = params["run"] ?? "";
  const name = params["name"] ?? "";
  const roundText = params["round"] ?? "";
  const validRound = /^[1-9][0-9]{0,3}$/.test(roundText);
  const round = Number(roundText);

  const [gate, setGate] = useState<Gate | null | undefined>(undefined);
  const [runStatus, setRunStatus] = useState<string | null>(null);
  const [pollError, setPollError] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const [offerStop, setOfferStop] = useState<StopOption | null>(null);
  const [stopNote, setStopNote] = useState<string | null>(null);
  const [comment, setComment] = useState("");
  const [sending, setSending] = useState(false);
  const [recorded, setRecorded] = useState(false);
  const [pending, setPending] = useState<Pending | null>(null);
  const generation = useRef(0); // bumped by every decision, so older reads are dropped
  const busy = useRef(false);
  const statusLine = useRef<HTMLParagraphElement>(null);

  const refresh = async () => {
    const started = generation.current;
    try {
      const [g, r] = await Promise.all([listGates(run), getRun(run).catch(() => null)]);
      if (started !== generation.current) return;
      const found = g.gates.find((x) => x.name === name && x.round === round);
      setGate((prev) => (found ? settle(prev, found) : prev === undefined ? null : prev));
      setRunStatus(r?.status ?? null);
      setPollError(null);
    } catch (e) {
      if (started === generation.current) setPollError(message(e));
    }
  };
  usePoll(refresh, 2000, validRound);

  useEffect(() => {
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
    const attemptAt = (n: number, last: string) => {
      const wait = DELIVERY_BACKOFF_MS[n];
      if (wait === undefined) {
        setPending((p) => (p ? { ...p, state: "gave_up", error: last } : p));
        return;
      }
      timer = setTimeout(() => {
        decide(run, name, round, delivering.kind, delivering.digest, delivering.comment).then(
          () => {
            if (!cancelled) delivered();
          },
          (e: unknown) => {
            if (cancelled) return;
            if (e instanceof ApiError && e.code === "gate_closed") delivered();
            else attemptAt(n + 1, message(e));
          },
        );
      }, wait);
    };
    const delivered = () => {
      generation.current += 1;
      setPending(null);
      setRecorded(true);
      void refresh();
    };
    attemptAt(0, delivering.error);
    return () => {
      cancelled = true;
      clearTimeout(timer);
    };
  }, [isDelivering, delivering?.attempt]);

  const send = async (kind: DecisionKind) => {
    if (gate == null || busy.current) return;
    if (kind !== "approve" && comment.trim() === "") {
      setActionError("A comment is required to request changes or reject.");
      return;
    }
    busy.current = true;
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
        setPending({ kind, digest: gate.subject_digest, comment, state: "delivering", attempt: 0, error: e.message });
      } else if (e instanceof ApiError && e.code === "gate_closed") {
        setActionError(`This gate is already ${e.gateStatus ?? "closed"}, closed by ${e.closedBy ?? "no one (no decision)"}.`);
        setOfferStop(e.stop);
        void refresh();
      } else {
        setActionError(message(e));
        setOfferStop(e instanceof ApiError ? e.stop : null);
      }
    } finally {
      busy.current = false;
      setSending(false);
    }
  };

  const stop = async () => {
    setStopNote(null);
    try {
      await stopRun(run);
      setStopNote("Stop requested.");
      setOfferStop(null);
    } catch (e) {
      setActionError(message(e));
    }
  };

  if (!validRound) {
    return (
      <Layout title="Gate">
        <p role="alert">No gate {name} round {roundText}: the round must be a whole number.</p>
      </Layout>
    );
  }
  const stopped = runStatus === "CANCELLING" || runStatus === "CANCELLED";
  return (
    <Layout title={`Gate ${name}, round ${String(round)}`}>
      <p>
        <a href={`/runs/${encodeURIComponent(run)}`}>Back to run {run}</a>
      </p>
      {stopped && (
        <p role="note">
          This run is {runStatus}. A stopped run&apos;s gate stays open for now, and deciding it
          changes nothing else.
        </p>
      )}
      {gate === null && <p role="alert">No gate {name} round {round} on this run.</p>}
      {pollError !== null && <p role="alert">{pollError}</p>}
      {actionError !== null && <p role="alert">{actionError}</p>}
      {offerStop !== null && (
        <button type="button" onClick={() => void stop()}>
          Stop
        </button>
      )}
      {stopNote !== null && <p role="status">{stopNote}</p>}
      {pending?.state === "delivering" && (
        <p role="status" ref={statusLine} tabIndex={-1}>
          Decision recorded, delivering it to the run…
        </p>
      )}
      {pending?.state === "gave_up" && (
        <>
          <p role="alert" ref={statusLine} tabIndex={-1}>
            Decision recorded, but it was not delivered to the run: {pending.error}
          </p>
          <button
            type="button"
            onClick={() => {
              setPending({ ...pending, state: "delivering", attempt: pending.attempt + 1 });
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
