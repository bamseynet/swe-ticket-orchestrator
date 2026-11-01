import { useState } from "react";
import { ApiError, decide, listGates, type DecisionKind, type Gate } from "../../../../../lib/api";
import { Layout, message } from "../../../../../lib/Layout";
import { usePoll } from "../../../../../lib/usePoll";

const ACTIONS: { label: string; kind: DecisionKind }[] = [
  { label: "Approve", kind: "approve" },
  { label: "Request changes", kind: "request_changes" },
  { label: "Reject", kind: "reject" },
];

export default function GatePage({ params }: { params: Record<string, string> }) {
  const run = params["run"] ?? "";
  const name = params["name"] ?? "";
  const round = Number(params["round"]);
  const [gate, setGate] = useState<Gate | null | undefined>(undefined);
  const [comment, setComment] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [sending, setSending] = useState(false);
  const [done, setDone] = useState(false);
  const refresh = async () => {
    try {
      const found = (await listGates(run)).gates.find((g) => g.name === name && g.round === round);
      setGate(found ?? null);
    } catch (e) {
      setError(message(e));
    }
  };
  usePoll(refresh);
  const send = async (kind: DecisionKind) => {
    if (gate == null) return;
    if (kind !== "approve" && comment.trim() === "") {
      setError("A comment is required to request changes or reject.");
      return;
    }
    setSending(true);
    setError(null);
    try {
      await decide(run, name, round, kind, gate.subject_digest, comment);
      setDone(true);
      await refresh();
    } catch (e) {
      if (e instanceof ApiError && e.code === "gate_closed") {
        setError(`This gate is already ${e.gateStatus ?? "closed"}, closed by ${e.closedBy ?? "someone"}.`);
        await refresh();
      } else {
        setError(message(e));
      }
    } finally {
      setSending(false);
    }
  };
  return (
    <Layout title={`Gate ${name}, round ${String(round)}`}>
      <p>
        <a href={`/runs/${run}`}>Back to run {run}</a>
      </p>
      {gate === null && <p role="alert">No gate {name} round {round} on this run.</p>}
      {error !== null && <p role="alert">{error}</p>}
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
          {gate.status === "OPEN" ? (
            <form
              onSubmit={(e) => {
                e.preventDefault();
              }}
            >
              <label>
                Comment
                <textarea
                  value={comment}
                  onChange={(e) => {
                    setComment(e.target.value);
                  }}
                />
              </label>
              {ACTIONS.map((a) => (
                <button key={a.kind} type="button" disabled={sending} onClick={() => void send(a.kind)}>
                  {a.label}
                </button>
              ))}
            </form>
          ) : (
            <p data-testid="closed-by">
              {gate.status}, closed by {gate.closed_by ?? "unknown"}
            </p>
          )}
          {done && gate.status !== "OPEN" && <p>Decision recorded.</p>}
        </>
      )}
    </Layout>
  );
}
