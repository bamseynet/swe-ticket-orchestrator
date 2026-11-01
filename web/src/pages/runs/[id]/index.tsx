import { useRef, useState } from "react";
import {
  getRun,
  listEvents,
  listGates,
  stopRun,
  type Gate,
  type Run,
  type RunEvent,
} from "../../../lib/api";
import { FINISHED, Layout, message } from "../../../lib/Layout";
import { usePoll } from "../../../lib/usePoll";

const STOPPABLE = new Set(["QUEUED", "RUNNING", "WAITING_HUMAN", "WAITING_EXTERNAL", "BLOCKED"]);
const PAGE = 500;

export default function Timeline({ params }: { params: Record<string, string> }) {
  const id = params["id"] ?? "";
  const [run, setRun] = useState<Run | null>(null);
  const [events, setEvents] = useState<RunEvent[]>([]);
  const [gates, setGates] = useState<Gate[]>([]);
  const [pollError, setPollError] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const [note, setNote] = useState<string | null>(null);
  const [over, setOver] = useState(false);
  const cursor = useRef<string | null>(null);
  usePoll(
    async () => {
      try {
        // The run is read first: if it is finished here, every event already exists, so the
        // read of events that follows is the last one needed.
        const r = await getRun(id);
        const [g, page] = await Promise.all([listGates(id), listEvents(id, cursor.current)]);
        setRun(r);
        setGates(g.gates);
        if (page.events.length > 0) {
          setEvents((old) => [...old, ...page.events.filter((e) => !old.some((o) => o.seq === e.seq))]);
        }
        cursor.current = page.cursor ?? cursor.current;
        setPollError(null);
        if (FINISHED.has(r.status) && page.events.length < PAGE) setOver(true);
      } catch (e) {
        setPollError(message(e));
      }
    },
    2000,
    !over,
  );
  const stop = async () => {
    setActionError(null);
    setNote(null);
    try {
      await stopRun(id);
      setNote("Stop requested.");
    } catch (e) {
      setActionError(message(e));
    }
  };
  const enc = encodeURIComponent;
  return (
    <Layout title={`Run ${id}`}>
      {pollError !== null && <p role="alert">{pollError}</p>}
      {actionError !== null && <p role="alert">{actionError}</p>}
      {note !== null && <p role="status">{note}</p>}
      {run && (
        <p>
          <span data-testid="run-status">{run.status}</span> <span>{run.stage ?? ""}</span>{" "}
          <span>{run.ticket ?? ""}</span>
          {run.driver_error !== null && <span> Error: {run.driver_error}</span>}
          {run.held !== null && <span> Held: {run.held}</span>}
        </p>
      )}
      {run && STOPPABLE.has(run.status) && (
        <button type="button" onClick={() => void stop()}>
          Stop
        </button>
      )}
      <h2>Gates</h2>
      <ul>
        {gates.map((g) => (
          <li key={g.id}>
            <a href={`/gate/${enc(id)}/${enc(g.name)}/${String(g.round)}`}>
              {g.name} round {g.round}
            </a>{" "}
            <span>{g.status}</span>
            {g.closed_by !== null && <span> closed by {g.closed_by}</span>}
          </li>
        ))}
      </ul>
      <h2>Timeline</h2>
      <ol>
        {events.map((e) => (
          <li key={e.seq}>
            <span>{e.type}</span> <span>{e.stage ?? ""}</span> <span>{e.status}</span>
            {e.outcome !== "applied" && <span> {e.outcome}</span>}
            {e.detail !== "" && <span> {e.detail}</span>}
          </li>
        ))}
      </ol>
    </Layout>
  );
}
