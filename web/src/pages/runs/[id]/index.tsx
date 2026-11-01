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
import { Layout, message } from "../../../lib/Layout";
import { usePoll } from "../../../lib/usePoll";

const STOPPABLE = new Set(["QUEUED", "RUNNING", "WAITING_HUMAN", "WAITING_EXTERNAL", "BLOCKED"]);

function isSimulated(e: RunEvent): boolean {
  const receipt = e.data["receipt"];
  return (
    typeof receipt === "object" &&
    receipt !== null &&
    (receipt as Record<string, unknown>)["simulated"] === true
  );
}

export default function Timeline({ params }: { params: Record<string, string> }) {
  const id = params["id"] ?? "";
  const [run, setRun] = useState<Run | null>(null);
  const [events, setEvents] = useState<RunEvent[]>([]);
  const [gates, setGates] = useState<Gate[]>([]);
  const [error, setError] = useState<string | null>(null);
  const cursor = useRef<string | null>(null);
  usePoll(async () => {
    try {
      const [r, g, page] = await Promise.all([getRun(id), listGates(id), listEvents(id, cursor.current)]);
      setRun(r);
      setGates(g.gates);
      if (page.events.length > 0) {
        setEvents((old) => [...old, ...page.events.filter((e) => !old.some((o) => o.seq === e.seq))]);
      }
      cursor.current = page.cursor ?? cursor.current;
      setError(null);
    } catch (e) {
      setError(message(e));
    }
  });
  const stop = async () => {
    try {
      await stopRun(id);
    } catch (e) {
      setError(message(e));
    }
  };
  return (
    <Layout title={`Run ${id}`}>
      {error !== null && <p role="alert">{error}</p>}
      {run && (
        <p>
          <span>{run.status}</span> <span>{run.stage ?? ""}</span> <span>{run.ticket ?? ""}</span>
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
            <a href={`/gate/${id}/${g.name}/${String(g.round)}`}>
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
            {isSimulated(e) && <strong data-testid="simulated-write"> simulated</strong>}
            {e.detail !== "" && <span> {e.detail}</span>}
          </li>
        ))}
      </ol>
    </Layout>
  );
}
