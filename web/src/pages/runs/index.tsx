import { useRef, useState } from "react";
import { listRuns, startRun, type Run } from "../../lib/api";
import { Layout, message } from "../../lib/Layout";
import { navigate } from "../../lib/nav";
import { usePoll } from "../../lib/usePoll";

export default function Runs() {
  const [first, setFirst] = useState<Run[] | null>(null);
  const [firstCursor, setFirstCursor] = useState<string | null>(null);
  const [more, setMore] = useState<Run[]>([]);
  const [moreCursor, setMoreCursor] = useState<string | null | undefined>(undefined);
  const [pollError, setPollError] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const starting = useRef(false);
  const [busy, setBusy] = useState(false);

  usePoll(async () => {
    try {
      const page = await listRuns();
      setFirst(page.runs);
      setFirstCursor(page.cursor);
      setPollError(null);
    } catch (e) {
      setPollError(message(e));
    }
  });
  const next = moreCursor === undefined ? firstCursor : moreCursor;
  const loadMore = async () => {
    if (next === null) return;
    setActionError(null);
    try {
      const page = await listRuns(next);
      setMore((old) => [...old, ...page.runs]);
      setMoreCursor(page.cursor);
    } catch (e) {
      setActionError(message(e));
    }
  };
  const start = async () => {
    if (starting.current) return;
    starting.current = true;
    setBusy(true);
    setActionError(null);
    try {
      const run = await startRun(`DEMO-${String(Date.now() % 100000)}`);
      navigate(`/runs/${encodeURIComponent(run.id)}`); // the oldest runs come first: go to the new one
    } catch (e) {
      setActionError(message(e));
    } finally {
      starting.current = false;
      setBusy(false);
    }
  };
  const seen = new Set<string>();
  const runs = [...(first ?? []), ...more].filter((r) => !seen.has(r.id) && seen.add(r.id));
  return (
    <Layout title="Runs">
      <button type="button" disabled={busy} onClick={() => void start()}>
        Start a run
      </button>
      {pollError !== null && <p role="alert">{pollError}</p>}
      {actionError !== null && <p role="alert">{actionError}</p>}
      {first?.length === 0 && <p>No runs yet.</p>}
      <ul>
        {runs.map((r) => (
          <li key={r.id}>
            <a href={`/runs/${encodeURIComponent(r.id)}`}>{r.id}</a> <span>{r.status}</span>{" "}
            <span>{r.stage ?? ""}</span> <span>{r.ticket ?? ""}</span>
          </li>
        ))}
      </ul>
      {next !== null && (
        <button type="button" onClick={() => void loadMore()}>
          Load more
        </button>
      )}
    </Layout>
  );
}
