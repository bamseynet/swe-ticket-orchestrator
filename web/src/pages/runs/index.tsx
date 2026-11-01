import { useState } from "react";
import { listRuns, startRun, type Run } from "../../lib/api";
import { Layout, message } from "../../lib/Layout";
import { usePoll } from "../../lib/usePoll";

export default function Runs() {
  const [runs, setRuns] = useState<Run[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const refresh = async () => {
    try {
      setRuns((await listRuns()).runs);
      setError(null);
    } catch (e) {
      setError(message(e));
    }
  };
  usePoll(refresh);
  const start = async () => {
    try {
      await startRun(`DEMO-${String(Date.now() % 100000)}`);
      await refresh();
    } catch (e) {
      setError(message(e));
    }
  };
  return (
    <Layout title="Runs">
      <button type="button" onClick={() => void start()}>
        Start a run
      </button>
      {error !== null && <p role="alert">{error}</p>}
      {runs?.length === 0 && <p>No runs yet.</p>}
      <ul>
        {runs?.map((r) => (
          <li key={r.id}>
            <a href={`/runs/${r.id}`}>{r.id}</a> <span>{r.status}</span> <span>{r.stage ?? ""}</span>{" "}
            <span>{r.ticket ?? ""}</span>
          </li>
        ))}
      </ul>
    </Layout>
  );
}
