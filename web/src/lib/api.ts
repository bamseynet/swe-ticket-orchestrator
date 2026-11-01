// The API v0 client (D1-08). Every string that comes back is model or ticket text at worst, so
// callers render it as React text children and never as markup.

const BASE = "/api"; // the dev server and the browser test forward this to the API
const TOKEN = (import.meta.env["VITE_DEV_TOKEN"] as string | undefined) ?? "dev-token"; // local default

export interface Run {
  id: string;
  status: string;
  stage: string | null;
  blocked_reason: string | null;
  ticket: string | null;
  held: string | null;
  driver_error: string | null;
}
export interface RunEvent {
  seq: number;
  type: string;
  outcome: string;
  data: Record<string, unknown>;
  status: string;
  stage: string | null;
  detail: string;
}
export interface Gate {
  id: string;
  name: string;
  round: number;
  type: string;
  status: string;
  closed_by: string | null;
  subject_digest: string;
  head_sha: string | null;
}
export type DecisionKind = "approve" | "request_changes" | "reject";

export class ApiError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    message: string,
    readonly closedBy: string | null = null,
    readonly gateStatus: string | null = null,
  ) {
    super(message);
  }
}

async function call<T>(path: string, method = "GET", body?: unknown): Promise<T> {
  const headers = new Headers({ Authorization: `Bearer ${TOKEN}` });
  const init: RequestInit = { method, headers };
  if (body !== undefined) {
    headers.set("Content-Type", "application/json");
    init.body = JSON.stringify(body);
  }
  const res = await fetch(BASE + path, init);
  const text = await res.text();
  let json: unknown;
  try {
    json = JSON.parse(text);
  } catch {
    json = undefined; // a proxy error page is not ours
  }
  if (!res.ok) {
    const e = (json as { error?: Record<string, unknown> } | undefined)?.error;
    throw new ApiError(
      res.status,
      typeof e?.["code"] === "string" ? e["code"] : `http_${String(res.status)}`,
      typeof e?.["message"] === "string" ? e["message"] : `the server answered ${String(res.status)}`,
      typeof e?.["closed_by"] === "string" ? e["closed_by"] : null,
      typeof e?.["status"] === "string" ? e["status"] : null,
    );
  }
  return json as T;
}

export const listRuns = () => call<{ runs: Run[]; cursor: string | null }>("/runs?limit=50");
export const startRun = (ticket: string) => call<Run>("/runs", "POST", { ticket });
export const getRun = (id: string) => call<Run>(`/runs/${encodeURIComponent(id)}`);
export const listGates = (id: string) =>
  call<{ gates: Gate[] }>(`/runs/${encodeURIComponent(id)}/gates`);
export const listEvents = (id: string, after: string | null) =>
  call<{ events: RunEvent[]; cursor: string | null }>(
    `/runs/${encodeURIComponent(id)}/events?limit=500${after ? `&after=${encodeURIComponent(after)}` : ""}`,
  );
export const stopRun = (id: string) =>
  call<{ accepted: boolean }>(`/runs/${encodeURIComponent(id)}/cancel`, "POST");
export const decide = (
  run: string,
  name: string,
  round: number,
  kind: DecisionKind,
  subjectDigest: string,
  comment: string,
) =>
  call<{ decision_id: string; gate: Gate }>(
    `/runs/${encodeURIComponent(run)}/gates/${encodeURIComponent(name)}/${String(round)}/decisions`,
    "POST",
    { kind, subject_digest: subjectDigest, comment },
  );
