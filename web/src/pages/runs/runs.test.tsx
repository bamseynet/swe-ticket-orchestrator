import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import Runs from "./index";
import Timeline from "./[id]/index";

const HOSTILE = "<img src=x id=pwn>TICKET";
afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});
function route(table: Record<string, unknown>): string[] {
  const seen: string[] = [];
  vi.stubGlobal(
    "fetch",
    vi.fn((url: string, init?: RequestInit) => {
      seen.push(`${init?.method ?? "GET"} ${url}`);
      const hit = table[`${init?.method ?? "GET"} ${url}`];
      return Promise.resolve(new Response(JSON.stringify(hit ?? {}), { status: hit ? 200 : 404 }));
    }),
  );
  return seen;
}
const run = (over = {}) => ({
  id: "R1", status: "WAITING_HUMAN", stage: "review_gate", blocked_reason: null,
  ticket: HOSTILE, held: null, driver_error: null, ...over,
});

it("lists runs, with ticket text as plain text and a link to each", async () => {
  route({ "GET /api/runs?limit=50": { runs: [run()], cursor: null } });
  const { container } = render(<Runs />);
  expect(await screen.findByText(HOSTILE)).toBeTruthy();
  expect(container.querySelector("#pwn")).toBeNull();
  expect(screen.getByRole("link", { name: "R1" }).getAttribute("href")).toBe("/runs/R1");
});

it("starts a run from the list", async () => {
  const seen = route({
    "GET /api/runs?limit=50": { runs: [], cursor: null },
    "POST /api/runs": run(),
  });
  render(<Runs />);
  fireEvent.click(await screen.findByRole("button", { name: "Start a run" }));
  await waitFor(() => { expect(seen).toContain("POST /api/runs"); });
});

it("shows the simulated-writes banner", async () => {
  route({ "GET /api/runs?limit=50": { runs: [], cursor: null } });
  render(<Runs />);
  expect((await screen.findByTestId("simulated-banner")).textContent).toMatch(/simulated/i);
});

const events = [
  { seq: 0, type: "run.started", outcome: "applied", data: {}, status: "RUNNING", stage: "implement", detail: "" },
  { seq: 1, type: "effect.done", outcome: "applied", data: { receipt: { simulated: true, external_id: "pr-1" } },
    status: "RUNNING", stage: "merge", detail: "<b>merged</b>" },
  { seq: 2, type: "effect.done", outcome: "applied", data: { receipt: { simulated: false, external_id: "pr-2" } },
    status: "RUNNING", stage: "merge", detail: "" },
];

it("shows the timeline, marks simulated writes, links the open gate and offers no markup", async () => {
  route({
    "GET /api/runs/R1": run(),
    "GET /api/runs/R1/events?limit=500": { events, cursor: "e2" },
    "GET /api/runs/R1/gates": { gates: [{ id: "g", name: "review_gate", round: 1, type: "review",
      status: "OPEN", closed_by: null, subject_digest: "d", head_sha: "abc" }] },
  });
  const { container } = render(<Timeline params={{ id: "R1" }} />);
  await screen.findByText("run.started");
  expect(screen.getAllByTestId("simulated-write")).toHaveLength(1); // only the receipt that says so
  expect(screen.getByText("<b>merged</b>")).toBeTruthy(); // text, not bold
  expect(container.querySelector("b")).toBeNull();
  expect(screen.getByRole("link", { name: /review_gate/ }).getAttribute("href")).toBe(
    "/gate/R1/review_gate/1",
  );
});

it("polls from the cursor and does not repeat events", async () => {
  vi.useFakeTimers({ shouldAdvanceTime: true });
  try {
    const seen = route({
      "GET /api/runs/R1": run(),
      "GET /api/runs/R1/events?limit=500": { events: events.slice(0, 1), cursor: "e0" },
      "GET /api/runs/R1/events?limit=500&after=e0": { events: events.slice(1, 2), cursor: "e1" },
      "GET /api/runs/R1/gates": { gates: [] },
    });
    render(<Timeline params={{ id: "R1" }} />);
    await screen.findByText("run.started");
    await waitFor(
      () => {
        expect(seen).toContain("GET /api/runs/R1/events?limit=500&after=e0");
      },
      { timeout: 5000 },
    );
    await screen.findByText("effect.done");
    expect(screen.getAllByText("run.started")).toHaveLength(1);
  } finally {
    vi.useRealTimers();
  }
});

it("offers Stop only when the run can still be stopped, and sends it", async () => {
  const seen = route({
    "GET /api/runs/R1": run(),
    "GET /api/runs/R1/events?limit=500": { events: [], cursor: null },
    "GET /api/runs/R1/gates": { gates: [] },
    "POST /api/runs/R1/cancel": { id: "R1", accepted: true },
  });
  render(<Timeline params={{ id: "R1" }} />);
  fireEvent.click(await screen.findByRole("button", { name: "Stop" }));
  await waitFor(() => { expect(seen).toContain("POST /api/runs/R1/cancel"); });
});

it("offers no Stop on a finished run", async () => {
  route({
    "GET /api/runs/R1": run({ status: "DONE" }),
    "GET /api/runs/R1/events?limit=500": { events: [], cursor: null },
    "GET /api/runs/R1/gates": { gates: [] },
  });
  render(<Timeline params={{ id: "R1" }} />);
  await screen.findByText(/DONE/);
  expect(screen.queryByRole("button", { name: "Stop" })).toBeNull();
});
