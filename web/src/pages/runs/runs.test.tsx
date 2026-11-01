import { act, cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { json, serve, type Call } from "../../lib/testing";
import Timeline from "./[id]/index";
import Runs from "./index";

vi.mock("../../lib/nav", () => ({ navigate: vi.fn() }));
const nav = (await import("../../lib/nav")).navigate;

const HOSTILE = "<img src=x id=pwn>TICKET";
const run = (over = {}) => ({
  id: "R1", status: "WAITING_HUMAN", stage: "review_gate", blocked_reason: null,
  ticket: HOSTILE, held: null, driver_error: null, ...over,
});
const tick = (ms: number) => act(async () => { await vi.advanceTimersByTimeAsync(ms); });
const posts = (calls: Call[], url?: string) => calls.filter((c) => c.method === "POST" && (!url || c.url === url));

beforeEach(() => {
  vi.useFakeTimers({ shouldAdvanceTime: true });
  vi.mocked(nav).mockClear();
});
afterEach(() => {
  cleanup();
  vi.useRealTimers();
  vi.unstubAllGlobals();
});

it("lists runs, with ticket text as plain text and an encoded link to each", async () => {
  serve(() => json(200, { runs: [run({ id: "a/b" })], cursor: null }));
  const { container } = render(<Runs />);
  expect(await screen.findByText(HOSTILE)).toBeTruthy();
  expect(container.querySelector("#pwn")).toBeNull();
  expect(screen.getByRole("link", { name: "a/b" }).getAttribute("href")).toBe("/runs/a%2Fb");
  expect(screen.getByTestId("simulated-banner").textContent).toMatch(/simulated/i);
});

it("starts a run once on a double click, then goes to the new run", async () => {
  let release: (r: Response) => void = () => undefined;
  const calls = serve((c) => c.method === "POST"
    ? (new Promise<Response>((r) => { release = r; }))
    : json(200, { runs: [], cursor: null }));
  render(<Runs />);
  const start = await screen.findByRole("button", { name: "Start a run" });
  fireEvent.click(start);
  fireEvent.click(start);
  await waitFor(() => { expect((start as HTMLButtonElement).disabled).toBe(true); });
  expect(posts(calls)).toHaveLength(1);
  release(json(202, run({ id: "NEW 1" })));
  await waitFor(() => { expect(nav).toHaveBeenCalledWith("/runs/NEW%201"); });
});

it("a failed Start keeps its alert through the next poll and allows another try", async () => {
  serve((c) => c.method === "POST" ? json(503, { error: { code: "store_conflict", message: "busy now" } }) : json(200, { runs: [], cursor: null }));
  render(<Runs />);
  fireEvent.click(await screen.findByRole("button", { name: "Start a run" }));
  await screen.findByText("busy now");
  await tick(2100);
  expect(screen.getByText("busy now")).toBeTruthy();
  expect(screen.getByRole<HTMLButtonElement>("button", { name: "Start a run" }).disabled).toBe(false);
  expect(nav).not.toHaveBeenCalled();
});

it("follows the cursor with Load more, beyond the first 50 runs", async () => {
  const calls = serve((c) => c.url.includes("cursor=c1")
    ? json(200, { runs: [run({ id: "R51", ticket: "late" })], cursor: null })
    : json(200, { runs: [run({ id: "R1", ticket: "early" })], cursor: "c1" }));
  render(<Runs />);
  fireEvent.click(await screen.findByRole("button", { name: "Load more" }));
  expect(await screen.findByText("late")).toBeTruthy();
  expect(screen.getByText("early")).toBeTruthy();
  expect(calls.some((c) => c.url === "/api/runs?limit=50&cursor=c1")).toBe(true);
  expect(screen.queryByRole("button", { name: "Load more" })).toBeNull();
  await tick(2100); // the poll refreshes the first page and keeps the loaded ones
  expect(screen.getByText("late")).toBeTruthy();
});

it("a list error clears on the next good poll", async () => {
  let n = 0;
  serve(() => (++n === 1 ? json(503, { error: { code: "store_conflict", message: "busy" } }) : json(200, { runs: [], cursor: null })));
  render(<Runs />);
  await screen.findByText("busy");
  await tick(2100);
  await waitFor(() => { expect(screen.queryByText("busy")).toBeNull(); });
});

// ------------------------------------------------------------------ timeline
const events = [
  { seq: 0, type: "run.started", outcome: "applied", data: {}, status: "RUNNING", stage: "implement", detail: "" },
  { seq: 1, type: "effect.done", outcome: "applied", data: {}, status: "RUNNING", stage: "merge", detail: "<b>merged</b>" },
];
const openGate = { id: "g", name: "review gate", round: 1, type: "review", status: "OPEN", closed_by: null, subject_digest: "d", head_sha: "abc" };

interface World { run: object; events: typeof events; cursor: string | null; stop: () => Response }
function world(w: Partial<World> = {}) {
  const state: World = { run: run(), events, cursor: "e1", stop: () => json(202, { id: "R1", accepted: true }), ...w };
  const calls = serve((c) => {
    if (c.url.endsWith("/cancel")) return state.stop();
    if (c.url.endsWith("/gates")) return json(200, { gates: [openGate] });
    if (c.url.includes("/events")) return json(200, { events: state.events, cursor: state.cursor });
    return json(200, state.run);
  });
  return { calls, state };
}

it("shows the timeline as text, with an encoded link to the open gate", async () => {
  world();
  const { container } = render(<Timeline params={{ id: "R1" }} />);
  await screen.findByText("run.started");
  expect(screen.getByText("<b>merged</b>")).toBeTruthy();
  expect(container.querySelector("b")).toBeNull();
  expect(screen.getByRole("link", { name: /review gate/ }).getAttribute("href")).toBe("/gate/R1/review%20gate/1");
});

it("polls from the cursor and does not repeat events", async () => {
  const { calls, state } = world({ events: events.slice(0, 1), cursor: "e0" });
  render(<Timeline params={{ id: "R1" }} />);
  await screen.findByText("run.started");
  state.events = events.slice(1);
  state.cursor = "e1";
  await tick(2100);
  await screen.findByText("effect.done");
  expect(calls.some((c) => c.url === "/api/runs/R1/events?limit=500&after=e0")).toBe(true);
  expect(screen.getAllByText("run.started")).toHaveLength(1);
});

it("sends Stop, says so, and keeps a failed Stop's alert through the next poll", async () => {
  const { calls, state } = world();
  render(<Timeline params={{ id: "R1" }} />);
  fireEvent.click(await screen.findByRole("button", { name: "Stop" }));
  expect((await screen.findByText("Stop requested.")).getAttribute("role")).toBe("status");
  expect(posts(calls, "/api/runs/R1/cancel")).toHaveLength(1);
  state.stop = () => json(409, { error: { code: "run_finished", message: "already over" } });
  fireEvent.click(screen.getByRole("button", { name: "Stop" }));
  await screen.findByText("already over");
  expect(screen.queryByText("Stop requested.")).toBeNull();
  await tick(2100);
  expect(screen.getByText("already over")).toBeTruthy();
  expect(screen.getByRole("button", { name: "Stop" })).toBeTruthy();
});

it("a timeline error clears on the next good poll", async () => {
  let n = 0;
  const { state } = world();
  serve((c) => (++n <= 1 ? json(503, { error: { code: "store_conflict", message: "busy" } }) : c.url.endsWith("/gates") ? json(200, { gates: [] }) : c.url.includes("/events") ? json(200, { events: [], cursor: null }) : json(200, state.run)));
  render(<Timeline params={{ id: "R1" }} />);
  await screen.findByText("busy");
  await tick(2100);
  await waitFor(() => { expect(screen.queryByText("busy")).toBeNull(); });
  await screen.findByTestId("run-status");
});

it("offers no Stop on a finished run, and stops polling it after the last events", async () => {
  const { calls } = world({ run: run({ status: "DONE" }) });
  render(<Timeline params={{ id: "R1" }} />);
  expect((await screen.findByTestId("run-status")).textContent).toBe("DONE");
  expect(screen.queryByRole("button", { name: "Stop" })).toBeNull();
  await waitFor(() => { expect(screen.getByText("effect.done")).toBeTruthy(); });
  const before = calls.length;
  await tick(10000);
  expect(calls.length).toBe(before);
});

it("keeps polling a run that is not finished", async () => {
  const { calls } = world();
  render(<Timeline params={{ id: "R1" }} />);
  await screen.findByText("run.started");
  const before = calls.length;
  await tick(4300);
  expect(calls.length).toBeGreaterThan(before);
});

it("stops polling when the page goes away", async () => {
  const { calls } = world();
  const { unmount } = render(<Timeline params={{ id: "R1" }} />);
  await screen.findByText("run.started");
  unmount();
  const before = calls.length;
  await tick(10000);
  expect(calls.length).toBe(before);
});

it("encodes the run id in the timeline requests", async () => {
  const { calls } = world();
  render(<Timeline params={{ id: "a/b" }} />);
  await screen.findByText("run.started");
  expect(calls.every((c) => c.url.startsWith("/api/runs/a%2Fb"))).toBe(true);
  expect(calls.some((c) => c.url.includes("/events"))).toBe(true);
});

it("two Start clicks in the same tick, before any re-render, start one run", async () => {
  const calls = serve((c) => (c.method === "POST" ? json(202, run()) : json(200, { runs: [], cursor: null })));
  render(<Runs />);
  const start = await screen.findByRole("button", { name: "Start a run" });
  act(() => {
    start.click();
    start.click();
  });
  await waitFor(() => { expect(nav).toHaveBeenCalled(); });
  expect(posts(calls)).toHaveLength(1);
});
