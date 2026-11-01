import { act, cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { json, serve, type Call, type Handler } from "../../lib/testing";
import Gate, { DELIVERY_BACKOFF_MS } from "./[run]/[name]/[round]/index";

const gate = (over: object) => ({
  id: "g", name: "review_gate", round: 1, type: "review", status: "OPEN",
  closed_by: null, subject_digest: "d-r1", head_sha: "abc", ...over,
});
// Several gates and rounds, so a lookup that ignores the name or the round picks a wrong one.
const GATES = [
  gate({ id: "g1", round: 1, status: "CHANGES_REQUESTED", closed_by: "alice", subject_digest: "d-r1" }),
  gate({ id: "g2", round: 2, subject_digest: "d-r2" }),
  gate({ id: "g3", name: "qa_gate", round: 1, type: "qa", subject_digest: "d-qa" }),
];
const params = { run: "R1", name: "review_gate", round: "2" };
const DECISION = "/api/runs/R1/gates/review_gate/2/decisions";
const posts = (calls: Call[]) => calls.filter((c) => c.method === "POST");

/** The usual server: gates, a running run, and `decision` for the POST. */
function api(decision: Handler = () => json(202, { decision_id: "x", gate: { ...GATES[1], status: "APPROVED", closed_by: "dev" } }), gates: unknown[] = GATES): Handler {
  return (c) => {
    if (c.method === "POST") return decision(c);
    if (c.url.endsWith("/gates")) return json(200, { gates });
    return json(200, { id: "R1", status: "WAITING_HUMAN" });
  };
}
const tick = (ms: number) => act(async () => { await vi.advanceTimersByTimeAsync(ms); });
const open = () => screen.findByRole("button", { name: "Approve" });

beforeEach(() => {
  vi.useFakeTimers({ shouldAdvanceTime: true });
});
afterEach(() => {
  cleanup();
  vi.useRealTimers();
  vi.unstubAllGlobals();
});

it("decides the gate in the URL, with that gate's digest, among other gates and rounds", async () => {
  const calls = serve(api());
  render(<Gate params={params} />);
  fireEvent.click(await open());
  await waitFor(() => { expect(posts(calls)).toHaveLength(1); });
  expect(posts(calls)[0]).toMatchObject({
    url: DECISION,
    body: { kind: "approve", subject_digest: "d-r2", comment: "" },
  });
});

it("shows the gate that matches the name and the round", async () => {
  serve(api());
  render(<Gate params={{ run: "R1", name: "qa_gate", round: "1" }} />);
  expect((await screen.findByText("d-qa"))).toBeTruthy();
  expect(screen.queryByText("d-r2")).toBeNull();
});

it.each(["Request changes", "Reject"])("%s without a comment is refused and sends nothing", async (label) => {
  const calls = serve(api());
  render(<Gate params={params} />);
  fireEvent.click(await screen.findByRole("button", { name: label }));
  expect((await screen.findByRole("alert")).textContent).toMatch(/comment is required/i);
  expect(posts(calls)).toHaveLength(0);
});

it("says a comment is required before the click", async () => {
  serve(api());
  render(<Gate params={params} />);
  await open();
  expect(screen.getByLabelText("Comment").getAttribute("aria-describedby")).toBe("comment-hint");
  expect(document.getElementById("comment-hint")?.textContent).toMatch(/comment is required/i);
});

it("a whitespace comment is still refused", async () => {
  const calls = serve(api());
  render(<Gate params={params} />);
  fireEvent.change(await screen.findByLabelText("Comment"), { target: { value: "   " } });
  fireEvent.click(screen.getByRole("button", { name: "Reject" }));
  await screen.findByRole("alert");
  expect(posts(calls)).toHaveLength(0);
});

it.each([["Request changes", "request_changes"], ["Reject", "reject"]])(
  "%s with a comment sends the kind and the comment", async (label, kind) => {
    const calls = serve(api());
    render(<Gate params={params} />);
    fireEvent.change(await screen.findByLabelText("Comment"), { target: { value: "nope" } });
    fireEvent.click(screen.getByRole("button", { name: label }));
    await waitFor(() => { expect(posts(calls)).toHaveLength(1); });
    expect(posts(calls)[0]?.body).toMatchObject({ kind, comment: "nope" });
  });

it("disables the buttons while a decision is in flight and sends a double click once", async () => {
  let release: (r: Response) => void = () => undefined;
  const calls = serve(api(() => new Promise<Response>((r) => { release = r; })));
  render(<Gate params={params} />);
  const approve = await open();
  fireEvent.click(approve);
  fireEvent.click(approve);
  await waitFor(() => { expect((approve as HTMLButtonElement).disabled).toBe(true); });
  expect(screen.getByRole("button", { name: "Reject" }).hasAttribute("disabled")).toBe(true);
  expect(posts(calls)).toHaveLength(1);
  release(json(202, { decision_id: "x", gate: { ...GATES[1], status: "APPROVED", closed_by: "dev" } }));
  await screen.findByText("Decision recorded.");
});

it("two clicks in the same tick, before any re-render, still send once", async () => {
  const calls = serve(api());
  render(<Gate params={params} />);
  const approve = await open();
  act(() => {
    approve.click();
    approve.click();
  });
  await screen.findByText("Decision recorded.");
  expect(posts(calls)).toHaveLength(1);
});

it("confirms only after the server accepted, and refreshes afterwards", async () => {
  const calls = serve(api());
  render(<Gate params={params} />);
  fireEvent.click(await open());
  const status = await screen.findByRole("status");
  expect(status.textContent).toBe("Decision recorded.");
  await waitFor(() => { expect(calls.at(-1)?.method).toBe("GET"); });
  const lastPost = calls.map((c) => c.method).lastIndexOf("POST");
  expect(calls.slice(lastPost + 1).some((c) => c.url.endsWith("/gates"))).toBe(true);
});

it.each([
  [422, { error: { code: "comment_required", message: "say why" } }, /say why/],
  [409, { error: { code: "stale_subject", message: "the code changed" } }, /the code changed/],
])("a %s refusal shows the server's reason, not success or 'already closed'", async (status, body, text) => {
  serve(api(() => json(status, body)));
  render(<Gate params={params} />);
  fireEvent.click(await open());
  const alert = await screen.findByRole("alert");
  expect(alert.textContent).toMatch(text);
  expect(alert.textContent).not.toMatch(/already/);
  expect(screen.queryByText("Decision recorded.")).toBeNull();
  expect((await open()).hasAttribute("disabled")).toBe(false); // can try again
});

it("a network failure on the decision is an alert, not success", async () => {
  serve(api(() => new Error("offline")));
  render(<Gate params={params} />);
  fireEvent.click(await open());
  expect((await screen.findByRole("alert")).textContent).toMatch(/could not reach/);
  expect(screen.queryByText("Decision recorded.")).toBeNull();
});

it("shows the closed gate from the 202 even when the follow-up read fails", async () => {
  let down = false;
  serve((c) => {
    if (c.method === "POST") { down = true; return json(202, { decision_id: "x", gate: { ...GATES[1], status: "APPROVED", closed_by: "dev" } }); }
    return down ? json(503, { error: { code: "store_conflict", message: "busy" } }) : api()(c);
  });
  render(<Gate params={params} />);
  fireEvent.click(await open());
  expect((await screen.findByTestId("closed-by")).textContent).toContain("dev");
  expect(screen.getByText("Decision recorded.")).toBeTruthy();
  expect(screen.queryByRole("button", { name: "Approve" })).toBeNull();
});

it("a read that was in flight before the decision cannot reopen the closed gate", async () => {
  let held: ((r: Response) => void) | null = null;
  let armed = false;
  let staleRun = false;
  serve((c) => {
    if (staleRun && c.method === "GET" && !c.url.endsWith("/gates")) {
      staleRun = false;
      return json(200, { id: "R1", status: "CANCELLED" });
    }
    if (c.method === "POST") return json(202, { decision_id: "x", gate: { ...GATES[1], status: "APPROVED", closed_by: "dev" } });
    if (armed && c.url.endsWith("/gates") && held === null) {
      return new Promise<Response>((r) => { held = r; });
    }
    return api()(c);
  });
  render(<Gate params={params} />);
  await open();
  armed = true;
  staleRun = true;
  await tick(2100); // a poll starts and hangs
  await waitFor(() => { expect(held).not.toBeNull(); });
  fireEvent.click(screen.getByRole("button", { name: "Approve" }));
  await screen.findByText("Decision recorded.");
  await act(async () => { (held as unknown as (r: Response) => void)(json(200, { gates: GATES })); await Promise.resolve(); });
  expect((await screen.findByTestId("closed-by")).textContent).toContain("dev");
  expect(screen.queryByRole("button", { name: "Approve" })).toBeNull();
  expect(screen.getByText("Decision recorded.")).toBeTruthy();
  expect(screen.queryByText(/This run is CANCELLED/)).toBeNull(); // the old read's run status is dropped too
});

it("a closed gate shows who closed it and offers no decision", async () => {
  serve(api());
  render(<Gate params={{ ...params, round: "1" }} />);
  expect((await screen.findByTestId("closed-by")).textContent).toContain("alice");
  expect(screen.queryByRole("button", { name: "Approve" })).toBeNull();
});

it("says 'no decision' for a gate nobody decided", async () => {
  serve(api(undefined, [gate({ status: "EXPIRED", closed_by: null, round: 2 })]));
  render(<Gate params={params} />);
  expect((await screen.findByTestId("closed-by")).textContent).toContain("closed, no decision");
});

it("a 409 gate_closed shows who closed it, and offers Stop when the API does", async () => {
  const calls = serve((c) => {
    if (c.url.endsWith("/cancel")) return json(202, { id: "R1", accepted: true });
    return api(() => json(409, { error: { code: "gate_closed", message: "m", closed_by: "bob", status: "REJECTED",
      stop: { method: "POST", href: "/runs/R1/cancel" } } }))(c);
  });
  render(<Gate params={params} />);
  fireEvent.click(await open());
  expect((await screen.findByRole("alert")).textContent).toContain("bob");
  fireEvent.click(await screen.findByRole("button", { name: "Stop" }));
  expect((await screen.findByText("Stop requested.")).getAttribute("role")).toBe("status");
  expect(calls.some((c) => c.method === "POST" && c.url === "/api/runs/R1/cancel")).toBe(true);
});

it("offers no Stop when the API does not", async () => {
  serve(api(() => json(409, { error: { code: "gate_closed", message: "m", closed_by: "bob", status: "REJECTED" } })));
  render(<Gate params={params} />);
  fireEvent.click(await open());
  await screen.findByRole("alert");
  expect(screen.queryByRole("button", { name: "Stop" })).toBeNull();
});

const FAILED = json(503, { error: { code: "delivery_failed", message: "not delivered", decision_recorded: true } });
const failed = () => FAILED.clone();

it("a recorded but undelivered decision is repeated until accepted", async () => {
  let n = 0;
  const calls = serve(api(() => (++n < 3 ? failed() : json(202, { decision_id: "x", gate: GATES[1] }))));
  render(<Gate params={params} />);
  fireEvent.click(await open());
  expect((await screen.findByRole("status")).textContent).toMatch(/recorded, delivering/);
  expect(screen.queryByRole("button", { name: "Approve" })).toBeNull(); // not offered again
  await tick(DELIVERY_BACKOFF_MS[0] ?? 0);
  await tick(DELIVERY_BACKOFF_MS[1] ?? 0);
  await screen.findByText("Decision recorded.");
  expect(posts(calls)).toHaveLength(3);
  expect(new Set(posts(calls).map((c) => JSON.stringify(c.body))).size).toBe(1); // the same request
  await tick(20000);
  expect(posts(calls)).toHaveLength(3); // and it stops
});

it("a 409 gate_closed on the repeat means it was delivered", async () => {
  let n = 0;
  const calls = serve(api(() => (++n < 2 ? failed() : json(409, { error: { code: "gate_closed", message: "m", closed_by: "dev", status: "APPROVED" } }))));
  render(<Gate params={params} />);
  fireEvent.click(await open());
  await screen.findByText(/delivering/);
  await tick(DELIVERY_BACKOFF_MS[0] ?? 0);
  await screen.findByText("Decision recorded.");
  expect(posts(calls)).toHaveLength(2);
  expect(screen.queryByRole("alert")).toBeNull();
});

it("gives up with a visible Retry delivery button, which repeats the request", async () => {
  let succeed = false;
  const calls = serve(api(() => (succeed ? json(202, { decision_id: "x", gate: GATES[1] }) : failed())));
  render(<Gate params={params} />);
  fireEvent.click(await open());
  await screen.findByText(/delivering/);
  for (const ms of DELIVERY_BACKOFF_MS) await tick(ms);
  const retry = await screen.findByRole("button", { name: "Retry delivery" });
  expect(screen.getByRole("alert").textContent).toMatch(/not delivered/);
  expect(posts(calls)).toHaveLength(1 + DELIVERY_BACKOFF_MS.length);
  succeed = true;
  fireEvent.click(retry);
  await tick(DELIVERY_BACKOFF_MS[0] ?? 0);
  await screen.findByText("Decision recorded.");
  expect(screen.queryByRole("button", { name: "Retry delivery" })).toBeNull();
});

it("a poll error clears on the next good poll, and polling survives a failed tick", async () => {
  let reads = 0;
  serve((c) => (c.url.endsWith("/gates") && ++reads === 1 ? json(503, { error: { code: "store_conflict", message: "busy" } }) : api()(c)));
  render(<Gate params={params} />);
  expect((await screen.findByRole("alert")).textContent).toMatch(/busy/);
  await tick(2100);
  await open();
  expect(screen.queryByRole("alert")).toBeNull();
});

it("a poll error does not hide that the decision was recorded", async () => {
  let down = false;
  serve((c) => {
    if (c.method === "POST") { down = true; return json(202, { decision_id: "x", gate: { ...GATES[1], status: "APPROVED", closed_by: "dev" } }); }
    return down ? json(503, { error: { code: "store_conflict", message: "busy" } }) : api()(c);
  });
  render(<Gate params={params} />);
  fireEvent.click(await open());
  await screen.findByText("Decision recorded.");
  await tick(2100);
  expect(screen.getByText("Decision recorded.")).toBeTruthy();
  expect(screen.getByText("busy")).toBeTruthy();
});

it("stops polling when the page goes away", async () => {
  const calls = serve(api());
  const { unmount } = render(<Gate params={params} />);
  await open();
  unmount();
  const before = calls.length;
  await tick(10000);
  expect(calls.length).toBe(before);
});

it("encodes the run and gate names in the request", async () => {
  const calls = serve(api(undefined, [gate({ name: "x y", round: 2 })]));
  render(<Gate params={{ run: "a/b", name: "x y", round: "2" }} />);
  fireEvent.click(await open());
  await waitFor(() => { expect(posts(calls)).toHaveLength(1); });
  expect(posts(calls)[0]?.url).toBe("/api/runs/a%2Fb/gates/x%20y/2/decisions");
  expect(screen.getByRole("link", { name: /Back to run/ }).getAttribute("href")).toBe("/runs/a%2Fb");
});

it.each(["1e0", "abc", "0", "-1", "1.5", ""])("rejects the round %j without asking the API", (round) => {
  const calls = serve(api());
  render(<Gate params={{ ...params, round }} />);
  expect(screen.getByRole("alert").textContent).toMatch(/whole number/);
  expect(calls).toHaveLength(0);
});

it("says so when there is no such gate", async () => {
  serve(api(undefined, []));
  render(<Gate params={params} />);
  expect((await screen.findByRole("alert")).textContent).toMatch(/no gate/i);
});

it("warns when the run was stopped", async () => {
  serve((c) => (c.url.endsWith("/gates") ? json(200, { gates: GATES }) : json(200, { id: "R1", status: "CANCELLED" })));
  render(<Gate params={params} />);
  expect((await screen.findByText(/This run is CANCELLED/)).getAttribute("role")).toBe("note");
});

it("renders the server's message as text, never as markup", async () => {
  serve(api(() => json(422, { error: { code: "x", message: "<img src=x id=pwn>" } })));
  const { container } = render(<Gate params={params} />);
  fireEvent.click(await open());
  await screen.findByRole("alert");
  expect(container.querySelector("#pwn")).toBeNull();
});

it("a later read that still says OPEN (a lagging replica) cannot reopen a closed gate", async () => {
  let decided = false;
  serve((c) => {
    if (c.method === "POST") { decided = true; return json(202, { decision_id: "x", gate: { ...GATES[1], status: "APPROVED", closed_by: "dev" } }); }
    return decided && c.url.endsWith("/gates") ? json(200, { gates: GATES }) : api()(c);
  });
  render(<Gate params={params} />);
  fireEvent.click(await open());
  await screen.findByText("Decision recorded.");
  await tick(2100);
  expect(screen.getByTestId("closed-by").textContent).toContain("dev");
  expect(screen.queryByRole("button", { name: "Approve" })).toBeNull();
});

it("a read that was in flight before the decision and then failed shows no error", async () => {
  let held: ((r: Response) => void) | null = null;
  let armed = false;
  serve((c) => {
    if (c.method === "POST") return json(202, { decision_id: "x", gate: { ...GATES[1], status: "APPROVED", closed_by: "dev" } });
    if (armed && c.url.endsWith("/gates") && held === null) return new Promise<Response>((r) => { held = r; });
    return api()(c);
  });
  render(<Gate params={params} />);
  await open();
  armed = true;
  await tick(2100);
  await waitFor(() => { expect(held).not.toBeNull(); });
  fireEvent.click(screen.getByRole("button", { name: "Approve" }));
  await screen.findByText("Decision recorded.");
  await act(async () => { (held as unknown as (r: Response) => void)(json(503, { error: { code: "store_conflict", message: "stale busy" } })); await Promise.resolve(); });
  expect(screen.queryByText("stale busy")).toBeNull();
});

it("leaving the page during delivery stops the repeats", async () => {
  const calls = serve(api(() => failed()));
  const { unmount } = render(<Gate params={params} />);
  fireEvent.click(await open());
  await screen.findByText(/delivering/);
  unmount();
  const before = posts(calls).length;
  await tick(30000);
  expect(posts(calls)).toHaveLength(before);
});

it("a repeat that was in flight when the page went away does not schedule more", async () => {
  let n = 0;
  let late: (r: Response) => void = () => undefined;
  const calls = serve(api(() => (++n === 2 ? (new Promise<Response>((r) => { late = r; })) : failed())));
  const { unmount } = render(<Gate params={params} />);
  fireEvent.click(await open());
  await screen.findByText(/delivering/);
  await tick(DELIVERY_BACKOFF_MS[0] ?? 0); // the second request is now in flight
  expect(posts(calls)).toHaveLength(2);
  unmount();
  await act(async () => { late(failed()); await Promise.resolve(); });
  await tick(30000);
  expect(posts(calls)).toHaveLength(2);
});
