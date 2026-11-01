import { afterEach, expect, it, vi } from "vitest";
import { ApiError, TIMEOUT_MS, decide, listRuns } from "./api";

function reply(status: number, body: unknown): void {
  vi.stubGlobal(
    "fetch",
    vi.fn(() => Promise.resolve(new Response(JSON.stringify(body), { status }))),
  );
}
afterEach(() => {
  vi.unstubAllGlobals();
});

it("sends the dev token and reads the run list", async () => {
  reply(200, { runs: [], cursor: null });
  await listRuns();
  const [url, init] = vi.mocked(fetch).mock.calls[0] as [string, RequestInit];
  expect(url).toBe("/api/runs?limit=50");
  expect(new Headers(init.headers).get("Authorization")).toMatch(/^Bearer .+/);
});

it("turns the ErrorResponse shape into an ApiError with who closed the gate", async () => {
  reply(409, {
    error: {
      code: "gate_closed",
      message: "closed",
      closed_by: "dev",
      status: "APPROVED",
      stop: { method: "POST", href: "/runs/R/cancel" },
    },
  });
  const err = await decide("R", "review_gate", 1, "approve", "d", "").catch((e: unknown) => e);
  expect(err).toBeInstanceOf(ApiError);
  expect(err).toMatchObject({ status: 409, code: "gate_closed", closedBy: "dev" });
});

it("survives a non-JSON failure (a proxy error page)", async () => {
  vi.stubGlobal(
    "fetch",
    vi.fn(() => Promise.resolve(new Response("<html>bad gateway</html>", { status: 502 }))),
  );
  const err = await listRuns().catch((e: unknown) => e);
  expect(err).toMatchObject({ status: 502, code: "http_502" });
});

it("keeps decision_recorded and the Stop option of an error", async () => {
  reply(503, { error: { code: "delivery_failed", message: "m", decision_recorded: true } });
  expect(await decide("R", "g", 1, "approve", "d", "").catch((e: unknown) => e)).toMatchObject({
    status: 503, decisionRecorded: true, stop: null,
  });
  reply(409, { error: { code: "gate_closed", message: "m", stop: { method: "POST", href: "/runs/R/cancel" } } });
  expect(await decide("R", "g", 1, "reject", "", "x").catch((e: unknown) => e)).toMatchObject({
    decisionRecorded: false, stop: { href: "/runs/R/cancel" },
  });
});

it("puts a timeout on every request, and a hung or failed one is an ApiError", async () => {
  const spy = vi.spyOn(AbortSignal, "timeout").mockReturnValue(AbortSignal.abort());
  vi.stubGlobal(
    "fetch",
    vi.fn((_url: string, init: RequestInit) =>
      init.signal?.aborted ? Promise.reject(new Error("aborted")) : new Promise<Response>(() => undefined),
    ),
  );
  // Without a signal the fetch above never answers: lose the race with a named reason instead.
  const hung = new Promise<string>((r) => setTimeout(() => { r("HUNG: the request has no abort signal"); }, 100));
  const outcome = await Promise.race([listRuns().catch((e: unknown) => e), hung]);
  expect(outcome).toMatchObject({ status: 0, code: "network" });
  expect(vi.mocked(fetch).mock.calls[0]?.[1]?.signal).toBeInstanceOf(AbortSignal);
  expect(spy).toHaveBeenCalledWith(TIMEOUT_MS);
  spy.mockRestore();
});

it("sends the cursor, encoded", async () => {
  reply(200, { runs: [], cursor: null });
  await listRuns("a b");
  expect(vi.mocked(fetch).mock.calls[0]?.[0]).toBe("/api/runs?limit=50&cursor=a%20b");
});
