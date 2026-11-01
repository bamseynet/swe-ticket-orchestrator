import { afterEach, expect, it, vi } from "vitest";
import { ApiError, decide, listRuns } from "./api";

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
