import { vi } from "vitest";

export interface Call {
  method: string;
  url: string;
  body: unknown;
}
export type Handler = (c: Call) => Response | Promise<Response> | Error;

export function json(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), { status });
}

/** Stub `fetch` with a handler; returns the log of every call (method, url, parsed body). */
export function serve(handler: Handler): Call[] {
  const calls: Call[] = [];
  vi.stubGlobal(
    "fetch",
    vi.fn((url: string, init?: RequestInit) => {
      const c: Call = {
        method: init?.method ?? "GET",
        url,
        body: typeof init?.body === "string" ? (JSON.parse(init.body) as unknown) : undefined,
      };
      calls.push(c);
      const out = handler(c);
      return out instanceof Error ? Promise.reject(out) : Promise.resolve(out);
    }),
  );
  return calls;
}
