import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { render } from "@testing-library/react";
import { expect, it, vi } from "vitest";
import { App } from "./App";

// H4: LAN mode is plain HTTP, where `crypto.subtle` is undefined. No client code may use it.
// Resolved from this file, not the cwd, so it scans web/src from any working directory.
const SRC = import.meta.dirname;

function sources(dir: string): string[] {
  return readdirSync(dir, { withFileTypes: true }).flatMap((e) => {
    const p = join(dir, e.name);
    if (e.isDirectory()) return sources(p);
    return /\.(ts|tsx|js|jsx|mjs|cjs)$/.test(e.name) && p !== import.meta.filename ? [p] : [];
  });
}

it("scans real web sources", () => {
  expect(sources(SRC).length).toBeGreaterThan(3);
});

it("no source file depends on crypto.subtle", () => {
  const offenders = sources(SRC).filter((f) => /\bsubtle\b/.test(readFileSync(f, "utf8")));
  expect(offenders).toEqual([]);
});

it("renders <App/> when crypto.subtle is absent (plain-HTTP LAN)", () => {
  vi.stubGlobal("crypto", { randomUUID: () => "x" });
  try {
    expect(() => render(<App />)).not.toThrow();
  } finally {
    vi.unstubAllGlobals();
  }
});
