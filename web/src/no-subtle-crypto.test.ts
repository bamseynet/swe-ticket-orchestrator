import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { expect, it } from "vitest";

// H4: LAN mode is plain HTTP, where `crypto.subtle` is undefined. No client code may use it.
function sources(dir: string): string[] {
  return readdirSync(dir).flatMap((name) => {
    const p = join(dir, name);
    if (statSync(p).isDirectory()) return sources(p);
    return /\.(ts|tsx)$/.test(name) && !name.endsWith("no-subtle-crypto.test.ts") ? [p] : [];
  });
}

it("no source file depends on crypto.subtle", () => {
  const offenders = sources("src").filter((f) => /\bsubtle\b/.test(readFileSync(f, "utf8")));
  expect(offenders).toEqual([]);
});
