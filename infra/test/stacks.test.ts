import { App, Stack } from "aws-cdk-lib";
import { Bucket } from "aws-cdk-lib/aws-s3";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { applyNag, buildApp, discoverStackFiles } from "../lib/app.js";

const cfg = { name: "sto", region: "eu-west-1", profile: "dev" as const };
const env = { account: "000000000000", region: "eu-west-1" };

describe("app", () => {
  it("defines the stacks the D11 issues declare, empty, from lib/*-stack.ts", async () => {
    const app = await buildApp(cfg, env);
    const assembly = app.synth();
    expect(assembly.stacks.map((s) => s.id).sort()).toEqual(
      [
        "agent-plane",
        "control-plane",
        "foundation",
        "identity",
        "observability",
        "sandbox",
        "web",
      ].map((n) => `sto-${n}`),
    );
    for (const s of assembly.stacks) {
      expect(Object.keys(s.template.Resources ?? {})).toEqual([]);
    }
  });

  it("synthesizes with no missing context (so no lookup could be needed)", async () => {
    const assembly = (await buildApp(cfg, env)).synth();
    expect(assembly.manifest.missing ?? []).toEqual([]);
  });

  it("picks up a new *-stack.ts with no central edit", async () => {
    const dir = mkdtempSync(join(tmpdir(), "stacks-"));
    writeFileSync(
      join(dir, "extra-stack.ts"),
      `import { Stack } from "aws-cdk-lib";
export default class ExtraStack extends Stack {}
`,
    );
    writeFileSync(join(dir, "helper.ts"), "export const x = 1;\n"); // not a stack file
    expect(discoverStackFiles(dir).map((f) => f.name)).toEqual(["extra"]);
    const app = await buildApp(cfg, env, dir);
    expect(app.synth().stacks.map((s) => s.id)).toEqual(["sto-extra"]);
  });

  it("rejects a stack file without a default Stack export", async () => {
    const dir = mkdtempSync(join(tmpdir(), "stacks-"));
    writeFileSync(join(dir, "bad-stack.ts"), "export const x = 1;\n");
    await expect(buildApp(cfg, env, dir)).rejects.toThrow(/bad-stack/);
  });
});

describe("cdk-nag", () => {
  it("a nag error makes app.synth() throw (this is what fails the synth job)", () => {
    const app = new App();
    new Bucket(new Stack(app, "Bad", { env }), "Open"); // no SSL enforcement, no access logs
    applyNag(app);
    expect(() => app.synth()).toThrow(/AwsSolutions-S10/);
  });

  it("passes a compliant app", () => {
    const app = new App();
    new Stack(app, "Empty", { env });
    applyNag(app);
    expect(() => app.synth()).not.toThrow();
  });
});
