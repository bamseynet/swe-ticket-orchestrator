import { App, type Environment } from "aws-cdk-lib";
import { Validations } from "aws-cdk-lib/core";
import { AwsSolutionsChecks } from "cdk-nag";
import { readdirSync } from "node:fs";
import { basename, dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import type { Deployment } from "./config.js";

const LIB_DIR = dirname(fileURLToPath(import.meta.url));
const SUFFIX = "-stack.ts";

// cdk-nag runs through aws-cdk-lib's native validations: any finding interrupts
// app.synth(), so `cdk synth` exits non-zero.
export function applyNag(app: App): void {
  Validations.of(app).addPlugins(new AwsSolutionsChecks(app, { verbose: true }));
}

export interface StackFile {
  name: string; // "control-plane" for control-plane-stack.ts
  path: string;
}

export function discoverStackFiles(dir: string = LIB_DIR): StackFile[] {
  return readdirSync(dir)
    .filter((f) => f.endsWith(SUFFIX))
    .sort()
    .map((f) => ({ name: basename(f, SUFFIX), path: join(dir, f) }));
}

// Stacks receive only `env` (and the name), by design: nothing here is shared between
// them. When a D11 stack needs another stack's values, share them without editing this
// file: write SSM parameters under `/${cfg.name}/<stack>/<key>` in the producer and read
// them with ssm.StringParameter.valueForStringParameter in the consumer, or export a
// typed registry module from the producer's own file. Not built yet.
//
// Each lib/<x>-stack.ts default-exports a Stack class; adding a file adds a
// stack with no edit here, so parallel issues never touch a shared file.
export async function buildApp(cfg: Deployment, env: Environment, dir?: string): Promise<App> {
  const app = new App();
  for (const { name, path } of discoverStackFiles(dir)) {
    const mod = (await import(pathToFileURL(path).href)) as { default?: unknown };
    if (typeof mod.default !== "function") {
      throw new Error(`${name}-stack.ts must default-export a Stack class`);
    }
    const Ctor = mod.default as new (scope: App, id: string, props: { env: Environment }) => unknown;
    new Ctor(app, `${cfg.name}-${name}`, { env });
  }
  applyNag(app);
  return app;
}
