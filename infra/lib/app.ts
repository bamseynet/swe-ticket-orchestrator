import { App, Aspects, type Environment } from "aws-cdk-lib";
import { AwsSolutionsChecks } from "cdk-nag";
import type { Deployment } from "./config.js";
import { EmptyStack, STACK_NAMES } from "./stacks.js";

// cdk-nag findings are error annotations, so `cdk synth` exits non-zero on any.
export function applyNag(app: App): void {
  Aspects.of(app).add(new AwsSolutionsChecks({ verbose: true }));
}

export function buildApp(cfg: Deployment, env: Environment): App {
  const app = new App();
  for (const name of STACK_NAMES) {
    new EmptyStack(app, `${cfg.name}-${name}`, { env });
  }
  applyNag(app);
  return app;
}
