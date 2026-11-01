import { App, Stack } from "aws-cdk-lib";
import { Annotations, Match, Template } from "aws-cdk-lib/assertions";
import { Bucket } from "aws-cdk-lib/aws-s3";
import { describe, expect, it } from "vitest";
import { buildApp, applyNag } from "../lib/app.js";
import { STACK_NAMES } from "../lib/stacks.js";

const cfg = { name: "sto", region: "eu-west-1", profile: "dev" as const };
const env = { account: "111111111111", region: "eu-west-1" };

describe("app", () => {
  it("defines the six stacks from PLAN 16.1, empty", () => {
    const app = buildApp(cfg, env);
    const assembly = app.synth();
    expect(assembly.stacks.map((s) => s.id).sort()).toEqual(
      STACK_NAMES.map((n) => `${cfg.name}-${n}`).sort(),
    );
    for (const s of assembly.stacks) {
      expect(Object.keys(s.template.Resources ?? {})).toEqual([]);
    }
  });

  it("has no cdk-nag errors or warnings on the empty stacks", () => {
    const app = buildApp(cfg, env);
    for (const stack of app.node.children.filter(Stack.isStack)) {
      Annotations.fromStack(stack).hasNoError("*", Match.anyValue());
      Annotations.fromStack(stack).hasNoWarning("*", Match.anyValue());
    }
  });
});

describe("cdk-nag", () => {
  it("reports an error for a non-compliant resource (this is what fails the synth job)", () => {
    const app = new App();
    const stack = new Stack(app, "Bad", { env });
    new Bucket(stack, "Open"); // no SSL enforcement, no access logs
    applyNag(app);
    const errors = Annotations.fromStack(stack).findError("*", Match.stringLikeRegexp("AwsSolutions-S"));
    expect(errors.length).toBeGreaterThan(0);
    expect(Template.fromStack(stack).toJSON()).toBeDefined();
  });
});
