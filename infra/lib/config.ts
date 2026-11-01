import { readFileSync } from "node:fs";
import { parse } from "yaml";
import { z } from "zod";

// Typed deployment.yaml (PLAN 16.1). Strict: unknown keys fail, and there is
// deliberately no account field, so no account ID can be committed.
export const DeploymentSchema = z
  .object({
    name: z.string().regex(/^[a-z][a-z0-9-]{1,19}$/, "lowercase letters, digits, hyphens"),
    region: z.string().regex(/^[a-z]{2}(-[a-z]+)+-\d$/, "an AWS Region such as eu-west-1"),
    profile: z.enum(["dev", "staging", "prod"]),
  })
  .strict();

export type Deployment = z.infer<typeof DeploymentSchema>;

export function parseDeployment(text: string): Deployment {
  return DeploymentSchema.parse(parse(text));
}

export function loadDeployment(path: string): Deployment {
  return parseDeployment(readFileSync(path, "utf8"));
}
