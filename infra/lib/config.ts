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

const DUMMY_ACCOUNT = "000000000000";

// The account is never in deployment.yaml. STO_ACCOUNT must be exactly 12 digits;
// an unset variable means the dummy, anything else malformed fails loudly.
export function resolveAccount(value: string | undefined): string {
  if (value === undefined) return DUMMY_ACCOUNT;
  if (!/^\d{12}$/.test(value)) {
    throw new Error(`STO_ACCOUNT must be a 12-digit AWS account ID, got ${JSON.stringify(value)}`);
  }
  return value;
}
