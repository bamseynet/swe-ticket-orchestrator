import { Stack, type StackProps } from "aws-cdk-lib";
import type { Construct } from "constructs";

// PLAN 16.1. Empty for now; later issues add resources to their own stack file.
export const STACK_NAMES = [
  "Foundation",
  "Identity",
  "ControlPlane",
  "AgentPlane",
  "Web",
  "Observability",
] as const;

export class EmptyStack extends Stack {
  constructor(scope: Construct, id: string, props?: StackProps) {
    super(scope, id, props);
  }
}
