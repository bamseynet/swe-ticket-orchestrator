import { Stack, type StackProps } from "aws-cdk-lib";
import type { Construct } from "constructs";

export default class AgentPlaneStack extends Stack {
  constructor(scope: Construct, id: string, props?: StackProps) {
    super(scope, id, props);
  }
}
