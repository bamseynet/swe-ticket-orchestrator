import { loadDeployment } from "../lib/config.js";
import { buildApp } from "../lib/app.js";

// No credentials or lookups: the account is a fixed dummy unless the caller
// (a real deploy) provides CDK_DEFAULT_ACCOUNT.
const cfg = loadDeployment(process.env.STO_DEPLOYMENT ?? "deployment.yaml");
buildApp(cfg, {
  account: process.env.CDK_DEFAULT_ACCOUNT ?? "000000000000",
  region: cfg.region,
}).synth();
