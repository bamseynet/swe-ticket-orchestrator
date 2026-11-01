import { buildApp } from "../lib/app.js";
import { loadDeployment } from "../lib/config.js";

// The CDK CLI fills CDK_DEFAULT_ACCOUNT from whatever host credentials resolve,
// which could bind a real account into a synth. So it is ignored: the account is
// an explicit STO_ACCOUNT, defaulting to a dummy. Deploys pass it deliberately.
const cfg = loadDeployment(process.env.STO_DEPLOYMENT ?? "deployment.yaml");
const app = await buildApp(cfg, {
  account: process.env.STO_ACCOUNT ?? "000000000000",
  region: cfg.region,
});
app.synth();
