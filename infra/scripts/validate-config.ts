import { loadDeployment } from "../lib/config.js";

const path = process.env.STO_DEPLOYMENT ?? "deployment.yaml";
try {
  loadDeployment(path);
  console.log(`${path}: ok`);
} catch (e) {
  console.error(`${path}: invalid\n${e instanceof Error ? e.message : String(e)}`);
  process.exit(1);
}
