import { describe, expect, it } from "vitest";
import { parseDeployment, resolveAccount } from "../lib/config.js";

describe("deployment.yaml schema", () => {
  it("accepts a valid config", () => {
    const cfg = parseDeployment("name: sto\nregion: eu-west-1\nprofile: dev\n");
    expect(cfg.profile).toBe("dev");
  });

  it("rejects a missing field", () => {
    expect(() => parseDeployment("name: sto\nregion: eu-west-1\n")).toThrow(/profile/);
  });

  it("rejects unknown keys (typos must not pass silently)", () => {
    expect(() => parseDeployment("name: sto\nregion: eu-west-1\nprofile: dev\nregon: x\n")).toThrow();
  });

  it("rejects an account id in the file", () => {
    expect(() =>
      parseDeployment("name: sto\nregion: eu-west-1\nprofile: dev\naccount: '123456789012'\n"),
    ).toThrow();
  });

  it("rejects a bad profile", () => {
    expect(() => parseDeployment("name: sto\nregion: eu-west-1\nprofile: qa\n")).toThrow(/profile/);
  });
});

describe("STO_ACCOUNT", () => {
  it("defaults to the dummy account", () => {
    expect(resolveAccount(undefined)).toBe("000000000000");
  });
  it("accepts 12 digits", () => {
    expect(resolveAccount("123456789012")).toBe("123456789012");
  });
  it.each(["", "1234", "12345678901a", "1234567890123"])("rejects %j loudly", (v) => {
    expect(() => resolveAccount(v)).toThrow(/STO_ACCOUNT/);
  });
});
