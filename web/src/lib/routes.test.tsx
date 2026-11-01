import { describe, expect, it } from "vitest";
import { findRoute, routesFromModules } from "./routes";

const Page = () => null;

describe("routesFromModules", () => {
  it("routes a page folder with no central edit", () => {
    const routes = routesFromModules({
      "../pages/home/index.tsx": { default: Page },
      "../pages/runs/index.tsx": { default: Page },
    });
    expect(routes.map((r) => r.path)).toEqual(["/", "/runs"]);
  });

  it("ignores files that are not a page entry", () => {
    expect(routesFromModules({ "../pages/runs/helper.tsx": { default: Page } })).toEqual([]);
  });

  it("finds routes, tolerating a trailing slash", () => {
    const routes = routesFromModules({ "../pages/runs/index.tsx": { default: Page } });
    expect(findRoute(routes, "/runs/")?.path).toBe("/runs");
    expect(findRoute(routes, "/nope")).toBeUndefined();
  });
});
