import { describe, expect, it } from "vitest";
import { findRoute, routesFromModules } from "./routes";

const Page = () => null;
const mod = { default: Page };

describe("routesFromModules", () => {
  it("routes a page folder with no central edit", () => {
    const routes = routesFromModules({
      "./pages/home/index.tsx": mod,
      "./pages/runs/index.tsx": mod,
    });
    expect(routes.map((r) => r.path)).toEqual(["/", "/runs"]);
  });

  it("maps only the top-level home folder to /", () => {
    const routes = routesFromModules({ "./pages/a/home/index.tsx": mod });
    expect(routes.map((r) => r.path)).toEqual(["/a/home"]);
  });

  it("ignores files that are not a page entry", () => {
    expect(routesFromModules({ "./pages/runs/helper.tsx": mod })).toEqual([]);
  });

  it("turns a [id] folder into a path parameter", () => {
    const routes = routesFromModules({ "./pages/run/[id]/index.tsx": mod });
    expect(routes.map((r) => r.path)).toEqual(["/run/:id"]);
  });

  it("finds routes, tolerating a trailing slash", () => {
    const routes = routesFromModules({ "./pages/runs/index.tsx": mod });
    expect(findRoute(routes, "/runs/")?.route.path).toBe("/runs");
    expect(findRoute(routes, "/nope")).toBeUndefined();
  });

  it("extracts and decodes parameters, preferring static routes", () => {
    const routes = routesFromModules({
      "./pages/run/[id]/index.tsx": mod,
      "./pages/run/new/index.tsx": mod,
    });
    expect(findRoute(routes, "/run/a%20b")?.params).toEqual({ id: "a b" });
    expect(findRoute(routes, "/run/new")?.route.path).toBe("/run/new");
    expect(findRoute(routes, "/run")).toBeUndefined();
  });
});
