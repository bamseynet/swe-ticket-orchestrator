import type { ComponentType } from "react";

export type Params = Record<string, string>;

export interface PageRoute {
  /** e.g. `/`, `/runs`, `/run/:id` */
  path: string;
  Component: ComponentType<{ params: Params }>;
}

type PageModules = Record<string, { default: ComponentType<{ params: Params }> }>;

function compare(a: string, b: string): number {
  // ":param" sorts after static segments, so `/run/new` wins over `/run/:id`.
  const [x, y] = [a.replaceAll(":", "~"), b.replaceAll(":", "~")];
  return x < y ? -1 : x > y ? 1 : 0;
}

/**
 * Turn glob results (`./pages/<folders>/index.tsx`) into routes. The folder path is the
 * route, so nothing central lists pages:
 * - `pages/runs` is `/runs`
 * - `pages/home` (top level only) is `/`
 * - a `[name]` folder is a path parameter: `pages/run/[id]` is `/run/:id`
 */
export function routesFromModules(modules: PageModules): PageRoute[] {
  const routes: PageRoute[] = [];
  for (const [file, mod] of Object.entries(modules)) {
    const folder = /\/pages\/(.+)\/index\.tsx$/.exec(file)?.[1];
    if (folder === undefined) continue;
    const path =
      folder === "home" ? "/" : "/" + folder.replace(/\[(\w+)\]/g, (_, name: string) => `:${name}`);
    routes.push({ path, Component: mod.default });
  }
  return routes.sort((a, b) => compare(a.path, b.path));
}

export interface Match {
  route: PageRoute;
  params: Params;
}

export function findRoute(routes: PageRoute[], pathname: string): Match | undefined {
  const clean = pathname.length > 1 ? pathname.replace(/\/+$/, "") : pathname;
  const parts = clean.split("/");
  for (const route of routes) {
    const want = route.path.split("/");
    if (want.length !== parts.length) continue;
    const params: Params = {};
    const ok = want.every((seg, i) => {
      const got = parts[i] ?? "";
      if (!seg.startsWith(":")) return seg === got;
      if (got === "") return false;
      params[seg.slice(1)] = decodeURIComponent(got);
      return true;
    });
    if (ok) return { route, params };
  }
  return undefined;
}
