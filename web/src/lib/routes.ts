import type { ComponentType } from "react";

export interface PageRoute {
  path: string;
  Component: ComponentType;
}

type PageModules = Record<string, { default: ComponentType }>;

/**
 * Turn glob results (`./pages/<name>/index.tsx`) into routes. A page folder is the
 * route: `pages/runs` is `/runs`, and `pages/home` is `/`. Nothing central lists pages.
 */
export function routesFromModules(modules: PageModules): PageRoute[] {
  const routes: PageRoute[] = [];
  for (const [file, mod] of Object.entries(modules)) {
    const match = /\/pages\/([^/]+)\/index\.tsx$/.exec(file);
    const name = match?.[1];
    if (name === undefined) continue;
    routes.push({ path: name === "home" ? "/" : `/${name}`, Component: mod.default });
  }
  return routes.sort((a, b) => a.path.localeCompare(b.path));
}

export function findRoute(routes: PageRoute[], pathname: string): PageRoute | undefined {
  const clean = pathname.length > 1 ? pathname.replace(/\/+$/, "") : pathname;
  return routes.find((r) => r.path === clean);
}
