import { useEffect, useState } from "react";
import { findRoute, routesFromModules } from "./lib/routes";

// Discovered at build time: adding src/pages/<name>/index.tsx adds a route with no other edit.
const routes = routesFromModules(
  import.meta.glob<{ default: React.ComponentType }>("./pages/*/index.tsx", { eager: true }),
);

export function App() {
  const [pathname, setPathname] = useState(window.location.pathname);
  useEffect(() => {
    const onPop = () => {
      setPathname(window.location.pathname);
    };
    window.addEventListener("popstate", onPop);
    return () => {
      window.removeEventListener("popstate", onPop);
    };
  }, []);
  const route = findRoute(routes, pathname);
  if (!route) return <main><h1>Not found</h1></main>;
  return <route.Component />;
}
