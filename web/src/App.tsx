import { useEffect, useState } from "react";
import { findRoute, routesFromModules, type Params } from "./lib/routes";

// Discovered at build time: adding src/pages/**/index.tsx adds a route with no other edit.
const routes = routesFromModules(
  import.meta.glob<{ default: React.ComponentType<{ params: Params }> }>("./pages/**/index.tsx", {
    eager: true,
  }),
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
  const match = findRoute(routes, pathname);
  if (!match) {
    return (
      <main>
        <h1>Not found</h1>
      </main>
    );
  }
  return <match.route.Component params={match.params} />;
}
