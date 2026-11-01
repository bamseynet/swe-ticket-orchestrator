import type { ReactNode } from "react";

/** The pages of the run UI: the local build only simulates its writes, and says so. */
export function Layout({ title, children }: { title: string; children: ReactNode }) {
  return (
    <main>
      <p data-testid="simulated-banner" role="note">
        Local demo: writes to GitHub and other systems are <strong>simulated</strong>.
      </p>
      <nav>
        <a href="/runs">Runs</a>
      </nav>
      <h1>{title}</h1>
      {children}
    </main>
  );
}

export function message(e: unknown): string {
  return e instanceof Error ? e.message : "something went wrong";
}

export const FINISHED = new Set(["DONE", "CANCELLED", "REJECTED", "CLOSED", "EXPIRED"]);
