import { useEffect, useRef } from "react";

/** Call `tick` now and then every `ms`, one at a time, until unmount or `enabled` is false. A
 * failing tick is the caller's to report; polling carries on, because the runtime retries a
 * failing run after a cool-down of up to about 30 seconds. */
export function usePoll(tick: () => Promise<void>, ms = 2000, enabled = true): void {
  const latest = useRef(tick);
  latest.current = tick;
  useEffect(() => {
    if (!enabled) return;
    let stopped = false;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const loop = async () => {
      try {
        await latest.current();
      } catch {
        // reported by the tick itself
      }
      if (!stopped) timer = setTimeout(() => void loop(), ms);
    };
    void loop();
    return () => {
      stopped = true;
      clearTimeout(timer);
    };
  }, [ms, enabled]);
}
