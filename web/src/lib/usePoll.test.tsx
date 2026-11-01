import { act, cleanup, render } from "@testing-library/react";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { usePoll } from "./usePoll";

function Probe({ tick, enabled }: { tick: () => Promise<void>; enabled?: boolean }) {
  usePoll(tick, 1000, enabled);
  return null;
}
const advance = (ms: number) => act(async () => { await vi.advanceTimersByTimeAsync(ms); });

beforeEach(() => {
  vi.useFakeTimers();
});
afterEach(() => {
  cleanup();
  vi.useRealTimers();
});

it("carries on after a tick that throws", async () => {
  const tick = vi.fn(() => Promise.reject(new Error("boom")));
  render(<Probe tick={tick} />);
  await advance(3500);
  expect(tick.mock.calls.length).toBeGreaterThanOrEqual(3);
});

it("does not overlap ticks: the next waits for the last", async () => {
  let running = 0;
  let worst = 0;
  const tick = () => {
    running += 1;
    worst = Math.max(worst, running);
    return new Promise<void>((r) => setTimeout(() => { running -= 1; r(); }, 2500));
  };
  render(<Probe tick={tick} />);
  await advance(10000);
  expect(worst).toBe(1);
});

it("stops on unmount and when disabled", async () => {
  const tick = vi.fn(() => Promise.resolve());
  const { unmount, rerender } = render(<Probe tick={tick} />);
  await advance(1500);
  rerender(<Probe tick={tick} enabled={false} />);
  const n = tick.mock.calls.length;
  await advance(5000);
  expect(tick.mock.calls.length).toBe(n);
  unmount();
});
