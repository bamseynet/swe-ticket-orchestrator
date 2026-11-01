import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, expect, it } from "vitest";
import Home from "./index";

afterEach(cleanup);

it("links to the runs page, so the landing page leads into the demo", () => {
  render(<Home />);
  const link = screen.getByRole("link", { name: /runs/i });
  expect(link.getAttribute("href")).toBe("/runs");
});

it("states that nothing here is deployed", () => {
  render(<Home />);
  expect(screen.getByText(/never deployed/i)).toBeTruthy();
});
