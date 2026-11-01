import { render, screen } from "@testing-library/react";
import { expect, it } from "vitest";
import { App } from "./App";

it("discovers the placeholder page from src/pages without a router file", () => {
  render(<App />);
  expect(screen.getByRole("heading", { name: "SWE Ticket Orchestrator" })).toBeTruthy();
});
