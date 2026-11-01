import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import Gate from "./[run]/[name]/[round]/index";

const open = {
  id: "g1", name: "review_gate", round: 1, type: "review", status: "OPEN",
  closed_by: null, subject_digest: "digest-1", head_sha: "abc",
};
const closed = { ...open, status: "APPROVED", closed_by: "alice" };

type Call = { url: string; body: unknown };
function server(gates: unknown[], decision?: Response): Call[] {
  const calls: Call[] = [];
  vi.stubGlobal(
    "fetch",
    vi.fn((url: string, init?: RequestInit) => {
      if (init?.method === "POST") {
        calls.push({ url, body: JSON.parse(init.body as string) });
        return Promise.resolve(decision ?? new Response("{}", { status: 202 }));
      }
      return Promise.resolve(new Response(JSON.stringify({ gates }), { status: 200 }));
    }),
  );
  return calls;
}
const params = { run: "R1", name: "review_gate", round: "1" };
afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

it("approves with the subject seen and no comment", async () => {
  const calls = server([open]);
  render(<Gate params={params} />);
  fireEvent.click(await screen.findByRole("button", { name: "Approve" }));
  await waitFor(() => { expect(calls).toHaveLength(1); });
  expect(calls[0]).toEqual({
    url: "/api/runs/R1/gates/review_gate/1/decisions",
    body: { kind: "approve", subject_digest: "digest-1", comment: "" },
  });
});

it.each(["Request changes", "Reject"])(
  "%s without a comment is refused and sends nothing",
  async (label) => {
    const calls = server([open]);
    render(<Gate params={params} />);
    fireEvent.click(await screen.findByRole("button", { name: label }));
    expect((await screen.findByRole("alert")).textContent).toMatch(/comment is required/i);
    expect(calls).toHaveLength(0);
  },
);

it("a blank (whitespace) comment is still refused", async () => {
  const calls = server([open]);
  render(<Gate params={params} />);
  fireEvent.change(await screen.findByLabelText("Comment"), { target: { value: "   " } });
  fireEvent.click(screen.getByRole("button", { name: "Reject" }));
  await screen.findByRole("alert");
  expect(calls).toHaveLength(0);
});

it.each([["Request changes", "request_changes"], ["Reject", "reject"]])(
  "%s with a comment sends the kind and the comment",
  async (label, kind) => {
    const calls = server([open]);
    render(<Gate params={params} />);
    fireEvent.change(await screen.findByLabelText("Comment"), { target: { value: "nope" } });
    fireEvent.click(screen.getByRole("button", { name: label }));
    await waitFor(() => { expect(calls).toHaveLength(1); });
    expect(calls[0]?.body).toMatchObject({ kind, comment: "nope" });
  },
);

it("a closed gate shows who closed it and offers no decision", async () => {
  server([closed]);
  render(<Gate params={params} />);
  expect((await screen.findByTestId("closed-by")).textContent).toContain("alice");
  expect(screen.queryByRole("button", { name: "Approve" })).toBeNull();
});

it("a 409 gate_closed from a race shows who closed it", async () => {
  server(
    [open],
    new Response(
      JSON.stringify({ error: { code: "gate_closed", message: "m", closed_by: "bob", status: "REJECTED" } }),
      { status: 409 },
    ),
  );
  render(<Gate params={params} />);
  fireEvent.click(await screen.findByRole("button", { name: "Approve" }));
  expect((await screen.findByRole("alert")).textContent).toContain("bob");
});

it("renders the server's error message as text, never as markup", async () => {
  server(
    [open],
    new Response(JSON.stringify({ error: { code: "x", message: "<img src=x id=pwn>" } }), { status: 422 }),
  );
  const { container } = render(<Gate params={params} />);
  fireEvent.click(await screen.findByRole("button", { name: "Approve" }));
  await screen.findByRole("alert");
  expect(container.querySelector("#pwn")).toBeNull();
});

it("says so when there is no such gate", async () => {
  server([]);
  render(<Gate params={params} />);
  expect((await screen.findByRole("alert")).textContent).toMatch(/no gate/i);
});
