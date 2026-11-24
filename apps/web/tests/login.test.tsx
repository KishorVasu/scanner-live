import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import LoginForm from "@/components/LoginForm";
import { api } from "@/lib/api";

function mockFetch(responses: Array<{ status?: number; body: unknown }>) {
  const fn = vi.fn();
  for (const r of responses) {
    fn.mockResolvedValueOnce({ ok: (r.status ?? 200) < 400, status: r.status ?? 200, statusText: "x", json: async () => r.body });
  }
  vi.stubGlobal("fetch", fn);
  return fn;
}

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
  document.cookie = "sp_csrf=; expires=Thu, 01 Jan 1970 00:00:00 GMT";
});

function fill(label: string, value: string) {
  fireEvent.change(screen.getByLabelText(label), { target: { value } });
}

describe("api client", () => {
  it("sends the CSRF header only on unsafe methods", async () => {
    document.cookie = "sp_csrf=abc123";
    const fetchMock = mockFetch([{ body: {} }, { body: {} }]);
    await api("/api/auth/me");
    await api("/api/auth/logout", { method: "POST" });
    expect(fetchMock.mock.calls[0][1].headers["X-CSRF-Token"]).toBeUndefined();
    expect(fetchMock.mock.calls[1][1].headers["X-CSRF-Token"]).toBe("abc123");
    expect(fetchMock.mock.calls[1][1].credentials).toBe("same-origin");
  });
});

describe("LoginForm", () => {
  it("signs in with password and TOTP", async () => {
    const fetchMock = mockFetch([{ body: { status: "ok" } }]);
    const onDone = vi.fn();
    render(<LoginForm onDone={onDone} />);
    fill("Email", "a@example.test");
    fill("Password", "long-enough-pass");
    fill("Authenticator code", "123456");
    fireEvent.click(screen.getByRole("button", { name: /sign in/i }));
    await waitFor(() => expect(onDone).toHaveBeenCalled());
    expect(JSON.parse(fetchMock.mock.calls[0][1].body)).toEqual({
      email: "a@example.test", password: "long-enough-pass", totp_code: "123456",
    });
  });

  it("walks a first login through TOTP enrolment", async () => {
    mockFetch([
      { body: { status: "totp_setup_required" } },
      { body: { otpauth_uri: "otpauth://totp/test" } },
      { body: { status: "ok" } },
    ]);
    const onDone = vi.fn();
    render(<LoginForm onDone={onDone} />);
    fill("Email", "a@example.test");
    fill("Password", "long-enough-pass");
    fireEvent.click(screen.getByRole("button", { name: /sign in/i }));
    expect(await screen.findByTestId("otpauth-uri")).toHaveProperty("textContent", "otpauth://totp/test");
    fill("Authenticator code", "654321");
    fireEvent.click(screen.getByRole("button", { name: /confirm/i }));
    await waitFor(() => expect(onDone).toHaveBeenCalled());
  });

  it("shows the API error", async () => {
    mockFetch([{ status: 401, body: { detail: "invalid credentials" } }]);
    render(<LoginForm onDone={() => undefined} />);
    fill("Email", "a@example.test");
    fill("Password", "x");
    fireEvent.click(screen.getByRole("button", { name: /sign in/i }));
    expect(await screen.findByText("invalid credentials")).toBeTruthy();
  });
});
