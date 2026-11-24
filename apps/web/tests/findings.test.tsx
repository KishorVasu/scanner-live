import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import FindingsTable, { type Finding } from "@/components/FindingsTable";

function row(i: number): Finding {
  return {
    id: `f${i}`, project: "Fixture", scanner: "osv_scanner", rule_id: `GHSA-fixt-${i}`, title: `fixture ${i}`,
    severity: "high", confidence: "high", status: "open", file_path: null, line: null, package: `pkg${i}`,
    package_version: "1.0.0", last_seen_at: "2026-11-24T10:00:00+00:00",
  };
}

function page(offset: number, limit: number, total: number, scanned = true) {
  const items = Array.from({ length: Math.max(0, Math.min(limit, total - offset)) }, (_, k) => row(offset + k));
  return { total, offset, limit, scanned, items };
}

function mockApi(total: number, scanned = true) {
  const fn = vi.fn(async (url: string) => {
    const q = new URL(url, "http://x").searchParams;
    const body = page(Number(q.get("offset")), Number(q.get("limit")), total, scanned);
    return { ok: true, status: 200, statusText: "OK", json: async () => body };
  });
  vi.stubGlobal("fetch", fn);
  return fn;
}

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

describe("FindingsTable", () => {
  it("shows a bottom paginator and loads the next page from the API", async () => {
    const fetchMock = mockApi(60);
    const { container } = render(<FindingsTable />);
    expect(await screen.findByText("fixture 0")).toBeTruthy();
    const paginator = container.querySelector(".p-paginator-bottom");
    expect(paginator).toBeTruthy();
    expect(paginator?.textContent).toContain("1–25 of 60");
    fireEvent.click(container.querySelector(".p-paginator-next") as Element);
    expect(await screen.findByText("fixture 25")).toBeTruthy();
    const last = new URL(fetchMock.mock.calls.at(-1)![0], "http://x").searchParams;
    expect([last.get("offset"), last.get("limit")]).toEqual(["25", "25"]);
    expect(last.getAll("status")).toEqual(["open", "in_progress"]);
  });

  it("says 'not scanned' instead of 'no findings' when nothing was scanned", async () => {
    mockApi(0, false);
    render(<FindingsTable />);
    expect(await screen.findByText(/Not scanned yet/)).toBeTruthy();
  });

  it("never calls an empty scanned result secure", async () => {
    mockApi(0, true);
    render(<FindingsTable />);
    await waitFor(() => expect(screen.getByText(/does not mean the project is secure/)).toBeTruthy());
  });
});
