import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MeContext, type Me } from "@/lib/me";
import { ApprovalActions, type Approval } from "@/components/ApprovalActions";
import { ScanStateTag } from "@/components/Tags";
import FindingsTable from "@/components/FindingsTable";

vi.mock("next/navigation", () => ({ usePathname: () => "/" }));

const ME: Me = { id: "u1", email: "a@example.test", roles: ["approver"],
  permissions: ["dashboard:view", "approvals:decide", "findings:triage", "findings:accept_risk"] };

function withMe(ui: React.ReactNode, me: Me = ME) {
  return render(<MeContext.Provider value={me}>{ui}</MeContext.Provider>);
}

function mockFetch(handler: (url: string, init?: RequestInit) => unknown) {
  const fn = vi.fn(async (url: string, init?: RequestInit) => ({ ok: true, status: 200, statusText: "OK",
    json: async () => handler(url, init) }));
  vi.stubGlobal("fetch", fn);
  return fn;
}

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

const approval = (requested_by: string): Approval => ({ id: "a1", action: "run_codeql", scope: {}, reason: "r", risks: "",
  status: "pending", requested_by, approver_id: null, expires_at: "2026-11-25T00:00:00Z" });

describe("approvals", () => {
  it("disables approve on your own request and explains why", () => {
    const onDecide = vi.fn();
    withMe(<ApprovalActions a={approval("u1")} onDecide={onDecide} />);
    const btn = screen.getByRole("button", { name: /approve/i });
    expect((btn as HTMLButtonElement).disabled).toBe(true);
    expect(screen.getByText(/another approver must decide/)).toBeTruthy();
  });

  it("lets another approver decide", () => {
    const onDecide = vi.fn();
    withMe(<ApprovalActions a={approval("someone-else")} onDecide={onDecide} />);
    fireEvent.click(screen.getByRole("button", { name: /approve/i }));
    expect(onDecide).toHaveBeenCalledWith(expect.objectContaining({ id: "a1" }), true);
  });

  it("shows nothing to a role that cannot decide", () => {
    const { container } = withMe(<ApprovalActions a={approval("x")} onDecide={vi.fn()} />,
      { ...ME, permissions: ["dashboard:view"] });
    expect(container.textContent).toBe("");
  });
});

describe("not scanned is never 'no findings'", () => {
  it("labels not scanned explicitly", () => {
    render(<ScanStateTag state="not_scanned" />);
    expect(screen.getByText("not scanned")).toBeTruthy();
  });
});

describe("finding triage", () => {
  it("opens the finding and keeps Save disabled until a status is chosen", async () => {
    mockFetch((url, init) => {
      if (url.startsWith("/api/findings?")) {
        return { total: 1, offset: 0, limit: 25, scanned: true, items: [{ id: "f1", project: "P", scanner: "osv_scanner",
          rule_id: "GHSA-x", title: "fixture finding", severity: "high", confidence: "high", status: "open", file_path: null,
          line: null, package: "lodash", package_version: "4.17.20", last_seen_at: "2026-11-24T00:00:00Z" }] };
      }
      if (url === "/api/findings/f1" && init?.method !== "PATCH") {
        return { id: "f1", title: "fixture finding", severity: "high", status: "open", scanner: "osv_scanner", rule_id: "GHSA-x",
          package: "lodash", package_version: "4.17.20", file_path: null, line: null, triage_note: null, advisory_ids: [],
          evidence: [] };
      }
      return { id: "f1", status: "accepted_risk" };
    });
    withMe(<FindingsTable />);
    fireEvent.click(await screen.findByRole("button", { name: /open fixture finding/i }));
    await screen.findByText(/evidence history/i);
    const save = screen.getByRole("button", { name: "Save" }) as HTMLButtonElement;
    expect(save.disabled).toBe(true); // no status chosen yet
    expect(screen.getByLabelText(/^note/i)).toBeTruthy();
  });
});
