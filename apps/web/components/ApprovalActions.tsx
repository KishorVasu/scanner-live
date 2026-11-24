"use client";

import { Button } from "primereact/button";
import { useCan, useMe } from "@/lib/me";

export type Approval = { id: string; action: string; scope: Record<string, unknown>; reason: string; risks: string;
  status: string; requested_by: string; approver_id: string | null; expires_at: string };

export function ApprovalActions({ a, onDecide }: { a: Approval; onDecide: (a: Approval, approve: boolean) => void }) {
  const me = useMe();
  const canDecide = useCan("approvals:decide");
  if (a.status !== "pending" || !canDecide) return null;
  // The API refuses self-approval regardless; the disabled button only explains it up front.
  const own = me?.id === a.requested_by;
  const why = own ? "You requested this; another approver must decide" : undefined;
  return (
    <span title={why}>
      <Button label="Approve" size="small" disabled={own} onClick={() => onDecide(a, true)} aria-describedby={own ? `own-${a.id}` : undefined} />{" "}
      <Button label="Reject" size="small" severity="secondary" disabled={own} onClick={() => onDecide(a, false)} />
      {own && <span id={`own-${a.id}`} className="sr-only">{why}</span>}
    </span>
  );
}
