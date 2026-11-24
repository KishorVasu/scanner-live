"use client";

import { useCallback, useEffect, useState } from "react";
import { Column } from "primereact/column";
import { DataTable } from "primereact/datatable";
import { api, ApiError } from "@/lib/api";
import { ApprovalActions, type Approval } from "@/components/ApprovalActions";
import { StatusTag, when } from "@/components/Tags";
import TotpDialog from "@/components/TotpDialog";

export default function ApprovalsPage() {
  const [rows, setRows] = useState<Approval[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [deciding, setDeciding] = useState<{ a: Approval; approve: boolean } | null>(null);
  const load = useCallback(() => {
    api<Approval[]>("/api/approvals").then(setRows).catch((e) => setError(e instanceof ApiError ? e.message : "Load failed"));
  }, []);
  useEffect(load, [load]);

  return (
    <section>
      <h1>Approvals</h1>
      <p>Each approval covers one operation with this exact scope and expires. Nobody can approve their own request.</p>
      {error && <p role="alert">{error}</p>}
      {rows && (
        <DataTable value={rows} dataKey="id" size="small" stripedRows paginator paginatorPosition="bottom" rows={25}
          rowsPerPageOptions={[25, 50, 100]} emptyMessage="No approval requests.">
          <Column header="Status" body={(a: Approval) => <StatusTag value={a.status} />} />
          <Column field="action" header="Action" />
          <Column header="Scope" body={(a: Approval) => <code>{JSON.stringify(a.scope)}</code>} />
          <Column field="reason" header="Reason" />
          <Column field="risks" header="Risks" />
          <Column header="Expires" body={(a: Approval) => when(a.expires_at)} />
          <Column header="" body={(a: Approval) => <ApprovalActions a={a} onDecide={(x, approve) => setDeciding({ a: x, approve })} />} />
        </DataTable>
      )}
      {deciding && (
        <TotpDialog title={`${deciding.approve ? "Approve" : "Reject"} ${deciding.a.action}`}
          confirm={(code) => api(`/api/approvals/${deciding.a.id}/decision`, { method: "POST",
            body: { totp_code: code, approve: deciding.approve } })}
          onDone={(ok) => { setDeciding(null); if (ok) load(); }} />
      )}
    </section>
  );
}
