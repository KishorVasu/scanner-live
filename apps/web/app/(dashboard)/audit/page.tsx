"use client";

import { useEffect, useState } from "react";
import { Button } from "primereact/button";
import { Column } from "primereact/column";
import { DataTable } from "primereact/datatable";
import { api, ApiError } from "@/lib/api";
import { useCan } from "@/lib/me";
import { when } from "@/components/Tags";

type Row = { id: string; at: string; actor_type: string; actor_id: string | null; action: string; target_type: string | null;
  target_id: string | null; outcome: string; ip: string | null };
const LIMIT = 50;

/** The audit API pages by time (keyset), so the pager walks a stack of cursors instead of page numbers. */
export default function AuditPage() {
  const canView = useCan("audit:view");
  const [cursors, setCursors] = useState<(string | null)[]>([null]);
  const [rows, setRows] = useState<Row[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const cursor = cursors[cursors.length - 1];

  useEffect(() => {
    if (!canView) return;
    const q = cursor ? `?limit=${LIMIT}&before=${encodeURIComponent(cursor)}` : `?limit=${LIMIT}`;
    api<Row[]>(`/api/audit${q}`).then(setRows).catch((e) => setError(e instanceof ApiError ? e.message : "Load failed"));
  }, [cursor, canView]);

  if (!canView) return <section><h1>Audit Log</h1><p>Your role cannot view the audit log.</p></section>;
  return (
    <section>
      <h1>Audit Log</h1>
      <p>Append-only: the application cannot change or delete these rows.</p>
      {error && <p role="alert">{error}</p>}
      <DataTable value={rows ?? []} dataKey="id" size="small" stripedRows emptyMessage="No entries.">
        <Column header="When" body={(r: Row) => when(r.at)} />
        <Column field="actor_type" header="Actor" />
        <Column header="Actor ID" body={(r: Row) => (r.actor_id ?? "").slice(0, 8)} />
        <Column field="action" header="Action" />
        <Column field="outcome" header="Outcome" />
        <Column header="Target" body={(r: Row) => [r.target_type, (r.target_id ?? "").slice(0, 8)].filter(Boolean).join(" ")} />
        <Column field="ip" header="IP" />
      </DataTable>
      <nav aria-label="Audit log pages" style={{ display: "flex", gap: "0.5rem", justifyContent: "flex-end", marginTop: "0.5rem" }}>
        <Button label="Newer" icon="pi pi-angle-left" text disabled={cursors.length === 1}
          onClick={() => setCursors((c) => c.slice(0, -1))} />
        <span>Page {cursors.length}</span>
        <Button label="Older" icon="pi pi-angle-right" iconPos="right" text disabled={!rows || rows.length < LIMIT}
          onClick={() => rows && setCursors((c) => [...c, rows[rows.length - 1].at])} />
      </nav>
    </section>
  );
}
