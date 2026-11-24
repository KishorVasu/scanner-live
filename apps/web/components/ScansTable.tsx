"use client";

import { Column } from "primereact/column";
import { DataTable } from "primereact/datatable";
import { pagedProps, usePaged } from "@/lib/usePaged";
import { StatusTag, when } from "@/components/Tags";

type Scan = { id: string; project: string; component: string; scanner: string; trigger: string; status: string;
  error: string | null; created_at: string; finished_at: string | null };

export default function ScansTable({ projectId }: { projectId?: string }) {
  const p = usePaged<Scan>("/api/scans", projectId ? `project_id=${projectId}` : "");
  if (p.error) return <p role="alert">{p.error}</p>;
  return (
    <DataTable value={p.page?.items ?? []} dataKey="id" {...pagedProps(p)} emptyMessage="No scans have run.">
      <Column header="Queued" body={(s: Scan) => when(s.created_at)} />
      <Column field="project" header="Project" />
      <Column field="component" header="Component" />
      <Column field="scanner" header="Scanner" />
      <Column field="trigger" header="Trigger" />
      <Column header="Status" body={(s: Scan) => <StatusTag value={s.status} />} />
      <Column header="Finished" body={(s: Scan) => when(s.finished_at)} />
      <Column header="Error" body={(s: Scan) => s.error ?? ""} />
    </DataTable>
  );
}
