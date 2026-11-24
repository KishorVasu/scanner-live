"use client";

import { useEffect, useState } from "react";
import { Column } from "primereact/column";
import { DataTable, type DataTableStateEvent } from "primereact/datatable";
import { api, ApiError } from "@/lib/api";

export type Finding = {
  id: string;
  project: string;
  scanner: string;
  rule_id: string;
  title: string;
  severity: string;
  confidence: string;
  status: string;
  file_path: string | null;
  line: number | null;
  package: string | null;
  package_version: string | null;
  last_seen_at: string;
};

type Page = { total: number; offset: number; limit: number; scanned: boolean; items: Finding[] };

// ponytail: shows open + in-progress findings only; filter controls come with the triage UI.
const OPEN = "status=open&status=in_progress";

export default function FindingsTable() {
  const [first, setFirst] = useState(0);
  const [rows, setRows] = useState(25);
  const [page, setPage] = useState<Page | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let live = true;
    setLoading(true);
    api<Page>(`/api/findings?${OPEN}&offset=${first}&limit=${rows}`)
      .then((p) => live && (setPage(p), setError(null)))
      .catch((e) => live && setError(e instanceof ApiError ? e.message : "Could not load findings"))
      .finally(() => live && setLoading(false));
    return () => {
      live = false;
    };
  }, [first, rows]);

  if (error) return <p role="alert">{error}</p>;
  if (page && page.total === 0 && !page.scanned) {
    // Rule 11: never let "not scanned" read as "no findings".
    return <p><strong>Not scanned yet.</strong> No scan has completed, so there are no results. This is not the same as &ldquo;no findings&rdquo;.</p>;
  }

  return (
    <DataTable
      value={page?.items ?? []}
      dataKey="id"
      lazy
      loading={loading}
      paginator
      paginatorPosition="bottom"
      first={first}
      rows={rows}
      totalRecords={page?.total ?? 0}
      rowsPerPageOptions={[25, 50, 100]}
      paginatorTemplate="FirstPageLink PrevPageLink PageLinks NextPageLink LastPageLink RowsPerPageDropdown CurrentPageReport"
      currentPageReportTemplate="{first}–{last} of {totalRecords}"
      onPage={(e: DataTableStateEvent) => {
        setFirst(e.first);
        setRows(e.rows);
      }}
      emptyMessage="No open findings in completed scans. Scans can miss things; this does not mean the project is secure."
      size="small"
      stripedRows
    >
      <Column field="severity" header="Severity" />
      <Column field="project" header="Project" />
      <Column field="title" header="Title" />
      <Column header="Where" body={(f: Finding) =>
        f.package ? `${f.package}@${f.package_version ?? "?"}` : `${f.file_path ?? ""}${f.line ? `:${f.line}` : ""}`} />
      <Column field="rule_id" header="Rule" />
      <Column field="scanner" header="Scanner" />
      <Column field="confidence" header="Confidence" />
      <Column field="status" header="Status" />
      <Column header="Last seen" body={(f: Finding) => new Date(f.last_seen_at).toLocaleString()} />
    </DataTable>
  );
}
