"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import { Column } from "primereact/column";
import { DataTable } from "primereact/datatable";
import { api, ApiError } from "@/lib/api";
import { ScanStateTag, SeverityTag } from "@/components/Tags";

type Row = {
  project_id: string; project: string; criticality: string; repositories: number; scanned_repositories: number;
  scan_state: "not_scanned" | "partial" | "scanned"; open_findings: Record<string, number>;
  affected_advisories: number; known_exploited: number;
};

const ORDER = ["critical", "high", "medium", "low", "informational"];

export default function OverviewPage() {
  const [rows, setRows] = useState<Row[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    api<{ projects: Row[] }>("/api/overview").then((r) => setRows(r.projects))
      .catch((e) => setError(e instanceof ApiError ? e.message : "Could not load the overview"));
  }, []);

  return (
    <section>
      <h1>Overview</h1>
      <p>What the scanners and advisory matching found per project. &ldquo;Not scanned&rdquo; means nothing was examined;
        it is never the same as &ldquo;no findings&rdquo;, and no row here means a project is secure.</p>
      {error && <p role="alert">{error}</p>}
      {rows && rows.length === 0 && <p>No projects are registered yet, so nothing has been scanned.</p>}
      {rows && rows.length > 0 && (
        <DataTable value={rows} dataKey="project_id" paginator paginatorPosition="bottom" rows={25}
          size="small" stripedRows sortField="known_exploited" sortOrder={-1}>
          <Column header="Project" body={(r: Row) => <Link href={`/projects/${r.project_id}`}>{r.project}</Link>} sortable sortField="project" />
          <Column field="criticality" header="Criticality" sortable />
          <Column header="Scan coverage" body={(r: Row) => (
            <span><ScanStateTag state={r.scan_state} /> {r.scanned_repositories}/{r.repositories} repositories</span>)} />
          <Column header="Open findings" body={(r: Row) => r.scan_state === "not_scanned" ? "—"
            : Object.keys(r.open_findings).length === 0 ? "none open from scans"
            : ORDER.filter((s) => r.open_findings[s]).map((s) => (
              <span key={s} style={{ marginRight: "0.4rem" }}><SeverityTag value={s} /> {r.open_findings[s]}</span>))} />
          <Column field="affected_advisories" header="Affected advisories" sortable />
          <Column field="known_exploited" header="Known exploited" sortable />
        </DataTable>
      )}
    </section>
  );
}
