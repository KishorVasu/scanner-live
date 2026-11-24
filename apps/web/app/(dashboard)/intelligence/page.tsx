"use client";

import { useEffect, useState } from "react";
import { Column } from "primereact/column";
import { DataTable } from "primereact/datatable";
import { api, ApiError } from "@/lib/api";
import ImpactsTable from "@/components/ImpactsTable";

type Cell = { project_id: string; project: string; counts: Record<string, number> };
const COLS = ["confirmed_affected", "potentially_affected", "needs_verification", "not_affected_on_evidence", "not_scanned"];

export default function IntelligencePage() {
  const [grid, setGrid] = useState<Cell[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    api<Cell[]>("/api/impacts/matrix").then(setGrid).catch((e) => setError(e instanceof ApiError ? e.message : "Load failed"));
  }, []);
  return (
    <section>
      <h1>Security Intelligence</h1>
      <h2>Impact matrix</h2>
      {error && <p role="alert">{error}</p>}
      {grid && (
        <DataTable value={grid} dataKey="project_id" size="small" stripedRows paginator paginatorPosition="bottom" rows={25}
          emptyMessage="No advisory has been matched against an inventory yet.">
          <Column field="project" header="Project" />
          {COLS.map((c) => <Column key={c} header={c.replaceAll("_", " ")} body={(r: Cell) => r.counts[c] ?? 0} />)}
        </DataTable>
      )}
      <h2>Advisory impacts</h2>
      <ImpactsTable />
    </section>
  );
}
