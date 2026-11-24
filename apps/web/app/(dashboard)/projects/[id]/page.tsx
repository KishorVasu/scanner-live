"use client";

import { use, useEffect, useState } from "react";
import { Column } from "primereact/column";
import { DataTable } from "primereact/datatable";
import { TabPanel, TabView } from "primereact/tabview";
import { api, ApiError } from "@/lib/api";
import FindingsTable from "@/components/FindingsTable";
import ImpactsTable from "@/components/ImpactsTable";
import ScansTable from "@/components/ScansTable";
import { when } from "@/components/Tags";

type Repo = { id: string; source: string; full_name: string | null; local_path_alias: string | null;
  inventory_complete: boolean | null; last_inventory_at: string | null };
type Project = { id: string; name: string; description: string | null; criticality: string; status: string;
  llm_allowed: boolean; components: { id: string; kind: string; name: string; repositories: Repo[] }[] };

export default function ProjectPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = use(params);
  const [p, setP] = useState<Project | null>(null);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    api<Project>(`/api/projects/${id}`).then(setP).catch((e) => setError(e instanceof ApiError ? e.message : "Load failed"));
  }, [id]);
  if (error) return <p role="alert">{error}</p>;
  if (!p) return <p>Loading…</p>;
  const repos = p.components.flatMap((c) => c.repositories.map((r) => ({ ...r, component: c.name, kind: c.kind })));

  return (
    <section>
      <h1>{p.name}</h1>
      <p>Criticality {p.criticality} · status {p.status} · LLM {p.llm_allowed ? "allowed" : "not allowed"}</p>
      {p.description && <p>{p.description}</p>}
      <TabView>
        <TabPanel header="Repositories">
          <DataTable value={repos} dataKey="id" size="small" stripedRows paginator paginatorPosition="bottom" rows={25}
            emptyMessage="No repositories registered; nothing in this project is scanned.">
            <Column field="component" header="Component" />
            <Column field="kind" header="Kind" />
            <Column header="Repository" body={(r: Repo) => r.full_name ?? r.local_path_alias ?? r.id} />
            <Column field="source" header="Source" />
            <Column header="Inventory" body={(r: Repo) => r.inventory_complete === null ? "never inventoried"
              : r.inventory_complete ? "complete" : "partial"} />
            <Column header="Last inventory" body={(r: Repo) => when(r.last_inventory_at)} />
          </DataTable>
        </TabPanel>
        <TabPanel header="Findings"><FindingsTable projectId={id} /></TabPanel>
        <TabPanel header="Advisory impacts"><ImpactsTable projectId={id} /></TabPanel>
        <TabPanel header="Scan history"><ScansTable projectId={id} /></TabPanel>
      </TabView>
    </section>
  );
}
