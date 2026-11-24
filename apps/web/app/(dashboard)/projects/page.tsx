"use client";

import Link from "next/link";
import { useCallback, useEffect, useState } from "react";
import { Button } from "primereact/button";
import { Checkbox } from "primereact/checkbox";
import { Column } from "primereact/column";
import { DataTable } from "primereact/datatable";
import { Dialog } from "primereact/dialog";
import { Dropdown } from "primereact/dropdown";
import { InputText } from "primereact/inputtext";
import { Message } from "primereact/message";
import { api, ApiError } from "@/lib/api";
import { useCan } from "@/lib/me";

type Project = { id: string; name: string; slug: string; criticality: string; status: string; llm_allowed: boolean;
  components: { repositories: unknown[] }[] };

const CRIT = ["critical", "high", "medium", "low"].map((v) => ({ label: v, value: v }));

function NewProject({ onDone }: { onDone: (created: boolean) => void }) {
  const [name, setName] = useState("");
  const [slug, setSlug] = useState("");
  const [criticality, setCriticality] = useState("medium");
  const [llm, setLlm] = useState(true);
  const [error, setError] = useState<string | null>(null);
  async function save() {
    try {
      await api("/api/projects", { method: "POST", body: { name, slug, criticality, llm_allowed: llm } });
      onDone(true);
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Could not create the project");
    }
  }
  return (
    <Dialog header="New project" visible onHide={() => onDone(false)} style={{ width: "32rem" }}>
      {error && <Message severity="error" text={error} />}
      <div className="field"><label htmlFor="p-name">Name</label>
        <InputText id="p-name" value={name} onChange={(e) => setName(e.target.value)} style={{ width: "100%" }} /></div>
      <div className="field"><label htmlFor="p-slug">Slug (lowercase, digits, hyphens)</label>
        <InputText id="p-slug" value={slug} onChange={(e) => setSlug(e.target.value)} style={{ width: "100%" }} /></div>
      <div className="field"><label htmlFor="p-crit">Criticality</label>
        <Dropdown inputId="p-crit" value={criticality} options={CRIT} onChange={(e) => setCriticality(e.value)} /></div>
      <div className="field"><Checkbox inputId="p-llm" checked={llm} onChange={(e) => setLlm(!!e.checked)} />
        <label htmlFor="p-llm"> Allow redacted findings to be sent to the LLM (OQ-6)</label></div>
      <Button label="Create" onClick={save} disabled={!name || !slug} />
    </Dialog>
  );
}

export default function ProjectsPage() {
  const [rows, setRows] = useState<Project[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [creating, setCreating] = useState(false);
  const canManage = useCan("projects:manage");
  const load = useCallback(() => {
    api<Project[]>("/api/projects").then(setRows).catch((e) => setError(e instanceof ApiError ? e.message : "Load failed"));
  }, []);
  useEffect(load, [load]);

  return (
    <section>
      <h1>Projects</h1>
      {canManage && <Button label="New project" icon="pi pi-plus" onClick={() => setCreating(true)} />}
      {error && <p role="alert">{error}</p>}
      {rows && (
        <DataTable value={rows} dataKey="id" paginator paginatorPosition="bottom" rows={25} rowsPerPageOptions={[25, 50, 100]}
          size="small" stripedRows emptyMessage="No projects are registered yet.">
          <Column header="Project" body={(p: Project) => <Link href={`/projects/${p.id}`}>{p.name}</Link>} sortable sortField="name" />
          <Column field="criticality" header="Criticality" sortable />
          <Column field="status" header="Status" sortable />
          <Column header="Repositories" body={(p: Project) => p.components.reduce((n, c) => n + c.repositories.length, 0)} />
          <Column header="LLM allowed" body={(p: Project) => (p.llm_allowed ? "yes" : "no")} />
        </DataTable>
      )}
      {creating && <NewProject onDone={(ok) => { setCreating(false); if (ok) load(); }} />}
    </section>
  );
}
