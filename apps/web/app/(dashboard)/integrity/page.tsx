"use client";

import { Column } from "primereact/column";
import { DataTable } from "primereact/datatable";
import { pagedProps, usePaged } from "@/lib/usePaged";
import { SeverityTag, when } from "@/components/Tags";

type Event = { id: string; project: string; component: string; kind: string; severity: string; ref: string | null;
  before_sha: string | null; after_sha: string | null; source: string; created_at: string; detail: Record<string, unknown> };

export default function IntegrityPage() {
  const p = usePaged<Event>("/api/integrity/events");
  return (
    <section>
      <h1>Repository Integrity</h1>
      <p>Force-pushes, history rewrites and suspicious changes, detected statically. Nothing here was executed.</p>
      {p.error && <p role="alert">{p.error}</p>}
      <DataTable value={p.page?.items ?? []} dataKey="id" {...pagedProps(p)}
        emptyMessage="No integrity events recorded. Only repositories connected through the GitHub App or a local agent are watched.">
        <Column header="When" body={(e: Event) => when(e.created_at)} />
        <Column header="Severity" body={(e: Event) => <SeverityTag value={e.severity} />} />
        <Column header="Event" body={(e: Event) => e.kind.replaceAll("_", " ")} />
        <Column field="project" header="Project" />
        <Column field="component" header="Component" />
        <Column field="ref" header="Ref" />
        <Column header="Commits" body={(e: Event) => e.before_sha ? `${e.before_sha.slice(0, 8)} → ${(e.after_sha ?? "").slice(0, 8)}` : ""} />
        <Column field="source" header="Source" />
      </DataTable>
    </section>
  );
}
