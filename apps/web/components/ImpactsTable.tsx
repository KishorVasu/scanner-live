"use client";

import { useState } from "react";
import { Column } from "primereact/column";
import { DataTable, type DataTableExpandedRows } from "primereact/datatable";
import { MultiSelect } from "primereact/multiselect";
import { pagedProps, usePaged } from "@/lib/usePaged";
import { AiLabel, ImpactTag, SeverityTag, when } from "@/components/Tags";

type Impact = {
  id: string; project: string; classification: string; reasoning: string; references: string[];
  decided_by_rule: string | null; decided_at: string;
  advisory: { external_id: string; aliases: string[]; title: string; url: string | null; package: string | null;
    severity: string | null; known_exploited: boolean; patched_versions: string[]; vendor_facts: string;
    ai_interpretation: string | null; extra_conditions: { condition: string; quote: string }[] | null };
};

const CLASSES = ["confirmed_affected", "potentially_affected", "needs_verification", "not_affected_on_evidence", "not_scanned"];

/** Vendor facts and AI interpretation are always shown apart, and the AI part is labelled. */
function Detail({ i }: { i: Impact }) {
  const a = i.advisory;
  return (
    <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "1rem" }}>
      <div>
        <h4>Vendor facts ({a.external_id})</h4>
        <p style={{ whiteSpace: "pre-wrap" }}>{a.vendor_facts}</p>
        {a.url && <p><a href={a.url} target="_blank" rel="noopener noreferrer">Source advisory</a></p>}
        <p>Fixed in: {a.patched_versions.join(", ") || "no fixed version published"}</p>
      </div>
      <div>
        <h4>Interpretation <AiLabel /></h4>
        <p>{a.ai_interpretation ?? "No AI interpretation yet."}</p>
        {a.extra_conditions && a.extra_conditions.length > 0 && (
          <ul>{a.extra_conditions.map((c, k) => <li key={k}>{c.condition} — <q>{c.quote}</q></li>)}</ul>)}
        <h4>Why this classification</h4>
        <p>{i.reasoning}</p>
        <p>{i.decided_by_rule ? `Decided by rule ${i.decided_by_rule}` : "Chosen by the Impact Analysis agent within the rules"}
          {" "}on {when(i.decided_at)}.</p>
      </div>
    </div>
  );
}

export default function ImpactsTable({ projectId }: { projectId?: string }) {
  const [classes, setClasses] = useState<string[]>(["confirmed_affected", "potentially_affected", "needs_verification"]);
  const [expanded, setExpanded] = useState<DataTableExpandedRows | undefined>();
  const query = [...classes.map((c) => `classification=${c}`), ...(projectId ? [`project_id=${projectId}`] : [])].join("&");
  const p = usePaged<Impact>("/api/impacts", query);
  if (p.error) return <p role="alert">{p.error}</p>;
  return (
    <>
      <div style={{ marginBottom: "0.75rem" }}>
        <label htmlFor="i-class">Impact </label>
        <MultiSelect inputId="i-class" value={classes} options={CLASSES.map((c) => ({ label: c.replaceAll("_", " "), value: c }))}
          onChange={(e) => setClasses(e.value)} display="chip" placeholder="Any" />
      </div>
      <DataTable value={p.page?.items ?? []} dataKey="id" {...pagedProps(p)} expandedRows={expanded}
        onRowToggle={(e) => setExpanded(e.data as DataTableExpandedRows)} rowExpansionTemplate={(i: Impact) => <Detail i={i} />}
        emptyMessage="No advisory impacts match. Advisory matching only covers inventoried repositories.">
        <Column expander style={{ width: "3rem" }} />
        <Column header="Impact" body={(i: Impact) => <ImpactTag value={i.classification} />} />
        <Column field="project" header="Project" />
        <Column header="Advisory" body={(i: Impact) => i.advisory.external_id} />
        <Column header="Package" body={(i: Impact) => i.advisory.package} />
        <Column header="Severity" body={(i: Impact) => <SeverityTag value={i.advisory.severity} />} />
        <Column header="Known exploited" body={(i: Impact) => (i.advisory.known_exploited ? "yes (CISA KEV)" : "")} />
        <Column header="Title" body={(i: Impact) => i.advisory.title} />
      </DataTable>
    </>
  );
}
