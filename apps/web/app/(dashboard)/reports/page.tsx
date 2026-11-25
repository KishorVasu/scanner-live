"use client";

import { useEffect, useState } from "react";
import { Button } from "primereact/button";
import { Column } from "primereact/column";
import { DataTable } from "primereact/datatable";
import { Dialog } from "primereact/dialog";
import { Dropdown } from "primereact/dropdown";
import { Message } from "primereact/message";
import { api, ApiError } from "@/lib/api";
import { useCan, useMe } from "@/lib/me";
import { pagedProps, usePaged } from "@/lib/usePaged";
import { AiLabel, StatusTag, when } from "@/components/Tags";
import TotpDialog from "@/components/TotpDialog";

type Report = { id: string; kind: string; title: string; status: string; created_at: string; created_by: string;
  approved_by: string | null; has_narrative: boolean; narrative_note: string | null };
type Full = Report & { narrative: string | null; content: { statement: string; not_scanned: string[];
  projects: { project: string; open_findings_by_severity: Record<string, number> }[] } };

function View({ id, onClose }: { id: string; onClose: () => void }) {
  const [r, setR] = useState<Full | null>(null);
  useEffect(() => { api<Full>(`/api/reports/${id}`).then(setR).catch(() => setR(null)); }, [id]);
  return (
    <Dialog header={r?.title ?? "Report"} visible onHide={onClose} style={{ width: "50rem" }}>
      {r && (
        <>
          <p><StatusTag value={r.status} /> {r.status === "draft" && "Draft: not approved yet."}</p>
          <Message severity="warn" text={r.content.statement} />
          <h3>Not scanned</h3>
          {r.content.not_scanned.length ? <ul>{r.content.not_scanned.map((n) => <li key={n}>{n}</li>)}</ul>
            : <p>Every listed repository has at least one successful scan.</p>}
          {r.narrative ? (<><h3>Summary <AiLabel /></h3><p style={{ whiteSpace: "pre-wrap" }}>{r.narrative}</p></>)
            : r.narrative_note && <p><em>{r.narrative_note}</em></p>}
          <h3>Projects</h3>
          <ul>{r.content.projects.map((p) => <li key={p.project}>{p.project}: {Object.entries(p.open_findings_by_severity)
            .map(([k, v]) => `${k} ${v}`).join(", ") || "no open findings recorded by scans"}</li>)}</ul>
          <a href={`/api/reports/${r.id}/pdf`}>Download PDF</a>
        </>
      )}
    </Dialog>
  );
}

export default function ReportsPage() {
  const me = useMe();
  const canGenerate = useCan("scans:trigger");
  const canApprove = useCan("reports:approve");
  const p = usePaged<Report>("/api/reports");
  const [projects, setProjects] = useState<{ label: string; value: string | null }[]>([]);
  const [scope, setScope] = useState<string | null>(null);
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);
  const [viewing, setViewing] = useState<string | null>(null);
  const [approving, setApproving] = useState<Report | null>(null);

  useEffect(() => {
    api<{ id: string; name: string }[]>("/api/projects")
      .then((ps) => setProjects([{ label: "All projects (portfolio)", value: null }, ...ps.map((x) => ({ label: x.name, value: x.id }))]))
      .catch(() => setProjects([{ label: "All projects (portfolio)", value: null }]));
  }, []);

  async function generate() {
    try {
      await api("/api/reports", { method: "POST", body: { project_id: scope } });
      setMsg({ ok: true, text: "Report requested. The draft appears here when the worker finishes." });
    } catch (e) {
      setMsg({ ok: false, text: e instanceof ApiError ? e.message : "Request failed" });
    }
  }

  return (
    <section>
      <h1>Reports</h1>
      <p>Reports are drafts until an approver who did not request them approves them.</p>
      {canGenerate && (
        <div style={{ display: "flex", gap: "0.5rem", alignItems: "center", marginBottom: "0.75rem" }}>
          <label htmlFor="r-scope">Scope</label>
          <Dropdown inputId="r-scope" pt={{ select: { "aria-label": "Scope" }, trigger: { "aria-label": "Show Scope options" } }} value={scope} options={projects} onChange={(e) => setScope(e.value)} />
          <Button label="Generate draft" onClick={generate} />
        </div>
      )}
      {msg && <Message severity={msg.ok ? "info" : "error"} text={msg.text} />}
      {p.error && <p role="alert">{p.error}</p>}
      <DataTable value={p.page?.items ?? []} dataKey="id" {...pagedProps(p)} emptyMessage="No reports yet.">
        <Column header="Created" body={(r: Report) => when(r.created_at)} />
        <Column field="title" header="Title" />
        <Column header="Status" body={(r: Report) => <StatusTag value={r.status} />} />
        <Column header="AI summary" body={(r: Report) => (r.has_narrative ? "included" : r.narrative_note ? "none" : "")} />
        <Column header="" body={(r: Report) => (
          <span>
            <Button label="View" text onClick={() => setViewing(r.id)} aria-label={`View ${r.title}`} />
            {canApprove && r.status === "draft" && (
              <span title={r.created_by === me?.id ? "You requested this report; another approver must approve it" : undefined}>
                <Button label="Approve" size="small" disabled={r.created_by === me?.id} onClick={() => setApproving(r)} />
              </span>
            )}
          </span>
        )} />
      </DataTable>
      {viewing && <View id={viewing} onClose={() => setViewing(null)} />}
      {approving && (
        <TotpDialog title={`Approve ${approving.title}`}
          confirm={(code) => api(`/api/reports/${approving.id}/approve`, { method: "POST", body: { totp_code: code } })}
          onDone={(ok) => { setApproving(null); if (ok) p.reload(); }} />
      )}
    </section>
  );
}
