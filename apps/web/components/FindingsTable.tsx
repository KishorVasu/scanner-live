"use client";

import { useEffect, useState } from "react";
import { Button } from "primereact/button";
import { Column } from "primereact/column";
import { DataTable } from "primereact/datatable";
import { Dialog } from "primereact/dialog";
import { Dropdown } from "primereact/dropdown";
import { InputTextarea } from "primereact/inputtextarea";
import { Message } from "primereact/message";
import { MultiSelect } from "primereact/multiselect";
import { api, ApiError } from "@/lib/api";
import { useCan } from "@/lib/me";
import { pagedProps, usePaged } from "@/lib/usePaged";
import { SeverityTag, StatusTag, when } from "@/components/Tags";

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

type Detail = Finding & { triage_note: string | null; advisory_ids: string[];
  evidence: { captured_at: string; evidence: string; commit_sha: string | null }[] };

const STATUSES = ["open", "in_progress", "false_positive", "accepted_risk", "resolved"];
const SEVERITIES = ["critical", "high", "medium", "low", "informational"];
const opts = (xs: string[]) => xs.map((x) => ({ label: x.replaceAll("_", " "), value: x }));

function where(f: Finding) {
  return f.package ? `${f.package}@${f.package_version ?? "?"}` : `${f.file_path ?? ""}${f.line ? `:${f.line}` : ""}`;
}

function TriageDialog({ id, onClose }: { id: string; onClose: (changed: boolean) => void }) {
  const [d, setD] = useState<Detail | null>(null);
  const [status, setStatus] = useState<string | null>(null);
  const [note, setNote] = useState("");
  const [error, setError] = useState<string | null>(null);
  const canTriage = useCan("findings:triage");
  const canAccept = useCan("findings:accept_risk");

  useEffect(() => {
    api<Detail>(`/api/findings/${id}`).then(setD).catch((e) => setError(e instanceof ApiError ? e.message : "Load failed"));
  }, [id]);
  const choices = ["open", "in_progress", ...(canAccept ? ["false_positive", "accepted_risk"] : [])];
  const needsNote = status === "false_positive" || status === "accepted_risk";

  async function save() {
    try {
      await api(`/api/findings/${id}`, { method: "PATCH", body: { status, note } });
      onClose(true);
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Save failed");
    }
  }

  return (
    <Dialog header={d?.title ?? "Finding"} visible onHide={() => onClose(false)} style={{ width: "48rem" }}>
      {error && <Message severity="error" text={error} />}
      {d && (
        <>
          <p><SeverityTag value={d.severity} /> <StatusTag value={d.status} /> {d.scanner} · {d.rule_id} · {where(d)}</p>
          {d.advisory_ids.length > 0 && <p>Advisories: {d.advisory_ids.join(", ")}</p>}
          {d.triage_note && <p><strong>Triage note:</strong> {d.triage_note}</p>}
          <h3>Evidence history</h3>
          <ul>{d.evidence.map((e, i) => <li key={i}>{when(e.captured_at)}: <code>{e.evidence}</code></li>)}</ul>
          {canTriage && d.status !== "resolved" && (
            <section aria-label="Triage">
              <h3>Triage</h3>
              <label htmlFor="triage-status">New status</label>
              <Dropdown inputId="triage-status" value={status} options={opts(choices)} onChange={(e) => setStatus(e.value)}
                placeholder="Choose" style={{ marginLeft: "0.5rem" }} />
              <div style={{ marginTop: "0.5rem" }}>
                <label htmlFor="triage-note">Note{needsNote ? " (required, at least 10 characters)" : ""}</label>
                <InputTextarea id="triage-note" value={note} onChange={(e) => setNote(e.target.value)} rows={3}
                  style={{ width: "100%" }} />
              </div>
              <Button label="Save" onClick={save} disabled={!status || (needsNote && note.trim().length < 10)} />
            </section>
          )}
          {d.status === "resolved" && <p>Resolved by a successful scan. It reopens only if a scan reports it again.</p>}
        </>
      )}
    </Dialog>
  );
}

export default function FindingsTable({ projectId }: { projectId?: string }) {
  const [status, setStatus] = useState<string[]>(["open", "in_progress"]);
  const [severity, setSeverity] = useState<string[]>([]);
  const [open, setOpen] = useState<string | null>(null);
  const query = [...status.map((s) => `status=${s}`), ...severity.map((s) => `severity=${s}`),
    ...(projectId ? [`project_id=${projectId}`] : [])].join("&");
  const p = usePaged<Finding>("/api/findings", query);

  if (p.error) return <p role="alert">{p.error}</p>;
  if (p.page && p.page.total === 0 && !p.page.scanned) {
    // Rule 11: never let "not scanned" read as "no findings".
    return <p><strong>Not scanned yet.</strong> No scan has completed, so there are no results. This is not the same as &ldquo;no findings&rdquo;.</p>;
  }

  return (
    <>
      <div style={{ display: "flex", gap: "1rem", marginBottom: "0.75rem", alignItems: "center" }}>
        <label htmlFor="f-status">Status</label>
        <MultiSelect inputId="f-status" value={status} options={opts(STATUSES)} onChange={(e) => setStatus(e.value)} display="chip" />
        <label htmlFor="f-sev">Severity</label>
        <MultiSelect inputId="f-sev" value={severity} options={opts(SEVERITIES)} onChange={(e) => setSeverity(e.value)}
          placeholder="Any" display="chip" />
      </div>
      <DataTable value={p.page?.items ?? []} dataKey="id" {...pagedProps(p)} selectionMode="single"
        onRowClick={(e) => setOpen((e.data as Finding).id)}
        emptyMessage="No findings match in completed scans. Scans can miss things; this does not mean the project is secure.">
        <Column header="Severity" body={(f: Finding) => <SeverityTag value={f.severity} />} />
        <Column field="project" header="Project" />
        <Column field="title" header="Title" />
        <Column header="Where" body={where} />
        <Column field="rule_id" header="Rule" />
        <Column field="scanner" header="Scanner" />
        <Column header="Status" body={(f: Finding) => <StatusTag value={f.status} />} />
        <Column header="Last seen" body={(f: Finding) => when(f.last_seen_at)} />
        <Column header="" body={(f: Finding) => <Button label="Open" text onClick={() => setOpen(f.id)} aria-label={`Open ${f.title}`} />} />
      </DataTable>
      {open && <TriageDialog id={open} onClose={(changed) => { setOpen(null); if (changed) p.reload(); }} />}
    </>
  );
}
