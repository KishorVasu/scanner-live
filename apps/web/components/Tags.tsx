import { Tag } from "primereact/tag";

type Sev = "danger" | "warning" | "info" | "success" | "secondary" | "contrast" | null;

const SEVERITY: Record<string, Sev> = { critical: "danger", high: "danger", medium: "warning", low: "info", informational: "secondary" };

export function SeverityTag({ value }: { value: string | null }) {
  return <Tag value={value ?? "unknown"} severity={value ? SEVERITY[value] ?? null : "secondary"} />;
}

const IMPACT: Record<string, Sev> = {
  confirmed_affected: "danger", potentially_affected: "warning", needs_verification: "info",
  not_affected_on_evidence: "success", not_scanned: "contrast",
};

export function ImpactTag({ value }: { value: string }) {
  return <Tag value={value.replaceAll("_", " ")} severity={IMPACT[value] ?? null} />;
}

/**
 * Rule 11: "not scanned" must never look like "no findings". It gets its own dark tag and the word "not scanned";
 * a scanned project with no open findings says "no open findings from scans", never "clean" or "secure".
 */
export function ScanStateTag({ state }: { state: "not_scanned" | "partial" | "scanned" }) {
  if (state === "not_scanned") return <Tag value="not scanned" severity="contrast" icon="pi pi-eye-slash" />;
  if (state === "partial") return <Tag value="partly scanned" severity="warning" />;
  return <Tag value="scanned" severity="info" />;
}

export function StatusTag({ value }: { value: string }) {
  const sev: Sev = value === "failed" || value === "rejected" || value === "expired" ? "danger"
    : value === "succeeded" || value === "approved" || value === "executed" ? "success"
    : value === "pending" || value === "running" || value === "queued" || value === "draft" ? "warning" : "secondary";
  return <Tag value={value.replaceAll("_", " ")} severity={sev} />;
}

export function AiLabel() {
  return <Tag value="AI-written" severity="secondary" icon="pi pi-sparkles" aria-label="AI-written text" />;
}

export function when(iso: string | null | undefined): string {
  return iso ? new Date(iso).toLocaleString() : "—";
}
