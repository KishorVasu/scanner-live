// Dashboard sections and the phase that built each one (docs/IMPLEMENTATION_ROADMAP.md). Learning Notes was removed
// from scope on 2026-11-25.
export const SECTIONS = [
  { href: "/", label: "Overview", phase: 5 },
  { href: "/projects", label: "Projects", phase: 2 },
  { href: "/intelligence", label: "Security Intelligence", phase: 4 },
  { href: "/findings", label: "Scans & Findings", phase: 3 },
  { href: "/integrity", label: "Repository Integrity", phase: 3 },
  { href: "/reports", label: "Reports", phase: 5 },
  { href: "/approvals", label: "Approvals", phase: 5 },
  { href: "/settings", label: "Settings", phase: 2 },
  { href: "/audit", label: "Audit Log", phase: 5 },
] as const;
