// Dashboard sections and the phase that builds each one (docs/IMPLEMENTATION_ROADMAP.md). All built in Phase 5 except
// Learning Notes, which stays a placeholder (later phase).
export const SECTIONS = [
  { href: "/", label: "Overview", phase: 5 },
  { href: "/projects", label: "Projects", phase: 2 },
  { href: "/intelligence", label: "Security Intelligence", phase: 4 },
  { href: "/findings", label: "Scans & Findings", phase: 3 },
  { href: "/integrity", label: "Repository Integrity", phase: 3 },
  { href: "/reports", label: "Reports", phase: 5 },
  { href: "/approvals", label: "Approvals", phase: 5 },
  { href: "/learning-notes", label: "Learning Notes", phase: 7 },
  { href: "/settings", label: "Settings", phase: 2 },
  { href: "/audit", label: "Audit Log", phase: 5 },
] as const;
