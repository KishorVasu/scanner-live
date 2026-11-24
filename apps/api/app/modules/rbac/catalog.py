"""Role → permission matrix from docs/SECURITY_POLICIES.md §4.

The baseline migration seeds a frozen copy of this; tests/test_rbac.py fails if they drift.
"""

ROLES = ("admin", "approver", "developer", "viewer")

ROLE_PERMISSIONS: dict[str, frozenset[str]] = {
    "admin": frozenset({
        "dashboard:view", "projects:manage", "scans:trigger", "findings:triage", "findings:accept_risk",
        "approvals:request", "agents:manage", "github:manage", "users:manage", "policies:manage", "audit:view",
    }),
    "approver": frozenset({
        "dashboard:view", "scans:trigger", "findings:triage", "findings:accept_risk",
        "approvals:request", "approvals:decide", "reports:approve", "audit:view",
    }),
    "developer": frozenset({"dashboard:view", "scans:trigger", "findings:triage", "approvals:request"}),
    "viewer": frozenset({"dashboard:view"}),
}

ALL_PERMISSIONS = frozenset().union(*ROLE_PERMISSIONS.values())
