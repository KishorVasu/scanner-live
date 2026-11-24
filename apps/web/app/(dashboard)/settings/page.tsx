"use client";

import { useCallback, useEffect, useState } from "react";
import { Button } from "primereact/button";
import { Column } from "primereact/column";
import { DataTable } from "primereact/datatable";
import { Dialog } from "primereact/dialog";
import { InputText } from "primereact/inputtext";
import { Message } from "primereact/message";
import { MultiSelect } from "primereact/multiselect";
import { Password } from "primereact/password";
import { api, ApiError } from "@/lib/api";
import { useCan, useMe } from "@/lib/me";

type User = { id: string; email: string; roles: string[]; is_active: boolean; totp_enrolled: boolean };
const ROLES = ["admin", "approver", "developer", "viewer"].map((r) => ({ label: r, value: r }));

function NewUser({ onDone }: { onDone: (ok: boolean) => void }) {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [roles, setRoles] = useState<string[]>(["viewer"]);
  const [error, setError] = useState<string | null>(null);
  async function save() {
    try {
      await api("/api/users", { method: "POST", body: { email, password, roles } });
      onDone(true);
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Could not create the user");
    }
  }
  return (
    <Dialog header="New user" visible onHide={() => onDone(false)} style={{ width: "28rem" }}>
      {error && <Message severity="error" text={error} />}
      <div className="field"><label htmlFor="u-email">Email</label>
        <InputText id="u-email" value={email} onChange={(e) => setEmail(e.target.value)} style={{ width: "100%" }} /></div>
      <div className="field"><label htmlFor="u-pass">Initial password</label>
        <Password inputId="u-pass" value={password} onChange={(e) => setPassword(e.target.value)} feedback={false} toggleMask /></div>
      <div className="field"><label htmlFor="u-roles">Roles</label>
        <MultiSelect inputId="u-roles" value={roles} options={ROLES} onChange={(e) => setRoles(e.value)} display="chip" /></div>
      <p>The user enrols an authenticator app at first sign-in.</p>
      <Button label="Create" onClick={save} disabled={!email || !password || roles.length === 0} />
    </Dialog>
  );
}

export default function SettingsPage() {
  const me = useMe();
  const canManage = useCan("users:manage");
  const [users, setUsers] = useState<User[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [creating, setCreating] = useState(false);
  const load = useCallback(() => {
    if (!canManage) return;
    api<User[]>("/api/users").then(setUsers).catch((e) => setError(e instanceof ApiError ? e.message : "Load failed"));
  }, [canManage]);
  useEffect(load, [load]);

  async function deactivate(u: User) {
    try {
      await api(`/api/users/${u.id}/deactivate`, { method: "POST" });
      load();
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Failed");
    }
  }

  return (
    <section>
      <h1>Settings</h1>
      <h2>Your account</h2>
      <p>{me?.email} · roles: {me?.roles.join(", ")}</p>
      {canManage && (
        <>
          <h2>Users</h2>
          <Button label="New user" icon="pi pi-plus" onClick={() => setCreating(true)} />
          {error && <p role="alert">{error}</p>}
          <DataTable value={users ?? []} dataKey="id" size="small" stripedRows paginator paginatorPosition="bottom" rows={25}>
            <Column field="email" header="Email" sortable />
            <Column header="Roles" body={(u: User) => u.roles.join(", ")} />
            <Column header="Authenticator" body={(u: User) => (u.totp_enrolled ? "enrolled" : "not enrolled")} />
            <Column header="Active" body={(u: User) => (u.is_active ? "yes" : "no")} />
            <Column header="" body={(u: User) => u.is_active && u.id !== me?.id && (
              <Button label="Deactivate" size="small" severity="danger" text onClick={() => deactivate(u)}
                aria-label={`Deactivate ${u.email}`} />)} />
          </DataTable>
          {creating && <NewUser onDone={(ok) => { setCreating(false); if (ok) load(); }} />}
        </>
      )}
    </section>
  );
}
