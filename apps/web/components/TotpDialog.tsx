"use client";

import { useState } from "react";
import { Button } from "primereact/button";
import { Dialog } from "primereact/dialog";
import { InputText } from "primereact/inputtext";
import { Message } from "primereact/message";
import { ApiError } from "@/lib/api";

/** Re-authentication before a decision: the API checks the code; this only collects it. */
export default function TotpDialog({ title, confirm, onDone }: {
  title: string; confirm: (code: string) => Promise<unknown>; onDone: (ok: boolean) => void;
}) {
  const [code, setCode] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  async function go() {
    setBusy(true);
    try {
      await confirm(code);
      onDone(true);
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Failed");
    } finally {
      setBusy(false);
    }
  }
  return (
    <Dialog header={title} visible onHide={() => onDone(false)} style={{ width: "26rem" }}>
      {error && <Message severity="error" text={error} />}
      <label htmlFor="totp">Authenticator code</label>
      <InputText id="totp" value={code} onChange={(e) => setCode(e.target.value.replace(/\D/g, "").slice(0, 6))}
        inputMode="numeric" autoComplete="one-time-code" style={{ width: "100%", margin: "0.5rem 0" }} />
      <Button label="Confirm" onClick={go} disabled={code.length !== 6 || busy} />
    </Dialog>
  );
}
