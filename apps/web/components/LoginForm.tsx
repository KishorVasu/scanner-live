"use client";

import { useState, type FormEvent } from "react";
import { InputText } from "primereact/inputtext";
import { Button } from "primereact/button";
import { Message } from "primereact/message";
import { api, ApiError } from "@/lib/api";
import styles from "./LoginForm.module.scss";

type Step = "credentials" | "setup" | "confirm";

export default function LoginForm({ onDone = () => window.location.assign("/") }: { onDone?: () => void }) {
  const [step, setStep] = useState<Step>("credentials");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [code, setCode] = useState("");
  const [uri, setUri] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  async function run(fn: () => Promise<void>) {
    setBusy(true);
    setError("");
    try {
      await fn();
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Request failed");
    } finally {
      setBusy(false);
    }
  }

  const submitCredentials = (e: FormEvent) => {
    e.preventDefault();
    run(async () => {
      const res = await api<{ status: string }>("/api/auth/login", {
        method: "POST",
        body: { email, password, totp_code: code || undefined },
      });
      if (res.status === "totp_setup_required") {
        const setup = await api<{ otpauth_uri: string }>("/api/auth/totp/setup", { method: "POST" });
        setUri(setup.otpauth_uri);
        setCode("");
        setStep("confirm");
      } else {
        onDone();
      }
    });
  };

  const submitConfirm = (e: FormEvent) => {
    e.preventDefault();
    run(async () => {
      await api("/api/auth/totp/confirm", { method: "POST", body: { code } });
      onDone();
    });
  };

  return (
    <main className={styles.wrap}>
      <h1 className={styles.title}>Security Platform</h1>
      {error && <Message severity="error" text={error} />}
      {step === "credentials" && (
        <form onSubmit={submitCredentials} className={styles.form}>
          <label htmlFor="email">Email</label>
          <InputText id="email" type="email" autoComplete="username" value={email}
            onChange={(e) => setEmail(e.target.value)} required />
          <label htmlFor="password">Password</label>
          <InputText id="password" type="password" autoComplete="current-password" value={password}
            onChange={(e) => setPassword(e.target.value)} required />
          <label htmlFor="totp">Authenticator code</label>
          <InputText id="totp" inputMode="numeric" autoComplete="one-time-code" maxLength={6} value={code}
            onChange={(e) => setCode(e.target.value)} />
          <Button type="submit" label="Sign in" loading={busy} />
        </form>
      )}
      {step === "confirm" && (
        <form onSubmit={submitConfirm} className={styles.form}>
          <p>Add this account to your authenticator app, then enter the 6-digit code.</p>
          {/* ponytail: manual-entry URI; add a QR renderer only if users ask for it. */}
          <code className={styles.uri} data-testid="otpauth-uri">{uri}</code>
          <label htmlFor="confirm">Authenticator code</label>
          <InputText id="confirm" inputMode="numeric" autoComplete="one-time-code" maxLength={6} value={code}
            onChange={(e) => setCode(e.target.value)} required />
          <Button type="submit" label="Confirm" loading={busy} />
        </form>
      )}
    </main>
  );
}
