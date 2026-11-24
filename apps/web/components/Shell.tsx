"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { useEffect, useState } from "react";
import { Button } from "primereact/button";
import { api, ApiError } from "@/lib/api";
import { SECTIONS } from "@/lib/sections";
import { MeContext, type Me } from "@/lib/me";
import styles from "./Shell.module.scss";


export default function Shell({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();
  const [me, setMe] = useState<Me | null>(null);

  useEffect(() => {
    api<Me>("/api/auth/me")
      .then(setMe)
      .catch((e) => {
        if (e instanceof ApiError && e.status === 401) window.location.assign("/login");
      });
  }, []);

  // The API enforces every permission; hiding content here is only presentation.
  if (!me) return <p className={styles.loading}>Loading…</p>;

  async function logout() {
    await api("/api/auth/logout", { method: "POST" }).catch(() => undefined);
    window.location.assign("/login");
  }

  return (
    <div className={styles.shell}>
      <nav className={styles.nav} aria-label="Main">
        <strong className={styles.brand}>Security Platform</strong>
        <ul>
          {SECTIONS.map((s) => (
            <li key={s.href}>
              <Link href={s.href} aria-current={pathname === s.href ? "page" : undefined}
                className={pathname === s.href ? styles.active : undefined}>
                {s.label}
              </Link>
            </li>
          ))}
        </ul>
      </nav>
      <div className={styles.main}>
        <header className={styles.header}>
          <span>{me.email} · {me.roles.join(", ")}</span>
          <Button label="Sign out" text onClick={logout} />
        </header>
        <MeContext.Provider value={me}>
          <main>{children}</main>
        </MeContext.Provider>
      </div>
    </div>
  );
}
