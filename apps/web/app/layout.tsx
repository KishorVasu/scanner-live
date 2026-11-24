import type { Metadata } from "next";
import { connection } from "next/server";
import "primereact/resources/themes/lara-light-blue/theme.css";
import "primereact/resources/primereact.min.css";
import "./globals.scss";

export const metadata: Metadata = { title: "Security Platform" };

export default async function RootLayout({ children }: { children: React.ReactNode }) {
  // Render per request so Next can stamp the CSP nonce (set in proxy.ts) on its scripts.
  // Prerendered HTML has no nonce and 'strict-dynamic' would block it.
  await connection();
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
