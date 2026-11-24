import { defineConfig } from "vitest/config";
import react from "@vitejs/plugin-react";
import { fileURLToPath } from "node:url";

export default defineConfig({
  plugins: [react()],
  resolve: { alias: { "@": fileURLToPath(new URL(".", import.meta.url)) } },
  css: { modules: { localsConvention: "camelCase" } },
  test: { environment: "jsdom", include: ["tests/**/*.test.tsx", "tests/**/*.test.ts"], css: false },
});
