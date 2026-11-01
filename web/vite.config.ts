import react from "@vitejs/plugin-react";
import { defineConfig } from "vitest/config";

// 5710 is this project's dedicated web port; the API is on 8710 (D0-02). The UI calls `/api/...`
// on its own origin and this forwards it, so the API needs no CORS (D1-09).
const api = {
  "^/api/": {
    target: `http://127.0.0.1:${process.env["STO_API_PORT"] ?? "8710"}`,
    rewrite: (path: string) => path.replace(/^\/api/, ""),
  },
};
export default defineConfig({
  plugins: [react()],
  server: { port: Number(process.env["STO_WEB_PORT"] ?? 5710), strictPort: true, proxy: api },
  preview: { port: Number(process.env["STO_WEB_PORT"] ?? 5710), strictPort: true, proxy: api },
  test: { environment: "jsdom", include: ["src/**/*.test.{ts,tsx}"] },
});
