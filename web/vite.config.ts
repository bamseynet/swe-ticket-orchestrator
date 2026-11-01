import react from "@vitejs/plugin-react";
import { defineConfig } from "vitest/config";

// 5710 is this project's dedicated web port; the API is on 8710 (D0-02).
export default defineConfig({
  plugins: [react()],
  server: { port: Number(process.env["STO_WEB_PORT"] ?? 5710), strictPort: true },
  test: { environment: "jsdom", include: ["src/**/*.test.{ts,tsx}"] },
});
