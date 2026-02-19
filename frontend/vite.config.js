import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  server: {
    port: 3001,
    proxy: {
      "/analyze": "http://backend:8001",
      "/export":  "http://backend:8001",
      "/health":  "http://backend:8001",
    },
  },
});
