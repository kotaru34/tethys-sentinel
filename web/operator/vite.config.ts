import { defineConfig } from "vite";
import preact from "@preact/preset-vite";

export default defineConfig({
  plugins: [preact()],
  base: "/",
  build: {
    outDir: "../../internal/operatorweb/dist",
    emptyOutDir: true,
    sourcemap: false,
    assetsDir: "assets",
  },
});
