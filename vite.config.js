import { defineConfig } from 'vite';

// Root vite config — used for any top-level Vite operations.
// The renderer has its own vite.config.js at renderer/vite.config.js.
export default defineConfig({
  // Root-level config intentionally minimal; renderer config drives the build.
});
