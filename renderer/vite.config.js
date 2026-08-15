import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import path from 'path';

// Renderer Vite config.
// base './' ensures asset paths are relative — required for Electron's file:// protocol.
// outDir points to renderer/dist, which electron-builder picks up via `files` globs.
export default defineConfig({
  root: __dirname,
  plugins: [react()],
  base: './',
  build: {
    outDir: path.resolve(__dirname, 'dist'),
    emptyOutDir: true,
  },
  resolve: {
    alias: {
      '@': path.resolve(__dirname, 'src'),
    },
  },
  server: {
    port: 5173,
    strictPort: true,
  },
});
