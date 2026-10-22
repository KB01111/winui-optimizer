import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

// Vite config for the AI Antivirus dashboard.
//
// Tauri (see src-tauri/tauri.conf.json) expects:
//   - devUrl            http://localhost:1420  -> fixed port, strictPort
//   - frontendDist      ../dist                -> default `vite build` output
//
// `envPrefix` exposes VITE_* and TAURI_* variables to the webview.
export default defineConfig({
  plugins: [react()],
  clearScreen: false,
  server: {
    port: 1420,
    strictPort: true,
  },
  envPrefix: ['VITE_', 'TAURI_'],
  build: {
    // WebView2 on supported Windows 11 builds is Chromium 105+.
    target: 'chrome105',
    sourcemap: false,
    // Fluent UI v9 is a large (but local-disk) dependency; the dashboard is
    // loaded from the app bundle, not the network.
    chunkSizeWarningLimit: 1000,
  },
});
