import { defineConfig } from 'vitest/config';
import react from '@vitejs/plugin-react';

// Frontend test config. Kept separate from vite.config.ts so that the dev
// server / build configuration mirrors exactly what Tauri expects.
export default defineConfig({
  plugins: [react()],
  test: {
    environment: 'jsdom',
    setupFiles: ['tests/frontend/setup.ts'],
    include: ['tests/frontend/**/*.test.{ts,tsx}'],
    css: false,
    clearMocks: true,
  },
});
