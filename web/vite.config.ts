import react from '@vitejs/plugin-react';
import { defineConfig } from 'vite';

export default defineConfig({
  plugins: [react()],
  server: {
    // `npm run dev` talks to the FastAPI server on :8000.
    proxy: { '/api': 'http://127.0.0.1:8000', '/healthz': 'http://127.0.0.1:8000' },
  },
  build: { outDir: 'dist', sourcemap: false },
});
